"""Enrichment pass (runs after verdicts are decided).

A dedicated pass keeps the hot analyzer prompt lean and mirrors the existing
evaluator/validator multi-pass design. Produces an ``Enrichment`` per finding:
rationale, business logic, developer explanation, and a paste-ready remediation
with an exact paste target. Every finding gets an enrichment — when the LLM is
unavailable a deterministic fallback is emitted so the output schema is stable.
"""

from __future__ import annotations

import asyncio
import logging

from pydantic_ai import Agent, PromptedOutput

from ..config import get_config
from ..prompts.enrich import ENRICH_INSTRUCTION, build_enrich_message
from ..schema import Enrichment, EvidenceBundle, Remediation, Verdict
from .deps import AnalyzerDeps
from .runner import _build_deps, _build_run_kwargs, _error_detail, _run_with_retry
from .tools import grep_code, read_file, trace_callers

log = logging.getLogger(__name__)

_OUTPUT_RETRIES = 3


def build_enricher() -> Agent[AnalyzerDeps, Enrichment]:
    cfg = get_config()
    kwargs: dict = dict(
        deps_type=AnalyzerDeps,
        output_type=PromptedOutput(Enrichment),
        instructions=ENRICH_INSTRUCTION,
        output_retries=_OUTPUT_RETRIES,
    )
    # Let the enricher confirm sanitizer sufficiency / paste regions by reading code.
    if cfg.model.tool_calling and not cfg.findings_analysis:
        kwargs["tools"] = [read_file, grep_code, trace_callers]
    return Agent(cfg.build_model(), **kwargs)


def fallback_enrichment(bundle: EvidenceBundle, verdict: Verdict, error: str | None = None) -> Enrichment:
    """Deterministic enrichment when the LLM pass failed/was unavailable.

    Honest and minimal: rationale mirrors the verdict reason, remediation points
    at the flagged region with the scanner's own suggested fix when one exists.
    Keeps the output schema stable so downstream consumers (UI, dashboards)
    never miss the keys.
    """
    f = bundle.finding
    note = f"Automated enrichment unavailable ({error})." if error else \
        "Automated enrichment unavailable."
    cg = getattr(f, "context_graph", None)
    flow = ""
    if isinstance(cg, dict) and cg.get("paths"):
        n_paths = len(cg["paths"])
        reach = sorted({p.get("reachability") or "?" for p in cg["paths"]})
        tainted = sum(1 for p in cg["paths"] if p.get("tainted"))
        flow = (f" Deterministic context graph: {n_paths} source→sink path(s), "
                f"reachability {'/'.join(reach)}, {tainted} tainted.")
    return Enrichment(
        rationale=verdict.reason,
        business_logic=f"Code at {f.path}:{f.line} flagged by {f.check_id}. {note}",
        explanation=(f.message or "").strip() + flow,
        remediation=Remediation(
            summary=(f.fix.strip().splitlines()[0] if f.fix else
                     "Review the flagged line and apply the rule's recommended fix."),
            code_patch="",
            file=f.path,
            start_line=f.line,
            end_line=f.end_line,
            original_code=f.lines or "",
            preserves_logic=True,
            notes=note + (" Scanner-suggested fix included in summary." if f.fix else ""),
        ),
    )


async def _enrich_one(
    enricher, index: int, bundle: EvidenceBundle, verdict: Verdict,
    codebase, sem: asyncio.Semaphore, timeout: float, request_limit: int,
) -> tuple[int, Enrichment]:
    label = f"enrich {bundle.finding.path}:{bundle.finding.line}"
    async with sem:
        deps = _build_deps(codebase, bundle.finding.path)
        run_kwargs, _ = _build_run_kwargs(deps, request_limit, None, label=label)
        message = build_enrich_message(bundle, verdict)
        try:
            result = await asyncio.wait_for(
                _run_with_retry(enricher, message, label=label, **run_kwargs),
                timeout=timeout,
            )
            return index, result.output
        except asyncio.TimeoutError:
            log.warning("enrich: timed out for %s:%s", bundle.finding.path, bundle.finding.line)
            return index, fallback_enrichment(bundle, verdict, f"timed out after {timeout:.0f}s")
        except Exception as exc:
            log.warning("enrich: failed for %s:%s: %s", bundle.finding.path, bundle.finding.line, exc)
            return index, fallback_enrichment(bundle, verdict, _error_detail(exc))


async def enrich_all(
    items: list[tuple[int, EvidenceBundle, Verdict]],
    codebase,
    concurrency: int,
) -> dict[int, Enrichment]:
    """Enrich a set of (index, bundle, verdict) items. Returns {index: Enrichment}.

    Never drops an item: failures degrade to fallback_enrichment().
    """
    if not items:
        return {}
    cfg = get_config()
    enricher = build_enricher()
    sem = asyncio.Semaphore(max(1, concurrency))
    results = await asyncio.gather(*(
        _enrich_one(enricher, i, b, v, codebase, sem,
                    timeout=cfg.finding_timeout, request_limit=cfg.request_limit)
        for i, b, v in items
    ))
    return dict(results)
