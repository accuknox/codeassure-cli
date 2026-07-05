"""Enrichment + graph-coloring pass (runs after verdicts are decided).

A dedicated pass keeps the hot analyzer prompt lean and mirrors the existing
evaluator/validator multi-pass design. Produces an ``Enrichment`` per finding:
rationale, business logic, developer explanation, a safe copy-paste remediation,
and a per-node / per-path color overlay for the deterministic context graph.
"""

from __future__ import annotations

import asyncio
import logging

from pydantic_ai import Agent, PromptedOutput

from ..config import get_config
from ..prompts.enrich import ENRICH_INSTRUCTION, build_enrich_message
from ..schema import Enrichment, EvidenceBundle, Verdict
from .deps import AnalyzerDeps
from .runner import _build_deps, _build_run_kwargs
from .tools import grep_code, read_file

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
    # Let the enricher confirm sanitizer sufficiency by reading code, when supported.
    if cfg.model.tool_calling and not cfg.findings_analysis:
        kwargs["tools"] = [read_file, grep_code]
    return Agent(cfg.build_model(), **kwargs)


async def _enrich_one(
    enricher, index: int, bundle: EvidenceBundle, verdict: Verdict,
    codebase, sem: asyncio.Semaphore, timeout: float, request_limit: int,
) -> tuple[int, Enrichment | None]:
    async with sem:
        deps = _build_deps(codebase, bundle.finding.path)
        run_kwargs, _ = _build_run_kwargs(deps, request_limit, None,
                                          label=f"enrich {bundle.finding.path}:{bundle.finding.line}")
        message = build_enrich_message(bundle, verdict)
        try:
            result = await asyncio.wait_for(enricher.run(message, **run_kwargs), timeout=timeout)
            return index, result.output
        except asyncio.TimeoutError:
            log.warning("enrich: timed out for %s:%s", bundle.finding.path, bundle.finding.line)
        except Exception as exc:
            log.warning("enrich: failed for %s:%s: %s", bundle.finding.path, bundle.finding.line, exc)
        return index, None


async def enrich_all(
    items: list[tuple[int, EvidenceBundle, Verdict]],
    codebase,
    concurrency: int,
) -> dict[int, Enrichment]:
    """Enrich a set of (index, bundle, verdict) items. Returns {index: Enrichment}."""
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
    return {i: e for i, e in results if e is not None}
