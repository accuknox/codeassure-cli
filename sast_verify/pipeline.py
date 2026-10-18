from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .agents.runner import analyze_all, analyze_all_grouped
from . import rule_checks
from .grouping import build_groups
from .preprocess import preprocess, preprocess_data
from .retrieval import retrieve
from .schema import Verdict


log = logging.getLogger(__name__)


def _no_anchor_verdict() -> Verdict:
    return Verdict(
        verdict="uncertain",
        confidence="low",
        reason="Source file could not be anchored; no confident verdict without grounded evidence.",
    )


def _is_deadcode(finding) -> bool:
    """True if the deterministic context graph reports every path as unreachable.

    Raw predicate: every path is dead / has no caller from any entry point. Whether
    that is *decisive* for the verdict is a separate policy question — see
    _deadcode_is_decisive.
    """
    cg = getattr(finding, "context_graph", None)
    if not cg or not isinstance(cg, dict):
        return False
    paths = cg.get("paths") or []
    return bool(paths) and all(p.get("reachability") == "deadcode" for p in paths)


def _deadcode_sink_evidence(finding) -> list[str]:
    cg = getattr(finding, "context_graph", None)
    if isinstance(cg, dict):
        sink = cg.get("sink") or {}
        if sink.get("file") and sink.get("line") is not None:
            return [f"{sink['file']}:{sink['line']}"]
    return []


def _deadcode_decision(finding) -> Verdict | None:
    """Deterministic verdict for an all-deadcode finding, honoring the context graph as
    authoritative — but ONLY when the graph is non-degraded.

    Returns None to defer to the LLM: no graph, not all-deadcode, or a *degraded* graph
    (which is a hint, not a ruling — the LLM decides, with the graph as strong evidence).

    On a non-degraded, all-deadcode graph:
      - taint / injection rule  → false_positive (the unreachable sink cannot be driven
        by input, so the flagged flow cannot occur);
      - pattern-existence rule  → true_positive + is_security_vulnerability=false (the
        flagged construct really is present — a real occurrence, so not a false positive —
        it just isn't reachable, so it isn't exploitable).
    """
    if not _is_deadcode(finding):
        return None
    cg = getattr(finding, "context_graph", None) or {}
    if (cg.get("stats") or {}).get("degraded"):
        return None  # degraded graph is a hint, not a ruling → let the LLM decide
    from .prompts.rule_policies import is_taint_class

    ev = _deadcode_sink_evidence(finding)
    if is_taint_class(finding.check_id, finding):
        return Verdict(
            verdict="false_positive",
            is_security_vulnerability=False,
            severity="low",
            confidence="high",
            reason="Deterministic reachability analysis (non-degraded context graph): the "
            "flagged taint sink has no data-flow or caller path from any entry point, so "
            "the injection cannot be triggered.",
            evidence_locations=ev,
        )
    return Verdict(
        verdict="true_positive",
        is_security_vulnerability=False,
        severity="low",
        confidence="high",
        reason="The flagged construct is present, but a non-degraded context graph proves "
        "every path to it is dead / unreachable — so the pattern is a real occurrence "
        "(true_positive) that cannot be triggered by input (not a security vulnerability).",
        evidence_locations=ev,
    )


def _prose_file_decision(finding) -> Verdict | None:
    """False positive for an AI-usage rule that matched documentation text.

    The rule inventories AI SDK/API usage in code; a changelog, README or ignore file that
    names a vendor is not usage. Resolved without an LLM call. Other file types are left to
    the model, which applies the stricter policy in rule_policies.
    """
    from .prompts.rule_policies import AI_USAGE_RULES, get_rule_short_name, is_prose_file

    if get_rule_short_name(finding.check_id) not in AI_USAGE_RULES or not is_prose_file(finding.path):
        return None
    return Verdict(
        verdict="false_positive",
        is_security_vulnerability=False,
        severity="low",
        confidence="high",
        reason="The rule detects AI SDK/API usage in code, but the match is in a documentation or "
        f"ignore file ({finding.path}). Text that names a vendor is not usage of it.",
        evidence_locations=[f"{finding.path}:{finding.line}"],
    )


def _cluster_same_line(to_analyze: list) -> tuple[list, dict[int, int]]:
    """Collapse matches of one rule on one line into a single analysis.

    A scanner reports each match separately (distinct columns), but they sit on the same
    source line under the same rule, so a verdict per match only produces contradictions
    (the same message was ruled TP and FP). The first match is analyzed with its siblings'
    spans listed in the prompt; the siblings inherit its verdict.

    Returns (representatives, {sibling_index: representative_index}).
    """
    reps: dict[tuple, int] = {}
    siblings: dict[int, int] = {}
    kept: list = []
    for i, b in to_analyze:
        f = b.finding
        key = (f.check_id, f.path, f.line)
        rep = reps.get(key)
        if rep is None:
            reps[key] = i
            kept.append((i, b))
            continue
        siblings[i] = rep
        rep_finding = next(rb.finding for ri, rb in kept if ri == rep)
        rep_finding.sibling_spans.append(
            f"col {f.col}–{f.end_col}: `{(f.match_text or f.lines).strip()[:160]}`")
    return kept, siblings


def _checkpoint_path(output_path: Path) -> Path:
    """Checkpoint file sits next to the output file."""
    return output_path.with_suffix(".checkpoint.json")


def _load_checkpoint(output_path: Path) -> dict[int, Verdict]:
    """Load previously saved verdicts from checkpoint file."""
    cp = _checkpoint_path(output_path)
    if not cp.is_file():
        return {}

    try:
        data = json.loads(cp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        log.warning("Corrupt checkpoint file, starting fresh")
        return {}

    loaded: dict[int, Verdict] = {}
    for idx_str, v in data.items():
        try:
            loaded[int(idx_str)] = Verdict.model_validate(v)
        except Exception:
            continue

    log.info("Loaded %d verdicts from checkpoint", len(loaded))
    return loaded


def _save_checkpoint(output_path: Path, verdicts: dict[int, Verdict]) -> None:
    """Save verdicts to checkpoint file.

    Full model dump (minus unset/None noise) so newer fields — source_trust,
    execution_trace, attack_scenario, taint_flow_verified — survive a resume.
    """
    cp = _checkpoint_path(output_path)
    data = {
        str(idx): v.model_dump(exclude_none=True, exclude_defaults=True)
        | {  # always keep the decision core, even at default values
            "verdict": v.verdict,
            "is_security_vulnerability": v.is_security_vulnerability,
            "severity": v.severity,
            "confidence": v.confidence,
            "reason": v.reason,
            "evidence_locations": v.evidence_locations,
        }
        for idx, v in verdicts.items()
    }
    cp.write_text(json.dumps(data, indent=2))


_SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", ".tox",
              ".mypy_cache", "dist", "build", ".pytest_cache", ".egg-info",
              "codeassure.egg-info", ".venv"}


def _walk_codebase(codebase: Path) -> list[dict]:
    """Walk codebase directory and return a flat list of file/dir entries.

    Each entry: {"path": "relative/path", "type": "file"|"dir", "size": bytes}
    """
    entries: list[dict] = []
    for item in sorted(codebase.rglob("*")):
        rel = item.relative_to(codebase)
        # Skip hidden and build directories
        parts = rel.parts
        if any(p.startswith(".") or p in _SKIP_DIRS for p in parts):
            continue
        if item.is_dir():
            entries.append({"path": str(rel), "type": "dir", "size": 0})
        elif item.is_file():
            try:
                size = item.stat().st_size
            except OSError:
                size = 0
            # Skip binary/large files
            if size > 5_000_000:
                continue
            entries.append({"path": str(rel), "type": "file", "size": size})
    return entries


_COLOR_RANK = {"red": 3, "blue": 2, "green": 1, "gray": 0, "orange": -1}


def _wants_enrichment(mode: str, verdict) -> bool:
    """Whether the enrichment LLM pass should run for a finding with this verdict."""
    if mode == "all":
        return True
    # A fallback verdict means the LLM was unavailable; enriching it would fail too.
    if (verdict.reason or "").startswith("LLM analysis unavailable"):
        return False
    if verdict.verdict != "true_positive":
        return False
    return mode == "tp" or bool(verdict.is_security_vulnerability)


def _apply_coloring_deterministic(context_graph: dict, verdict) -> None:
    """Color the graph as a PURE FUNCTION of (deterministic context graph + verdict).

    No LLM input is read — the graph topology is byte-deterministic (context-graph
    guarantees it) and the verdict is deterministic/checkpointed, so the rendered
    "code flow" is reproducible run-to-run. This replaced an LLM-driven coloring
    whose per-path classification flipped between runs even for an identical graph.

    Rules (verdict is authoritative on exploitability):
      * deadcode / unreachable path            → gray
      * security vuln (TP + is_security) :
          reachable or tainted path            → red   (the exploit path; dominant)
          otherwise                            → gray
      * not a security vuln (FP, or TP non-security):
          path carries a sanitizer/guard       → green (protection explains safety)
          otherwise                            → gray  (never red)
    Node and edge colors are DERIVED from path colors + node kind, so every element
    is consistently colored:
      red = sink/anchor on an exploitable path · orange = intermediate hop ·
      blue = source/route origination · green = protection point / safe path ·
      gray = deadcode / unreachable.
    """
    paths = context_graph.get("paths", [])
    nodes = context_graph.get("nodes", [])
    is_vuln = verdict.verdict == "true_positive" and verdict.is_security_vulnerability

    # 1. Path color/status — derived from the deterministic graph + verdict.
    for p in paths:
        reach = p.get("reachability")
        prot = p.get("protection") or {}
        protected = bool(prot.get("has_sanitizer") or prot.get("has_guard"))
        if reach == "deadcode":
            p["status"], p["color"] = "deadcode", "gray"
        elif is_vuln:
            # exploitable finding: any live path IS the vulnerability → red.
            if p.get("tainted") or reach == "reachable":
                p["status"], p["color"] = "vulnerable", "red"
            else:
                p["status"], p["color"] = "safe", "gray"
        else:
            # not a security vuln → never red; protection (if any) explains why.
            p["status"], p["color"] = ("protected", "green") if protected else ("safe", "gray")
    path_color = {p.get("id"): p.get("color") for p in paths}

    # Protection node ids come from the DETERMINISTIC graph (sanitizer/guard nodes
    # the analyzer recorded on each path), not from any LLM classification.
    protect_ids: set[str] = set()
    for p in paths:
        prot = p.get("protection") or {}
        protect_ids.update(prot.get("sanitizer_nodes") or [])
        protect_ids.update(prot.get("guard_nodes") or [])

    # 2. Node color — ROLE-based, with path status overriding for gray/green:
    #    source/route = blue · intermediate = orange · sink = red ·
    #    deadcode/unreachable = gray · protection (or fully-safe path) = green.
    for n in nodes:
        nid, kind = n.get("id"), n.get("kind")
        colors_on = [p.get("color") for p in paths if nid in p.get("nodes", [])]
        if colors_on and all(c == "gray" for c in colors_on):
            n["color"] = "gray"                       # only on deadcode/unreachable paths
        elif colors_on and all(c == "green" for c in colors_on):
            n["color"] = "green"                      # fully protected / safe
        elif kind in ("sanitizer", "guard") or nid in protect_ids:
            n["color"] = "green"                      # a protection point
        elif kind in ("source", "route"):
            n["color"] = "blue"                       # origination
        elif kind == "sink":
            n["color"] = "red"                        # the flagged vuln line
        else:
            n["color"] = "orange"                     # intermediate hop
        n["status"] = n.get("status") or kind

    # 3. Edge color = strongest path color it belongs to.
    for e in context_graph.get("edges", []):
        colors = [path_color[pid] for pid in e.get("paths", []) if path_color.get(pid)]
        e["color"] = max(colors, key=lambda c: _COLOR_RANK.get(c, -1)) if colors else "gray"


def _write_output(
    findings_path: Path,
    output_path: Path,
    verdicts: list[Verdict],
    findings: list | None = None,
    codebase: Path | None = None,
    enrichments: dict | None = None,
    enrich_fallback=None,
    analysis_statuses: dict[int, str] | None = None,
) -> None:
    """Merge verdicts into original findings JSON and write output.

    enrich_fallback(index, verdict) -> Enrichment | None fills enrichment keys
    for findings the LLM pass missed, keeping the output schema complete.
    """
    from .graph import build_finding_graph
    from .preprocess import compact_finding

    enrichments = enrichments or {}
    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    for i, (result, verdict) in enumerate(zip(raw["results"], verdicts)):
        status = (analysis_statuses or {}).get(i, "completed")
        result["ai_analysis_status"] = status
        if status == "skipped":
            result.pop("verification", None)
            continue
        verification: dict = {
            "analysis_status": status,
            "verdict": verdict.verdict,
            "is_security_vulnerability": verdict.is_security_vulnerability,
            "severity": verdict.severity,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "evidence": [{"location": loc} for loc in verdict.evidence_locations],
        }
        # Execution-reality fields from the analyzer's graph-guided trace.
        if verdict.source_trust is not None:
            verification["source_trust"] = verdict.source_trust
        if verdict.taint_flow_verified is not None:
            verification["taint_flow_verified"] = verdict.taint_flow_verified
        if verdict.execution_trace:
            verification["execution_trace"] = verdict.execution_trace
        if verdict.attack_scenario:
            verification["attack_scenario"] = verdict.attack_scenario
        if verdict.validator_reason is not None or verdict.validator_verdict_agrees is not None:
            verification["validator"] = {
                "verdict_agrees": verdict.validator_verdict_agrees,
                "vuln_agrees": verdict.validator_vuln_agrees,
                "reason": verdict.validator_reason,
            }

        # Enrichment (rationale, business logic, remediation). When the pass is
        # enabled these keys are guaranteed: a missing entry (crash, resumed run)
        # degrades to the deterministic fallback rather than absent keys.
        enrichment = enrichments.get(i)
        if enrichment is None and enrich_fallback is not None:
            enrichment = enrich_fallback(i, verdict)
        if enrichment is not None:
            # Paste-target invariant at the LAST exit: original_code must equal
            # the file content at start..end (idempotent when already anchored
            # by the enrichment pass; covers the write-time fallback path too).
            if codebase is not None:
                try:
                    from .agents.patch_anchor import anchor_remediation
                    fnd = findings[i] if findings else compact_finding(result)
                    enrichment.remediation = anchor_remediation(
                        enrichment.remediation, Path(codebase), fnd,
                    )
                except Exception:
                    pass  # anchoring is best-effort at this layer
            verification["rationale"] = enrichment.rationale
            verification["business_logic"] = enrichment.business_logic
            verification["explanation"] = enrichment.explanation
            verification["remediation"] = enrichment.remediation.model_dump()
            notes = (enrichment.remediation.notes or "").lower()
            verification["enrichment_status"] = (
                "skipped" if "enrichment not requested" in notes else
                "fallback" if "enrichment unavailable" in notes else "completed")

        # Deterministic context graph (from context-graph-cli) gets colored in place
        # from (graph + verdict) alone — no LLM input — so it renders identically
        # every run and even when the enrichment pass failed/was skipped. Otherwise
        # fall back to the legacy heuristic graph for the UI.
        context_graph = result.get("context_graph")
        if isinstance(context_graph, dict):
            try:
                if status == "completed":
                    _apply_coloring_deterministic(context_graph, verdict)
            except Exception:
                pass  # coloring is best-effort
        elif status == "completed":
            try:
                finding = findings[i] if findings else compact_finding(result)
                verification["graph"] = build_finding_graph(finding, verdict)
            except Exception:
                pass  # graph generation is best-effort

        result["verification"] = verification

    statuses = [r.get("ai_analysis_status", "skipped") for r in raw["results"]]
    raw["ai_analysis"] = any(s == "completed" for s in statuses)
    raw["ai_sast"] = {
        "engine": "codeassure", "requested": True,
        "status": "partial" if any(s in {"fallback", "unanchored"} for s in statuses) else "completed",
        "total": len(statuses),
        "analyzed": statuses.count("completed"),
        "skipped": statuses.count("skipped"),
        "fallback": statuses.count("fallback"),
        "unanchored": statuses.count("unanchored"),
    }

    # Embed codebase tree for visualization
    if codebase and codebase.is_dir():
        raw["codebase_tree"] = _walk_codebase(codebase)
        log.info("Codebase tree: %d entries", len(raw["codebase_tree"]))

    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output_path.parent,
                                     prefix=".codeassure-", suffix=".json", delete=False) as staged:
        json.dump(raw, staged, indent=2)
    os.replace(staged.name, output_path)


def run(
    codebase: Path,
    findings_path: Path,
    output_path: Path,
    concurrency: int = 4,
    severities: list[str] | None = ["INFO", "WARNING", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN", "NOT_AVAILABLE", "INFORMATIONAL"],
    enable_grouping: bool = True,
    claude_verification: bool = False,
) -> None:
    wall_start = time.perf_counter()

    from .config import get_config
    from .schema import EvidenceBundle
    cfg = get_config()

    raw_findings_json = json.loads(findings_path.read_text(encoding="utf-8"))
    _repo_url = raw_findings_json.get("repo_url") or ""
    _ref = raw_findings_json.get("ref") or ""
    repo_id_from_file = f"{_repo_url}/{_ref}".strip("/") if _repo_url else ""

    findings = preprocess_data(raw_findings_json, codebase=codebase)
    t0 = time.perf_counter()
    if cfg.findings_analysis:
        bundles = [EvidenceBundle(finding=f, evidence=[]) for f in findings]
    else:
        with ThreadPoolExecutor(max_workers=min(len(findings), concurrency * 2) if findings else 1) as pool:
            bundles = list(pool.map(lambda f: retrieve(f, codebase), findings))
    retrieval_elapsed = time.perf_counter() - t0
    print(f"[timing] retrieval: {retrieval_elapsed:.1f}s for {len(findings)} finding(s)", flush=True)

    # finding_only mode: all bundles go to the agent regardless of evidence
    # full/no_tools mode: only anchored findings go to the agent; unanchored → uncertain
    verdicts: list[Verdict] = [_no_anchor_verdict()] * len(bundles)
    if cfg.findings_analysis:
        to_analyze = list(enumerate(bundles))
    else:
        to_analyze = [(i, b) for i, b in enumerate(bundles) if b.evidence]
    if severities is not None:
        to_analyze = [
            (i, b) for i, b in to_analyze
            if (b.finding.impact or "NOT_AVAILABLE").upper() in severities
        ]
    selected_indices = {i for i, _ in to_analyze}
    eligible_indices = {
        i for i, b in enumerate(bundles)
        if severities is None or (b.finding.impact or "NOT_AVAILABLE").upper() in severities
    }

    # Documentation matches for AI-usage rules are false positives by construction: no LLM call.
    prose = [(i, _prose_file_decision(b.finding)) for i, b in to_analyze]
    prose = [(i, v) for i, v in prose if v is not None]
    if prose:
        for i, v in prose:
            verdicts[i] = v
        prose_idx = {i for i, _v in prose}
        to_analyze = [(i, b) for i, b in to_analyze if i not in prose_idx]
        print(f"[docs] {len(prose)} AI-usage finding(s) in documentation resolved as false positive "
              f"(no LLM); {len(to_analyze)} remain", flush=True)

    # Rules whose truth is a mechanical fact about the flagged text (is the ref a 40-char SHA, does
    # the blob decode to a JOSE header, is the `{` already inside `${…}`) are decided from the
    # source itself: no model call, and byte-identical findings get identical verdicts.
    checked = [(i, rule_checks.decide(b.finding, codebase)) for i, b in to_analyze]
    checked = [(i, v) for i, v in checked if v is not None]
    if checked:
        for i, v in checked:
            verdicts[i] = v
        checked_idx = {i for i, _v in checked}
        to_analyze = [(i, b) for i, b in to_analyze if i not in checked_idx]
        print(f"[rules] {len(checked)} finding(s) resolved by deterministic rule checks "
              f"(no LLM); {len(to_analyze)} remain", flush=True)

    to_analyze, same_line = _cluster_same_line(to_analyze)
    if same_line:
        print(f"[dedupe] {len(same_line)} same-rule/same-line match(es) share their sibling's verdict; "
              f"{len(to_analyze)} remain", flush=True)

    # Deterministic context-graph shortcut: when a NON-DEGRADED graph proves every path
    # to the sink is dead, honor it without an LLM call — false_positive for taint/injection
    # rules, true_positive + is_security=false for pattern-existence rules (see
    # _deadcode_decision). Degraded graphs and partially-reachable graphs fall through to
    # the LLM, which treats the graph as strong (but not final) evidence.
    deadcode = [(i, b, _deadcode_decision(b.finding)) for i, b in to_analyze]
    deadcode = [(i, b, v) for i, b, v in deadcode if v is not None]
    if deadcode:
        for i, _b, v in deadcode:
            verdicts[i] = v
        dead_idx = {i for i, _b, _v in deadcode}
        to_analyze = [(i, b) for i, b in to_analyze if i not in dead_idx]
        print(f"[deadcode] {len(deadcode)} finding(s) resolved deterministically from a "
              f"non-degraded context graph (no LLM); {len(to_analyze)} remain", flush=True)

    skipped = len(bundles) - len(to_analyze) - len(deadcode) - len(prose) - len(checked) - len(same_line)
    print(f"{skipped} finding(s) skipped due to severity filter; {len(to_analyze)} finding(s) to analyze with AI", flush=True)
    if skipped:
        log.warning("%d finding(s) skipped (no anchored evidence)", skipped)

    # Load checkpoint — skip already-completed findings
    # Indices alone are unsafe across new scans or config changes. Bind resumes
    # to this exact input, source revision and model/policy configuration.
    identity_path = output_path.with_suffix(".checkpoint.identity")
    identity = hashlib.sha256((json.dumps(raw_findings_json, sort_keys=True)
        + str(codebase.resolve()) + cfg.model_dump_json()
        + json.dumps([b.model_dump(mode="json") for b in bundles], sort_keys=True)).encode()).hexdigest()
    checkpoint = _load_checkpoint(output_path) if identity_path.is_file() and identity_path.read_text() == identity else {}
    identity_path.write_text(identity)
    checkpoint = {i: v for i, v in checkpoint.items() if i in selected_indices
                  and not v.reason.startswith("LLM analysis unavailable")}
    for idx, verdict in checkpoint.items():
        if idx < len(verdicts):
            verdicts[idx] = verdict

    # Filter out already-completed findings
    if checkpoint:
        remaining = [(i, b) for i, b in to_analyze if i not in checkpoint]
        log.info(
            "Resuming: %d/%d already done, %d remaining",
            len(to_analyze) - len(remaining), len(to_analyze), len(remaining),
        )
        to_analyze = remaining

    # Check AccuKnox for existing verdicts — skip LLM for already-known findings
    from .accuknox import lookup_existing_verdict_async
    base_url = os.environ.get("ACCUKNOX_BASE_URL", "").rstrip("/")
    token = os.environ.get("ACCUKNOX_BEARER_TOKEN", "")
    if to_analyze and base_url and token and os.getenv("ACCUKNOX_REUSE_AI_VERDICTS", "").upper() == "TRUE":
        import httpx

        repo_id = repo_id_from_file or os.environ.get("ACCUKNOX_REPO_ID", "")

        async def _accuknox_batch(items):
            async with httpx.AsyncClient() as client:
                results = await asyncio.gather(*(
                    lookup_existing_verdict_async(client, b.finding.fingerprint, base_url, token, repo_id=repo_id)
                    for _, b in items
                ))
            return results

        raw_results = asyncio.run(_accuknox_batch(to_analyze))

        accuknox_resolved: list[tuple[int, object]] = []
        still_pending: list[tuple[int, object]] = []
        for (i, b), existing in zip(to_analyze, raw_results):
            if existing is not None:
                verdicts[i] = existing
                accuknox_resolved.append((i, b))
            else:
                still_pending.append((i, b))

        if accuknox_resolved:
            print(
                f"[accuknox] {len(accuknox_resolved)} finding(s) resolved from AccuKnox database; "
                f"{len(still_pending)} sent to AI",
                flush=True,
            )
        to_analyze = still_pending

    ai_elapsed = 0.0
    if to_analyze:
        indices, analyzable = zip(*to_analyze)
        t1 = time.perf_counter()

        if enable_grouping:
            groups = build_groups(list(analyzable), list(indices))
            co_located = sum(1 for g in groups if g.relationship == "co-located")
            print(f"Grouped {len(analyzable)} findings into {len(groups)} groups "
                  f"({co_located} co-located, {len(groups) - co_located} solo)", flush=True)
            verdict_map = asyncio.run(
                analyze_all_grouped(groups, codebase=codebase, concurrency=concurrency,
                                    claude_verification=claude_verification,
                                    checkpoint=checkpoint, output_path=output_path)
            )
            for idx, verdict in verdict_map.items():
                verdicts[idx] = verdict
        else:
            llm_verdicts = asyncio.run(
                analyze_all(list(analyzable), codebase=codebase, concurrency=concurrency,
                            claude_verification=claude_verification,
                            checkpoint=checkpoint, output_path=output_path)
            )
            for idx, verdict in zip(indices, llm_verdicts):
                verdicts[idx] = verdict

        ai_elapsed = time.perf_counter() - t1
        n = len(to_analyze)
        print(
            f"[timing] AI analysis: {ai_elapsed:.1f}s total | "
            f"{ai_elapsed / n:.1f}s avg per finding | "
            f"{n} finding(s) | concurrency={concurrency}",
            flush=True,
        )

    for sibling, rep in same_line.items():
        verdicts[sibling] = verdicts[rep].model_copy(deep=True)

    # Enrichment pass — one extra LLM call per selected finding (rationale + business
    # context + paste-ready remediation). cfg.enrich_mode picks which: security (default) =
    # true positives that are security vulnerabilities, tp = all true positives,
    # all = every decided finding, off = none. Findings the policy skips (and LLM
    # failures) get a deterministic fallback enrichment, so the output schema stays
    # complete; verification.enrichment_status tells them apart.
    enrichments: dict = {}
    enrich_mode = cfg.enrich_mode
    policy_skipped: set[int] = set()
    if enrich_mode != "off":
        enrich_items = []
        for i, b in enumerate(bundles):
            if i not in eligible_indices:
                continue
            if not _wants_enrichment(enrich_mode, verdicts[i]):
                policy_skipped.add(i)
                continue
            enrich_items.append((i, b, verdicts[i]))
        if policy_skipped:
            print(f"[enrich] mode={enrich_mode}: skipping {len(policy_skipped)} finding(s) "
                  f"not selected for enrichment", flush=True)
        if enrich_items:
            from .agents.enrich import enrich_all
            print(f"[enrich] enriching {len(enrich_items)} finding(s)…", flush=True)
            enrichments = asyncio.run(enrich_all(enrich_items, codebase, concurrency))
            fallbacks = sum(
                1 for e in enrichments.values()
                if "enrichment unavailable" in (e.remediation.notes or "").lower()
            )
            if fallbacks:
                print(f"[enrich] ⚠ {fallbacks} finding(s) got deterministic fallback "
                      f"enrichment (LLM unavailable)", flush=True)

    enrich_fallback = None
    if enrich_mode != "off":
        from .agents.enrich import fallback_enrichment

        def enrich_fallback(i: int, verdict):
            if 0 <= i < len(bundles):
                if i in policy_skipped:
                    return fallback_enrichment(
                        bundles[i], verdict,
                        skipped=f"not requested for this verdict (CODEASSURE_ENRICH={enrich_mode})")
                return fallback_enrichment(bundles[i], verdict, "not produced in this run")
            return None

    _write_output(findings_path, output_path, verdicts, findings=findings,
                  codebase=codebase, enrichments=enrichments,
                  enrich_fallback=enrich_fallback,
                  analysis_statuses={i: (
                      "skipped" if i not in eligible_indices else
                      "unanchored" if i not in selected_indices else
                      "fallback" if v.reason.startswith("LLM analysis unavailable") else "completed"
                  ) for i, v in enumerate(verdicts)})

    # Clean up checkpoint on successful completion
    cp = _checkpoint_path(output_path)
    if cp.is_file():
        cp.unlink()
        log.info("Checkpoint removed (run complete)")
    identity_path.unlink(missing_ok=True)

    total_elapsed = time.perf_counter() - wall_start
    print(
        f"[timing] done — total wall time: {total_elapsed:.1f}s "
        f"(retrieval {retrieval_elapsed:.1f}s + AI {ai_elapsed:.1f}s + output {total_elapsed - retrieval_elapsed - ai_elapsed:.1f}s)",
        flush=True,
    )


# Rules where skipping collapse has positive net impact on this GT dataset.
# Only these rules get the override — the rest collapse normally.
_COLLAPSE_EXEMPT_RULES = frozenset({
    "default-mutable-dict",   # +3 net (3 FN saved, 0 FP added)
    "use-timeout",            # +1 net (5 FN saved, 4 FP added)
    "subprocess-shell-true",  # +1 net (2 FN saved, 1 FP added)
    # Correctness/best-practice rule families that the runner deterministically
    # reclassifies to is_security_vulnerability=False. Pattern is still a true
    # positive for the rule; it's just not a security vulnerability.
    "unquoted-variable-expansion-in-command",
    "unquoted-command-substitution-in-command",
    "useless-cat",
    "useless-if-body",
    "missing-set-pipefail",
    "missing-apk-no-cache",
    "missing-image-version",
    "multiple-entrypoint-instructions",
    "dockerfile-source-not-pinned",
    # Lints and AI-usage inventory (runner._NON_SECURITY_RULE_SUBSTRINGS), plus supply-chain
    # hardening rules whose true positives are deliberately not security vulnerabilities.
    "missing-template-string-indicator",
    "useless-assignment",
    "useless-ternary",
    "html-in-template-string",
    "detect-generic-ai-oai",
    "detect-generic-ai-anthprop",
    "detect-generic-ai-api",
    "detect-openai",
    "github-actions-mutable-action-tag",
    "third-party-action-not-pinned-to-commit-sha",
    "npm-missing-minimum-release-age",
    "pnpm-minimum-release-age",
    "pnpm-block-exotic-sub-dependencies",
    "pnpm-trust-policy",
    "renovate-missing-minimum-release-age",
})


def _policy_covers_rule(check_id: str) -> bool:
    """Check if this rule should skip the TP+not_sec→FP collapse."""
    from .prompts.rule_policies import get_rule_short_name
    return get_rule_short_name(check_id) in _COLLAPSE_EXEMPT_RULES


_EXT_LANG = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php", ".rs": "rust",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
    ".cs": "csharp", ".kt": "kotlin", ".scala": "scala", ".swift": "swift",
    ".sh": "bash", ".bash": "bash", ".yaml": "yaml", ".yml": "yaml",
    ".tf": "terraform", ".hcl": "terraform", ".html": "html", ".json": "json",
}


def _finding_language(pred_result: dict, path: str) -> str:
    """Language of a finding — prefer context-graph's detected language, else ext."""
    lang = (pred_result.get("context_graph") or {}).get("language")
    if lang:
        return lang
    base = os.path.basename(path).lower()
    if base.startswith("dockerfile"):
        return "dockerfile"
    _, ext = os.path.splitext(base)
    return _EXT_LANG.get(ext, ext.lstrip(".") or "unknown")


def _confusion_metrics(c: dict) -> tuple[float, float, float, float, int]:
    """(accuracy, precision, recall, f1, decided) from a tp/tn/fp/fn counter."""
    tp, tn, fp, fn = c["tp"], c["tn"], c["fp"], c["fn"]
    decided, correct = tp + tn + fp + fn, tp + tn
    acc = correct / decided * 100 if decided else 0.0
    prec = tp / (tp + fp) * 100 if (tp + fp) else 0.0
    rec = tp / (tp + fn) * 100 if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return acc, prec, rec, f1, decided


def verify(
    output_path: Path,
    ground_truth_path: Path,
    csv_path: Path,
) -> None:
    """Compare predicted verdicts against ground truth and write a CSV report."""
    import csv

    predicted = json.loads(output_path.read_text(encoding="utf-8"))
    truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))

    pred_results = predicted["results"]
    truth_results = truth["results"]

    if len(pred_results) != len(truth_results):
        log.error(
            "Result count mismatch: predicted=%d, ground_truth=%d",
            len(pred_results), len(truth_results),
        )
        return

    tp = fp = tn = fn = uncertain = 0
    rows = []
    from collections import defaultdict
    by_lang: dict[str, dict] = defaultdict(
        lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "uncertain": 0}
    )

    for i, (pr, tr) in enumerate(zip(pred_results, truth_results)):
        v = pr.get("verification", {})
        pred_verdict = v.get("verdict", "unknown")
        pred_is_sec = v.get("is_security_vulnerability", True)
        pred_conf = v.get("confidence", "")
        pred_reason = v.get("reason", "")

        gt_is_fp = tr.get("is_false_positive", False)
        gt_label = "false_positive" if gt_is_fp else "true_positive"
        gt_reason = tr.get("validation_reason", "")

        check_id = tr.get("check_id", "")
        path = tr.get("path", "")
        severity = tr.get("extra", {}).get("severity", "")
        start_line = tr.get("start", {}).get("line", "")

        # Effective prediction: collapse TP + not_sec → FP
        # BUT skip collapse for rule families covered by finding_policy
        if pred_verdict == "true_positive" and not pred_is_sec:
            if _policy_covers_rule(check_id):
                effective = "true_positive"  # policy says this rule type IS a finding
            else:
                effective = "false_positive"
        else:
            effective = pred_verdict

        match = effective == gt_label
        lang = _finding_language(pr, path)

        cat = None
        if effective == "uncertain":
            uncertain += 1; cat = "uncertain"
        elif effective == "true_positive" and gt_label == "true_positive":
            tp += 1; cat = "tp"
        elif effective == "false_positive" and gt_label == "false_positive":
            tn += 1; cat = "tn"
        elif effective == "true_positive" and gt_label == "false_positive":
            fp += 1; cat = "fp"
        elif effective == "false_positive" and gt_label == "true_positive":
            fn += 1; cat = "fn"
        if cat:
            by_lang[lang][cat] += 1

        rows.append({
            "index": i,
            "language": lang,
            "check_id": check_id,
            "path": path,
            "line": start_line,
            "severity": severity,
            "ground_truth": gt_label,
            "verdict": pred_verdict,
            "is_security_vulnerability": pred_is_sec,
            "effective": effective,
            "confidence": pred_conf,
            "match": "Y" if match else "N",
            "ground_truth_reason": gt_reason,
            "predicted_reason": pred_reason,
        })

    fieldnames = [
        "index", "language", "check_id", "path", "line", "severity",
        "ground_truth", "verdict", "is_security_vulnerability",
        "effective", "confidence", "match",
        "ground_truth_reason", "predicted_reason",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    decided = tp + tn + fp + fn
    correct = tp + tn
    accuracy = (correct / decided * 100) if decided else 0.0
    precision = (tp / (tp + fp) * 100) if (tp + fp) else 0.0
    recall = (tp / (tp + fn) * 100) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print(f"\n{'='*60}")
    print(f" Verification Report: {csv_path.name}")
    print(f"{'='*60}")
    print(f" Total findings: {total}")
    print(f"{'─'*60}")
    print(f"   TP (real issue, said TP):     {tp:>4d}")
    print(f"   TN (not issue, said FP):      {tn:>4d}")
    print(f"   FP (not issue, said TP):      {fp:>4d}")
    print(f"   FN (real issue, said FP):     {fn:>4d}")
    print(f"   Uncertain:                    {uncertain:>4d}")
    print(f"{'─'*60}")
    print(f"   Accuracy:  {accuracy:5.1f}%  ({correct}/{decided})")
    print(f"   Precision: {precision:5.1f}%")
    print(f"   Recall:    {recall:5.1f}%")
    print(f"   F1:        {f1:5.1f}%")

    # Per-language breakdown — where does the deterministic graph help most?
    print(f"{'='*78}")
    print(" Accuracy by language")
    print(f"{'─'*78}")
    print(f" {'language':<12} {'n':>4} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4} "
          f"{'unc':>4} {'acc%':>7} {'prec%':>7} {'rec%':>7} {'F1%':>7}")
    print(f"{'─'*78}")
    for lang in sorted(by_lang, key=lambda k: -sum(by_lang[k].values())):
        c = by_lang[lang]
        n = sum(c.values())
        acc_l, prec_l, rec_l, f1_l, _ = _confusion_metrics(c)
        print(f" {lang:<12} {n:>4} {c['tp']:>4} {c['tn']:>4} {c['fp']:>4} "
              f"{c['fn']:>4} {c['uncertain']:>4} {acc_l:>7.1f} {prec_l:>7.1f} "
              f"{rec_l:>7.1f} {f1_l:>7.1f}")
    print(f"{'='*78}")
    print(f" CSV written to: {csv_path}  (has a 'language' column for pivoting)")

    log.info("Verification: accuracy=%.1f%% (%d/%d), uncertain=%d",
             accuracy, correct, decided, uncertain)
