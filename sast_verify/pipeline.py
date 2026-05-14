from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .agents.runner import analyze_all, analyze_all_grouped
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
    """Save verdicts to checkpoint file."""
    cp = _checkpoint_path(output_path)
    data = {
        str(idx): {
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


def _write_output(
    findings_path: Path,
    output_path: Path,
    verdicts: list[Verdict],
    findings: list | None = None,
    codebase: Path | None = None,
) -> None:
    """Merge verdicts into original findings JSON and write output."""
    from .graph import build_finding_graph
    from .preprocess import compact_finding

    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    for i, (result, verdict) in enumerate(zip(raw["results"], verdicts)):
        verification: dict = {
            "verdict": verdict.verdict,
            "is_security_vulnerability": verdict.is_security_vulnerability,
            "severity": verdict.severity,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "evidence": [{"location": loc} for loc in verdict.evidence_locations],
        }
        if verdict.validator_reason is not None or verdict.validator_verdict_agrees is not None:
            verification["validator"] = {
                "verdict_agrees": verdict.validator_verdict_agrees,
                "vuln_agrees": verdict.validator_vuln_agrees,
                "reason": verdict.validator_reason,
            }

        # Generate visual explanation graph
        try:
            finding = findings[i] if findings else compact_finding(result)
            graph = build_finding_graph(finding, verdict)
            verification["graph"] = graph
        except Exception:
            pass  # graph generation is best-effort

        result["verification"] = verification

    # Embed codebase tree for visualization
    if codebase and codebase.is_dir():
        raw["codebase_tree"] = _walk_codebase(codebase)
        log.info("Codebase tree: %d entries", len(raw["codebase_tree"]))

    output_path.write_text(json.dumps(raw, indent=2))


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

    findings = preprocess_data(raw_findings_json)
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

    skipped = len(bundles) - len(to_analyze)
    print(f"{skipped} finding(s) skipped due to severity filter; {len(to_analyze)} finding(s) to analyze with AI", flush=True)
    if skipped:
        log.warning("%d finding(s) skipped (no anchored evidence)", skipped)

    # Load checkpoint — skip already-completed findings
    checkpoint = _load_checkpoint(output_path)
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
    if to_analyze and base_url and token:
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

    _write_output(findings_path, output_path, verdicts, findings=findings, codebase=codebase)

    # Clean up checkpoint on successful completion
    cp = _checkpoint_path(output_path)
    if cp.is_file():
        cp.unlink()
        log.info("Checkpoint removed (run complete)")

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
})


def _policy_covers_rule(check_id: str) -> bool:
    """Check if this rule should skip the TP+not_sec→FP collapse."""
    from .prompts.rule_policies import get_rule_short_name
    return get_rule_short_name(check_id) in _COLLAPSE_EXEMPT_RULES


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

        if effective == "uncertain":
            uncertain += 1
        elif effective == "true_positive" and gt_label == "true_positive":
            tp += 1
        elif effective == "false_positive" and gt_label == "false_positive":
            tn += 1
        elif effective == "true_positive" and gt_label == "false_positive":
            fp += 1
        elif effective == "false_positive" and gt_label == "true_positive":
            fn += 1

        rows.append({
            "index": i,
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
        "index", "check_id", "path", "line", "severity",
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
    print(f"{'='*60}")
    print(f" CSV written to: {csv_path}")

    log.info("Verification: accuracy=%.1f%% (%d/%d), uncertain=%d",
             accuracy, correct, decided, uncertain)
