from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from .agents.runner import analyze_all, analyze_all_grouped
from .grouping import build_groups
from .preprocess import preprocess
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
            "confidence": v.confidence,
            "reason": v.reason,
            "evidence_locations": v.evidence_locations,
        }
        for idx, v in verdicts.items()
    }
    cp.write_text(json.dumps(data, indent=2))


def _write_output(
    findings_path: Path,
    output_path: Path,
    verdicts: list[Verdict],
) -> None:
    """Merge verdicts into original findings JSON and write output."""
    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    for result, verdict in zip(raw["results"], verdicts):
        verification: dict = {
            "verdict": verdict.verdict,
            "is_security_vulnerability": verdict.is_security_vulnerability,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "evidence": [{"location": loc} for loc in verdict.evidence_locations],
        }
        if verdict.claude_verdict_agrees is not None:
            verification["claude_validation"] = {
                "verdict_agrees": verdict.claude_verdict_agrees,
                "vuln_agrees": verdict.claude_vuln_agrees,
                "reason": verdict.claude_reason,
            }
        result["verification"] = verification
    output_path.write_text(json.dumps(raw, indent=2))


def run(
    codebase: Path,
    findings_path: Path,
    output_path: Path,
    concurrency: int = 4,
    severities: list[str] | None = ["INFO", "WARNING", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN", "NOT_AVAILABLE", "INFORMATIONAL"],
    enable_grouping: bool = True,
) -> None:
    findings = preprocess(findings_path)
    bundles = [retrieve(finding, codebase) for finding in findings]

    # Only anchored findings go to the agent; unanchored → deterministic uncertain
    verdicts: list[Verdict] = [_no_anchor_verdict()] * len(bundles)
    to_analyze = [(i, b) for i, b in enumerate(bundles) if b.evidence]
    if severities is not None:
        to_analyze = [
            (i, b) for i, b in to_analyze
            if (b.finding.impact or "NOT_AVAILABLE").upper() in severities
        ]

    skipped = len(bundles) - len(to_analyze)
    print(f"{skipped} finding(s) skipped due to severity filter; {len(to_analyze)} finding(s) to analyze with AI")
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

    if to_analyze:
        indices, analyzable = zip(*to_analyze)

        if enable_grouping:
            groups = build_groups(list(analyzable), list(indices))
            verdict_map = asyncio.run(
                analyze_all_grouped(
                    groups, codebase=codebase, concurrency=concurrency,
                    checkpoint=checkpoint, output_path=output_path,
                )
            )
            for idx, verdict in verdict_map.items():
                verdicts[idx] = verdict
        else:
            llm_verdicts = asyncio.run(
                analyze_all(
                    list(analyzable), codebase=codebase, concurrency=concurrency,
                    checkpoint=checkpoint, output_path=output_path,
                )
            )
            for idx, verdict in zip(indices, llm_verdicts):
                verdicts[idx] = verdict

    _write_output(findings_path, output_path, verdicts)

    # Clean up checkpoint on successful completion
    cp = _checkpoint_path(output_path)
    if cp.is_file():
        cp.unlink()
        log.info("Checkpoint removed (run complete)")


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
        if pred_verdict == "true_positive" and not pred_is_sec:
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
