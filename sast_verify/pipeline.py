from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from .agents.runner import analyze_all
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


def run(
    codebase: Path,
    findings_path: Path,
    output_path: Path,
    concurrency: int = 4,
) -> None:
    findings = preprocess(findings_path)
    bundles = [retrieve(finding, codebase) for finding in findings]

    # Only anchored findings go to the agent; unanchored → deterministic uncertain
    verdicts: list[Verdict] = [_no_anchor_verdict()] * len(bundles)
    to_analyze = [(i, b) for i, b in enumerate(bundles) if b.evidence]

    skipped = len(bundles) - len(to_analyze)
    if skipped:
        log.warning("%d finding(s) skipped (no anchored evidence)", skipped)

    if to_analyze:
        indices, analyzable = zip(*to_analyze)
        llm_verdicts = asyncio.run(
            analyze_all(list(analyzable), codebase=codebase, concurrency=concurrency)
        )
        for idx, verdict in zip(indices, llm_verdicts):
            verdicts[idx] = verdict

    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    for result, verdict in zip(raw["results"], verdicts):
        result["verification"] = {
            "verdict": verdict.verdict,
            "finding_correct": verdict.finding_correct,
            "is_security_vulnerability": verdict.is_security_vulnerability,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "evidence": [{"location": loc} for loc in verdict.evidence_locations],
        }

    output_path.write_text(json.dumps(raw, indent=2))


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

    # Confusion matrix counters — dual metrics
    # Finding correctness: raw verdict (did the model agree with GT on detection accuracy?)
    fc_tp = fc_fp = fc_tn = fc_fn = fc_uncertain = 0
    # Security vulnerability: collapsed view (existing logic)
    sv_tp = sv_fp = sv_tn = sv_fn = sv_uncertain = 0
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

        # Finding correctness: raw verdict
        finding_correctness = pred_verdict

        # Security vulnerability: collapsed view (existing logic)
        # Only collapse when is_security_vulnerability is explicitly False;
        # None means "not assessed" (uncertain/fallback) — don't collapse.
        if pred_verdict == "true_positive" and pred_is_sec is False:
            security_effective = "false_positive"
        else:
            security_effective = pred_verdict

        fc_match = finding_correctness == gt_label
        sv_match = security_effective == gt_label

        # Finding correctness confusion matrix
        if finding_correctness == "uncertain":
            fc_uncertain += 1
        elif finding_correctness == "true_positive" and gt_label == "true_positive":
            fc_tp += 1
        elif finding_correctness == "false_positive" and gt_label == "false_positive":
            fc_tn += 1
        elif finding_correctness == "true_positive" and gt_label == "false_positive":
            fc_fp += 1
        elif finding_correctness == "false_positive" and gt_label == "true_positive":
            fc_fn += 1

        # Security vulnerability confusion matrix
        if security_effective == "uncertain":
            sv_uncertain += 1
        elif security_effective == "true_positive" and gt_label == "true_positive":
            sv_tp += 1
        elif security_effective == "false_positive" and gt_label == "false_positive":
            sv_tn += 1
        elif security_effective == "true_positive" and gt_label == "false_positive":
            sv_fp += 1
        elif security_effective == "false_positive" and gt_label == "true_positive":
            sv_fn += 1

        rows.append({
            "index": i,
            "check_id": check_id,
            "path": path,
            "line": start_line,
            "severity": severity,
            "ground_truth": gt_label,
            "predicted": pred_verdict,
            "is_security_vulnerability": pred_is_sec,
            "finding_correctness": finding_correctness,
            "security_effective": security_effective,
            "confidence": pred_conf,
            "fc_match": "Y" if fc_match else "N",
            "sv_match": "Y" if sv_match else "N",
            "ground_truth_reason": gt_reason,
            "predicted_reason": pred_reason,
        })

    fieldnames = [
        "index", "check_id", "path", "line", "severity",
        "ground_truth", "predicted", "is_security_vulnerability",
        "finding_correctness", "security_effective", "confidence",
        "fc_match", "sv_match",
        "ground_truth_reason", "predicted_reason",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)

    def _print_metrics(label, tp, tn, fp, fn, uncertain):
        decided = tp + tn + fp + fn
        correct = tp + tn
        accuracy = (correct / decided * 100) if decided else 0.0
        precision = (tp / (tp + fp) * 100) if (tp + fp) else 0.0
        recall = (tp / (tp + fn) * 100) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        print(f"\n{'─'*60}")
        print(f" {label}")
        print(f"{'─'*60}")
        print(f"   TP (real issue, said TP):     {tp:>4d}")
        print(f"   TN (not issue, said FP):      {tn:>4d}")
        print(f"   FP (not issue, said TP):      {fp:>4d}")
        print(f"   FN (real issue, said FP):     {fn:>4d}")
        print(f"   Uncertain:                    {uncertain:>4d}")
        print(f"   Accuracy:  {accuracy:5.1f}%  ({correct}/{decided})")
        print(f"   Precision: {precision:5.1f}%")
        print(f"   Recall:    {recall:5.1f}%")
        print(f"   F1:        {f1:5.1f}%")
        return accuracy, decided, uncertain

    print(f"\n{'='*60}")
    print(f" Verification Report: {csv_path.name}")
    print(f"{'='*60}")
    print(f" Total findings: {total}")

    _print_metrics(
        "Finding Correctness (raw verdict vs GT)",
        fc_tp, fc_tn, fc_fp, fc_fn, fc_uncertain,
    )
    sv_accuracy, sv_decided, sv_uncertain = _print_metrics(
        "Security Vulnerability (collapsed: TP+not_sec → FP)",
        sv_tp, sv_tn, sv_fp, sv_fn, sv_uncertain,
    )

    print(f"\n{'='*60}")
    print(f" CSV written to: {csv_path}")

    log.info("Verification: sv_accuracy=%.1f%% (%d/%d), uncertain=%d",
             sv_accuracy, sv_decided - sv_uncertain, sv_decided, sv_uncertain)
