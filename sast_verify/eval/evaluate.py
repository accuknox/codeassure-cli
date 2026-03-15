from __future__ import annotations

import json
from pathlib import Path


def evaluate(output_path: Path, ground_truth_path: Path) -> dict:
    output = json.loads(output_path.read_text(encoding="utf-8"))
    truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))

    truth_by_fp: dict[str, bool] = {}
    for item in truth.get("results", []):
        fp = item.get("extra", {}).get("fingerprint", "")
        if "is_false_positive" in item:
            truth_by_fp[fp] = item["is_false_positive"]

    total = correct = uncertain = 0

    for item in output.get("results", []):
        fp = item.get("extra", {}).get("fingerprint", "")
        verification = item.get("verification", {})
        verdict = verification.get("verdict")

        if fp not in truth_by_fp:
            continue

        total += 1

        if verdict == "uncertain":
            uncertain += 1
            continue

        predicted_fp = verdict == "false_positive"
        if predicted_fp == truth_by_fp[fp]:
            correct += 1

    decided = total - uncertain
    incorrect = decided - correct

    return {
        "total": total,
        "decided": decided,
        "correct": correct,
        "incorrect": incorrect,
        "uncertain": uncertain,
        "accuracy_decided": round(correct / decided, 4) if decided else 0.0,
        "accuracy_total": round(correct / total, 4) if total else 0.0,
        "abstention_rate": round(uncertain / total, 4) if total else 0.0,
    }
