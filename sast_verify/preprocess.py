from __future__ import annotations

import json
from pathlib import Path

from .schema import Finding


def compact_finding(item: dict) -> Finding:
    extra = item.get("extra", {})
    metadata = extra.get("metadata", {})

    fields: dict = {
        "fingerprint": extra.get("fingerprint", ""),
        "check_id": item.get("check_id", ""),
        "path": item.get("path", ""),
        "line": item.get("start", {}).get("line", 0),
        "end_line": item.get("end", {}).get("line", 0),
        "severity": extra.get("severity", ""),
        "category": metadata.get("category", ""),
        "message": extra.get("message", ""),
        "lines": extra.get("lines", ""),
    }

    if cwe := metadata.get("cwe"):
        fields["cwe"] = cwe

    for key in ("confidence", "likelihood", "impact"):
        if val := metadata.get(key):
            fields[key] = val

    if trace := extra.get("dataflow_trace"):
        src = trace.get("taint_source")
        if src and len(src) >= 2 and isinstance(src[1], list) and len(src[1]) >= 2:
            fields["taint_source"] = src[1][1]
        sink = trace.get("taint_sink")
        if sink and len(sink) >= 2 and isinstance(sink[1], list) and len(sink[1]) >= 2:
            fields["taint_sink"] = sink[1][1]

    if fix := extra.get("fix"):
        fields["fix"] = fix

    return Finding(**fields)


def preprocess(results_path: Path) -> list[Finding]:
    data = json.loads(results_path.read_text(encoding="utf-8"))
    return [compact_finding(r) for r in data.get("results", [])]
