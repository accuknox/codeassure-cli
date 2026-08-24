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
        fields["cwe"] = [cwe] if isinstance(cwe, str) else cwe

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

    # Deterministic source→sink graph attached by context-graph-cli (if it ran).
    if cg := item.get("context_graph"):
        fields["context_graph"] = cg

    return Finding(**fields)


def normalize_finding_path(path: str, codebase: Path) -> str:
    """Rewrite a scanner path to codebase-relative POSIX form.

    Scanners invoked with an absolute target emit absolute paths; retrieval,
    the agent tools, evidence validation, and remediation paste targets all
    assume codebase-relative. An absolute path resolving under the codebase is
    rewritten; one that does not is matched by suffix against the codebase
    directory name; anything else is returned unchanged.
    """
    if not path:
        return path
    p = Path(path)
    if not p.is_absolute():
        rel = str(p).replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        return rel or path
    try:
        return p.resolve().relative_to(Path(codebase).resolve()).as_posix()
    except (ValueError, OSError):
        pass
    name = Path(codebase).resolve().name
    parts = p.parts
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] == name:
            rel = Path(*parts[i + 1:]).as_posix()
            if rel and (Path(codebase) / rel).is_file():
                return rel
            break
    return path


def preprocess_data(data: dict, codebase: Path | None = None) -> list[Finding]:
    findings = [compact_finding(r) for r in data.get("results", [])]
    if codebase is not None:
        for f in findings:
            f.path = normalize_finding_path(f.path, codebase)
    return findings


def preprocess(results_path: Path) -> list[Finding]:
    data = json.loads(results_path.read_text(encoding="utf-8"))
    return preprocess_data(data)
