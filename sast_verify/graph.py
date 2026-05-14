"""Finding visualization — generates Mermaid flow diagrams explaining each finding."""

from __future__ import annotations

from .schema import Evidence, Finding, Verdict


def _escape_mermaid(text: str) -> str:
    """Escape text for Mermaid labels."""
    return (
        text.replace('"', "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("&", "&amp;")
        .replace("\n", "<br/>")
    )


def _short_check(check_id: str) -> str:
    return check_id.rsplit(".", 1)[-1]


def _truncate(text: str, n: int = 50) -> str:
    return text[:n] + "..." if len(text) > n else text


def build_finding_graph(
    finding: Finding,
    verdict: Verdict,
    evidence: list[Evidence] | None = None,
) -> dict:
    """Build a graph representation for a finding.

    Returns dict with:
      - summary: one-line text description of the flow
      - mermaid: renderable Mermaid diagram
      - nodes: list of node dicts
      - edges: list of edge dicts
    """
    check = _short_check(finding.check_id)

    # Dispatch to finding-type-specific builders
    if finding.taint_source or finding.taint_sink:
        return _build_taint_graph(finding, verdict, check)

    if "subprocess" in check or "shell-true" in check or "pickle" in check:
        return _build_sink_graph(finding, verdict, check)

    if "dockerfile" in check or "entrypoint" in check or "pipefail" in check or "package-cache" in check:
        return _build_dockerfile_graph(finding, verdict, check)

    if "timeout" in check or "raise-for-status" in check or "cert-validation" in check:
        return _build_http_graph(finding, verdict, check)

    if "detect-" in check:
        return _build_detection_graph(finding, verdict, check)

    # Generic fallback
    return _build_generic_graph(finding, verdict, check)


def _build_taint_graph(finding: Finding, verdict: Verdict, check: str) -> dict:
    """Taint/dataflow finding: source → intermediates → sink."""
    nodes = []
    edges = []

    src_label = _escape_mermaid(_truncate(finding.taint_source or "unknown source"))
    sink_label = _escape_mermaid(_truncate(finding.taint_sink or finding.lines.strip()))
    flagged_label = _escape_mermaid(_truncate(finding.lines.strip()))

    nodes.append({"id": "source", "label": src_label, "type": "source"})
    nodes.append({"id": "flagged", "label": flagged_label,
                  "type": "sink", "location": f"{finding.path}:{finding.line}"})

    if finding.taint_sink and finding.taint_sink != finding.lines.strip():
        nodes.append({"id": "sink", "label": _escape_mermaid(_truncate(finding.taint_sink)),
                      "type": "sink"})
        edges.append({"from": "source", "to": "flagged", "label": "flows to"})
        edges.append({"from": "flagged", "to": "sink", "label": "reaches"})
    else:
        edges.append({"from": "source", "to": "flagged", "label": "flows to"})

    # Add evidence nodes
    for i, loc in enumerate(verdict.evidence_locations[:3]):
        if loc != f"{finding.path}:{finding.line}":
            nodes.append({"id": f"ev{i}", "label": loc, "type": "evidence"})
            edges.append({"from": f"ev{i}", "to": "flagged", "label": "context"})

    mermaid = _render_mermaid(nodes, edges, verdict)
    summary = f"Taint flow: {finding.taint_source or 'input'} → {finding.path}:{finding.line}"

    return {"summary": summary, "mermaid": mermaid, "nodes": nodes, "edges": edges}


def _build_sink_graph(finding: Finding, verdict: Verdict, check: str) -> dict:
    """Dangerous sink finding: show the call and its inputs."""
    nodes = []
    edges = []

    flagged = _escape_mermaid(_truncate(finding.lines.strip()))
    nodes.append({"id": "flagged", "label": f"{flagged}<br/>{finding.path}:{finding.line}",
                  "type": "sink"})

    # Add evidence as input nodes
    for i, loc in enumerate(verdict.evidence_locations[:4]):
        if loc != f"{finding.path}:{finding.line}":
            nodes.append({"id": f"ev{i}", "label": loc, "type": "evidence"})
            edges.append({"from": f"ev{i}", "to": "flagged", "label": "input"})

    if not edges:
        nodes.append({"id": "caller", "label": "caller", "type": "source"})
        edges.append({"from": "caller", "to": "flagged", "label": "calls"})

    mermaid = _render_mermaid(nodes, edges, verdict)
    summary = f"{check} at {finding.path}:{finding.line}"

    return {"summary": summary, "mermaid": mermaid, "nodes": nodes, "edges": edges}


def _build_http_graph(finding: Finding, verdict: Verdict, check: str) -> dict:
    """HTTP-related finding: show the request call and what's missing."""
    nodes = []
    edges = []

    call_label = _escape_mermaid(_truncate(finding.lines.strip()))
    nodes.append({"id": "call", "label": f"{call_label}<br/>{finding.path}:{finding.line}",
                  "type": "flagged"})

    missing = []
    if "timeout" in check:
        missing.append("timeout")
    if "raise-for-status" in check:
        missing.append("raise_for_status()")
    if "cert-validation" in check:
        missing.append("SSL verification")

    for i, m in enumerate(missing):
        nodes.append({"id": f"missing{i}", "label": f"missing: {m}", "type": "missing"})
        edges.append({"from": "call", "to": f"missing{i}", "label": "lacks"})

    mermaid = _render_mermaid(nodes, edges, verdict)
    summary = f"HTTP call at {finding.path}:{finding.line} missing {', '.join(missing)}"

    return {"summary": summary, "mermaid": mermaid, "nodes": nodes, "edges": edges}


def _build_dockerfile_graph(finding: Finding, verdict: Verdict, check: str) -> dict:
    """Dockerfile finding: show instruction context."""
    nodes = []
    edges = []

    flagged = _escape_mermaid(_truncate(finding.lines.strip()))
    nodes.append({"id": "instruction", "label": f"{flagged}",
                  "type": "flagged", "location": f"{finding.path}:{finding.line}"})

    issue = check.replace("-", " ")
    nodes.append({"id": "issue", "label": issue, "type": "missing"})
    edges.append({"from": "instruction", "to": "issue", "label": "triggers"})

    mermaid = _render_mermaid(nodes, edges, verdict)
    summary = f"{check} at {finding.path}:{finding.line}"

    return {"summary": summary, "mermaid": mermaid, "nodes": nodes, "edges": edges}


def _build_detection_graph(finding: Finding, verdict: Verdict, check: str) -> dict:
    """Informational detection: library/framework usage."""
    nodes = []
    edges = []

    flagged = _escape_mermaid(_truncate(finding.lines.strip()))
    nodes.append({"id": "code", "label": f"{flagged}<br/>{finding.path}:{finding.line}",
                  "type": "flagged"})

    what = check.replace("detect-generic-ai-", "").replace("detect-", "")
    nodes.append({"id": "detected", "label": f"detected: {what}", "type": "info"})
    edges.append({"from": "code", "to": "detected", "label": "uses"})

    mermaid = _render_mermaid(nodes, edges, verdict)
    summary = f"Detection: {what} usage at {finding.path}:{finding.line}"

    return {"summary": summary, "mermaid": mermaid, "nodes": nodes, "edges": edges}


def _build_generic_graph(finding: Finding, verdict: Verdict, check: str) -> dict:
    """Generic fallback for any finding type."""
    nodes = []
    edges = []

    flagged = _escape_mermaid(_truncate(finding.lines.strip()))
    nodes.append({"id": "flagged", "label": f"{flagged}<br/>{finding.path}:{finding.line}",
                  "type": "flagged"})

    nodes.append({"id": "issue", "label": _escape_mermaid(_truncate(finding.message, 60)),
                  "type": "issue"})
    edges.append({"from": "flagged", "to": "issue", "label": check})

    for i, loc in enumerate(verdict.evidence_locations[:3]):
        if loc != f"{finding.path}:{finding.line}":
            nodes.append({"id": f"ev{i}", "label": loc, "type": "evidence"})
            edges.append({"from": f"ev{i}", "to": "flagged", "label": "context"})

    mermaid = _render_mermaid(nodes, edges, verdict)
    summary = f"{check} at {finding.path}:{finding.line}"

    return {"summary": summary, "mermaid": mermaid, "nodes": nodes, "edges": edges}


def _render_mermaid(
    nodes: list[dict],
    edges: list[dict],
    verdict: Verdict,
) -> str:
    """Render nodes and edges as a Mermaid diagram."""
    style_map = {
        "source": "fill:#6cf,stroke:#036,color:#000",
        "sink": "fill:#f66,stroke:#900,color:#000",
        "flagged": "fill:#f96,stroke:#930,color:#000",
        "missing": "fill:#fcc,stroke:#c66,color:#000",
        "evidence": "fill:#eee,stroke:#999,color:#000",
        "info": "fill:#cef,stroke:#69c,color:#000",
        "issue": "fill:#fec,stroke:#c90,color:#000",
    }

    lines = ["graph TD"]

    for n in nodes:
        label = n["label"]
        loc = n.get("location", "")
        if loc and loc not in label:
            label = f"{label}<br/><i>{loc}</i>"
        lines.append(f'    {n["id"]}["{label}"]')

    for e in edges:
        label = e.get("label", "")
        if label:
            lines.append(f'    {e["from"]} -->|{label}| {e["to"]}')
        else:
            lines.append(f'    {e["from"]} --> {e["to"]}')

    for n in nodes:
        style = style_map.get(n["type"])
        if style:
            lines.append(f'    style {n["id"]} {style}')

    # Add verdict badge
    verdict_color = {
        "true_positive": "fill:#f66,stroke:#900,color:#fff",
        "false_positive": "fill:#6c6,stroke:#090,color:#fff",
        "uncertain": "fill:#fc6,stroke:#c90,color:#000",
    }
    v = verdict.verdict
    lines.append(f'    verdict_badge["{v.upper()}"]')
    lines.append(f'    style verdict_badge {verdict_color.get(v, "")}')

    return "\n".join(lines)
