"""Tests for context-graph consumption, coloring, and deadcode shortcut."""

from sast_verify.preprocess import compact_finding
from sast_verify.prompts import _build_context_graph_section
from sast_verify.pipeline import _apply_coloring, _is_deadcode
from sast_verify.schema import (
    Enrichment,
    GraphColoring,
    NodeColoring,
    PathColoring,
    Remediation,
    Verdict,
)


def _result_with_graph(reachability="reachable"):
    return {
        "check_id": "java.sqli",
        "path": "svc/Repo.java",
        "start": {"line": 7},
        "end": {"line": 7},
        "extra": {"message": "sqli", "severity": "ERROR", "lines": "execute(q)"},
        "context_graph": {
            "engine": "joern", "language": "java",
            "sink": {"file": "svc/Repo.java", "line": 7},
            "nodes": [
                {"id": "n0", "kind": "source", "role": "http-request",
                 "label": "Ctrl.java:6", "file": "Ctrl.java", "line": 6,
                 "function": "get", "code": "String get() {...}"},
                {"id": "n_sink", "kind": "sink", "label": "Repo.java:7",
                 "file": "svc/Repo.java", "line": 7, "function": "fetch",
                 "code": "String fetch() {...}"},
            ],
            "edges": [{"id": "e0", "from": "n0", "to": "n_sink", "kind": "data-flows-to", "paths": ["p0"]}],
            "paths": [{"id": "p0", "nodes": ["n0", "n_sink"], "reachability": reachability,
                       "tainted": True, "protection": {"has_sanitizer": False, "has_guard": False}}],
        },
    }


def test_preprocess_passes_context_graph():
    f = compact_finding(_result_with_graph())
    assert f.context_graph is not None
    assert f.context_graph["engine"] == "joern"


def test_context_graph_section_renders():
    f = compact_finding(_result_with_graph())
    section = _build_context_graph_section(f)
    assert section is not None
    assert "Context Graph" in section
    assert "Path p0" in section
    assert "[SINK]" in section and "[SOURCE" in section
    assert "String fetch()" in section  # node code included


def test_context_graph_section_none_without_graph():
    result = _result_with_graph()
    del result["context_graph"]
    f = compact_finding(result)
    assert _build_context_graph_section(f) is None


def test_is_deadcode():
    assert _is_deadcode(compact_finding(_result_with_graph("deadcode"))) is True
    assert _is_deadcode(compact_finding(_result_with_graph("reachable"))) is False
    # no graph → not deadcode
    r = _result_with_graph()
    del r["context_graph"]
    assert _is_deadcode(compact_finding(r)) is False


def _tp_verdict():
    return Verdict(verdict="true_positive", is_security_vulnerability=True,
                   severity="high", confidence="high", reason="x")


def test_apply_coloring_derives_node_colors_from_paths():
    cg = _result_with_graph()["context_graph"]  # source n0 → sink n_sink, path p0
    coloring = GraphColoring(
        paths=[PathColoring(id="p0", status="vulnerable", color="red", reason="tainted")],
        nodes=[],  # node colors are DERIVED now
    )
    _apply_coloring(cg, coloring, _tp_verdict())
    assert cg["paths"][0]["color"] == "red" and cg["paths"][0]["status"] == "vulnerable"
    # role-based node colors: source=blue, sink=red; exploitable path edge=red
    assert {n["id"]: n["color"] for n in cg["nodes"]} == {"n0": "blue", "n_sink": "red"}
    assert cg["edges"][0]["color"] == "red"


def test_apply_coloring_fills_uncolored_paths_by_verdict():
    cg = _result_with_graph("deadcode")["context_graph"]
    _apply_coloring(cg, GraphColoring(), _tp_verdict())  # no LLM colors
    # deadcode path → gray regardless of verdict; every node colored (no None)
    assert cg["paths"][0]["color"] == "gray"
    assert all(n.get("color") for n in cg["nodes"])


def test_enrichment_schema_roundtrip():
    e = Enrichment(
        rationale="r", business_logic="b", explanation="e",
        remediation=Remediation(summary="use params", code_patch="stmt.setString(1,id)"),
        coloring=GraphColoring(paths=[PathColoring(id="p0", status="safe", color="green")]),
    )
    d = e.model_dump()
    assert d["remediation"]["preserves_logic"] is True
    assert d["coloring"]["paths"][0]["color"] == "green"
