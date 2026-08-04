"""Regression tests for multi-signal FP/TP determination.

Guards the core thesis: reachability is one GATED signal, not the arbiter of the
verdict. For pattern-existence rules the verdict is a pure at-site presence check;
reachability may only touch is_security_vulnerability / severity.
"""
import sast_verify.prompts.analyzer as A
from sast_verify.pipeline import _deadcode_decision, _is_deadcode
from sast_verify.preprocess import compact_finding
from sast_verify.prompts import build_user_message
from sast_verify.prompts.analyzer import _ANALYZER_VARIANTS
from sast_verify.prompts.rule_policies import is_taint_class, rule_kind_of
from sast_verify.schema import Evidence, EvidenceBundle


def _finding(check_id, path="src/app/http.py", reach=None, tainted=False, degraded=False):
    result = {
        "check_id": check_id, "path": path,
        "start": {"line": 10}, "end": {"line": 10},
        "extra": {"message": "m", "severity": "WARNING", "lines": "open(p)"},
    }
    if reach is not None:
        cg = {
            "engine": "joern", "language": "python", "sink": {"file": path, "line": 10},
            "nodes": [{"id": "s", "kind": "sink", "file": path, "line": 10}], "edges": [],
            "paths": [{"id": "p0", "nodes": ["s"], "reachability": reach,
                       "tainted": tainted, "protection": {}}],
        }
        if degraded:
            cg["stats"] = {"degraded": True}
        result["context_graph"] = cg
    return compact_finding(result)


def _bundle(f):
    return EvidenceBundle(
        finding=f,
        evidence=[Evidence(path=f.path, start_line=8, end_line=12, content="8: open(p)")],
    )


# --- classifier --------------------------------------------------------------

def test_known_families_are_pattern_existence():
    assert is_taint_class("python.lang.best-practice.use-timeout") is False
    assert rule_kind_of("python.lang.best-practice.use-timeout") == "best_practice"


def test_injection_check_ids_are_taint_class():
    assert is_taint_class("java.sqli") is True
    assert is_taint_class("py.rule.command-injection") is True
    assert rule_kind_of("java.sqli") == "taint_class"


# --- prompt injection (F1) ---------------------------------------------------

def test_rule_policy_injected_for_known_rule_closes_gate():
    msg = build_user_message(_bundle(_finding("python.lang.best-practice.use-timeout")))
    assert "Rule-Specific Verdict Guidance" in msg
    assert "best_practice" in msg
    assert "timeout" in msg                       # constraint checklist text
    assert "Reachability gate — CLOSED" in msg    # verdict = pattern presence


def test_rule_policy_generic_fallback_for_unknown_rule():
    msg = build_user_message(_bundle(_finding("some.unknown.rule")))
    assert "Rule-Specific Verdict Guidance" in msg
    assert "pattern described in the scanner's claim" in msg  # generic constraints


def test_taint_rule_opens_reachability_gate():
    assert "Reachability gate — OPEN" in build_user_message(_bundle(_finding("java.sqli")))


def test_lifecycle_triage_flags_test_files():
    msg = build_user_message(_bundle(_finding("java.sqli", path="tests/test_repo.py")))
    assert "Context Triage" in msg


# --- gated deadcode (F2) -----------------------------------------------------

def test_deadcode_pattern_existence_is_tp_not_security():
    """Non-degraded all-deadcode on a pattern-existence rule → deterministic
    true_positive + is_security=false (the construct is really present, just unreachable),
    NOT false_positive. The context graph stays authoritative."""
    f = _finding("python.best-practice.use-timeout", reach="deadcode")
    assert _is_deadcode(f) is True
    v = _deadcode_decision(f)
    assert v is not None
    assert v.verdict == "true_positive"
    assert v.is_security_vulnerability is False
    assert v.confidence == "high"                    # non-degraded graph is authoritative
    assert v.evidence_locations == [f"{f.path}:10"]  # cites the sink


def test_deadcode_taint_class_is_false_positive():
    f = _finding("java.sqli", reach="deadcode", tainted=True)
    v = _deadcode_decision(f)
    assert v is not None
    assert v.verdict == "false_positive"
    assert v.is_security_vulnerability is False
    assert v.confidence == "high"
    assert v.evidence_locations == [f"{f.path}:10"]  # cites the sink


def test_deadcode_degraded_graph_routes_to_llm():
    f = _finding("java.sqli", reach="deadcode", tainted=True, degraded=True)
    assert _is_deadcode(f) is True
    assert _deadcode_decision(f) is None             # degraded → LLM decides, graph is a hint


# --- guardrail propagation (F4) ----------------------------------------------

def test_all_analyzer_variants_carry_guardrails():
    for name in _ANALYZER_VARIANTS:
        t = getattr(A, name)
        assert "## Common pitfalls" in t, name
        assert "nosemgrep" in t, name
        assert "Verdict and security flag are independent" in t, name
