"""Resilience layer: transient-error detection, retry, and the deterministic
fallback verdict that replaces blanket 'uncertain' when the LLM is unavailable."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from sast_verify.agents.runner import (
    _deterministic_fallback,
    _error_detail,
    _is_transient,
    _run_with_retry,
)
from sast_verify.schema import EvidenceBundle, Finding


def _finding(check_id: str, context_graph: dict | None = None) -> Finding:
    return Finding(
        fingerprint="fp", check_id=check_id, path="src/app.py", line=10,
        end_line=12, severity="ERROR", category="security",
        message="claim", lines="dangerous()", context_graph=context_graph,
    )


def _bundle(check_id: str, cg: dict | None = None) -> EvidenceBundle:
    return EvidenceBundle(finding=_finding(check_id, cg), evidence=[])


class _Status(Exception):
    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}")


class TestTransientDetection:
    def test_rate_limit_status_transient(self):
        assert _is_transient(_Status(429))
        assert _is_transient(_Status(529))
        assert _is_transient(_Status(503))

    def test_client_errors_not_transient(self):
        assert not _is_transient(_Status(401))
        assert not _is_transient(_Status(404))
        assert not _is_transient(_Status(422))

    def test_httpx_transport_errors_transient(self):
        assert _is_transient(httpx.ConnectError("boom"))
        assert _is_transient(httpx.ReadTimeout("slow"))

    def test_status_found_via_cause_chain(self):
        outer = RuntimeError("wrapped")
        outer.__cause__ = _Status(500)
        assert _is_transient(outer)

    def test_value_error_not_transient(self):
        assert not _is_transient(ValueError("bad config"))

    def test_error_detail_includes_status(self):
        assert "429" in _error_detail(_Status(429))


class _FlakyAgent:
    """Fails N times with the given exception, then succeeds."""
    def __init__(self, failures: int, exc: Exception):
        self.failures = failures
        self.exc = exc
        self.calls = 0

    async def run(self, message, **kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.exc
        return type("R", (), {"output": "ok"})()


class TestRunWithRetry:
    def test_retries_transient_then_succeeds(self):
        agent = _FlakyAgent(2, _Status(429))
        result = asyncio.run(_run_with_retry(agent, "m", retries=3, base_delay=0.01))
        assert result.output == "ok"
        assert agent.calls == 3

    def test_non_transient_raises_immediately(self):
        agent = _FlakyAgent(5, ValueError("bad request shape"))
        with pytest.raises(ValueError):
            asyncio.run(_run_with_retry(agent, "m", retries=3, base_delay=0.01))
        assert agent.calls == 1

    def test_exhausted_retries_raise(self):
        agent = _FlakyAgent(10, _Status(503))
        with pytest.raises(_Status):
            asyncio.run(_run_with_retry(agent, "m", retries=2, base_delay=0.01))
        assert agent.calls == 3  # 1 + 2 retries


def _graph(paths: list[dict], degraded: bool = False) -> dict:
    return {
        "sink": {"file": "src/app.py", "line": 10},
        "nodes": [{"id": "n_sink", "file": "src/app.py", "line": 10, "kind": "sink"}],
        "paths": paths,
        "stats": {"degraded": degraded},
    }


class TestDeterministicFallback:
    def test_taint_rule_with_tainted_reachable_path_is_tp(self):
        cg = _graph([{"id": "p0", "tainted": True, "reachability": "reachable", "nodes": ["n_sink"]}])
        v = _deterministic_fallback(_bundle("rules.python.sql-injection", cg), "HTTP 429")
        assert v.verdict == "true_positive"
        assert v.is_security_vulnerability is True
        assert "429" in v.reason

    def test_taint_rule_no_taint_nondegraded_is_fp(self):
        cg = _graph([{"id": "p0", "tainted": False, "reachability": "reachable", "nodes": ["n_sink"]}])
        v = _deterministic_fallback(_bundle("rules.go.command-injection", cg), "HTTP 529")
        assert v.verdict == "false_positive"
        assert v.is_security_vulnerability is False

    def test_taint_rule_degraded_graph_stays_uncertain(self):
        cg = _graph(
            [{"id": "p0", "tainted": False, "reachability": "reachable", "nodes": ["n_sink"]}],
            degraded=True,
        )
        v = _deterministic_fallback(_bundle("rules.go.command-injection", cg), "timeout")
        assert v.verdict == "uncertain"

    def test_taint_rule_no_graph_stays_uncertain(self):
        v = _deterministic_fallback(_bundle("rules.js.xss"), "HTTP 500")
        assert v.verdict == "uncertain"

    def test_pattern_rule_is_tp_with_rule_kind_security_flag(self):
        # security_config family → is_security_vulnerability=True
        v = _deterministic_fallback(_bundle("python.requests.disabled-cert-validation"), "HTTP 429")
        assert v.verdict == "true_positive"
        assert v.is_security_vulnerability is True
        # best_practice family → is_security_vulnerability=False
        v2 = _deterministic_fallback(_bundle("python.requests.use-timeout"), "HTTP 429")
        assert v2.verdict == "true_positive"
        assert v2.is_security_vulnerability is False

    def test_confidence_always_low_and_reason_names_error(self):
        v = _deterministic_fallback(_bundle("python.requests.use-timeout"), "ConnectError")
        assert v.confidence == "low"
        assert "ConnectError" in v.reason


class TestFallbackEnrichment:
    def test_always_produces_complete_remediation_block(self):
        from sast_verify.agents.enrich import fallback_enrichment
        from sast_verify.schema import Verdict

        cg = _graph([{"id": "p0", "tainted": True, "reachability": "reachable", "nodes": ["n_sink"]}])
        b = _bundle("rules.python.sql-injection", cg)
        v = Verdict(verdict="true_positive", confidence="low", reason="fallback")
        e = fallback_enrichment(b, v, "HTTP 429")
        assert e.rationale == "fallback"
        assert e.remediation.file == "src/app.py"
        assert e.remediation.start_line == 10
        assert e.remediation.end_line == 12
        assert "unavailable" in e.remediation.notes.lower()
        assert "1 tainted" in e.explanation
