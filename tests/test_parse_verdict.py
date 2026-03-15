"""Tests for _parse_verdict — the JSON extraction logic in runner.py."""
from __future__ import annotations

import pytest

from sast_verify.agents.runner import _parse_verdict
from sast_verify.schema import Verdict


# --- Clean JSON ---

def test_clean_json():
    text = '{"verdict": "true_positive", "confidence": "high", "reason": "vuln", "evidence_locations": ["f:1"]}'
    v = _parse_verdict(text)
    assert v.verdict == "true_positive"
    assert v.confidence == "high"


def test_clean_json_with_whitespace():
    text = '  \n {"verdict": "false_positive", "confidence": "medium", "reason": "safe", "evidence_locations": []}  \n'
    v = _parse_verdict(text)
    assert v.verdict == "false_positive"


# --- Embedded JSON ---

def test_json_in_prose():
    text = 'Here is my verdict:\n{"verdict": "true_positive", "confidence": "high", "reason": "x", "evidence_locations": []}\nDone.'
    v = _parse_verdict(text)
    assert v.verdict == "true_positive"


def test_json_in_markdown_fence():
    text = '```json\n{"verdict": "false_positive", "confidence": "low", "reason": "x", "evidence_locations": []}\n```'
    v = _parse_verdict(text)
    assert v.verdict == "false_positive"


def test_nested_braces_in_reason():
    """Properly escaped nested JSON in reason field."""
    text = r'{"verdict": "true_positive", "confidence": "high", "reason": "the dict {\"key\": \"val\"} is unsafe", "evidence_locations": []}'
    v = _parse_verdict(text)
    assert v.verdict == "true_positive"


def test_braces_in_reason_string():
    """Reason containing literal braces should not break parsing."""
    text = '{"verdict": "uncertain", "confidence": "low", "reason": "found pattern like func() { return; }", "evidence_locations": []}'
    v = _parse_verdict(text)
    assert v.verdict == "uncertain"


def test_multiple_json_objects_picks_verdict():
    """When prose contains a non-verdict JSON before the real one, pick the right one."""
    text = (
        'Example: {"name": "test"}\n'
        'Result: {"verdict": "false_positive", "confidence": "high", "reason": "x", "evidence_locations": []}'
    )
    v = _parse_verdict(text)
    assert v.verdict == "false_positive"


# --- Failures ---

def test_empty_string():
    with pytest.raises(ValueError, match="Empty response"):
        _parse_verdict("")


def test_whitespace_only():
    with pytest.raises(ValueError, match="Empty response"):
        _parse_verdict("   \n  ")


def test_no_json():
    with pytest.raises(ValueError, match="No JSON verdict"):
        _parse_verdict("I think this is a true positive.")


def test_json_without_verdict_key():
    with pytest.raises(ValueError, match="No JSON verdict"):
        _parse_verdict('{"confidence": "high", "reason": "x"}')


def test_invalid_verdict_value():
    """Valid JSON with verdict key but invalid enum value should fail validation."""
    with pytest.raises(Exception):
        _parse_verdict('{"verdict": "maybe", "confidence": "high", "reason": "x", "evidence_locations": []}')
