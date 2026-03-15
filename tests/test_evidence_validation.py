"""Tests for _validate_evidence — evidence groundedness check with line-level validation."""
from __future__ import annotations

from sast_verify.agents.runner import _validate_evidence


def test_finding_path_within_evidence_window():
    result = _validate_evidence(
        ["src/auth/login.py:42"], {}, "src/auth/login.py",
        finding_start=1, finding_end=100,
    )
    assert result == ["src/auth/login.py:42"]


def test_finding_path_outside_evidence_window_rejected():
    result = _validate_evidence(
        ["src/auth/login.py:9999"], {}, "src/auth/login.py",
        finding_start=1, finding_end=100,
    )
    assert result == []


def test_finding_path_outside_window_but_tool_read():
    """Line outside initial evidence, but tool read that range — accepted."""
    result = _validate_evidence(
        ["src/auth/login.py:200"],
        {"src/auth/login.py": [(190, 210)]},
        "src/auth/login.py",
        finding_start=1, finding_end=100,
    )
    assert result == ["src/auth/login.py:200"]


def test_accessed_path_with_valid_line():
    result = _validate_evidence(
        ["src/utils/sanitize.py:10"],
        {"src/utils/sanitize.py": [(1, 50)]},
        "src/auth/login.py",
        finding_start=1, finding_end=100,
    )
    assert result == ["src/utils/sanitize.py:10"]


def test_accessed_path_with_invalid_line():
    """File was accessed but cited line wasn't in any read range."""
    result = _validate_evidence(
        ["src/utils/sanitize.py:999"],
        {"src/utils/sanitize.py": [(1, 50)]},
        "src/auth/login.py",
        finding_start=1, finding_end=100,
    )
    assert result == []


def test_unaccessed_path_filtered():
    result = _validate_evidence(
        ["src/auth/login.py:42", "src/unrelated/foo.py:7"],
        {},
        "src/auth/login.py",
        finding_start=1, finding_end=100,
    )
    assert result == ["src/auth/login.py:42"]


def test_mixed_valid_and_invalid():
    result = _validate_evidence(
        ["a.py:5", "b.py:10", "c.py:3"],
        {"b.py": [(1, 20)]},
        "a.py",
        finding_start=1, finding_end=50,
    )
    assert result == ["a.py:5", "b.py:10"]


def test_bare_path_without_line_number():
    """File path without :line — accepted if file was accessed."""
    result = _validate_evidence(
        ["src/auth/login.py"],
        {},
        "src/auth/login.py",
        finding_start=1, finding_end=100,
    )
    assert result == ["src/auth/login.py"]


def test_bare_path_accessed_file():
    result = _validate_evidence(
        ["src/utils/helper.py"],
        {"src/utils/helper.py": [(1, 30)]},
        "a.py",
        finding_start=1, finding_end=50,
    )
    assert result == ["src/utils/helper.py"]


def test_empty_evidence():
    result = _validate_evidence([], {}, "a.py", finding_start=1, finding_end=50)
    assert result == []


def test_all_filtered():
    result = _validate_evidence(
        ["never/read.py:1", "also/never.py:2"],
        {},
        "src/auth/login.py",
        finding_start=1, finding_end=100,
    )
    assert result == []


def test_multiple_read_ranges():
    """File accessed in multiple ranges — line in any range is valid."""
    result = _validate_evidence(
        ["x.py:75"],
        {"x.py": [(1, 30), (70, 80), (100, 120)]},
        "a.py",
        finding_start=1, finding_end=50,
    )
    assert result == ["x.py:75"]
