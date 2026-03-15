"""Tests for retrieval.py — path resolution, safe file reading, streaming."""
from __future__ import annotations

import os
from pathlib import Path

from sast_verify.retrieval import (
    MAX_FILE_SIZE,
    _extract_window,
    _read_text_safe,
    _resolve_path,
    retrieve,
)
from sast_verify.schema import Finding


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        fingerprint="abc", check_id="test.rule", path="src/app.py",
        line=10, end_line=12, severity="ERROR", category="security",
        message="test", lines="x = input()",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# --- _read_text_safe ---

def test_read_text_safe_normal(tmp_path):
    f = tmp_path / "hello.py"
    f.write_text("print('hi')\n", encoding="utf-8")
    assert _read_text_safe(f) == "print('hi')\n"


def test_read_text_safe_binary(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x80\x81\x82\x83")
    assert _read_text_safe(f) is None


def test_read_text_safe_permission_error(tmp_path):
    f = tmp_path / "secret.py"
    f.write_text("secret", encoding="utf-8")
    f.chmod(0o000)
    try:
        assert _read_text_safe(f) is None
    finally:
        f.chmod(0o644)


def test_read_text_safe_missing_file(tmp_path):
    f = tmp_path / "gone.py"
    assert _read_text_safe(f) is None


# --- _resolve_path ---

def test_resolve_path_exact(tmp_path):
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "app.py"
    target.write_text("x = 1")
    assert _resolve_path("src/app.py", tmp_path) == target.resolve()


def test_resolve_path_missing(tmp_path):
    assert _resolve_path("src/nope.py", tmp_path) is None


def test_resolve_path_traversal(tmp_path):
    assert _resolve_path("../../etc/passwd", tmp_path) is None


# --- _extract_window ---

def test_extract_window_small_file(tmp_path):
    f = tmp_path / "small.py"
    f.write_text("line\n" * 10)
    result = _extract_window(f, 3, 5)
    assert result is not None
    start, lines = result
    assert start == 1  # small file → returns everything from line 1
    assert len(lines) == 10


def test_extract_window_large_line_count(tmp_path):
    """File with many lines gets windowed, not returned fully."""
    f = tmp_path / "big.py"
    f.write_text("".join(f"line {i}\n" for i in range(500)))
    result = _extract_window(f, 100, 105)
    assert result is not None
    start, lines = result
    assert start > 1  # not the whole file
    assert len(lines) < 500


def test_extract_window_streams_large_bytes(tmp_path):
    """File > MAX_FILE_SIZE is streamed, not fully loaded."""
    f = tmp_path / "huge.py"
    line = "x = 1  # padding\n"
    count = (MAX_FILE_SIZE // len(line)) + 100
    f.write_text(line * count)
    assert f.stat().st_size > MAX_FILE_SIZE

    result = _extract_window(f, 10, 15)
    assert result is not None
    start, lines = result
    assert start > 0
    assert len(lines) < count  # did not load entire file


def test_extract_window_unreadable(tmp_path):
    f = tmp_path / "secret.py"
    f.write_text("x\n" * 10)
    f.chmod(0o000)
    try:
        assert _extract_window(f, 1, 5) is None
    finally:
        f.chmod(0o644)


# --- retrieve ---

def test_retrieve_no_file(tmp_path):
    f = _make_finding(path="missing.py")
    bundle = retrieve(f, tmp_path)
    assert bundle.evidence == []


def test_retrieve_unreadable(tmp_path):
    target = tmp_path / "src" / "app.py"
    target.parent.mkdir()
    target.write_text("x = 1\n" * 5, encoding="utf-8")
    target.chmod(0o000)
    f = _make_finding(path="src/app.py")
    try:
        bundle = retrieve(f, tmp_path)
        assert bundle.evidence == []
    finally:
        target.chmod(0o644)


def test_retrieve_small_file(tmp_path):
    target = tmp_path / "src" / "app.py"
    target.parent.mkdir()
    target.write_text("line\n" * 10, encoding="utf-8")
    f = _make_finding(path="src/app.py", line=3, end_line=5)
    bundle = retrieve(f, tmp_path)
    assert len(bundle.evidence) == 1
    assert bundle.evidence[0].start_line == 1  # small file → full content
