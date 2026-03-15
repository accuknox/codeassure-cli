"""Tests for agent tools — sandboxing, regex guards, scan budgets, anchoring, tracking."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sast_verify.agents.deps import AnalyzerDeps
from sast_verify.agents.tools import (
    MAX_GREP_BYTES,
    MAX_GREP_FILE_SIZE,
    MAX_READ_FILE_SIZE,
    grep_code,
    read_file,
)


def _make_context(
    codebase: Path,
    finding_dir: str = "",
    anchor_root: str = "",
    track: bool = False,
) -> MagicMock:
    deps = AnalyzerDeps(
        codebase=str(codebase),
        finding_dir=finding_dir,
        anchor_root=anchor_root,
        accessed_paths={} if track else {},
        grep_max_file_size=MAX_GREP_FILE_SIZE,
        grep_max_bytes=MAX_GREP_BYTES,
    )
    ctx = MagicMock()
    ctx.deps = deps
    return ctx


# --- read_file ---

class TestReadFile:
    def test_normal_read(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("line1\nline2\nline3\n")
        ctx = _make_context(tmp_path)
        result = read_file(ctx, "a.py")
        assert result["status"] == "success"
        assert "line1" in result["content"]

    def test_path_outside_codebase(self, tmp_path):
        ctx = _make_context(tmp_path)
        result = read_file(ctx, "../../etc/passwd")
        assert result["status"] == "error"
        assert "outside" in result["error"]

    def test_missing_file(self, tmp_path):
        ctx = _make_context(tmp_path)
        result = read_file(ctx, "nope.py")
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()

    def test_permission_error(self, tmp_path):
        f = tmp_path / "secret.py"
        f.write_text("secret")
        f.chmod(0o000)
        ctx = _make_context(tmp_path)
        try:
            result = read_file(ctx, "secret.py")
            assert result["status"] == "error"
            assert "Cannot read" in result["error"]
        finally:
            f.chmod(0o644)

    def test_binary_file(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x80\x81\x82")
        ctx = _make_context(tmp_path)
        result = read_file(ctx, "data.bin")
        assert result["status"] == "error"


# --- read_file: anchor enforcement ---

class TestReadFileAnchor:
    def test_anchor_blocks_outside_scope(self, tmp_path):
        """read_file rejects paths outside the anchor scope."""
        (tmp_path / "src" / "auth").mkdir(parents=True)
        (tmp_path / "src" / "auth" / "login.py").write_text("ok\n")
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "readme.py").write_text("unrelated\n")

        ctx = _make_context(tmp_path, anchor_root="src")
        result = read_file(ctx, "docs/readme.py")
        assert result["status"] == "error"
        assert "analysis scope" in result["error"]

    def test_anchor_allows_within_scope(self, tmp_path):
        (tmp_path / "src" / "auth").mkdir(parents=True)
        (tmp_path / "src" / "auth" / "login.py").write_text("ok\n")

        ctx = _make_context(tmp_path, anchor_root="src")
        result = read_file(ctx, "src/auth/login.py")
        assert result["status"] == "success"

    def test_no_anchor_allows_everything(self, tmp_path):
        (tmp_path / "anywhere.py").write_text("ok\n")
        ctx = _make_context(tmp_path)  # no anchor_root
        result = read_file(ctx, "anywhere.py")
        assert result["status"] == "success"

    def test_shallow_finding_anchored_to_finding_dir(self, tmp_path):
        """One-level-deep finding (src/login.py) anchors to src/, not repo root."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "login.py").write_text("ok\n")
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "notes.py").write_text("unrelated\n")

        # anchor_root="src" simulates what runner computes for src/login.py
        ctx = _make_context(tmp_path, finding_dir="src", anchor_root="src")
        assert read_file(ctx, "src/login.py")["status"] == "success"
        result = read_file(ctx, "docs/notes.py")
        assert result["status"] == "error"
        assert "analysis scope" in result["error"]


# --- read_file: large file streaming ---

class TestReadFileLargeFile:
    def test_large_file_streams_window(self, tmp_path):
        big = tmp_path / "big.py"
        line = "x = 1  # some code\n"  # 20 bytes
        count = (MAX_READ_FILE_SIZE // len(line)) + 100
        big.write_text(line * count)
        assert big.stat().st_size > MAX_READ_FILE_SIZE

        ctx = _make_context(tmp_path)
        result = read_file(ctx, "big.py", start_line=10, end_line=20)
        assert result["status"] == "success"
        assert result["start_line"] == 10
        assert result["end_line"] == 20
        assert result["total_lines"] > 20  # estimated total


# --- grep_code: regex safety ---

class TestGrepRegexSafety:
    def test_valid_pattern(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("import os\nos.system('ls')\n")
        ctx = _make_context(tmp_path)
        result = grep_code(ctx, "os\\.system", path="a.py")
        assert result["status"] == "success"
        assert len(result["matches"]) == 1

    def test_invalid_regex(self, tmp_path):
        ctx = _make_context(tmp_path)
        result = grep_code(ctx, "[invalid")
        assert result["status"] == "error"
        assert "Invalid regex" in result["error"]

    def test_nested_quantifier_rejected(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("x")
        ctx = _make_context(tmp_path)
        result = grep_code(ctx, "(a+)+")
        assert result["status"] == "error"
        assert "backtracking" in result["error"].lower()

    def test_star_star_rejected(self, tmp_path):
        ctx = _make_context(tmp_path)
        result = grep_code(ctx, "a**")
        assert result["status"] == "error"


# --- grep_code: scan budgets ---

class TestGrepScanBudgets:
    def test_large_file_skipped(self, tmp_path):
        big = tmp_path / "big.py"
        big.write_text("needle\n" * (MAX_GREP_FILE_SIZE // 7 + 1))
        assert big.stat().st_size > MAX_GREP_FILE_SIZE

        small = tmp_path / "small.py"
        small.write_text("needle\n")

        ctx = _make_context(tmp_path)
        result = grep_code(ctx, "needle")
        assert result["status"] == "success"
        paths = [m["path"] for m in result["matches"]]
        assert "small.py" in paths
        assert "big.py" not in paths

    def test_bytes_budget_truncates(self, tmp_path):
        chunk = "x" * 1024 + "\n"
        n_files = (MAX_GREP_BYTES // 1024) + 10
        for i in range(n_files):
            (tmp_path / f"f{i:04d}.py").write_text(chunk)

        ctx = _make_context(tmp_path)
        result = grep_code(ctx, "x")
        assert result["truncated"] is True

    def test_match_limit(self, tmp_path):
        f = tmp_path / "many.py"
        f.write_text("match\n" * 100)
        ctx = _make_context(tmp_path)
        result = grep_code(ctx, "match", path="many.py")
        assert result["status"] == "success"
        assert result["truncated"] is True
        assert len(result["matches"]) == 30


# --- grep_code: anchoring ---

class TestGrepAnchoring:
    def test_default_scoped_to_finding_dir(self, tmp_path):
        """When path is empty, grep defaults to finding_dir, not repo root."""
        (tmp_path / "src" / "auth").mkdir(parents=True)
        (tmp_path / "src" / "auth" / "login.py").write_text("secret = get_input()\n")
        (tmp_path / "src" / "unrelated").mkdir(parents=True)
        (tmp_path / "src" / "unrelated" / "utils.py").write_text("secret = config()\n")

        ctx = _make_context(tmp_path, finding_dir="src/auth")
        result = grep_code(ctx, "secret")
        assert result["status"] == "success"
        paths = [m["path"] for m in result["matches"]]
        assert any("auth" in p for p in paths)
        assert not any("unrelated" in p for p in paths)

    def test_explicit_path_blocked_by_anchor(self, tmp_path):
        """grep_code(path=...) rejects paths outside anchor scope."""
        (tmp_path / "src" / "auth").mkdir(parents=True)
        (tmp_path / "src" / "auth" / "login.py").write_text("target\n")
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "notes.py").write_text("target\n")

        ctx = _make_context(tmp_path, finding_dir="src/auth", anchor_root="src")
        result = grep_code(ctx, "target", path="docs")
        assert result["status"] == "error"
        assert "analysis scope" in result["error"]

    def test_explicit_path_within_anchor(self, tmp_path):
        """grep_code(path=...) allows paths within anchor scope."""
        (tmp_path / "src" / "auth").mkdir(parents=True)
        (tmp_path / "src" / "auth" / "login.py").write_text("target\n")
        (tmp_path / "src" / "utils").mkdir(parents=True)
        (tmp_path / "src" / "utils" / "helper.py").write_text("target\n")

        ctx = _make_context(tmp_path, finding_dir="src/auth", anchor_root="src")
        result = grep_code(ctx, "target", path="src/utils")
        assert result["status"] == "success"
        assert any("utils" in m["path"] for m in result["matches"])

    def test_no_finding_dir_falls_back_to_root(self, tmp_path):
        (tmp_path / "a.py").write_text("needle\n")
        ctx = _make_context(tmp_path, finding_dir="")
        result = grep_code(ctx, "needle")
        assert result["status"] == "success"
        assert len(result["matches"]) == 1

    def test_path_traversal_blocked(self, tmp_path):
        ctx = _make_context(tmp_path)
        result = grep_code(ctx, "x", path="../../etc")
        assert result["status"] == "error"
        assert "outside" in result["error"]


# --- tool access tracking ---

class TestToolTracking:
    def test_read_file_tracks_path_and_lines(self, tmp_path):
        f = tmp_path / "tracked.py"
        f.write_text("a\nb\nc\nd\ne\n")
        ctx = _make_context(tmp_path, track=True)
        read_file(ctx, "tracked.py", start_line=2, end_line=4)
        assert "tracked.py" in ctx.deps.accessed_paths
        ranges = ctx.deps.accessed_paths["tracked.py"]
        assert (2, 4) in ranges

    def test_read_file_no_track_on_error(self, tmp_path):
        ctx = _make_context(tmp_path, track=True)
        read_file(ctx, "nonexistent.py")
        assert ctx.deps.accessed_paths == {}

    def test_grep_tracks_matched_paths_and_lines(self, tmp_path):
        (tmp_path / "a.py").write_text("line1\nfound\nline3\n")
        (tmp_path / "b.py").write_text("nope\n")
        ctx = _make_context(tmp_path, track=True)
        grep_code(ctx, "found")
        assert "a.py" in ctx.deps.accessed_paths
        assert "b.py" not in ctx.deps.accessed_paths
        # Should have a range covering the match + context
        ranges = ctx.deps.accessed_paths["a.py"]
        assert len(ranges) >= 1

    def test_multiple_reads_accumulate_ranges(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("".join(f"line{i}\n" for i in range(20)))
        ctx = _make_context(tmp_path, track=True)
        read_file(ctx, "a.py", start_line=1, end_line=5)
        read_file(ctx, "a.py", start_line=10, end_line=15)
        ranges = ctx.deps.accessed_paths["a.py"]
        assert (1, 5) in ranges
        assert (10, 15) in ranges
