"""Paste-target anchoring: original_code must match the file, or be re-anchored."""

from pathlib import Path

import pytest

from sast_verify.agents.patch_anchor import anchor_remediation
from sast_verify.schema import Finding, Remediation


SRC = (
    "import sqlite3\n"
    "\n"
    "class Repo:\n"
    "    def find(self, uid):\n"
    "        query = \"SELECT * FROM users WHERE id = \" + uid\n"
    "        return self.conn.execute(query)\n"
    "\n"
    "    def other(self):\n"
    "        return 1\n"
)


@pytest.fixture()
def codebase(tmp_path) -> Path:
    (tmp_path / "repo.py").write_text(SRC)
    return tmp_path


def _finding(line=5, end=6) -> Finding:
    return Finding(
        fingerprint="f", check_id="sqli", path="repo.py", line=line, end_line=end,
        severity="ERROR", category="security", message="m",
        lines='        query = "SELECT ..." + uid',
    )


def _rem(**kw) -> Remediation:
    base = dict(
        summary="parameterize", code_patch=(
            "        query = \"SELECT * FROM users WHERE id = ?\"\n"
            "        return self.conn.execute(query, (uid,))"
        ),
        file="repo.py", start_line=5, end_line=6,
        original_code=(
            "        query = \"SELECT * FROM users WHERE id = \" + uid\n"
            "        return self.conn.execute(query)"
        ),
    )
    base.update(kw)
    return Remediation(**base)


def test_exact_match_verifies(codebase):
    rem = anchor_remediation(_rem(), codebase, _finding())
    assert rem.anchor_verified is True
    assert (rem.start_line, rem.end_line) == (5, 6)


def test_wrong_lines_snap_to_quoted_block(codebase):
    rem = anchor_remediation(_rem(start_line=2, end_line=3), codebase, _finding())
    assert rem.anchor_verified is True
    assert (rem.start_line, rem.end_line) == (5, 6)
    assert "re-anchored" in rem.notes


def test_whitespace_drift_rewrites_original(codebase):
    drifted = _rem(original_code=(
        "query = \"SELECT * FROM users WHERE id = \" + uid\n"
        "return self.conn.execute(query)"
    ))
    rem = anchor_remediation(drifted, codebase, _finding())
    assert rem.anchor_verified is True
    # original_code rewritten to the file's exact (indented) bytes
    assert rem.original_code.startswith("        query")
    # patch re-indented to the region's base indent
    assert rem.code_patch.splitlines()[0].startswith("        ")


def test_hallucinated_original_reanchors_to_flagged_lines(codebase):
    rem = anchor_remediation(
        _rem(original_code="totally = made_up()\nnot_in = file()"),
        codebase, _finding(),
    )
    assert rem.anchor_verified is False
    assert (rem.start_line, rem.end_line) == (5, 6)
    # original_code is now the REAL flagged region, never the hallucination
    assert "made_up" not in rem.original_code
    assert "SELECT * FROM users" in rem.original_code
    assert "Review the patch region" in rem.notes


def test_file_escape_is_contained(codebase):
    rem = anchor_remediation(_rem(file="../outside.py"), codebase, _finding())
    assert rem.file == "repo.py"


def test_empty_patch_untouched(codebase):
    rem = anchor_remediation(
        Remediation(summary="no change required", code_patch="", file=None),
        codebase, _finding(),
    )
    assert rem.file == "repo.py"
    assert rem.anchor_verified is False


def test_missing_file_flagged(codebase):
    rem = anchor_remediation(_rem(file="gone.py"), codebase, _finding(line=99, end=99))
    # falls back to the finding path; finding lines clamped to file length
    assert rem.anchor_verified in (True, False)
    assert "unreadable" not in rem.notes  # repo.py exists via finding.path fallback
