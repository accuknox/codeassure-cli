"""Deterministic paste-target validation for remediations.

The enricher LLM emits ``code_patch`` + (``file``, ``start_line``, ``end_line``,
``original_code``). Customers apply the fix by REPLACING exactly those lines, so
one hallucinated line number or a paraphrased ``original_code`` corrupts their
file. This module enforces one invariant on every remediation before it is
written to the output JSON:

    ``original_code`` is the byte-exact content of ``file`` at
    ``start_line..end_line`` (1-indexed, inclusive), or the remediation is
    re-anchored to a region where that holds, or — when no anchor can be
    found — the mismatch is flagged in ``notes`` and ``anchor_verified``
    stays False.

Snap order:
 1. exact text at the claimed range → verified as-is;
 2. whitespace-normalized match at the claimed range → verified, original_code
    rewritten to the file's exact bytes;
 3. the quoted block found elsewhere in the file (unique, or nearest occurrence
    to the flagged line) → range snapped, original_code rewritten;
 4. no match → re-anchored to the flagged line span with the file's real
    content, patch kept, warning appended to notes.

When a snap succeeds via 2/3 the code_patch is re-indented to the anchored
region's base indentation (only when the patch shares a uniform base indent, so
we never mangle mixed-indent patches).
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..schema import Finding, Remediation

log = logging.getLogger(__name__)

_MAX_FILE_BYTES = 4 * 1024 * 1024


def _read_lines(path: Path) -> list[str] | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None


def _norm(line: str) -> str:
    return line.strip()


def _slice(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1:end])


def _find_block(lines: list[str], block: list[str], near_line: int) -> int | None:
    """1-indexed start of ``block`` in ``lines`` (whitespace-normalized match).

    Multiple occurrences → the one nearest ``near_line`` (the flagged line), so
    a repeated snippet snaps to the flagged region, not a random twin.
    """
    want = [_norm(x) for x in block]
    if not want or all(not w for w in want):
        return None
    hits: list[int] = []
    limit = len(lines) - len(want) + 1
    for i in range(limit):
        if all(_norm(lines[i + j]) == want[j] for j in range(len(want))):
            hits.append(i + 1)
    if not hits:
        return None
    return min(hits, key=lambda s: (abs(s - near_line), s))


def _base_indent(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line[: len(line) - len(line.lstrip())]
    return ""


def _reindent(patch: str, target_indent: str) -> str:
    """Shift ``patch`` from its own base indent to ``target_indent`` when every
    non-empty patch line carries the patch's base indent; otherwise unchanged."""
    if not patch.strip():
        return patch
    own = _base_indent(patch)
    if own == target_indent:
        return patch
    lines = patch.splitlines()
    for line in lines:
        if line.strip() and not line.startswith(own):
            return patch  # mixed base indent — do not touch
    out = [target_indent + line[len(own):] if line.strip() else line for line in lines]
    return "\n".join(out)


def anchor_remediation(rem: Remediation, codebase: Path, finding: Finding) -> Remediation:
    """Enforce the paste-target invariant on one remediation (in place).

    Never raises; on any I/O problem the remediation is returned unchanged with
    ``anchor_verified`` False.
    """
    codebase = Path(codebase)
    # No patch → nothing a customer will paste; still fix an unset file target.
    if not (rem.code_patch or "").strip():
        rem.file = rem.file or finding.path
        return rem

    rel = rem.file or finding.path
    full = (codebase / rel).resolve()
    try:
        full.relative_to(codebase.resolve())
    except ValueError:
        rel, full = finding.path, (codebase / finding.path).resolve()
    if not full.is_file() and rel != finding.path:
        # Model cited a file that doesn't exist — the flagged file is the target.
        rel, full = finding.path, (codebase / finding.path).resolve()
    lines = _read_lines(full)
    if lines is None:
        rem.notes = (rem.notes + " " if rem.notes else "") + \
            f"Paste target could not be verified ({rel} unreadable)."
        return rem
    rem.file = rel

    start = rem.start_line if isinstance(rem.start_line, int) and rem.start_line >= 1 else finding.line
    end = rem.end_line if isinstance(rem.end_line, int) and rem.end_line >= start else max(start, finding.end_line or start)
    start = min(start, len(lines))
    end = min(end, len(lines))

    quoted = (rem.original_code or "").splitlines()
    actual = _slice(lines, start, end)

    # 1. byte-exact at the claimed range
    if quoted and actual == rem.original_code.rstrip("\n") and rem.original_code.strip():
        rem.start_line, rem.end_line = start, end
        rem.anchor_verified = True
        return rem

    # 2. whitespace-normalized at the claimed range
    if quoted and len(quoted) == (end - start + 1) and \
            [_norm(x) for x in quoted] == [_norm(x) for x in lines[start - 1:end]]:
        rem.start_line, rem.end_line = start, end
        rem.original_code = actual
        rem.code_patch = _reindent(rem.code_patch, _base_indent(actual))
        rem.anchor_verified = True
        return rem

    # 3. quoted block found elsewhere in the file → snap
    if quoted:
        found = _find_block(lines, quoted, finding.line)
        if found is not None:
            new_end = found + len(quoted) - 1
            region = _slice(lines, found, new_end)
            rem.start_line, rem.end_line = found, new_end
            rem.original_code = region
            rem.code_patch = _reindent(rem.code_patch, _base_indent(region))
            rem.anchor_verified = True
            if (start, end) != (found, new_end):
                rem.notes = (rem.notes + " " if rem.notes else "") + \
                    f"Paste target re-anchored to lines {found}-{new_end} (model cited {start}-{end})."
            return rem

    # 4. no anchor — pin to the flagged region with the file's REAL content so
    # original_code is still truthful; the patch needs human review.
    f_start = min(finding.line, len(lines)) or 1
    f_end = min(max(finding.end_line or finding.line, f_start), len(lines))
    rem.start_line, rem.end_line = f_start, f_end
    rem.original_code = _slice(lines, f_start, f_end)
    rem.anchor_verified = False
    rem.notes = (rem.notes + " " if rem.notes else "") + (
        "Model-quoted original code did not match the file; target re-anchored to the "
        f"flagged lines {f_start}-{f_end}. Review the patch region before applying."
    )
    return rem
