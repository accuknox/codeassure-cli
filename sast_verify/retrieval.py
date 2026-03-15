from __future__ import annotations

import logging
from pathlib import Path

from .schema import Evidence, EvidenceBundle, Finding

log = logging.getLogger(__name__)

SMALL_FILE_THRESHOLD = 300
CONTEXT_LINES = 15
MAX_FILE_SIZE = 1024 * 1024  # 1 MB — read fully below this, stream above


def _numbered(lines: list[str], start: int) -> str:
    return "\n".join(
        f"{start + i}: {line}" for i, line in enumerate(lines)
    )


def _is_contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _resolve_path(finding_path: str, codebase: Path) -> Path | None:
    """Resolve finding path against codebase. Exact match only."""
    candidate = (codebase / finding_path).resolve()
    if _is_contained(candidate, codebase) and candidate.is_file():
        return candidate
    return None


def _read_text_safe(filepath: Path) -> str | None:
    try:
        return filepath.read_text(encoding="utf-8")
    except (UnicodeDecodeError, ValueError, PermissionError, OSError):
        log.warning("Cannot read file, skipping: %s", filepath)
        return None


def _extract_window(
    filepath: Path, line: int, end_line: int,
) -> tuple[int, list[str]] | None:
    """Extract a context window around the given line range.

    Returns (start_line_1indexed, lines) or None on read failure.
    For small files (≤ SMALL_FILE_THRESHOLD lines), returns the entire file.
    For large files by byte size (> MAX_FILE_SIZE), streams only the needed range.
    """
    try:
        size = filepath.stat().st_size
    except OSError:
        return None

    if size <= MAX_FILE_SIZE:
        content = _read_text_safe(filepath)
        if content is None:
            return None
        all_lines = content.splitlines()
        total = len(all_lines)
        if total <= SMALL_FILE_THRESHOLD:
            return 1, all_lines
        start = max(0, line - CONTEXT_LINES - 1)
        end = min(total, end_line + CONTEXT_LINES)
        return start + 1, all_lines[start:end]

    # Large file: stream only what we need
    start = max(0, line - CONTEXT_LINES - 1)
    end = end_line + CONTEXT_LINES
    try:
        lines = []
        with filepath.open(encoding="utf-8") as f:
            for i, raw in enumerate(f):
                if i >= end:
                    break
                if i >= start:
                    lines.append(raw.rstrip("\n\r"))
        return (start + 1, lines) if lines else None
    except (UnicodeDecodeError, PermissionError, OSError):
        log.warning("Cannot stream file, skipping: %s", filepath)
        return None


def retrieve(finding: Finding, codebase: Path) -> EvidenceBundle:
    filepath = _resolve_path(finding.path, codebase)

    if filepath is None:
        return EvidenceBundle(finding=finding, evidence=[])

    window = _extract_window(filepath, finding.line, finding.end_line)
    if window is None:
        return EvidenceBundle(finding=finding, evidence=[])

    start_line, lines = window
    evidence = [
        Evidence(
            path=finding.path,
            start_line=start_line,
            end_line=start_line + len(lines) - 1,
            content=_numbered(lines, start_line),
        )
    ]

    return EvidenceBundle(finding=finding, evidence=evidence)
