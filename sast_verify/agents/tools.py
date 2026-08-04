from __future__ import annotations

import logging
import re
from pathlib import Path

from pydantic_ai import RunContext

from .deps import AnalyzerDeps

log = logging.getLogger(__name__)

MAX_READ_LINES = 200
MAX_READ_FILE_SIZE = 1024 * 1024  # 1 MB — stream above this
MAX_GREP_MATCHES = 30
MAX_GREP_FILE_SIZE = 512 * 1024  # skip files larger than 512 KB
MAX_GREP_BYTES = 5 * 1024 * 1024  # stop scanning after 5 MB read


def _codebase(ctx: RunContext[AnalyzerDeps]) -> Path:
    return Path(ctx.deps.codebase)


def _is_contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _check_anchor(filepath: Path, root: Path, ctx: RunContext[AnalyzerDeps]) -> bool:
    """Anchor scope is ADVISORY, not a sandbox. Execution-reachability questions
    (who calls this entry point? where is this route registered?) are inherently
    repo-wide, so tools may roam anywhere INSIDE the codebase; the prompt keeps
    the model focused on the flagged file first. The only hard boundary is
    codebase containment, enforced separately by _is_contained."""
    return True


def _track_access(ctx: RunContext[AnalyzerDeps], path: str, start_line: int = 0, end_line: int = 0) -> None:
    """Record that a file path (and optional line range) was accessed by a tool."""
    accessed = ctx.deps.accessed_paths
    if path not in accessed:
        accessed[path] = []
    if start_line and end_line:
        accessed[path].append((start_line, end_line))


def read_file(
    ctx: RunContext[AnalyzerDeps],
    path: str,
    start_line: int = 1,
    end_line: int = 50,
) -> dict:
    """Read lines from a source file in the codebase.

    Args:
        path: File path relative to the codebase root.
        start_line: First line to read (1-indexed, default 1).
        end_line: Last line to read (inclusive, default 50).
    """
    root = _codebase(ctx)
    filepath = (root / path).resolve()

    if not _is_contained(filepath, root):
        return {"status": "error", "error": "Path is outside the codebase"}
    if not filepath.is_file():
        return {"status": "error", "error": f"File not found: {path}"}

    start = max(0, start_line - 1)
    end = end_line
    if end - start > MAX_READ_LINES:
        end = start + MAX_READ_LINES

    try:
        size = filepath.stat().st_size
    except OSError:
        return {"status": "error", "error": f"Cannot read file: {path}"}

    try:
        if size <= MAX_READ_FILE_SIZE:
            all_lines = filepath.read_text(encoding="utf-8").splitlines()
            total = len(all_lines)
            end = min(total, end)
            window = all_lines[start:end]
        else:
            # Large file: stream only the needed range
            window = []
            line_count = 0
            with filepath.open(encoding="utf-8") as f:
                for i, line in enumerate(f):
                    line_count = i + 1
                    if i >= end:
                        break
                    if i >= start:
                        window.append(line.rstrip("\n\r"))
            # Estimate total from sample
            if window and line_count > end:
                sample_bytes = sum(len(l) for l in window) + len(window)
                avg_line = sample_bytes / len(window)
                total = max(line_count, int(size / avg_line))
            else:
                total = line_count
    except (UnicodeDecodeError, PermissionError, OSError):
        return {"status": "error", "error": f"Cannot read file: {path}"}

    actual_start = start + 1
    actual_end = start + len(window)
    _track_access(ctx, path, actual_start, actual_end)

    numbered = "\n".join(
        f"{start + i + 1}: {l}" for i, l in enumerate(window)
    )
    return {
        "status": "success",
        "path": path,
        "total_lines": total,
        "start_line": actual_start,
        "end_line": actual_end,
        "content": numbered,
    }


def grep_code(
    ctx: RunContext[AnalyzerDeps],
    pattern: str,
    path: str = "",
    context_lines: int = 3,
) -> dict:
    """Search for a regex pattern in source files within the codebase.

    Args:
        pattern: Regex pattern to search for.
        path: Optional file or subdirectory to narrow the search.
        context_lines: Lines of surrounding context per match (0-10, default 3).
    """
    context_lines = max(0, min(10, context_lines))
    root = _codebase(ctx)
    if path:
        search_root = (root / path).resolve()
    else:
        # Default to the flagged file's directory, not the repo root
        finding_dir = ctx.deps.finding_dir
        search_root = (root / finding_dir).resolve() if finding_dir else root

    if not _is_contained(search_root, root):
        return {"status": "error", "error": "Path is outside the codebase"}

    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return {"status": "error", "error": f"Invalid regex: {e}"}

    # Reject patterns likely to cause catastrophic backtracking:
    # nested quantifiers like (a+)+, (a*)*b, (a|b+)* etc.
    if re.search(r"[+*]\)?[+*]", pattern):
        return {"status": "error", "error": "Regex rejected: nested quantifiers can cause excessive backtracking"}

    _SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", ".tox", ".mypy_cache", "dist", "build"}

    def _iter_files(root: Path):
        if root.is_file():
            yield root
            return
        try:
            children = sorted(root.iterdir())
        except OSError:
            return
        for child in children:
            if child.is_dir():
                if child.name in _SKIP_DIRS:
                    continue
                yield from _iter_files(child)
            else:
                yield child

    max_file_size = ctx.deps.grep_max_file_size
    max_bytes = ctx.deps.grep_max_bytes

    matches = []
    bytes_scanned = 0
    for f in _iter_files(search_root):
        if not f.is_file() or f.suffix in (".pyc", ".so", ".bin", ".o", ".whl", ".jar"):
            continue
        try:
            size = f.stat().st_size
        except OSError:
            continue
        if size > max_file_size:
            continue
        if bytes_scanned + size > max_bytes:
            return {"status": "success", "matches": matches, "truncated": True,
                    "reason": "Scan budget exhausted"}
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError, OSError):
            continue
        bytes_scanned += size
        all_lines = text.splitlines()
        for i, line in enumerate(all_lines):
            try:
                hit = compiled.search(line)
            except RecursionError:
                return {"status": "error",
                        "error": "Regex exceeded recursion limit"}
            if hit:
                ctx_start = max(0, i - context_lines)
                ctx_end = min(len(all_lines), i + 1 + context_lines)
                numbered = "\n".join(
                    f"{ctx_start + j + 1}: {all_lines[ctx_start + j]}"
                    for j in range(ctx_end - ctx_start)
                )
                rel_path = str(f.relative_to(root))
                matches.append({
                    "path": rel_path,
                    "line": i + 1,
                    "content": numbered,
                })
                _track_access(ctx, rel_path, ctx_start + 1, ctx_end)
                if len(matches) >= MAX_GREP_MATCHES:
                    return {"status": "success", "matches": matches, "truncated": True}

    return {"status": "success", "matches": matches, "truncated": False}


MAX_CALLER_MATCHES = 25

_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Definition-shaped lines (per common languages). A hit on one of these is the
# symbol's own definition, not a call site — classified, not dropped, so the
# model still learns where the function lives.
_DEF_LINE_PATTERNS = (
    r"^\s*(async\s+)?def\s+{s}\s*\(",                       # python
    r"^\s*func\s+(\([^)]*\)\s*)?{s}\s*\(",                  # go (incl. methods)
    r"^\s*(export\s+)?(default\s+)?(async\s+)?function\s*\*?\s*{s}\s*\(",  # js/ts
    r"^\s*(pub\s+)?(async\s+)?fn\s+{s}\s*\(",               # rust
    r"^\s*(public|private|protected|internal|static|final|override|open|suspend)[\w\s<>\[\],]*\b{s}\s*\([^;]*$",  # java/c#/kotlin
    r"^\s*{s}\s*[:=]\s*(async\s*)?(\([^)]*\)|function)\s*(=>|\{{)?",  # js arrow/expr defs
)


def trace_callers(
    ctx: RunContext[AnalyzerDeps],
    function_name: str,
    path: str = "",
) -> dict:
    """Find call sites of a function across the whole codebase — use this to verify
    execution reachability: who invokes an entry point, where a handler/route is
    registered, whether a source function is ever actually called.

    Args:
        function_name: Exact function/method name (identifier only, no parentheses).
        path: Optional subdirectory to narrow the search (default: entire codebase).
    """
    name = function_name.strip().removesuffix("()").strip()
    if not _SYMBOL_RE.match(name):
        return {"status": "error",
                "error": "function_name must be a plain identifier (letters, digits, underscore)"}

    root = _codebase(ctx)
    search_root = (root / path).resolve() if path else root
    if not _is_contained(search_root, root):
        return {"status": "error", "error": "Path is outside the codebase"}

    call_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*\(")
    def_res = [re.compile(p.format(s=re.escape(name))) for p in _DEF_LINE_PATTERNS]

    _SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", ".tox",
                  ".mypy_cache", "dist", "build"}

    def _iter_files(r: Path):
        if r.is_file():
            yield r
            return
        try:
            children = sorted(r.iterdir())
        except OSError:
            return
        for child in children:
            if child.is_dir():
                if child.name in _SKIP_DIRS:
                    continue
                yield from _iter_files(child)
            else:
                yield child

    max_file_size = ctx.deps.grep_max_file_size
    max_bytes = ctx.deps.grep_max_bytes

    calls: list[dict] = []
    definitions: list[dict] = []
    bytes_scanned = 0
    truncated = False
    for f in _iter_files(search_root):
        if not f.is_file() or f.suffix in (".pyc", ".so", ".bin", ".o", ".whl", ".jar",
                                           ".min.js", ".map", ".lock"):
            continue
        try:
            size = f.stat().st_size
        except OSError:
            continue
        if size > max_file_size:
            continue
        if bytes_scanned + size > max_bytes:
            truncated = True
            break
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError, OSError):
            continue
        bytes_scanned += size
        if name not in text:  # cheap pre-filter before line loop
            continue
        all_lines = text.splitlines()
        rel_path = str(f.relative_to(root))
        for i, line in enumerate(all_lines):
            if not call_re.search(line):
                continue
            is_def = any(dr.search(line) for dr in def_res)
            ctx_start = max(0, i - 2)
            ctx_end = min(len(all_lines), i + 3)
            numbered = "\n".join(
                f"{ctx_start + j + 1}: {all_lines[ctx_start + j]}"
                for j in range(ctx_end - ctx_start)
            )
            entry = {"path": rel_path, "line": i + 1, "content": numbered}
            _track_access(ctx, rel_path, ctx_start + 1, ctx_end)
            if is_def:
                definitions.append(entry)
            else:
                calls.append(entry)
            if len(calls) >= MAX_CALLER_MATCHES:
                return {"status": "success", "function": name, "call_sites": calls,
                        "definitions": definitions, "truncated": True}

    return {"status": "success", "function": name, "call_sites": calls,
            "definitions": definitions, "truncated": truncated,
            **({"note": "Scan budget exhausted before covering the whole codebase"}
               if truncated else {})}
