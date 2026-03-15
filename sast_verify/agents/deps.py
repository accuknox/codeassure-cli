from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnalyzerDeps:
    codebase: str
    finding_dir: str
    anchor_root: str
    accessed_paths: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    grep_max_file_size: int = 512 * 1024
    grep_max_bytes: int = 5 * 1024 * 1024
