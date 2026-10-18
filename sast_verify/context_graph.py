"""Run the deterministic graph CLI before sending findings to the AI verifier."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def graph_command() -> list[str]:
    executable = os.environ.get("CONTEXT_GRAPH_EXECUTABLE")
    if executable:
        return [executable]
    sibling = Path(sys.executable).with_name("context-graph.exe" if os.name == "nt" else "context-graph")
    if sibling.is_file():
        return [str(sibling)]
    source = os.environ.get("CONTEXT_GRAPH_SOURCE")
    if source:
        if getattr(sys, "frozen", False):
            raise ValueError("Use CONTEXT_GRAPH_EXECUTABLE with a standalone CodeAssure binary")
        entry = Path(source).expanduser().resolve() / "build_entry.py"
        if not entry.is_file():
            raise FileNotFoundError(f"Graph CLI entry point missing: {entry}")
        return [sys.executable, str(entry)]
    executable = shutil.which("context-graph")
    if executable:
        return [executable]
    if not getattr(sys, "frozen", False) and importlib.util.find_spec("context_graph"):
        return [sys.executable, "-m", "context_graph.cli"]
    # Development checkouts keep these two repositories next to one another.
    entry = Path(__file__).resolve().parents[2] / "code-context-graph" / "build_entry.py"
    if entry.is_file() and not getattr(sys, "frozen", False):
        return [sys.executable, str(entry)]
    raise FileNotFoundError(
        "context-graph is required. Install code-context-graph in the CodeAssure "
        "environment, or set CONTEXT_GRAPH_EXECUTABLE / CONTEXT_GRAPH_SOURCE."
    )


def generate_graphs(codebase: Path, findings: Path, output: Path, *,
                    config: Path | None = None, no_joern: bool = False,
                    timeout: int = 1200) -> None:
    command = [*graph_command(), "--codebase", str(codebase.resolve()),
               "--findings", str(findings.resolve()), "--output", str(output.resolve())]
    if config:
        command += ["--config", str(config.resolve())]
    if no_joern:
        command.append("--no-joern")
    subprocess.run(command, check=True, timeout=timeout)
    document = json.loads(output.read_text(encoding="utf-8"))
    original = json.loads(findings.read_text(encoding="utf-8"))
    if len(document.get("results", [])) != len(original.get("results", [])):
        raise ValueError("Graph CLI changed the finding count")
    # The graph CLI may degrade per finding; retain its actual coverage explicitly.
    graphs = [r.get("context_graph") for r in document.get("results", [])]
    built = sum(isinstance(g, dict) and bool(g.get("nodes")) for g in graphs)
    degraded = sum(bool((g.get("stats") or {}).get("degraded")) for g in graphs if isinstance(g, dict))
    document["graph_analysis"] = {
        "status": "completed" if built == len(graphs) else "partial",
        "total": len(graphs), "generated": built, "degraded": degraded,
    }
    output.write_text(json.dumps(document, indent=2), encoding="utf-8")
