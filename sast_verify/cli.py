from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile


def _load_dotenv() -> None:
    """Load ``.env`` from the working directory into the environment.

    ``.env`` is the documented home for API keys (see .env.example) and the
    ``"api_key": "$VAR"`` config syntax resolves against the environment, so
    the CLI must actually read it. Real environment variables win
    (``setdefault``); no third-party dependency.
    """
    env = Path.cwd() / ".env"
    if not env.is_file():
        return
    try:
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))
    except OSError:
        pass


def main() -> None:
    _load_dotenv()
    parser = argparse.ArgumentParser(
        prog="codeassure",
        description="AI-powered SAST finding verification",
    )
    parser.add_argument(
        "--codebase", type=Path, required=True, metavar="DIR",
        help="Root directory that finding paths are relative to",
    )
    parser.add_argument(
        "--findings", type=Path, required=True, metavar="FILE",
        help="SAST findings JSON (results.json)",
    )
    parser.add_argument(
        "--output", "-o", type=Path, required=True, metavar="FILE",
        help="Output path for verified findings",
    )
    parser.add_argument(
        "--config", "-c", type=Path, default=None, metavar="PATH",
        help="Path to codeassure.json (default: ./codeassure.json)",
    )
    parser.add_argument(
            "--severity","-s", type=str,
            default="INFO,WARNING,LOW,MEDIUM,HIGH,CRITICAL,UNKNOWN,NOT_AVAILABLE,INFORMATIONAL",
            help="Comma-separated list of severities to check for AI analysis. If any match, AI analysis will run on those findings."
        )
    parser.add_argument(
        "--jobs", "-j", type=int, default=None, metavar="N",
        help="Max concurrent LLM requests (overrides config)",
    )
    parser.add_argument("--no-context-graph", action="store_true",
                        help="Explicitly skip deterministic graph generation")
    parser.add_argument("--context-graph-config", type=Path,
                        help="Configuration for the context-graph CLI")
    parser.add_argument("--graph-no-joern", action="store_true",
                        help="Use the native tree-sitter graph tier without Joern")
    parser.add_argument("--graph-timeout", type=int, default=1200,
                        help="Maximum seconds for graph generation (default: 1200)")
    parser.add_argument(
        "--no-grouping", action="store_true", default=False,
        help="Disable finding grouping (analyze each finding independently)",
    )
    parser.add_argument(
        "--verify", type=Path, default=None, metavar="FILE",
        help="Compare output against a ground-truth JSON (final_results.json) and write a CSV report",
    )
    parser.add_argument(
        "--anthropic-key", type=str, default=None, metavar="KEY",
        help="Anthropic API key for Claude verdict validation (overrides ANTHROPIC_API_KEY env var)",
    )
    parser.add_argument(
        "--repo-id", type=str, default=None, metavar="ID",
        help="Repository ID for AccuKnox finding lookup (overrides ACCUKNOX_REPO_ID env var)",
    )
    parser.add_argument(
        "--grouping", action="store_true", default=False,
        help="Enable finding grouping — analyze findings in groups (default behavior)",
    )
    parser.add_argument(
        "--claude-verification", action="store_true", default=False,
        help="Enable Claude validation of verdicts (requires --anthropic-key or ANTHROPIC_API_KEY)",
    )
    args = parser.parse_args()

    import logging
    import os
    # CODEASSURE_LOG_LEVEL=DEBUG also logs every HTTP request/response status.
    level = getattr(logging, os.environ.get("CODEASSURE_LOG_LEVEL", "INFO").upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    http_level = logging.INFO if level <= logging.DEBUG else logging.WARNING
    logging.getLogger("httpx").setLevel(http_level)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    if args.anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = args.anthropic_key
    if args.repo_id:
        os.environ["ACCUKNOX_REPO_ID"] = args.repo_id

    from .config import load_config
    from .pipeline import run, verify

    try:
        cfg = load_config(args.config)
    except FileNotFoundError as e:
        parser.error(str(e))
    concurrency = args.jobs if args.jobs is not None else cfg.effective_concurrency

    if concurrency < 1:
        parser.error("--jobs must be at least 1")
    if args.graph_timeout < 1:
        parser.error("--graph-timeout must be at least 1")
    if not args.codebase.is_dir() or not args.findings.is_file():
        parser.error("--codebase must be a directory and --findings an existing JSON file")

    # A private intermediate keeps the original scan intact if either stage fails,
    # including when --findings and --output refer to the same file.
    with tempfile.TemporaryDirectory(prefix="codeassure-graph-") as directory:
        findings = args.findings
        if not args.no_context_graph:
            from .context_graph import generate_graphs
            findings = Path(directory) / "findings.json"
            generate_graphs(args.codebase, args.findings, findings,
                            config=args.context_graph_config, no_joern=args.graph_no_joern,
                            timeout=args.graph_timeout)
        run(
            args.codebase, findings, args.output,
            concurrency=concurrency,
            severities=[s.strip().upper() for s in args.severity.split(",")],
            enable_grouping=args.grouping and not args.no_grouping,
            claude_verification=args.claude_verification,
        )

    if args.verify:
        csv_path = args.output.with_suffix(".csv")
        verify(args.output, args.verify, csv_path)

    import json
    if json.loads(args.output.read_text(encoding="utf-8")).get("ai_sast", {}).get("status") == "partial":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
