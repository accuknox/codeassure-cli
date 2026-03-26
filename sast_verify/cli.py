from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
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
    parser.add_argument(
        "--verify", type=Path, default=None, metavar="FILE",
        help="Compare output against a ground-truth JSON (final_results.json) and write a CSV report",
    )
    parser.add_argument(
        "--anthropic-key", type=str, default=None, metavar="KEY",
        help="Anthropic API key for Claude verdict validation (overrides ANTHROPIC_API_KEY env var)",
    )
    parser.add_argument(
        "--grouping", action="store_true", default=False,
        help="Enable finding grouping — analyze findings in groups (default behavior)",
    )
    args = parser.parse_args()

    import os
    if args.anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = args.anthropic_key

    from .config import load_config
    from .pipeline import run, verify

    cfg = load_config(args.config)
    concurrency = args.jobs if args.jobs is not None else cfg.concurrency

    if concurrency < 1:
        parser.error("--jobs must be at least 1")

    run(
        args.codebase, args.findings, args.output,
        concurrency=concurrency,
        severities=args.severity.split(","),
        enable_grouping=args.grouping,
    )

    if args.verify:
        csv_path = args.output.with_suffix(".csv")
        verify(args.output, args.verify, csv_path)


if __name__ == "__main__":
    main()
