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
        "--jobs", "-j", type=int, default=None, metavar="N",
        help="Max concurrent LLM requests (overrides config)",
    )
    parser.add_argument(
        "--no-grouping", action="store_true", default=False,
        help="Disable finding grouping (analyze each finding independently)",
    )
    parser.add_argument(
        "--verify", type=Path, default=None, metavar="FILE",
        help="Compare output against a ground-truth JSON (final_results.json) and write a CSV report",
    )
    args = parser.parse_args()

    from .config import load_config
    from .pipeline import run, verify

    cfg = load_config(args.config)
    concurrency = args.jobs if args.jobs is not None else cfg.concurrency

    if concurrency < 1:
        parser.error("--jobs must be at least 1")

    run(
        args.codebase, args.findings, args.output,
        concurrency=concurrency,
        enable_grouping=not args.no_grouping,
    )

    if args.verify:
        csv_path = args.output.with_suffix(".csv")
        verify(args.output, args.verify, csv_path)


if __name__ == "__main__":
    main()
