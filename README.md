# CodeAssure

AI-powered SAST finding verification. Takes SAST scanner results and a codebase, uses an LLM agent to independently verify each finding, and produces enriched results with verdicts.

![CodeAssure System Architecture](./codeassure.png)

## Quick Start

```bash
uv sync
uv pip install -e .
codeassure \
  --codebase ./my-project \
  --findings results.json \
  --output verified.json
```

## How It Works

CodeAssure runs a two-stage agent pipeline on each SAST finding:

1. **Analyzer** — tool-using agent reads the flagged code, gathers context via `read_file` and `grep_code`, and produces a structured analysis
2. **Formatter** — extracts a JSON verdict from the analysis, with a repair loop for malformed output

The verdict answers two independent questions:
- **Did the scanner correctly detect the pattern?** (`verdict`: true_positive / false_positive / uncertain)
- **Is this a security vulnerability?** (`is_security_vulnerability`: true / false / null)

Known rule families get deterministic verdict policies to reduce false negatives on common patterns.

## CLI

```
codeassure --codebase DIR --findings FILE --output FILE [--config PATH] [--jobs N] [--verify FILE]
```

| Option | Required | Description |
|---|---|---|
| `--codebase DIR` | yes | Root directory that finding paths are relative to |
| `--findings FILE` | yes | SAST findings JSON |
| `--output, -o FILE` | yes | Output path for verified findings |
| `--config, -c PATH` | no | Path to codeassure.json (default: `./codeassure.json`) |
| `--jobs, -j N` | no | Max concurrent LLM requests (overrides config) |
| `--verify FILE` | no | Compare output against ground-truth JSON and write a CSV report |

## Configuration

**`codeassure.json`**:
```json
{
  "model": {
    "provider": "openai",
    "name": "qwen35-nvfp4",
    "api_base": "http://localhost:5000/v1"
  },
  "concurrency": 16,
}
```

## Brev Setup (Remote GPU Instance)

> Instance: `accuknox-nemotron-super-3`
> Local endpoint after port-forward: `http://localhost:5000`
> Model name: `qwen35-nvfp4`

```bash
brev login
brev list
brev port-forward accuknox-nemotron-super-3 --port 5000:5000
```

The vLLM endpoint is now available at `http://localhost:5000/v1`. The default `codeassure.json` is already configured to use this.

## Output

Each finding gets a `verification` block:
```json
{
  "verification": {
    "verdict": "true_positive",
    "finding_correct": true,
    "is_security_vulnerability": true,
    "confidence": "high",
    "reason": "subprocess.run called with dynamic user input and shell=True.",
    "evidence": [{"location": "app/utils.py:42"}]
  }
}
```

| Field | Values | Description |
|---|---|---|
| `verdict` | `true_positive`, `false_positive`, `uncertain` | Did the scanner correctly detect the pattern? |
| `finding_correct` | `true`, `false`, `null` | Does the flagged pattern exist in the code? |
| `is_security_vulnerability` | `true`, `false`, `null` | Is this exploitable? Assessed from code context, independent of verdict |
| `confidence` | `high`, `medium`, `low` | Confidence level |

## Benchmarking

Pass `--verify` with a ground-truth JSON (`is_false_positive: bool` per finding):

```bash
codeassure --codebase ./code --findings results.json --output out.json --verify ground_truth.json
```

Prints two confusion matrices:
1. **Finding Correctness** — raw verdict vs ground truth
2. **Security Vulnerability** — collapsed view (verdict=TP + is_sec=false maps to FP)

## Project Structure

```
sast_verify/
  cli.py                  # CLI entry point
  config.py               # Config model, loads codeassure.json
  pipeline.py             # Orchestration + dual-metric evaluation
  preprocess.py           # Normalizes raw SAST JSON into Finding objects
  retrieval.py            # Anchors findings to source code evidence
  schema.py               # Pydantic models: Finding, Evidence, Verdict

  agents/
    analyzer.py           # Builds analyzer + formatter agents
    runner.py             # Async runner: both stages per finding, concurrency control
    tools.py              # read_file, grep_code (sandboxed to codebase)

  prompts/
    __init__.py           # Message builders for analyzer and formatter
    analyzer.py           # System prompts for both agents
    rule_policies.py      # Deterministic verdict policies for known rule families

  eval/
    evaluate.py           # Fingerprint-based evaluation
```
