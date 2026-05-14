# CodeAssure

AI-powered SAST finding verification. Takes SAST scanner results and a codebase, uses an LLM agent to verify each finding, and produces enriched results with verdicts, severity ratings, and visual explanations.

## Quick Start

```bash
# Install
uv sync
uv pip install -e .

# Run
codeassure \
  --codebase ./my-project \
  --findings results.json \
  --output verified.json

# With benchmarking
codeassure \
  --codebase ./my-project \
  --findings results.json \
  --output verified.json \
  --verify ground_truth.json
```

## How It Works

CodeAssure runs a three-stage agent pipeline:

1. **Analyzer** (Generator) — tool-using agent reads the flagged code, gathers context via `read_file` and `grep_code`, produces a structured analysis
2. **Formatter** — extracts a JSON verdict from the analysis, with a repair loop for malformed output
3. **Evaluator** — reviews the verdict for internal consistency, assigns severity, and can reject for retry

Related findings are **grouped** before analysis — co-located findings on the same code get analyzed together with coherence constraints, so verdicts don't contradict each other.

A **finding policy** config tells the model what counts as a true positive for each customer (security-only vs. detection-semantics).

## CLI

```
codeassure --codebase DIR --findings FILE --output FILE [OPTIONS]
```

| Option | Description |
|---|---|
| `--codebase DIR` | Root directory that finding paths are relative to |
| `--findings FILE` | SAST findings JSON (e.g., Semgrep results.json) |
| `--output, -o FILE` | Output path for verified findings |
| `--config, -c PATH` | Path to codeassure.json (default: `./codeassure.json`) |
| `--jobs, -j N` | Max concurrent LLM requests (overrides config) |
| `--no-grouping` | Disable finding grouping (analyze each finding independently) |
| `--verify FILE` | Compare output against ground-truth JSON and write a CSV report |

## Configuration

**`codeassure.json`**:
```json
{
  "model": {
    "provider": "openai-compatible",
    "name": "your-model-name",
    "api_base": "http://localhost:5000",
    "api_key": "$YOUR_API_KEY_ENV_VAR",
    "tool_calling": true
  },
  "concurrency": 4,
  "stage_timeout": 120,
  "finding_timeout": 300,
  "finding_policy": {
    "best_practice_is_tp": true,
    "informational_detection_is_tp": true,
    "audit_rule_is_tp": true
  }
}
```

### Model fields

| Field | Required | Description |
|---|---|---|
| `provider` | yes | One of `openai`, `openai-compatible`, `anthropic`, `google`, `gemini` |
| `name` | yes | Model name as known by the provider |
| `api_base` | no | Root host URL — always provide without `/v1` (see table below) |
| `api_key` | no | API key literal or `$ENV_VAR` reference (e.g. `"$OPENAI_API_KEY"`) |
| `tool_calling` | no | `true` (default) — set to `false` for models that don't support tool/function calling |

### `api_base` per provider

| Provider | You set `api_base` | Actual endpoint called |
|---|---|---|
| `openai` / `openai-compatible` | `http://localhost:5000` | `http://localhost:5000/v1/chat/completions` |
| `anthropic` | `https://your-proxy.example.com` | `https://your-proxy.example.com/v1/messages` |
| `google` / `gemini` | `https://your-proxy.example.com` | `https://your-proxy.example.com/v1beta/models/{model}:generateContent` |

### Other config fields

| Field | Default | Description |
|---|---|---|
| `concurrency` | `4` | Max concurrent LLM requests |
| `stage_timeout` | `120` | Seconds per LLM stage (analyzer or formatter) |
| `finding_timeout` | `300` | Seconds for the entire finding (both stages + repair) |
| `request_limit` | `200` | Max requests per `agent.run()` call |
| `voting_rounds` | `1` | Run each finding N times and take majority verdict |
| `max_tokens` | `4096` | Max completion tokens per LLM call |
| `thinking_map` | `null` | Severity → thinking effort (`full`/`low`/`off`). null = disabled |
| `finding_policy` | all true | What counts as true_positive for this customer |

## Output

Each finding gets a `verification` block:
```json
{
  "verification": {
    "verdict": "true_positive",
    "is_security_vulnerability": true,
    "severity": "high",
    "confidence": "high",
    "severity": "high",
    "reason": "subprocess.run called with dynamic user input and shell=True.",
    "evidence": [{"location": "app/utils.py:42"}],
    "graph": {
      "summary": "Taint flow: os.environ → subprocess.run",
      "mermaid": "graph TD\n    ...",
      "nodes": [...],
      "edges": [...]
    }
  }
}
```

| Field | Values | Description |
|---|---|---|
| `verdict` | `true_positive`, `false_positive`, `uncertain` | Did the scanner correctly detect the pattern? |
| `is_security_vulnerability` | `true`, `false` | Is this exploitable? Assessed from code context, independent of verdict |
| `confidence` | `high`, `medium`, `low` | Confidence level |
| `severity` | `critical`, `high`, `medium`, `low` | Assessed severity for `true_positive`; always `low` for `false_positive`/`uncertain` |

The output also includes a `codebase_tree` for visualization:
```json
{
  "results": [...],
  "codebase_tree": [
    {"path": "src/app.py", "type": "file", "size": 1234},
    {"path": "src/utils", "type": "dir", "size": 0}
  ]
}
```

## Visualization UI

```bash
cd ui
pnpm install
pnpm dev --port 3333
```

Open http://localhost:3333 and drop the output JSON. The UI renders a D3 force graph with findings overlaid, severity shading, and a detail panel per finding.

## Checkpointing

If the run crashes mid-way, re-run the same command. CodeAssure saves progress to `<output>.checkpoint.json` every 5 findings and resumes from where it left off. The checkpoint is deleted on successful completion.

## Benchmarking

```bash
codeassure \
  --codebase samples/sample-9/k8s_jobs \
  --findings samples/sample-9/results.json \
  --output samples/sample-9/output.json \
  --verify samples/sample-9/final_results.json
```

Prints a confusion matrix comparing the effective verdict against ground truth (`is_false_positive` field). The collapse rule: `verdict=TP + is_security_vulnerability=false → effective FP`.

## Project Structure

```
sast_verify/
  cli.py                  # CLI entry point
  config.py               # Config model + FindingPolicy
  pipeline.py             # Orchestration, checkpointing, codebase tree walker
  preprocess.py           # Normalizes raw SAST JSON into Finding objects
  retrieval.py            # Anchors findings to source code evidence
  schema.py               # Pydantic models: Finding, Evidence, Verdict
  grouping.py             # Finding Relationship Graph: groups co-located findings
  graph.py                # Mermaid flow diagram generator per finding

  agents/
    analyzer.py           # Builds analyzer, formatter, evaluator agents
    runner.py             # Async runner: generator/evaluator pipeline, group analysis
    tools.py              # read_file, grep_code (sandboxed to codebase)
    deps.py               # AnalyzerDeps (tool access scope)

  prompts/
    __init__.py           # Message builders (single, group, evaluator)
    analyzer.py           # System prompts (analyzer, formatter, evaluator, group variants)
    rule_policies.py      # Deterministic verdict policies for known rule families

ui/                       # Next.js visualization app
  src/
    app/page.tsx          # Upload + force graph view
    components/
      ForceGraph.tsx      # D3 force graph with finding overlay
      FileUpload.tsx      # JSON file upload
    lib/
      types.ts            # TypeScript types matching output schema
      theme.ts            # AccuKnox brand colors
      graph-builder.ts    # Finding flow graph for detail view
```
