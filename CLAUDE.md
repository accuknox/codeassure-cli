# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

CodeAssure (`codeassure`) is a CLI that verifies SAST scanner findings with an LLM agent. Input: a scanner `results.json` (Semgrep-shaped) + the codebase the paths are relative to. Output: the same JSON with a `verification` block added to each finding (verdict, security flag, severity, reason, evidence, mermaid graph) plus a `codebase_tree`. Python package is `sast_verify`; the published binary/command is `codeassure`.

## Commands

```bash
# Install (Python ≥3.11; uses uv)
uv sync
uv pip install -e .

# Run
codeassure --codebase ./my-project --findings results.json --output verified.json
codeassure --codebase DIR --findings FILE -o OUT --grouping --verify ground_truth.json

# Tests (pytest is NOT in pyproject deps — install it separately, then run from repo root)
pip install pytest
pytest                                  # all
pytest tests/test_parse_verdict.py      # one file
pytest tests/test_tools.py::test_name   # one test

# Standalone binary (PyInstaller, entry = build_entry.py → codeassure.spec)
./build.sh                              # → dist/codeassure

# Visualization UI (Next.js; uses pnpm — NOT npm)
cd ui && pnpm install && pnpm dev --port 3333   # then drop the output JSON in the browser
```

Config is required: `codeassure.json` in cwd, or `--config PATH`. `codeassure.jsonc` is the fully-commented reference for every field. `.env` holds API keys (see `.env.example`); the env-var prefix must match the provider (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`).

## Pipeline (the big picture)

`cli.py:main` → `pipeline.run`:

1. **preprocess** (`preprocess.py`) — flattens raw scanner JSON `results[]` into `Finding` objects (`compact_finding` pulls from nested `extra`/`metadata`/`dataflow_trace`).
2. **retrieve** (`retrieval.py`) — anchors each finding to source, producing an `EvidenceBundle` (finding + a numbered code window). Runs in a `ThreadPoolExecutor`. Skipped entirely in finding-only mode.
3. **filter** — only bundles that anchored to a file go to the LLM; unanchored → fixed `uncertain` verdict. Then `--severity` filters further (see gotcha below).
4. **checkpoint + AccuKnox** — already-done findings load from `<output>.checkpoint.json`; remaining findings are looked up in the AccuKnox dashboard API (`accuknox.py`) to reuse prior human verdicts before spending an LLM call.
5. **grouping** (`grouping.py`) — `build_groups` clusters findings on the same file within `CO_LOCATION_GAP` (3) lines into "co-located" groups; everything else is "solo". Co-located findings are analyzed in one prompt with a coherence constraint so their verdicts can't contradict.
6. **analyze** (`agents/runner.py`) — async, `Semaphore`-bounded by `concurrency`. `analyze_all_grouped` (grouping on) or `analyze_all` (off). Writes verdicts back; saves checkpoint every 5 findings.
7. **write** (`pipeline._write_output`) — merges verdicts into the original JSON, builds the per-finding mermaid graph (`graph.py`), appends `codebase_tree`. Deletes the checkpoint on success.
8. **verify** (optional `--verify`) — confusion matrix + CSV vs ground truth (`is_false_positive` field).

## Agent model (`agents/`)

- **One structured analyzer pass is the hot path.** `analyzer.py` builds agents with `PromptedOutput(Verdict)` (text-JSON, **not** `ToolOutput`) — deliberate, so reasoning models can emit the verdict in their text channel without it colliding with the `read_file`/`grep_code` tool channel. The legacy formatter/parse-with-repair helpers in `runner.py` still exist for fallback and tests.
- **Tools** (`tools.py`): `read_file`, `grep_code`, and `trace_callers` (repo-wide call-site search that separates definitions from calls — used to verify entry points/reachability). Hard sandbox = codebase containment only; the per-finding `anchor_root` is **advisory** (execution tracing must cross the repo). Every read records line ranges into `AnalyzerDeps.accessed_paths`; verdict `evidence_locations` are validated against what was actually read (`_validate_evidence*`) and `execution_trace` steps against read/graph files (`_filter_execution_trace`) — the model can't cite code it never saw.
- **Resilience** (`runner.py`): every LLM call goes through `_run_with_retry` — transient errors (429/5xx/529, timeouts, connection drops, `UnexpectedModelBehavior`) retry with exponential backoff + jitter (`config.retries`, default 4). Exhausted retries / non-transient errors fall back to `_deterministic_fallback`: a decisive verdict from (context graph × rule kind) whose reason names the REAL error — never a bare "analyzer failed" uncertain. `_print_run_summary` reports verdict mix + fallback count.
- **Three analysis modes**, chosen by config, each with its own instruction set: full+tools (`tool_calling: true`), `no_tools` (pre-fetched window only), and finding-only (`findings_analysis: true` → model sees only the scanner snippet, no retrieval). Each has solo and group instruction variants.
- **Optional extra layers**, all off by default: evaluator pass (`config.evaluator`, assigns severity, can reject+retry), `voting_rounds>1` majority voting (`_majority_verdict`), a second-opinion `validator` model (`validator.py`, Gemini/Vertex), and `--claude-verification` (Claude sonnet cross-check, writes `claude_*` fields).
- **Enrichment is on by default** (`config.enrichment`) and covers EVERY finding (incl. uncertain + deadcode-shortcut): rationale, business_logic, explanation, and a paste-ready remediation (`code_patch` + `file`/`start_line`/`end_line` paste target + `original_code`). LLM failure degrades to `fallback_enrichment` so the output schema never loses keys.
- **Verdict schema** carries execution-reality fields: `source_trust` (attacker_controlled … hardcoded), `taint_flow_verified`, `execution_trace` (hop-by-hop verified steps), `attack_scenario`. The analyzer instructions mandate an Execution Trace Protocol over the context graph's trace targets (tool-call source nodes, classify data trust, verify propagation).

## Verdict semantics — read before touching verdict logic

`verdict` answers **"did the scanner correctly detect the pattern?"** (`true_positive`/`false_positive`/`uncertain`). `is_security_vulnerability` is **independent**: a true positive can have `is_security_vulnerability=false` (pattern is real but not exploitable — style/best-practice/detection rule). See `schema.py:Verdict` and `docs/architecture.md`.

Two places encode policy on top of this — keep them in sync when editing rule lists:
- `runner._apply_security_overrides` / `_NON_SECURITY_RULE_SUBSTRINGS` — forces `is_security_vulnerability=false` for known correctness-rule families (unquoted-expansion, useless-cat, missing-pipefail, dockerfile pinning, …).
- `pipeline._COLLAPSE_EXEMPT_RULES` / `_policy_covers_rule` — used **only in `verify()`** benchmarking. The "collapse rule" maps `TP + not security → effective false_positive`, except for exempt rules. This changes scored accuracy, not the written output.

`finding_policy` in config (`best_practice_is_tp`, `informational_detection_is_tp`, `audit_rule_is_tp`) tells the model what counts as a TP per customer.

## Config system

`config.py` is a global singleton: `load_config()` validates `codeassure.json` into a `Config` and stores it; `get_config()` retrieves it. `Config.build_model()` branches on `provider` to construct the right PydanticAI model. `api_base` URL handling differs per provider (`/v1` appended for openai, stripped for anthropic, raw for google) — give the base host either way. `thinking_map` (severity → `full`/`low`/`off`) only emits `extra_body` for reasoning models when set; null disables it.

## Gotchas

- **Grouping is opt-in despite the README.** `run()` receives `enable_grouping=args.grouping`, and `--grouping` defaults to `False`. So a bare `codeassure` invocation analyzes findings individually; pass `--grouping` to enable clustering. (`--no-grouping` exists but is not wired into the call.)
- **`--severity` filters on `finding.impact`, not `finding.severity`** (`pipeline.run`). A finding with no `impact` is treated as `NOT_AVAILABLE`.
- **AccuKnox lookup is silent unless `ACCUKNOX_BASE_URL` + `ACCUKNOX_BEARER_TOKEN` are set** (repo id from `--repo-id`, `ACCUKNOX_REPO_ID`, or the findings file's `repo_url`/`ref`).
- **Crash recovery is automatic**: re-run the identical command and it resumes from `<output>.checkpoint.json`.
- The `ui/` Next.js app is **not stock Next** — read `ui/AGENTS.md` (and the bundled docs it points to) before editing it; pnpm only.
- Dockerfile pins an old released version (`@v0.2.0` from git); `pyproject.toml` is `0.3.0`.
