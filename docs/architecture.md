# AccuKnox CodeAssist — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AccuKnox CodeAssist                              │
│                  AI-Powered SAST Finding Verification                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐    ┌──────────────┐    ┌───────────┐    ┌──────────────┐ │
│  │   CLI    │───▶│  Preprocess  │───▶│ Retrieve  │───▶│   Pipeline   │ │
│  │ (Entry)  │    │  (Normalize) │    │ (Anchor)  │    │ (Orchestrate)│ │
│  └──────────┘    └──────────────┘    └───────────┘    └──────┬───────┘ │
│       │                                                       │         │
│       │          ┌────────────────────────────────────────────┘         │
│       │          ▼                                                      │
│       │   ┌─────────────────────────────────────────────────────┐      │
│       │   │              Agent Runner (async)                    │      │
│       │   │         Semaphore-bounded concurrency                │      │
│       │   │                                                      │      │
│       │   │  ┌─────────────┐         ┌──────────────────────┐   │      │
│       │   │  │  Analyzer   │────────▶│  Verdict Formatter   │   │      │
│       │   │  │   Agent     │ analysis│      Agent           │   │      │
│       │   │  │             │  text   │                      │   │      │
│       │   │  │ ┌─────────┐ │         │  Parse ─▶ Repair ─▶  │   │      │
│       │   │  │ │  Tools  │ │         │  Fallback to analyzer │   │      │
│       │   │  │ │read_file│ │         └──────────┬───────────┘   │      │
│       │   │  │ │grep_code│ │                    │               │      │
│       │   │  │ └────┬────┘ │                    ▼               │      │
│       │   │  └──────┼──────┘            ┌──────────────┐        │      │
│       │   │         │                   │   Verdict     │        │      │
│       │   │         ▼                   │  (validated)  │        │      │
│       │   │  ┌─────────────┐            └──────────────┘        │      │
│       │   │  │AnalyzerDeps │                                    │      │
│       │   │  │ codebase    │◀── pass-by-reference               │      │
│       │   │  │ finding_dir │    (tools populate                 │      │
│       │   │  │ anchor_root │     accessed_paths)                │      │
│       │   │  │ accessed_   │                                    │      │
│       │   │  │   paths {}  │                                    │      │
│       │   │  └─────────────┘                                    │      │
│       │   └─────────────────────────────────────────────────────┘      │
│       │                                                                 │
│       │   ┌─────────────────────┐    ┌──────────────────────────┐      │
│       └──▶│   Config System     │───▶│   Hosted LLM Endpoint    │      │
│           │  codeassure.json    │    │   (OpenAI-compatible)     │      │
│           │  - model provider   │    │                           │      │
│           │  - api_base URL     │    │   ┌───────────────────┐  │      │
│           │  - concurrency      │    │   │  Qwen3.5-122B     │  │      │
│           │  - timeouts         │    │   │  Nemotron-120B    │  │      │
│           │  - thinking_map     │    │   │  Qwen3-Coder-27B  │  │      │
│           │  - request_limit    │    │   └───────────────────┘  │      │
│           └─────────────────────┘    └──────────────────────────┘      │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│  Output: verified_findings.json + optional benchmark CSV                │
└─────────────────────────────────────────────────────────────────────────┘
```

## Agent Pipeline (per finding)

```
┌─────────────────────────────────────────────────────────────────┐
│                    _analyze_one(bundle)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. SETUP                                                        │
│  ┌──────────────────────────────────┐                           │
│  │ Compute anchor_root from path    │                           │
│  │ Create AnalyzerDeps (empty)      │                           │
│  │ Get thinking_settings(severity)  │                           │
│  └──────────────┬───────────────────┘                           │
│                  ▼                                                │
│  2. STAGE 1: ANALYZER (tool-using agent)                         │
│  ┌──────────────────────────────────────────────────────┐       │
│  │                                                       │       │
│  │  System: ANALYZER_INSTRUCTION                         │       │
│  │  User:   build_user_message(evidence + claim)         │       │
│  │                                                       │       │
│  │  ┌──────────┐    ┌──────────┐                         │       │
│  │  │read_file │    │grep_code │  ◀── sandboxed tools    │       │
│  │  │ 200 lines│    │ 30 match │      scoped to          │       │
│  │  │ max/call │    │ max, 5MB │      anchor_root        │       │
│  │  └────┬─────┘    └────┬─────┘                         │       │
│  │       └───────┬───────┘                               │       │
│  │               ▼                                       │       │
│  │       accessed_paths populated                        │       │
│  │                                                       │       │
│  │  Output: analysis text (unstructured)                 │       │
│  └──────────────────────────┬───────────────────────────┘       │
│                              ▼                                   │
│  3. STAGE 2: VERDICT FORMATTER (no tools)                        │
│  ┌──────────────────────────────────────────────────────┐       │
│  │                                                       │       │
│  │  System: VERDICT_FORMATTER_INSTRUCTION                │       │
│  │  User:   build_formatter_message(analysis + finding)  │       │
│  │                                                       │       │
│  │  Output: JSON verdict                                 │       │
│  │  ┌──────────────────────────────────────────┐         │       │
│  │  │ { "verdict": "true_positive",            │         │       │
│  │  │   "finding_correct": true,               │         │       │
│  │  │   "is_security_vulnerability": true,     │         │       │
│  │  │   "confidence": "high",                  │         │       │
│  │  │   "reason": "...",                       │         │       │
│  │  │   "evidence_locations": ["file:line"] }  │         │       │
│  │  └──────────────────────────────────────────┘         │       │
│  └──────────────────────────┬───────────────────────────┘       │
│                              ▼                                   │
│  4. PARSE + REPAIR                                               │
│  ┌──────────────────────────────────────────────────────┐       │
│  │  _parse_verdict(response)                             │       │
│  │    ├─ Try direct JSON parse                           │       │
│  │    ├─ Try embedded JSON scan (raw_decode)             │       │
│  │    ├─ Try fix unquoted strings (regex)                │       │
│  │    │                                                  │       │
│  │    ├─ On failure: REPAIR LOOP                         │       │
│  │    │   └─ formatter.run(error_msg, message_history)   │       │
│  │    │                                                  │       │
│  │    └─ Last fallback: parse analyzer output            │       │
│  └──────────────────────────┬───────────────────────────┘       │
│                              ▼                                   │
│  5. EVIDENCE VALIDATION                                          │
│  ┌──────────────────────────────────────────────────────┐       │
│  │  _validate_evidence(                                  │       │
│  │    verdict.evidence_locations,                        │       │
│  │    deps.accessed_paths,       ◀── only what tools     │       │
│  │    finding.path/line          )    actually read       │       │
│  └──────────────────────────┬───────────────────────────┘       │
│                              ▼                                   │
│  6. COHERENCE CHECK                                              │
│  ┌──────────────────────────────────────────────────────┐       │
│  │  If finding_correct contradicts verdict:              │       │
│  │    finding_correct=true  + FP → override to TP        │       │
│  │    finding_correct=false + TP → override to FP        │       │
│  │    finding_correct=null       → skip (uncertain)      │       │
│  └──────────────────────────┬───────────────────────────┘       │
│                              ▼                                   │
│                       Return Verdict                             │
└─────────────────────────────────────────────────────────────────┘
```

## Concurrency Model

```
                    analyze_all(356 findings)
                            │
                   Semaphore(concurrency=16)
                            │
          ┌────────┬────────┼────────┬────────┐
          ▼        ▼        ▼        ▼        ▼
     Finding 0  Finding 1  ...  Finding 15  (wait)
     [analyze]  [analyze]       [analyze]
     [format ]  [format ]       [format ]
     [parse  ]  [parse  ]       [parse  ]
          │        │                │
          ▼        ▼                ▼
      Verdict   Verdict          Verdict
          │        │                │
          │   slot frees ──────────┘
          │        │
          ▼        ▼
     Finding 16  Finding 17 ...
     [analyze]   [analyze]
        ...         ...

    Timeouts:
    ├── stage_timeout (600s) per analyzer/formatter call
    └── finding_timeout (900s) per entire finding
```

## Module Dependency Graph

```
cli.py
  ├── config.py ─────────────────────────────┐
  │     └── PydanticAI (OpenAIChatModel)     │
  └── pipeline.py                             │
        ├── preprocess.py                     │
        │     └── schema.py (Finding)         │
        ├── retrieval.py                      │
        │     └── schema.py (Evidence,        │
        │         EvidenceBundle)              │
        └── agents/                           │
              ├── runner.py ◀─────────────────┘
              │     ├── analyzer.py
              │     │     └── config.build_model()
              │     ├── deps.py (AnalyzerDeps)
              │     └── prompts/
              │           ├── __init__.py (message builders)
              │           ├── analyzer.py (instructions)
              │           └── rule_policies.py (deterministic policies)
              ├── tools.py
              │     ├── read_file(ctx: RunContext[AnalyzerDeps])
              │     └── grep_code(ctx: RunContext[AnalyzerDeps])
              └── schema.py (Verdict)
```

## Data Flow

```
SAST Scanner Output                    Source Code Repository
(results.json)                         (k8s_jobs/, app/, ...)
       │                                       │
       ▼                                       │
┌──────────────┐                               │
│  Preprocess  │                               │
│  Normalize   │                               │
│  → Finding[] │                               │
└──────┬───────┘                               │
       │                                       │
       ▼                                       ▼
┌──────────────────────────────────────────────────┐
│  Retrieve: anchor each Finding to source code     │
│  → EvidenceBundle[] (Finding + code context)      │
└──────────────────────┬───────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │  Unanchored (no file)   │
          │  → Verdict("uncertain") │
          └─────────────────────────┘
                       │
                       ▼ (anchored only)
┌──────────────────────────────────────────────────┐
│  Analyze (concurrent, async)                      │
│                                                   │
│  Per finding:                                     │
│  EvidenceBundle ──▶ Analyzer Agent ──▶ Formatter  │
│       │                  │                  │     │
│       │            ┌─────┴─────┐            │     │
│       │            │read_file  │            │     │
│       │            │grep_code  │            │     │
│       │            └───────────┘            │     │
│       │                                     │     │
│       └─────────────────────────────────────┘     │
│                         │                         │
│                    Verdict[]                       │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────┐
│  Merge verdicts into original findings JSON       │
│  → verified_findings.json                         │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼ (optional --verify)
┌──────────────────────────────────────────────────┐
│  Benchmark against ground truth                   │
│  → Dual confusion matrices:                       │
│    1. Finding Correctness (raw verdict vs GT)      │
│    2. Security Vulnerability (collapsed view)      │
│  → report.csv                                     │
└──────────────────────────────────────────────────┘
```

## Configuration

```json
{
  "model": {
    "provider": "openai",
    "name": "qwen35-nvfp4",
    "api_base": "http://localhost:5000/v1"
  },
  "concurrency": 16,
  "stage_timeout": 600,
  "finding_timeout": 900,
  "request_limit": 200,
  "thinking_map": {             // optional, for reasoning models
    "ERROR": "low",
    "WARNING": "off",
    "INFO": "off"
  }
}
```

## Hosted Model Endpoint

```
┌──────────────────────────────────────────────────┐
│  GPU Server (RTX 6000 PRO Blackwell)             │
│  96GB VRAM / 144GB RAM                           │
│                                                   │
│  ┌────────────────────────────────────────────┐  │
│  │  vLLM v0.17.1 (OpenAI-compatible API)      │  │
│  │  POST /v1/chat/completions                 │  │
│  │  GET  /v1/models                           │  │
│  │                                            │  │
│  │  Features:                                 │  │
│  │  ├── Tool calling (--enable-auto-tool-     │  │
│  │  │   choice --tool-call-parser qwen3_coder)│  │
│  │  ├── Speculative decoding (MTP, 90% acc)   │  │
│  │  ├── Extended thinking (reasoning parser)  │  │
│  │  ├── KV cache (up to 90% utilization)      │  │
│  │  └── max_num_seqs=32 (concurrent batching) │  │
│  │                                            │  │
│  │  Models tested:                            │  │
│  │  ├── Qwen3.5-122B-A10B (nvfp4) ◀── best   │  │
│  │  ├── Nemotron-3-Super-120B-A12B (nvfp4)   │  │
│  │  └── Qwen3-Coder-27B (Q4_K_XL, remote)    │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## Verdict Schema

```
┌──────────────────────────────────────────┐
│  Verdict                                 │
├──────────────────────────────────────────┤
│  verdict:                                │
│    "true_positive"   (scanner correct)   │
│    "false_positive"  (scanner wrong)     │
│    "uncertain"       (can't decide)      │
│                                          │
│  finding_correct: bool | null            │
│    true  → flagged pattern exists        │
│    false → pattern does not exist        │
│    null  → uncertain / not assessed      │
│                                          │
│  is_security_vulnerability: bool | null  │
│    true  → injection, shell=True,        │
│           deserialization, container      │
│           misconfig, DoS, unpinned       │
│           images, auth bypass, SSRF      │
│    false → code style, mutable           │
│           defaults, AI detection,        │
│           missing raise_for_status       │
│    null  → uncertain / not assessed      │
│                                          │
│  confidence: "high"|"medium"|"low"       │
│  reason: str                             │
│  evidence_locations: ["file:line"]       │
└──────────────────────────────────────────┘

Verdict answers "did the scanner correctly detect the pattern?"
Security assessment is independent — a TP with is_security=false
is valid (pattern exists but isn't exploitable).

Coherence enforcement: if finding_correct contradicts verdict,
the runner overrides verdict to match finding_correct.
```

## Benchmark Results (sample-9, 356 findings)

```
Model               Accuracy  Precision  Recall    F1     Uncertain
─────────────────────────────────────────────────────────────────────
Qwen3.5-122B v1     67.7%     88.1%      25.3%    39.4%     3
Nemotron-120B       77.1%     89.4%      55.1%    68.2%    46
Qwen3-Coder-27B     79.0%     96.6%      47.5%    63.7%    47
─────────────────────────────────────────────────────────────────────
Qwen3.5-122B v2     (running — prompt fix for security classification)
  Projected         91.5%     96.0%      82.9%    89.0%     3
```
