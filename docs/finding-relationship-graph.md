# Finding Relationship Graph — Design Document (v3)

## Context

CodeAssure results (Qwen3.5-122B, sample-9, 356 findings):

**Core problem**: Each finding is analyzed independently. The model doesn't see related findings on the same code. This causes:

1. **Incoherent verdicts** — 16/33 co-located lines have contradictory verdicts (e.g., same HTTP call: cert=TP, timeout=TP, raise_for_status=FP)
2. **No compound severity** — multiple medium findings on one code point should signal a systemic issue

## Solution: Finding Relationship Graph

Findings are **nodes**. Relationships are **edges**. Phase 1 implements co-located and same-file edges only.

| Phase | Edge types | What it solves | External tools |
|-------|-----------|---------------|----------------|
| **Phase 1** | `co-located` (overlapping evidence windows only) | Verdict coherence, fewer LLM calls | None |
| **Phase 1.5** | `same-file` (if co-located proves value) | File-level security posture | None |
| **Phase 2** | `data-flows-to`, `calls` | Cross-point vulnerability chains | AST / Joern (future, separate design) |

---

## Key Design Decisions

### 1. Identity-based verdict keying (not positional)

The formatter returns verdicts keyed by finding number, not a positional array:

```json
{
  "verdicts": {
    "0": {"verdict": "true_positive", "confidence": "high", ...},
    "1": {"verdict": "false_positive", "confidence": "medium", ...}
  }
}
```

Why: positional arrays are brittle if the model reorders or drops items. With keyed output:
- Reordered → parsed correctly
- Dropped → detected, that finding gets "uncertain"
- Extra/unknown keys → ignored, logged

Note: duplicate key detection is not attempted — JSON parsing silently deduplicates before application code sees the object.

### 2. Evidence validation against shared prompt

`FindingGroup` carries both `shared_evidence` (deduplicated code shown in the prompt) and `evidence_map` (each finding's original windows). Evidence validation checks citations against `shared_evidence` + tool reads — what the model was actually shown. This prevents rejecting citations that appear in the shared prompt but not in a specific finding's original window.

### 3. Co-located only, no same-file mega-grouping

Phase 1 groups only findings with overlapping evidence windows (within 3 lines). Same-file grouping is deferred until co-located grouping proves value. This prevents lumping unrelated findings together (e.g., `ai_utils/azure_utils.py` has 8 findings across very different code locations).

### 4. Pattern stats deferred

Codebase-wide check_id frequency is computed but NOT injected into prompts in Phase 1. The analyzer is code-first; repo-wide statistics could bias the model.

### 5. Shared runner primitives (no parallel implementation)

Common logic (timeout handling, thinking settings, formatter repair, evidence validation) is extracted from `_analyze_one()` into reusable functions. Both paths call the same primitives.

### 6. anchor_root reuses single-finding logic

Phase 1 is co-located (same file) only. All findings in a group share the same path, so anchor_root is computed from the first finding using existing logic. No new "common ancestor" computation.

---

## Architecture

```
Before:  356 findings → 356 independent LLM calls
After:   356 findings → ~160 groups → ~160 LLM calls (coherent verdicts within groups)
```

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Preprocess  │────▶│  build_groups()  │────▶│  Group Analyzer  │
│  356 findings│     │                  │     │  ~160 groups     │
│              │     │  1. Group by file│     │                  │
│  retrieve()  │     │  2. Sub-group by │     │  Per group:      │
│  per finding │     │     line (~3 ln) │     │  - Shared code   │
│              │     │  3. Build        │     │  - All claims    │
│              │     │     evidence_map │     │  - Coherence     │
│              │     │  4. Dedup code   │     │  - Keyed verdicts│
└──────────────┘     └──────────────────┘     └─────────────────┘
```

---

## Step 1: Group I/O Contract — `sast_verify/grouping.py` (NEW)

### FindingGroup

```python
@dataclass
class FindingGroup:
    group_key: str                          # "nessus/nessus.py:187"
    bundles: list[EvidenceBundle]           # findings in this group
    original_indices: list[int]             # maps position-in-group → original findings index
    shared_evidence: list[Evidence]         # deduplicated code windows (for prompt + validation)
    evidence_map: dict[int, list[Evidence]] # original_index → finding's original evidence
    relationship: str                       # "co-located" | "solo"
    coherence_note: str | None              # injected into prompt if co-located
```

### Key functions

```python
def deduplicate_evidence(bundles: list[EvidenceBundle]) -> list[Evidence]:
    """Merge overlapping code windows. 3 findings on same line → 1 code block."""

def build_evidence_map(
    bundles: list[EvidenceBundle],
    original_indices: list[int],
) -> dict[int, list[Evidence]]:
    """Per-finding evidence windows for post-analysis validation."""

def build_groups(
    bundles: list[EvidenceBundle],
    original_indices: list[int],
) -> list[FindingGroup]:
    """Group by file → cluster by line proximity (within 3 lines).
    Clusters with 2+ findings → co-located group. Singles → solo.
    No same-file mega-grouping in Phase 1."""
```

---

## Step 2: Refactor Shared Runner Primitives — `agents/runner.py`

Extract from `_analyze_one()` into reusable functions:

```python
def _compute_anchor_root(finding_dir: Path) -> str
def _build_deps(codebase, finding_dir, anchor_root, ...) -> AnalyzerDeps
async def _run_analyzer_stage(analyzer, message, deps, limits, thinking, timeout) -> str | None
async def _run_formatter_stage(formatter, message, kwargs, timeout, history=None) -> str | None
async def _parse_with_repair(formatter, response, timeout, kwargs, format_result) -> Verdict | None
```

After extraction, `_analyze_one()` becomes a thin wrapper. The group path calls the same primitives with different prompt builders and parsers.

---

## Step 3: Group Prompts — `prompts/analyzer.py` + `prompts/__init__.py`

### GROUP_ANALYZER_INSTRUCTION

```
## Multi-Finding Analysis

You are analyzing MULTIPLE findings on the same code region.

1. **Shared context**: Your understanding of reachability, risk, and purpose
   must be consistent across all findings.
2. **Per-finding verdicts**: Each finding has its own detection criterion.
   Evaluate each claim independently against the shared understanding.
3. **Coherence**: If a call is reachable by untrusted input, that applies
   to ALL findings on that call.
4. **Output**: Provide a labeled verdict for EACH finding by number.
```

### GROUP_VERDICT_FORMATTER_INSTRUCTION

```
Respond with ONLY a JSON object. "verdicts" must be an object keyed by
finding number (as shown in the analysis):

{
  "verdicts": {
    "0": {"verdict": "...", "is_security_vulnerability": true,
          "confidence": "...", "reason": "...", "evidence_locations": [...]},
    "1": {"verdict": "...", ...}
  }
}

Keys must match finding numbers. Include exactly one entry per finding.
```

### build_group_message()

```python
def build_group_message(group: FindingGroup) -> str:
    """Structure:
    1. Shared code evidence (deduplicated — shown once)
    2. Coherence note (if co-located)
    3. Numbered scanner claims (one per finding)
    Solo groups delegate to build_user_message()."""
```

---

## Step 4: Group Analysis + Evidence Validation — `agents/runner.py`

### Keyed parse function

```python
def _parse_group_verdicts(text: str, expected_keys: list[str]) -> dict[str, Verdict]:
    """Parse keyed verdicts. Missing keys → 'uncertain'. Extra/unknown keys → ignored + warned."""
```

### Per-finding evidence validation

```python
def _validate_group_evidence(
    group: FindingGroup,
    verdicts: dict[str, Verdict],
    accessed_paths: dict[str, list[tuple[int, int]]],
) -> dict[str, Verdict]:
    """Validate evidence_locations against what the model was shown.
    Citations checked against shared_evidence (prompt code) + accessed_paths (tool reads)."""
```

### Group analysis function

```python
async def _analyze_one_group(analyzer, formatter, group, codebase, ...) -> dict[int, Verdict]:
    """Uses shared primitives. anchor_root from first finding (same file).
    Thinking = highest severity. Timeout = base + 60s * (size - 1)."""

async def analyze_all_grouped(groups, codebase, concurrency) -> dict[int, Verdict]:
    """Semaphore-bounded. Returns dict[original_index, Verdict]."""
```

---

## Step 5: Pipeline Integration — `pipeline.py` + `cli.py`

```python
def run(codebase, findings_path, output_path, concurrency=4, enable_grouping=True):
    ...
    if enable_grouping:
        groups = build_groups(list(analyzable), list(indices))
        verdict_map = asyncio.run(analyze_all_grouped(groups, codebase, concurrency))
        for idx, verdict in verdict_map.items():
            verdicts[idx] = verdict
    else:
        # Existing single-finding path
        ...
```

CLI: `--no-grouping` flag for A/B benchmarking.

---

## Implementation Order

| Order | Step | What | Why this order |
|-------|------|------|---------------|
| 1 | Step 1 | `grouping.py` — group contract, evidence_map, dedup | Pure data, testable |
| 2 | Step 2 | Refactor runner primitives | Before adding group path |
| 3 | Step 3 | Group prompts | Depends on FindingGroup |
| 4 | Step 4 | Group analysis + keyed parsing + evidence validation | Uses Steps 2+3 |
| 5 | Step 5 | Pipeline wiring + `--no-grouping` | Integration |
| 6 | Tests | grouping, keyed parsing, evidence attribution | Validation |
| 7 | Benchmark | A/B: grouped vs ungrouped | Measure impact |

## What is NOT in Phase 1

- Pattern statistics in prompts (deferred)
- Phase 2 data-flow stubs (separate design, requires anchor_root redesign)
- Parallel/duplicate implementation (prevented by shared primitives)

## Expected Impact

| Metric | Current (v6) | With grouping (est.) |
|--------|------:|------:|
| Contradictory co-located verdicts | 16 | 0-2 |
| LLM calls | 320 | ~160 |
| Wall-clock time | ~45 min | ~25 min |
| Accuracy | 85.0% | 87-89% |
| F1 | 79.7% | 83-86% |

## Verification

1. Unit tests: grouping logic, dedup, evidence_map, index mapping
2. Parse tests: keyed verdict parsing, missing/duplicate/extra key handling
3. Evidence tests: per-finding citation validation in grouped context
4. A/B benchmark on sample-9 with `--no-grouping` baseline
5. Coherence check: co-located findings no longer contradict

## Critical Files

| File | Action | Est. lines |
|------|--------|-----------|
| `sast_verify/grouping.py` | **NEW** | ~120 |
| `sast_verify/agents/runner.py` | Refactor + add group functions | ~120 (net ~60) |
| `sast_verify/prompts/analyzer.py` | Add group instructions | ~40 |
| `sast_verify/prompts/__init__.py` | Add `build_group_message()` | ~50 |
| `sast_verify/agents/analyzer.py` | Add group agent builders | ~12 |
| `sast_verify/pipeline.py` | Wire grouping | ~15 |
| `sast_verify/cli.py` | `--no-grouping` flag | ~3 |
