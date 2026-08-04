from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    fingerprint: str
    check_id: str
    path: str
    line: int
    end_line: int
    severity: str
    category: str
    message: str
    lines: str
    cwe: list[str] | None = None
    confidence: str | None = None
    likelihood: str | None = None
    impact: str | None = None
    taint_source: str | None = None
    taint_sink: str | None = None
    fix: str | None = None
    # Deterministic source→sink graph from context-graph-cli (None if not run).
    context_graph: dict | None = None


class Evidence(BaseModel):
    path: str
    start_line: int
    end_line: int
    content: str


class EvidenceBundle(BaseModel):
    finding: Finding
    evidence: list[Evidence]


class Verdict(BaseModel):
    verdict: Literal["true_positive", "false_positive", "uncertain"] = Field(
        description="Whether the SAST finding is a true positive, false positive, or uncertain",
    )
    is_security_vulnerability: bool = Field(
        default=True,
        description="True if the finding represents an exploitable security vulnerability; "
        "false if it is a best-practice recommendation, style issue, or informational notice",
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        default="low",
        description="Assessed severity for true_positive; always 'low' for false_positive/uncertain.",
    )
    confidence: Literal["high", "medium", "low"] = Field(
        description="Confidence level of the verdict",
    )
    reason: str = Field(
        description="Plain-English explanation of the verdict, no source code",
    )
    evidence_locations: list[str] = Field(
        default=[],
        description="file:line references that support the verdict",
    )
    source_trust: Literal[
        "attacker_controlled", "external_service", "operator_config",
        "internal", "hardcoded", "unknown",
    ] | None = Field(
        default=None,
        description="Trust classification of the data that reaches the flagged sink: "
        "attacker_controlled (HTTP request, user upload, untrusted CLI/network input), "
        "external_service (data from another service/API), operator_config (env vars, "
        "config files an operator controls), internal (values produced by this program), "
        "hardcoded (constants/literals only), unknown (could not be determined).",
    )
    taint_flow_verified: bool | None = Field(
        default=None,
        description="True if the source→sink data flow was verified hop-by-hop against the "
        "actual code (not assumed); false if the flow was checked and does NOT hold; "
        "null when not applicable (pattern-existence rules) or not traced.",
    )
    execution_trace: list[str] = Field(
        default=[],
        description="Hop-by-hop execution/data-flow trace that was actually verified, "
        "each entry 'file:line — what was confirmed there' (entry point, propagation, "
        "sanitizer, sink). Empty when no tracing was needed.",
    )
    attack_scenario: str | None = Field(
        default=None,
        description="For exploitable true positives: one concrete, realistic attack scenario "
        "(who sends what, through which entry point, causing what impact). For "
        "false positives / non-exploitable findings: null or why no attack is possible.",
    )
    voting_tally: dict[str, int] | None = Field(
        default=None,
        description="Vote counts per verdict label when voting_rounds > 1",
    )
    claude_verdict_agrees: bool | None = Field(
        default=None,
        description="Whether Claude agrees with the verdict",
    )
    claude_vuln_agrees: bool | None = Field(
        default=None,
        description="Whether Claude agrees with the is_security_vulnerability classification",
    )
    claude_reason: str | None = Field(
        default=None,
        description="Claude's reasoning for its validation",
    )
    validator_verdict_agrees: bool | None = Field(
        default=None,
        description="Whether the validator model agrees with the verdict",
    )
    validator_vuln_agrees: bool | None = Field(
        default=None,
        description="Whether the validator model agrees with the is_security_vulnerability flag",
    )
    validator_reason: str | None = Field(
        default=None,
        description="Validator's reasoning for its agreement/disagreement",
    )


class ValidationResult(BaseModel):
    """Structured output from the validator agent (second-opinion review)."""
    verdict_agrees: bool = Field(description="True if the verdict label is correct")
    vuln_agrees: bool = Field(description="True if the is_security_vulnerability flag is correct")
    reason: str = Field(description="1-3 sentence explanation covering both judgements")


class Remediation(BaseModel):
    """Contextual, copy-paste fix that preserves business logic."""
    summary: str = Field(description="One-line description of the fix")
    code_patch: str = Field(
        default="",
        description="Copy-paste-ready corrected code for the affected node(s). "
        "Must preserve the surrounding business logic and function contract.",
    )
    file: str | None = Field(
        default=None,
        description="File the patch applies to (repo-relative path of the flagged file)",
    )
    start_line: int | None = Field(
        default=None,
        description="First line (1-indexed, inclusive) of the region code_patch replaces",
    )
    end_line: int | None = Field(
        default=None,
        description="Last line (inclusive) of the region code_patch replaces",
    )
    original_code: str = Field(
        default="",
        description="The exact current code of the region being replaced (verbatim), so the "
        "developer can locate and diff it",
    )
    preserves_logic: bool = Field(
        default=True,
        description="True if applying the patch does not change intended behaviour",
    )
    notes: str = Field(default="", description="Caveats, follow-ups, or config changes needed")


class PathColoring(BaseModel):
    """Color verdict for one context-graph path."""
    id: str = Field(description="Path id from the context graph (e.g. 'p0')")
    status: Literal["vulnerable", "safe", "node-protected", "deadcode", "unknown"]
    color: Literal["red", "green", "blue", "gray"]
    reason: str = Field(default="", description="Why this path got this classification")


class NodeColoring(BaseModel):
    """Color verdict for one context-graph node."""
    id: str = Field(description="Node id from the context graph (e.g. 'n0', 'n_sink')")
    status: str = Field(default="", description="e.g. source, sink, protected, sanitizer")
    color: Literal["red", "orange", "green", "blue", "gray"]


class GraphColoring(BaseModel):
    """Per-path / per-node color overlay. ADVISORY / deprecated: graph colors are
    now computed deterministically in pipeline._apply_coloring_deterministic from
    the graph's own reachability/taint/protection fields + the verdict, so this LLM
    overlay is no longer read. Kept for schema back-compat; may be empty."""
    paths: list[PathColoring] = Field(default_factory=list)
    nodes: list[NodeColoring] = Field(default_factory=list)


class Enrichment(BaseModel):
    """Enriched, UI-facing explanation of a finding, produced after the verdict.

    Reasons over the deterministic context graph (plus optional tool calls) to
    explain the finding in business terms, give a safe copy-paste remediation,
    and color-code the graph (red=exploitable, green=safe, blue=node-protected,
    gray=deadcode).
    """
    rationale: str = Field(description="Why the verdict holds — the security reasoning")
    business_logic: str = Field(
        description="What this code does functionally / its role in the app, in plain terms",
    )
    explanation: str = Field(
        description="Enriched, developer-facing description of the finding and its data flow",
    )
    remediation: Remediation
    coloring: GraphColoring = Field(default_factory=GraphColoring)


class GroupVerdicts(BaseModel):
    """Wrapper for grouped finding verdicts. Keys are stringified finding numbers (0, 1, ...)."""
    verdicts: dict[str, Verdict] = Field(
        description="Verdict per finding, keyed by stringified finding number (e.g. \"0\", \"1\"). "
        "Must include exactly one entry for each finding number shown in the prompt.",
    )
