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


class GroupVerdicts(BaseModel):
    """Wrapper for grouped finding verdicts. Keys are stringified finding numbers (0, 1, ...)."""
    verdicts: dict[str, Verdict] = Field(
        description="Verdict per finding, keyed by stringified finding number (e.g. \"0\", \"1\"). "
        "Must include exactly one entry for each finding number shown in the prompt.",
    )
