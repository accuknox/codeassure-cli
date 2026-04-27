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
    confidence: Literal["high", "medium", "low"] = Field(
        description="Confidence level of the verdict",
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        default="low",
        description="Severity of the finding. Assessed severity for true_positive; always 'low' for false_positive/uncertain.",
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
        description="Vote counts per verdict label when voting_rounds > 1 (e.g. {\"false_positive\": 2, \"true_positive\": 1})",
    )
    claude_verdict_agrees: bool | None = Field(
        default=None,
        description="Whether Claude agrees with the verdict (true_positive/false_positive/uncertain)",
    )
    claude_vuln_agrees: bool | None = Field(
        default=None,
        description="Whether Claude agrees with the is_security_vulnerability classification",
    )
    claude_reason: str | None = Field(
        default=None,
        description="Claude's reasoning for its validation of both the verdict and vulnerability classification",
    )
