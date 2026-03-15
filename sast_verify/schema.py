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
    finding_correct: bool | None = Field(
        default=None,
        description="True if the scanner correctly detected the pattern it claims; "
        "false if not; null when verdict is uncertain or could not be determined",
    )
    is_security_vulnerability: bool | None = Field(
        default=None,
        description="True if the finding represents an exploitable security vulnerability; "
        "false if it is a best-practice recommendation, style issue, or informational notice; "
        "null when verdict is uncertain or could not be determined",
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
