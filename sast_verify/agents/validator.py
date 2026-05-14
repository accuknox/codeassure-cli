from __future__ import annotations

from pydantic_ai import Agent, PromptedOutput

from ..config import get_config
from ..schema import ValidationResult


VALIDATOR_INSTRUCTION = """\
You are a senior security engineer reviewing an automated SAST finding analysis.

You will receive a finding (check_id, location, severity, message, code snippet)
and a verdict produced by another model (verdict label, is_security_vulnerability,
confidence, reason). Independently judge:

1. Is the verdict label (true_positive / false_positive / uncertain) correct?
2. Is the is_security_vulnerability classification correct?

Return a ValidationResult via the structured-output tool with:
- verdict_agrees: true if the verdict label is correct
- vuln_agrees: true if the is_security_vulnerability flag is correct
- reason: 1-3 sentences explaining both judgements
"""


def build_validator() -> Agent[None, ValidationResult]:
    return Agent(
        get_config().build_validator_model(),
        output_type=PromptedOutput(ValidationResult),
        instructions=VALIDATOR_INSTRUCTION,
        output_retries=2,
    )
