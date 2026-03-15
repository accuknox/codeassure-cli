from __future__ import annotations

from pydantic_ai import Agent

from ..config import get_config
from ..prompts.analyzer import ANALYZER_INSTRUCTION, VERDICT_FORMATTER_INSTRUCTION
from .deps import AnalyzerDeps
from .tools import grep_code, read_file


def build_analyzer() -> Agent[AnalyzerDeps, str]:
    return Agent(
        get_config().build_model(),
        deps_type=AnalyzerDeps,
        instructions=ANALYZER_INSTRUCTION,
        tools=[read_file, grep_code],
    )


def build_verdict_formatter() -> Agent[None, str]:
    return Agent(
        get_config().build_model(),
        instructions=VERDICT_FORMATTER_INSTRUCTION,
    )
