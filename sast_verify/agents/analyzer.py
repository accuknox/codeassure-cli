from __future__ import annotations

from pydantic_ai import Agent

from ..config import get_config
from ..prompts.analyzer import (
    ANALYZER_INSTRUCTION,
    EVALUATOR_INSTRUCTION,
    GROUP_ANALYZER_INSTRUCTION,
    GROUP_EVALUATOR_INSTRUCTION,
    GROUP_VERDICT_FORMATTER_INSTRUCTION,
    VERDICT_FORMATTER_INSTRUCTION,
)
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


def build_group_analyzer() -> Agent[AnalyzerDeps, str]:
    return Agent(
        get_config().build_model(),
        deps_type=AnalyzerDeps,
        instructions=GROUP_ANALYZER_INSTRUCTION,
        tools=[read_file, grep_code],
    )


def build_group_verdict_formatter() -> Agent[None, str]:
    return Agent(
        get_config().build_model(),
        instructions=GROUP_VERDICT_FORMATTER_INSTRUCTION,
    )


def build_evaluator() -> Agent[None, str]:
    return Agent(
        get_config().build_model(),
        instructions=EVALUATOR_INSTRUCTION,
    )


def build_group_evaluator() -> Agent[None, str]:
    return Agent(
        get_config().build_model(),
        instructions=GROUP_EVALUATOR_INSTRUCTION,
    )
