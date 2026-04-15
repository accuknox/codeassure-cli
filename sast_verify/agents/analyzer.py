from __future__ import annotations

from pydantic_ai import Agent

from ..config import get_config
from ..prompts.analyzer import (
    ANALYZER_INSTRUCTION,
    ANALYZER_INSTRUCTION_NO_TOOLS,
    GROUP_ANALYZER_INSTRUCTION,
    GROUP_ANALYZER_INSTRUCTION_NO_TOOLS,
    GROUP_VERDICT_FORMATTER_INSTRUCTION,
    VERDICT_FORMATTER_INSTRUCTION,
)
from .deps import AnalyzerDeps
from .tools import grep_code, read_file


def build_analyzer() -> Agent[AnalyzerDeps, str]:
    cfg = get_config()
    if cfg.model.tool_calling:
        return Agent(
            cfg.build_model(),
            deps_type=AnalyzerDeps,
            instructions=ANALYZER_INSTRUCTION,
            tools=[read_file, grep_code],
        )
    return Agent(
        cfg.build_model(),
        deps_type=AnalyzerDeps,
        instructions=ANALYZER_INSTRUCTION_NO_TOOLS,
    )


def build_verdict_formatter() -> Agent[None, str]:
    return Agent(
        get_config().build_model(),
        instructions=VERDICT_FORMATTER_INSTRUCTION,
    )


def build_group_analyzer() -> Agent[AnalyzerDeps, str]:
    cfg = get_config()
    if cfg.model.tool_calling:
        return Agent(
            cfg.build_model(),
            deps_type=AnalyzerDeps,
            instructions=GROUP_ANALYZER_INSTRUCTION,
            tools=[read_file, grep_code],
        )
    return Agent(
        cfg.build_model(),
        deps_type=AnalyzerDeps,
        instructions=GROUP_ANALYZER_INSTRUCTION_NO_TOOLS,
    )


def build_group_verdict_formatter() -> Agent[None, str]:
    return Agent(
        get_config().build_model(),
        instructions=GROUP_VERDICT_FORMATTER_INSTRUCTION,
    )
