from __future__ import annotations

from pydantic_ai import Agent, PromptedOutput

from ..config import get_config
from ..prompts.analyzer import (
    ANALYZER_INSTRUCTION,
    ANALYZER_INSTRUCTION_FINDING_ONLY,
    ANALYZER_INSTRUCTION_NO_TOOLS,
    EVALUATOR_INSTRUCTION,
    GROUP_ANALYZER_INSTRUCTION,
    GROUP_ANALYZER_INSTRUCTION_FINDING_ONLY,
    GROUP_ANALYZER_INSTRUCTION_NO_TOOLS,
    GROUP_EVALUATOR_INSTRUCTION,
    GROUP_VERDICT_FORMATTER_INSTRUCTION,
    VERDICT_FORMATTER_INSTRUCTION,
)
from ..schema import GroupVerdicts, Verdict
from .deps import AnalyzerDeps
from .tools import grep_code, read_file

# PromptedOutput (text-based JSON parsing) instead of ToolOutput so reasoning models
# (Qwen3.6 with thinking) can emit JSON in their text response without colliding with
# the read_file/grep_code tool channel — which suppresses the final tool call.
_OUTPUT_RETRIES = 3

def build_analyzer() -> Agent[AnalyzerDeps, Verdict]:
    cfg = get_config()
    if cfg.findings_analysis:
        return Agent(
            cfg.build_model(),
            deps_type=AnalyzerDeps,
            output_type=PromptedOutput(Verdict),
            instructions=ANALYZER_INSTRUCTION_FINDING_ONLY,
            output_retries=_OUTPUT_RETRIES,
        )
    if cfg.model.tool_calling:
        return Agent(
            cfg.build_model(),
            deps_type=AnalyzerDeps,
            output_type=PromptedOutput(Verdict),
            instructions=ANALYZER_INSTRUCTION,
            tools=[read_file, grep_code],
            output_retries=_OUTPUT_RETRIES,
        )
    return Agent(
        cfg.build_model(),
        deps_type=AnalyzerDeps,
        output_type=PromptedOutput(Verdict),
        instructions=ANALYZER_INSTRUCTION_NO_TOOLS,
        output_retries=_OUTPUT_RETRIES,
    )


def build_verdict_formatter() -> Agent[None, str]:
    """Legacy formatter agent — retained for backward-compatibility with tests."""
    return Agent(
        get_config().build_model(),
        instructions=VERDICT_FORMATTER_INSTRUCTION,
    )


def build_group_analyzer() -> Agent[AnalyzerDeps, GroupVerdicts]:
    cfg = get_config()
    if cfg.findings_analysis:
        return Agent(
            cfg.build_model(),
            deps_type=AnalyzerDeps,
            output_type=PromptedOutput(GroupVerdicts),
            instructions=GROUP_ANALYZER_INSTRUCTION_FINDING_ONLY,
            output_retries=_OUTPUT_RETRIES,
        )
    if cfg.model.tool_calling:
        return Agent(
            cfg.build_model(),
            deps_type=AnalyzerDeps,
            output_type=PromptedOutput(GroupVerdicts),
            instructions=GROUP_ANALYZER_INSTRUCTION,
            tools=[read_file, grep_code],
            output_retries=_OUTPUT_RETRIES,
        )
    return Agent(
        cfg.build_model(),
        deps_type=AnalyzerDeps,
        output_type=PromptedOutput(GroupVerdicts),
        instructions=GROUP_ANALYZER_INSTRUCTION_NO_TOOLS,
        output_retries=_OUTPUT_RETRIES,
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
