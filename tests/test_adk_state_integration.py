"""Integration tests: deps mutation visibility + real Agent.run() path coverage.

PydanticAI passes deps by reference, so tool mutations to accessed_paths
are immediately visible to the caller — no get_session() workaround needed.

The FunctionModel-based tests exercise the actual Agent → tool-call → response
pipeline and the message_history-based formatter repair loop, without needing
a live LLM endpoint.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart

from sast_verify.agents.deps import AnalyzerDeps
from sast_verify.agents.tools import read_file


# ---------------------------------------------------------------------------
# Unit tests — dict/deps mutation semantics
# ---------------------------------------------------------------------------

def test_dict_state_mutation_semantics():
    """Verify that mutating a nested dict in state is visible from the outside.

    This is the fundamental contract that _track_access relies on:
    the state dict is passed by reference, so in-place mutations to
    nested containers (like accessed_paths) are visible to the caller.
    """
    state = {"accessed_paths": {}}

    # Simulate what _track_access does
    accessed = state.get("accessed_paths")
    assert isinstance(accessed, dict)
    accessed["some_file.py"] = [(1, 50)]

    # The mutation should be visible from the original state
    assert "some_file.py" in state["accessed_paths"]
    assert state["accessed_paths"]["some_file.py"] == [(1, 50)]


def test_deps_mutation_visible_without_refresh(tmp_path):
    """PydanticAI deps are passed by reference — no stale-state problem.

    When a tool mutates deps.accessed_paths, the caller sees the mutation
    immediately on the same deps object. No need to re-read from a session
    store like ADK required.
    """
    (tmp_path / "example.py").write_text("line1\nline2\nline3\n")

    deps = AnalyzerDeps(
        codebase=str(tmp_path),
        finding_dir="",
        anchor_root="",
        accessed_paths={},
    )
    ctx = MagicMock()
    ctx.deps = deps

    # Before tool call — empty
    assert deps.accessed_paths == {}

    # Tool call mutates deps.accessed_paths
    read_file(ctx, "example.py", start_line=1, end_line=3)

    # Mutation is immediately visible — no refresh needed
    assert "example.py" in deps.accessed_paths
    assert len(deps.accessed_paths["example.py"]) == 1
    assert deps.accessed_paths["example.py"][0] == (1, 3)


def test_multiple_tool_calls_accumulate_on_same_deps(tmp_path):
    """Multiple tool calls accumulate state on the same deps object."""
    (tmp_path / "a.py").write_text("".join(f"line{i}\n" for i in range(20)))
    (tmp_path / "b.py").write_text("content\n")

    deps = AnalyzerDeps(
        codebase=str(tmp_path),
        finding_dir="",
        anchor_root="",
        accessed_paths={},
    )
    ctx = MagicMock()
    ctx.deps = deps

    read_file(ctx, "a.py", start_line=1, end_line=5)
    read_file(ctx, "b.py", start_line=1, end_line=1)
    read_file(ctx, "a.py", start_line=10, end_line=15)

    assert "a.py" in deps.accessed_paths
    assert "b.py" in deps.accessed_paths
    assert (1, 5) in deps.accessed_paths["a.py"]
    assert (10, 15) in deps.accessed_paths["a.py"]


# ---------------------------------------------------------------------------
# FunctionModel integration tests — real Agent.run() path
# ---------------------------------------------------------------------------

@pytest.fixture
def codebase(tmp_path):
    """Create a minimal codebase for agent integration tests."""
    src = tmp_path / "src" / "app.py"
    src.parent.mkdir(parents=True)
    src.write_text("from flask import request\n\ndef login():\n    user = request.args.get('user')\n    return user\n")
    return tmp_path


def _make_analyzer_model():
    """FunctionModel that calls read_file then returns an analysis."""
    from pydantic_ai.models.function import FunctionModel, AgentInfo

    call_count = 0

    def callback(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            # First call: invoke read_file tool
            return ModelResponse(parts=[
                ToolCallPart(
                    tool_name="read_file",
                    args=json.dumps({"path": "src/app.py", "start_line": 1, "end_line": 5}),
                ),
            ])
        else:
            # Second call: return analysis text after seeing tool result
            return ModelResponse(parts=[
                TextPart(
                    content=(
                        "- **verdict_candidate**: true_positive\n"
                        "- **confidence**: high\n"
                        "- **mitigations_found**: none\n"
                        "- **assumptions**: none\n"
                        "- **unresolved_questions**: none\n"
                        "- **evidence_locations**: src/app.py:4\n"
                        "- **reasoning**: User input is returned unsanitized."
                    )
                ),
            ])

    return FunctionModel(callback)


def _make_formatter_model(valid_json: bool = True):
    """FunctionModel that returns a verdict JSON (optionally invalid on first try)."""
    from pydantic_ai.models.function import FunctionModel, AgentInfo

    call_count = 0

    def callback(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        nonlocal call_count
        call_count += 1

        if not valid_json and call_count == 1:
            # First attempt: invalid response to trigger repair loop
            return ModelResponse(parts=[
                TextPart(content="I think this is a true positive."),
            ])

        # Valid verdict JSON
        verdict = {
            "verdict": "true_positive",
            "confidence": "high",
            "reason": "User input returned without sanitization.",
            "evidence_locations": ["src/app.py:4"],
        }
        return ModelResponse(parts=[
            TextPart(content=json.dumps(verdict)),
        ])

    return FunctionModel(callback)


def _build_test_analyzer():
    """Build an analyzer Agent with a placeholder model (override before use)."""
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel

    from sast_verify.agents.deps import AnalyzerDeps
    from sast_verify.agents.tools import grep_code, read_file
    from sast_verify.prompts.analyzer import ANALYZER_INSTRUCTION

    return Agent(
        TestModel(),
        deps_type=AnalyzerDeps,
        instructions=ANALYZER_INSTRUCTION,
        tools=[read_file, grep_code],
    )


def _build_test_formatter():
    """Build a formatter Agent with a placeholder model (override before use)."""
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel

    from sast_verify.prompts.analyzer import VERDICT_FORMATTER_INSTRUCTION

    return Agent(
        TestModel(),
        instructions=VERDICT_FORMATTER_INSTRUCTION,
    )


@pytest.mark.anyio
async def test_analyzer_agent_calls_tools_and_tracks_access(codebase):
    """Real Agent.run() with FunctionModel: tool call populates deps.accessed_paths."""
    from sast_verify.agents.deps import AnalyzerDeps

    analyzer = _build_test_analyzer()
    deps = AnalyzerDeps(
        codebase=str(codebase),
        finding_dir="src",
        anchor_root="",
        accessed_paths={},
    )

    with analyzer.override(model=_make_analyzer_model()):
        result = await analyzer.run("Analyze this finding.", deps=deps)

    # Agent returned text analysis
    assert "true_positive" in result.output
    # Tool call populated accessed_paths on deps (by reference)
    assert "src/app.py" in deps.accessed_paths
    assert len(deps.accessed_paths["src/app.py"]) >= 1


@pytest.mark.anyio
async def test_formatter_repair_loop_with_message_history(codebase):
    """Formatter repair loop: invalid first response → retry with message_history → valid."""
    from sast_verify.agents.runner import _parse_verdict

    formatter = _build_test_formatter()

    # Use a formatter model that fails on first try, succeeds on second
    with formatter.override(model=_make_formatter_model(valid_json=False)):
        # First call — returns invalid text
        result1 = await formatter.run("Format this analysis into a verdict.")
        response = result1.output
        assert "true positive" in response.lower()

        # _parse_verdict should fail on the plain-text response
        with pytest.raises(ValueError):
            _parse_verdict(response)

        # Repair call with message_history — continues the conversation
        result2 = await formatter.run(
            "Return ONLY valid JSON.",
            message_history=result1.all_messages(),
        )
        repair_response = result2.output

        # Now it should parse
        verdict = _parse_verdict(repair_response)
        assert verdict.verdict == "true_positive"
        assert verdict.confidence == "high"


@pytest.mark.anyio
async def test_full_analyze_one_pipeline(codebase):
    """End-to-end _analyze_one: analyzer → formatter → verdict with evidence validation."""
    from sast_verify.agents.runner import _analyze_one
    from sast_verify.schema import Evidence, EvidenceBundle, Finding

    analyzer = _build_test_analyzer()
    formatter = _build_test_formatter()

    bundle = EvidenceBundle(
        finding=Finding(
            fingerprint="abc123",
            check_id="xss.reflected",
            path="src/app.py",
            line=4,
            end_line=4,
            severity="ERROR",
            category="security",
            message="Reflected XSS",
            lines="user = request.args.get('user')",
        ),
        evidence=[
            Evidence(
                path="src/app.py",
                start_line=1,
                end_line=5,
                content="from flask import request\n\ndef login():\n    user = request.args.get('user')\n    return user\n",
            )
        ],
    )

    with analyzer.override(model=_make_analyzer_model()), \
         formatter.override(model=_make_formatter_model(valid_json=True)):
        verdict = await _analyze_one(
            analyzer, formatter,
            bundle, codebase, index=0,
            stage_timeout=30,
        )

    assert verdict.verdict == "true_positive"
    assert verdict.confidence == "high"
    # evidence_locations should be validated against accessed_paths
    # src/app.py:4 is within the evidence window (1-5), so it should survive
    assert "src/app.py:4" in verdict.evidence_locations
