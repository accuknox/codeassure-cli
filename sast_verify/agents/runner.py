from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from pydantic_ai.usage import UsageLimits

from ..config import get_config
from ..prompts import build_formatter_message, build_user_message
from ..schema import EvidenceBundle, Verdict
from .analyzer import build_analyzer, build_verdict_formatter
from .deps import AnalyzerDeps

log = logging.getLogger(__name__)

DEFAULT_CONCURRENCY = 4
MAX_GREP_FILE_SIZE_DEFAULT = 512 * 1024
MAX_GREP_BYTES_DEFAULT = 5 * 1024 * 1024


import re


def _fix_unquoted_strings(text: str) -> str:
    """Fix JSON with unquoted string values — common with some models.

    Targets the "reason" field specifically, which nemotron often leaves unquoted.
    Uses a greedy match anchored to the last valid JSON delimiter to handle
    reason text that contains } or , characters.
    """
    # Match "reason": followed by unquoted text, greedily up to the last
    # , "next_key" or lone } that closes the object
    pattern = r'("reason")\s*:\s*(?!")(.+?)(?=,\s*"evidence_locations"\s*:|,\s*"verdict"\s*:|,\s*"confidence"\s*:|,\s*"is_security_vulnerability"\s*:|,\s*"finding_correct"\s*:|\s*}\s*$)'
    def _quote_value(m: re.Match) -> str:
        key = m.group(1)
        val = m.group(2).strip().rstrip(',').strip()
        val = val.replace('\\', '\\\\').replace('"', '\\"')
        return f'{key}: "{val}"'
    return re.sub(pattern, _quote_value, text, flags=re.DOTALL | re.MULTILINE)


def _parse_verdict(text: str) -> Verdict:
    """Try to parse a Verdict from text — handles clean JSON and embedded JSON."""
    text = text.strip()
    if not text:
        raise ValueError("Empty response")

    # Try direct parse first (clean JSON)
    if text.startswith("{"):
        try:
            return Verdict.model_validate(json.loads(text))
        except (json.JSONDecodeError, Exception):
            pass

    # Scan for embedded JSON objects using raw_decode — handles nested braces,
    # braces inside strings, and multiple objects correctly
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        pos = text.find("{", idx)
        if pos == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            idx = pos + 1
            continue
        if isinstance(obj, dict) and "verdict" in obj:
            return Verdict.model_validate(obj)
        idx = end

    # Last resort: try fixing unquoted string values (common with some models)
    fixed = _fix_unquoted_strings(text)
    if fixed != text:
        try:
            return Verdict.model_validate(json.loads(fixed))
        except Exception:
            pass
        # Also scan fixed text for embedded JSON
        idx = 0
        while idx < len(fixed):
            pos = fixed.find("{", idx)
            if pos == -1:
                break
            try:
                obj, end = decoder.raw_decode(fixed, pos)
            except json.JSONDecodeError:
                idx = pos + 1
                continue
            if isinstance(obj, dict) and "verdict" in obj:
                return Verdict.model_validate(obj)
            idx = end

    raise ValueError(f"No JSON verdict found in: {text[:200]}")


def _validate_evidence(
    evidence_locations: list[str],
    accessed_paths: dict[str, list[tuple[int, int]]],
    finding_path: str,
    finding_start: int,
    finding_end: int,
) -> list[str]:
    """Filter evidence_locations to only include files+lines actually accessed.

    accessed_paths maps file paths to lists of (start_line, end_line) ranges
    that were read by tools. The finding's own file is always valid within the
    evidence window provided to the analyzer.
    """
    validated = []
    for loc in evidence_locations:
        if ":" in loc:
            file_part, line_str = loc.rsplit(":", 1)
            try:
                cited_line = int(line_str)
            except ValueError:
                # Not a valid file:line format — keep if file was accessed
                file_part = loc
                cited_line = None
        else:
            file_part = loc
            cited_line = None

        if file_part == finding_path:
            # Finding's own file: the initial evidence window is always valid
            if cited_line is None or finding_start <= cited_line <= finding_end:
                validated.append(loc)
                continue
            # Also check if a tool read beyond the initial window
            ranges = accessed_paths.get(file_part, [])
            if any(s <= cited_line <= e for s, e in ranges):
                validated.append(loc)
            continue

        if file_part not in accessed_paths:
            continue

        ranges = accessed_paths[file_part]
        if cited_line is None:
            # No line cited — file was accessed, accept
            validated.append(loc)
        elif not ranges:
            # File tracked but no line ranges (shouldn't happen, but accept)
            validated.append(loc)
        elif any(s <= cited_line <= e for s, e in ranges):
            validated.append(loc)

    return validated


async def _analyze_one(
    analyzer,
    formatter,
    bundle: EvidenceBundle,
    codebase: Path,
    index: int,
    stage_timeout: float = 120,
    grep_max_file_size: int = MAX_GREP_FILE_SIZE_DEFAULT,
    grep_max_bytes: int = MAX_GREP_BYTES_DEFAULT,
    request_limit: int = 200,
    thinking_settings: dict | None = None,
) -> Verdict:
    # Compute anchor scope: finding_dir's parent, falling back to finding_dir itself
    finding_dir = Path(bundle.finding.path).parent
    if str(finding_dir) == ".":
        anchor_root = ""  # file at repo root → no narrower scope exists
    elif str(finding_dir.parent) == ".":
        anchor_root = str(finding_dir)  # one level deep → anchor to that directory
    else:
        anchor_root = str(finding_dir.parent)  # deeper → anchor to parent

    # Stage 1: Tool-using analysis
    deps = AnalyzerDeps(
        codebase=str(codebase.resolve()),
        finding_dir=str(finding_dir),
        anchor_root=anchor_root,
        accessed_paths={},
        grep_max_file_size=grep_max_file_size,
        grep_max_bytes=grep_max_bytes,
    )

    limits = UsageLimits(request_limit=request_limit)

    run_kwargs: dict = {"deps": deps, "usage_limits": limits}
    if thinking_settings:
        run_kwargs["model_settings"] = thinking_settings
        formatter_kwargs: dict = {"model_settings": thinking_settings}
        mode = "full" if not thinking_settings["extra_body"]["chat_template_kwargs"].get("low_effort") else "low"
        if not thinking_settings["extra_body"]["chat_template_kwargs"]["enable_thinking"]:
            mode = "off"
        log.info("Finding %d [%s] → thinking=%s", index, bundle.finding.severity, mode)
    else:
        formatter_kwargs = {}

    try:
        analysis_result = await asyncio.wait_for(
            analyzer.run(build_user_message(bundle), **run_kwargs),
            timeout=stage_timeout,
        )
        analysis = analysis_result.output
    except asyncio.TimeoutError:
        log.warning("Analyzer timed out for finding %d", index)
        return Verdict(
            verdict="uncertain",
            confidence="low",
            reason=f"Analyzer stage timed out after {stage_timeout}s.",
        )
    except Exception as exc:
        log.error("Analyzer failed for finding %d: %s", index, exc)
        return Verdict(
            verdict="uncertain",
            confidence="low",
            reason=f"Analyzer error: {type(exc).__name__}",
        )

    if not analysis.strip():
        log.warning("Empty analysis for finding %d", index)
        return Verdict(
            verdict="uncertain",
            confidence="low",
            reason="Analyzer produced no output.",
        )

    # accessed_paths already populated on deps — no get_session() needed
    accessed_paths = deps.accessed_paths

    # Stage 2: Verdict extraction with validation-error repair loop
    format_message = build_formatter_message(analysis, bundle)

    try:
        format_result = await asyncio.wait_for(
            formatter.run(format_message, **formatter_kwargs),
            timeout=stage_timeout,
        )
        response = format_result.output
    except asyncio.TimeoutError:
        log.warning("Formatter timed out for finding %d", index)
        response = ""
    except Exception as exc:
        log.error("Formatter failed for finding %d: %s", index, exc)
        response = ""

    # Try parsing formatter response
    verdict = None
    if response.strip():
        try:
            verdict = _parse_verdict(response)
        except Exception as exc:
            log.warning("Formatter parse failed for finding %d: %s", index, exc)

            # Send the error back to the formatter for correction (same conversation)
            repair_message = (
                f"Your response could not be parsed: {exc}\n\n"
                "Return ONLY a valid JSON object with these exact keys:\n"
                '{"verdict": "true_positive|false_positive|uncertain", '
                '"finding_correct": true or false or null, '
                '"is_security_vulnerability": true or false or null, '
                '"confidence": "high|medium|low", '
                '"reason": "...", "evidence_locations": ["file:line"]}\n'
                "No markdown fences, no prose."
            )

            try:
                repair_result = await asyncio.wait_for(
                    formatter.run(
                        repair_message,
                        message_history=format_result.all_messages(),
                        **formatter_kwargs,
                    ),
                    timeout=stage_timeout,
                )
                repair_response = repair_result.output
            except Exception:
                repair_response = ""

            if repair_response.strip():
                try:
                    verdict = _parse_verdict(repair_response)
                except Exception as repair_exc:
                    log.warning("Formatter repair failed for finding %d: %s", index, repair_exc)

    # Fallback: try parsing the analyzer's own output (may contain JSON)
    if verdict is None:
        try:
            verdict = _parse_verdict(analysis)
        except Exception:
            pass

    if verdict is None:
        log.error("All parse attempts failed for finding %d", index)
        return Verdict(
            verdict="uncertain",
            confidence="low",
            reason="Could not extract a valid verdict from LLM output.",
        )

    # Validate evidence_locations against actual tool usage
    # The initial evidence window covers what the analyzer was shown upfront
    if bundle.evidence:
        ev = bundle.evidence[0]
        finding_start, finding_end = ev.start_line, ev.end_line
    else:
        finding_start, finding_end = bundle.finding.line, bundle.finding.end_line
    verdict.evidence_locations = _validate_evidence(
        verdict.evidence_locations, accessed_paths, bundle.finding.path,
        finding_start, finding_end,
    )

    # Coherence: finding_correct must align with verdict (skip if None/uncertain)
    if verdict.finding_correct is not None:
        if verdict.finding_correct and verdict.verdict == "false_positive":
            log.warning("Finding %d: finding_correct=true contradicts verdict=FP → overriding to TP", index)
            verdict.verdict = "true_positive"
        elif not verdict.finding_correct and verdict.verdict == "true_positive":
            log.warning("Finding %d: finding_correct=false contradicts verdict=TP → overriding to FP", index)
            verdict.verdict = "false_positive"

    return verdict


async def analyze_all(
    bundles: list[EvidenceBundle],
    codebase: Path,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[Verdict]:
    cfg = get_config()
    stage_timeout = cfg.stage_timeout
    finding_timeout = cfg.finding_timeout
    grep_max_file_size = cfg.grep_max_file_kb * 1024
    grep_max_bytes = cfg.grep_max_scan_mb * 1024 * 1024
    request_limit = cfg.request_limit

    analyzer = build_analyzer()
    formatter = build_verdict_formatter()

    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(index: int, bundle: EvidenceBundle) -> Verdict:
        async with semaphore:
            thinking = cfg.get_thinking_settings(bundle.finding.severity)
            try:
                return await asyncio.wait_for(
                    _analyze_one(
                        analyzer, formatter,
                        bundle, codebase, index,
                        stage_timeout=stage_timeout,
                        grep_max_file_size=grep_max_file_size,
                        grep_max_bytes=grep_max_bytes,
                        request_limit=request_limit,
                        thinking_settings=thinking,
                    ),
                    timeout=finding_timeout,
                )
            except asyncio.TimeoutError:
                log.error("Finding %d timed out after %ds", index, finding_timeout)
                return Verdict(
                    verdict="uncertain",
                    confidence="low",
                    reason=f"Analysis timed out after {finding_timeout}s.",
                )
            except Exception as exc:
                log.error("Finding %d failed: %s", index, exc)
                return Verdict(
                    verdict="uncertain",
                    confidence="low",
                    reason=f"Analysis error: {type(exc).__name__}",
                )

    tasks = [_bounded(i, b) for i, b in enumerate(bundles)]
    return await asyncio.gather(*tasks)
