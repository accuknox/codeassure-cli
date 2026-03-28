from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path

from pydantic_ai.usage import UsageLimits

from ..config import get_config
from ..grouping import FindingGroup
from ..prompts import (
    build_evaluator_message,
    build_formatter_message,
    build_group_evaluator_message,
    build_group_message,
    build_user_message,
)
from ..schema import Evidence, EvidenceBundle, Verdict
from .analyzer import (
    build_analyzer,
    build_evaluator,
    build_group_analyzer,
    build_group_evaluator,
    build_group_verdict_formatter,
    build_verdict_formatter,
)
from .deps import AnalyzerDeps

log = logging.getLogger(__name__)

DEFAULT_CONCURRENCY = 4
MAX_GREP_FILE_SIZE_DEFAULT = 512 * 1024
MAX_GREP_BYTES_DEFAULT = 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# Shared primitives (used by both single-finding and group paths)
# ---------------------------------------------------------------------------


def _fix_unquoted_strings(text: str) -> str:
    """Fix JSON with unquoted string values — common with some models."""
    pattern = r'("reason")\s*:\s*(?!")(.+?)(?=,\s*"evidence_locations"\s*:|,\s*"verdict"\s*:|,\s*"confidence"\s*:|,\s*"is_security_vulnerability"\s*:|\s*}\s*$)'

    def _quote_value(m: re.Match) -> str:
        key = m.group(1)
        val = m.group(2).strip().rstrip(",").strip()
        val = val.replace("\\", "\\\\").replace('"', '\\"')
        return f'{key}: "{val}"'

    return re.sub(pattern, _quote_value, text, flags=re.DOTALL | re.MULTILINE)


def _compute_anchor_root(finding_path: str) -> tuple[str, str]:
    """Compute anchor scope and finding_dir from a finding's path.

    Returns (finding_dir, anchor_root).
    """
    finding_dir = Path(finding_path).parent
    if str(finding_dir) == ".":
        return "", ""
    elif str(finding_dir.parent) == ".":
        return str(finding_dir), str(finding_dir)
    else:
        return str(finding_dir), str(finding_dir.parent)


def _build_deps(
    codebase: Path,
    finding_path: str,
    grep_max_file_size: int = MAX_GREP_FILE_SIZE_DEFAULT,
    grep_max_bytes: int = MAX_GREP_BYTES_DEFAULT,
) -> AnalyzerDeps:
    """Construct AnalyzerDeps for a finding."""
    finding_dir, anchor_root = _compute_anchor_root(finding_path)
    return AnalyzerDeps(
        codebase=str(codebase.resolve()),
        finding_dir=finding_dir,
        anchor_root=anchor_root,
        accessed_paths={},
        grep_max_file_size=grep_max_file_size,
        grep_max_bytes=grep_max_bytes,
    )


def _build_run_kwargs(
    deps: AnalyzerDeps,
    request_limit: int,
    thinking_settings: dict | None,
    label: str = "",
) -> tuple[dict, dict]:
    """Build kwargs for analyzer.run() and formatter.run().

    Returns (analyzer_run_kwargs, formatter_kwargs).
    """
    limits = UsageLimits(request_limit=request_limit)
    run_kwargs: dict = {"deps": deps, "usage_limits": limits}
    if thinking_settings:
        run_kwargs["model_settings"] = thinking_settings
        formatter_kwargs: dict = {"model_settings": thinking_settings}
        mode = "full" if not thinking_settings["extra_body"]["chat_template_kwargs"].get("low_effort") else "low"
        if not thinking_settings["extra_body"]["chat_template_kwargs"]["enable_thinking"]:
            mode = "off"
        if label:
            log.info("%s → thinking=%s", label, mode)
    else:
        formatter_kwargs = {}
    return run_kwargs, formatter_kwargs


def _uncertain(reason: str) -> Verdict:
    """Create an uncertain verdict with the given reason."""
    return Verdict(verdict="uncertain", confidence="low", reason=reason)


async def _run_analyzer_stage(
    analyzer,
    message: str,
    run_kwargs: dict,
    stage_timeout: float,
    label: str = "",
) -> str | None:
    """Run analyzer agent. Returns analysis text or None on failure."""
    try:
        result = await asyncio.wait_for(
            analyzer.run(message, **run_kwargs),
            timeout=stage_timeout,
        )
        analysis = result.output
        if not analysis.strip():
            log.warning("%s: empty analysis", label)
            return None
        return analysis
    except asyncio.TimeoutError:
        log.warning("%s: analyzer timed out after %ds", label, stage_timeout)
        return None
    except Exception as exc:
        log.error("%s: analyzer failed: %s", label, exc)
        return None


async def _run_formatter_stage(
    formatter,
    message: str,
    formatter_kwargs: dict,
    stage_timeout: float,
    message_history=None,
) -> str:
    """Run formatter agent. Returns response text (may be empty on failure)."""
    try:
        kwargs = dict(formatter_kwargs)
        if message_history:
            kwargs["message_history"] = message_history
        result = await asyncio.wait_for(
            formatter.run(message, **kwargs),
            timeout=stage_timeout,
        )
        return result.output, result
    except asyncio.TimeoutError:
        return "", None
    except Exception:
        return "", None


async def _parse_with_repair(
    formatter,
    response: str,
    analysis: str,
    formatter_kwargs: dict,
    format_result,
    stage_timeout: float,
    label: str = "",
    repair_hint: str = "",
) -> Verdict | None:
    """Try to parse a single verdict, with repair loop and analyzer fallback.

    Returns Verdict or None if all attempts fail.
    """
    # Try parsing formatter response
    verdict = None
    if response.strip():
        try:
            verdict = _parse_verdict(response)
        except Exception as exc:
            log.warning("%s: formatter parse failed: %s", label, exc)

            # Repair: send error back to formatter
            if not repair_hint:
                repair_hint = (
                    '{"verdict": "true_positive|false_positive|uncertain", '
                    '"is_security_vulnerability": true or false, '
                    '"confidence": "high|medium|low", '
                    '"reason": "...", "evidence_locations": ["file:line"]}'
                )
            repair_message = (
                f"Your response could not be parsed: {exc}\n\n"
                f"Return ONLY a valid JSON object with these exact keys:\n"
                f"{repair_hint}\n"
                "No markdown fences, no prose."
            )

            if format_result is not None:
                repair_response, _ = await _run_formatter_stage(
                    formatter, repair_message, formatter_kwargs,
                    stage_timeout, message_history=format_result.all_messages(),
                )
                if repair_response.strip():
                    try:
                        verdict = _parse_verdict(repair_response)
                    except Exception as repair_exc:
                        log.warning("%s: repair failed: %s", label, repair_exc)

    # Fallback: try parsing analyzer's own output
    if verdict is None and analysis:
        try:
            verdict = _parse_verdict(analysis)
        except Exception:
            pass

    return verdict


def _validate_evidence_against_windows(
    evidence_locations: list[str],
    windows: list[tuple[str, int, int]],
    accessed_paths: dict[str, list[tuple[int, int]]],
) -> list[str]:
    """Filter evidence_locations against known visible code.

    A citation is valid if it falls within:
    - Any of the provided windows (prompt evidence), OR
    - Any range in accessed_paths (tool reads)

    windows is a list of (file_path, start_line, end_line) tuples.
    """
    validated = []
    for loc in evidence_locations:
        if ":" in loc:
            file_part, line_str = loc.rsplit(":", 1)
            try:
                cited_line = int(line_str)
            except ValueError:
                file_part = loc
                cited_line = None
        else:
            file_part = loc
            cited_line = None

        # Check against prompt evidence windows
        for w_path, w_start, w_end in windows:
            if file_part == w_path:
                if cited_line is None or w_start <= cited_line <= w_end:
                    validated.append(loc)
                    break
        else:
            # Not found in prompt windows — check tool reads
            if file_part in accessed_paths:
                ranges = accessed_paths[file_part]
                if cited_line is None:
                    validated.append(loc)
                elif not ranges:
                    validated.append(loc)
                elif any(s <= cited_line <= e for s, e in ranges):
                    validated.append(loc)

    return validated


# Keep original signature for backward compatibility with tests
def _validate_evidence(
    evidence_locations: list[str],
    accessed_paths: dict[str, list[tuple[int, int]]],
    finding_path: str,
    finding_start: int,
    finding_end: int,
) -> list[str]:
    """Filter evidence_locations to only include files+lines actually accessed."""
    windows = [(finding_path, finding_start, finding_end)]
    return _validate_evidence_against_windows(
        evidence_locations, windows, accessed_paths,
    )


# ---------------------------------------------------------------------------
# Evaluator (Generator/Evaluator pattern)
# ---------------------------------------------------------------------------


async def _run_evaluator(
    evaluator,
    eval_message: str,
    formatter_kwargs: dict,
    stage_timeout: float,
    label: str = "",
) -> dict | None:
    """Run the evaluator agent. Returns parsed evaluation or None."""
    try:
        result = await asyncio.wait_for(
            evaluator.run(eval_message, **formatter_kwargs),
            timeout=stage_timeout,
        )
        response = result.output.strip()
        if not response:
            return None

        # Parse evaluator JSON response
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(response):
            pos = response.find("{", idx)
            if pos == -1:
                break
            try:
                obj, end = decoder.raw_decode(response, pos)
            except json.JSONDecodeError:
                idx = pos + 1
                continue
            if isinstance(obj, dict) and "accept" in obj:
                return obj
            idx = end
        return None
    except (asyncio.TimeoutError, Exception) as exc:
        log.warning("%s: evaluator failed: %s", label, exc)
        return None


# ---------------------------------------------------------------------------
# Single-verdict parsing
# ---------------------------------------------------------------------------


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

    # Scan for embedded JSON objects
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

    # Last resort: fix unquoted strings
    fixed = _fix_unquoted_strings(text)
    if fixed != text:
        try:
            return Verdict.model_validate(json.loads(fixed))
        except Exception:
            pass
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


# ---------------------------------------------------------------------------
# Group verdict parsing
# ---------------------------------------------------------------------------


def _parse_group_verdicts(text: str, expected_keys: list[str]) -> dict[str, Verdict]:
    """Parse keyed verdicts from group analysis response.

    Expected format: {"verdicts": {"0": {...}, "1": {...}}}
    Missing keys get 'uncertain'. Extra keys are ignored + logged.
    """
    text = text.strip()
    if not text:
        return {k: _uncertain("Empty group response") for k in expected_keys}

    expected_set = set(expected_keys)

    # Try to find a JSON object with "verdicts" key
    def _try_parse_keyed(raw: str) -> dict[str, Verdict] | None:
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(raw):
            pos = raw.find("{", idx)
            if pos == -1:
                break
            try:
                obj, end = decoder.raw_decode(raw, pos)
            except json.JSONDecodeError:
                idx = pos + 1
                continue
            if isinstance(obj, dict) and "verdicts" in obj and isinstance(obj["verdicts"], dict):
                result: dict[str, Verdict] = {}
                for k, v in obj["verdicts"].items():
                    if k in expected_set:
                        try:
                            result[k] = Verdict.model_validate(v)
                        except Exception as exc:
                            log.warning("Group verdict key '%s' invalid: %s", k, exc)
                    else:
                        log.warning("Group verdict unexpected key '%s' — ignoring", k)
                return result
            idx = end
        return None

    result = _try_parse_keyed(text)

    # Retry with unquoted string fix
    if result is None:
        fixed = _fix_unquoted_strings(text)
        if fixed != text:
            result = _try_parse_keyed(fixed)

    # Fallback: scan for individual verdict objects and assign by order
    if result is None:
        log.warning("Group verdicts: no keyed format found, scanning for individual verdicts")
        result = {}
        decoder = json.JSONDecoder()
        idx = 0
        key_iter = iter(expected_keys)
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
                key = next(key_iter, None)
                if key is not None:
                    try:
                        result[key] = Verdict.model_validate(obj)
                    except Exception:
                        pass
            idx = end

    if result is None:
        result = {}

    # Fill missing keys with uncertain
    for k in expected_keys:
        if k not in result:
            log.warning("Group verdict missing key '%s' — defaulting to uncertain", k)
            result[k] = _uncertain("Verdict not returned by model for this finding")

    return result


# ---------------------------------------------------------------------------
# Single-finding analysis (refactored to use shared primitives)
# ---------------------------------------------------------------------------


async def _generate_verdict(
    analyzer, formatter, bundle, codebase, index,
    stage_timeout, grep_max_file_size, grep_max_bytes,
    request_limit, thinking_settings,
    retry_hint: str | None = None,
) -> Verdict | None:
    """Single generation pass: analyzer → formatter → parse. Returns Verdict or None."""
    label = f"Finding {index}"
    deps = _build_deps(codebase, bundle.finding.path, grep_max_file_size, grep_max_bytes)
    run_kwargs, formatter_kwargs = _build_run_kwargs(
        deps, request_limit, thinking_settings,
        label=f"{label} [{bundle.finding.severity}]",
    )

    # Build message, optionally with evaluator feedback
    user_message = build_user_message(bundle)
    if retry_hint:
        user_message += f"\n\n## Previous Attempt Feedback\n{retry_hint}"

    # Stage 1: Analyzer
    analysis = await _run_analyzer_stage(
        analyzer, user_message, run_kwargs, stage_timeout, label,
    )
    if analysis is None:
        return None, None, {}

    accessed_paths = deps.accessed_paths

    # Stage 2: Formatter
    format_message = build_formatter_message(analysis, bundle)
    response, format_result = await _run_formatter_stage(
        formatter, format_message, formatter_kwargs, stage_timeout,
    )

    # Parse with repair
    verdict = await _parse_with_repair(
        formatter, response, analysis, formatter_kwargs,
        format_result, stage_timeout, label,
    )

    if verdict is None:
        return None, None, accessed_paths

    # Validate evidence
    if bundle.evidence:
        ev = bundle.evidence[0]
        finding_start, finding_end = ev.start_line, ev.end_line
    else:
        finding_start, finding_end = bundle.finding.line, bundle.finding.end_line
    verdict.evidence_locations = _validate_evidence(
        verdict.evidence_locations, accessed_paths,
        bundle.finding.path, finding_start, finding_end,
    )
    return verdict, formatter_kwargs, accessed_paths


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
    evaluator=None,
    max_attempts: int = 2,
) -> Verdict:
    label = f"Finding {index}"

    retry_hint = None
    for attempt in range(max_attempts):
        result = await _generate_verdict(
            analyzer, formatter, bundle, codebase, index,
            stage_timeout, grep_max_file_size, grep_max_bytes,
            request_limit, thinking_settings,
            retry_hint=retry_hint,
        )

        if result is None or result[0] is None:
            if attempt == 0:
                log.error("%s: generation failed (attempt %d)", label, attempt + 1)
                return _uncertain("Analyzer produced no output or failed.")
            break

        verdict, formatter_kwargs, accessed_paths = result

        # Skip evaluator on last attempt or if no evaluator
        if evaluator is None or attempt == max_attempts - 1:
            return verdict

        # Stage 3: Evaluator reviews the verdict
        eval_message = build_evaluator_message(bundle, verdict)
        evaluation = await _run_evaluator(
            evaluator, eval_message, formatter_kwargs, stage_timeout, label,
        )

        if evaluation is None or evaluation.get("accept", True):
            # Evaluator accepts or couldn't run — use this verdict
            if evaluation and evaluation.get("accept"):
                log.info("%s: evaluator accepted (attempt %d)", label, attempt + 1)
            return verdict

        # Evaluator rejected — retry with feedback
        issues = evaluation.get("issues", [])
        suggestion = evaluation.get("suggestion", "")
        feedback_parts = []
        if issues:
            feedback_parts.append("Issues found: " + "; ".join(issues))
        if suggestion:
            feedback_parts.append(f"Suggestion: {suggestion}")
        retry_hint = " ".join(feedback_parts)
        log.info("%s: evaluator rejected (attempt %d): %s", label, attempt + 1, retry_hint[:100])

    # Should not reach here, but safety net
    return verdict if verdict else _uncertain("All attempts failed.")


# ---------------------------------------------------------------------------
# Group analysis
# ---------------------------------------------------------------------------


def _evidence_windows(group: FindingGroup) -> list[tuple[str, int, int]]:
    """Extract (path, start, end) tuples from a group's shared evidence."""
    return [(ev.path, ev.start_line, ev.end_line) for ev in group.shared_evidence]


async def _analyze_one_group(
    analyzer,
    formatter,
    group: FindingGroup,
    codebase: Path,
    group_index: int,
    stage_timeout: float = 120,
    grep_max_file_size: int = MAX_GREP_FILE_SIZE_DEFAULT,
    grep_max_bytes: int = MAX_GREP_BYTES_DEFAULT,
    request_limit: int = 200,
    thinking_settings: dict | None = None,
    evaluator=None,
    max_attempts: int = 2,
) -> dict[int, Verdict]:
    """Analyze a group of co-located findings together.

    Returns dict[original_finding_index, Verdict].
    """
    n = len(group.bundles)
    label = f"Group {group_index} ({group.group_key}, {n} findings)"

    # For solo groups, delegate to single-finding path
    if n == 1:
        verdict = await _analyze_one(
            analyzer, formatter, group.bundles[0], codebase,
            group.original_indices[0],
            stage_timeout=stage_timeout,
            grep_max_file_size=grep_max_file_size,
            grep_max_bytes=grep_max_bytes,
            request_limit=request_limit,
            thinking_settings=thinking_settings,
            evaluator=evaluator,
            max_attempts=max_attempts,
        )
        return {group.original_indices[0]: verdict}

    # Use first finding for anchor_root (all in same file for Phase 1)
    deps = _build_deps(codebase, group.bundles[0].finding.path, grep_max_file_size, grep_max_bytes)

    # Use highest severity for thinking settings
    run_kwargs, formatter_kwargs = _build_run_kwargs(
        deps, request_limit, thinking_settings, label=label,
    )

    # Scale timeout for group size
    group_timeout = stage_timeout + 60 * (n - 1)

    # Stage 1: Analyzer with group message
    message = build_group_message(group)
    analysis = await _run_analyzer_stage(
        analyzer, message, run_kwargs, group_timeout, label,
    )
    if analysis is None:
        return {idx: _uncertain("Group analyzer failed.") for idx in group.original_indices}

    accessed_paths = deps.accessed_paths

    # Stage 2: Formatter
    from ..prompts import build_group_formatter_message
    format_message = build_group_formatter_message(analysis, group)
    response, format_result = await _run_formatter_stage(
        formatter, format_message, formatter_kwargs, group_timeout,
    )

    # Parse keyed verdicts
    expected_keys = [str(i) for i in range(n)]
    verdicts_by_key: dict[str, Verdict] | None = None

    if response.strip():
        try:
            verdicts_by_key = _parse_group_verdicts(response, expected_keys)
        except Exception as exc:
            log.warning("%s: group parse failed: %s", label, exc)

            # Repair with group-specific hint
            repair_hint = (
                '{"verdicts": {"0": {"verdict": "...", "is_security_vulnerability": true, '
                '"confidence": "...", "reason": "...", "evidence_locations": [...]}, '
                '"1": {...}}}'
            )
            repair_message = (
                f"Your response could not be parsed: {exc}\n\n"
                f"Return ONLY a valid JSON object with this structure:\n"
                f"{repair_hint}\n"
                f"You must include keys 0 through {n - 1}.\n"
                "No markdown fences, no prose."
            )
            if format_result is not None:
                repair_response, _ = await _run_formatter_stage(
                    formatter, repair_message, formatter_kwargs,
                    group_timeout, message_history=format_result.all_messages(),
                )
                if repair_response.strip():
                    try:
                        verdicts_by_key = _parse_group_verdicts(repair_response, expected_keys)
                    except Exception as repair_exc:
                        log.warning("%s: group repair failed: %s", label, repair_exc)

    # Fallback: try parsing individual verdicts from analyzer output
    if verdicts_by_key is None and analysis:
        try:
            verdicts_by_key = _parse_group_verdicts(analysis, expected_keys)
        except Exception:
            pass

    if verdicts_by_key is None:
        log.error("%s: all group parse attempts failed", label)
        return {idx: _uncertain("Could not extract verdicts from group output.") for idx in group.original_indices}

    # Map key→original_index and validate evidence per finding
    windows = _evidence_windows(group)
    result: dict[int, Verdict] = {}
    for i, orig_idx in enumerate(group.original_indices):
        key = str(i)
        verdict = verdicts_by_key.get(key, _uncertain("Missing verdict"))
        verdict.evidence_locations = _validate_evidence_against_windows(
            verdict.evidence_locations, windows, accessed_paths,
        )
        result[orig_idx] = verdict

    # Stage 3: Group evaluator (checks cross-finding consistency)
    if evaluator is not None:
        eval_message = build_group_evaluator_message(group, verdicts_by_key)
        evaluation = await _run_evaluator(
            evaluator, eval_message, formatter_kwargs, group_timeout, label,
        )

        if evaluation and not evaluation.get("accept", True):
            issues = evaluation.get("issues", [])
            suggestion = evaluation.get("suggestion", "")
            log.info("%s: group evaluator rejected: %s", label, "; ".join(issues)[:100])

            # TODO: full group retry is expensive — for now, log the rejection
            # and return the verdicts as-is. Future: re-run with evaluator feedback.

    return result


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _save_checkpoint_sync(output_path: Path | None, checkpoint: dict[int, Verdict]) -> None:
    """Save checkpoint to disk (called from async context)."""
    if output_path is None:
        return
    from ..pipeline import _save_checkpoint
    _save_checkpoint(output_path, checkpoint)


async def analyze_all(
    bundles: list[EvidenceBundle],
    codebase: Path,
    concurrency: int = DEFAULT_CONCURRENCY,
    checkpoint: dict[int, Verdict] | None = None,
    output_path: Path | None = None,
) -> list[Verdict]:
    """Analyze findings individually (legacy path, used with --no-grouping)."""
    cfg = get_config()
    stage_timeout = cfg.stage_timeout
    finding_timeout = cfg.finding_timeout
    grep_max_file_size = cfg.grep_max_file_kb * 1024
    grep_max_bytes = cfg.grep_max_scan_mb * 1024 * 1024
    request_limit = cfg.request_limit

    if checkpoint is None:
        checkpoint = {}

    analyzer = build_analyzer()
    formatter = build_verdict_formatter()
    evaluator = build_evaluator()

    semaphore = asyncio.Semaphore(concurrency)
    completed = 0

    async def _bounded(index: int, bundle: EvidenceBundle) -> Verdict:
        nonlocal completed
        async with semaphore:
            thinking = cfg.get_thinking_settings(bundle.finding.severity)
            try:
                verdict = await asyncio.wait_for(
                    _analyze_one(
                        analyzer, formatter,
                        bundle, codebase, index,
                        stage_timeout=stage_timeout,
                        grep_max_file_size=grep_max_file_size,
                        grep_max_bytes=grep_max_bytes,
                        request_limit=request_limit,
                        thinking_settings=thinking,
                        evaluator=evaluator,
                    ),
                    timeout=finding_timeout,
                )
            except asyncio.TimeoutError:
                log.error("Finding %d timed out after %ds", index, finding_timeout)
                verdict = _uncertain(f"Analysis timed out after {finding_timeout}s.")
            except Exception as exc:
                log.error("Finding %d failed: %s", index, exc)
                verdict = _uncertain(f"Analysis error: {type(exc).__name__}")

            # Save incrementally
            checkpoint[index] = verdict
            completed += 1
            if completed % 5 == 0:
                _save_checkpoint_sync(output_path, checkpoint)
                log.info("Checkpoint saved: %d findings complete", len(checkpoint))
            return verdict

    tasks = [_bounded(i, b) for i, b in enumerate(bundles)]
    results = await asyncio.gather(*tasks)

    # Final checkpoint save
    _save_checkpoint_sync(output_path, checkpoint)

    return results


async def analyze_all_grouped(
    groups: list[FindingGroup],
    codebase: Path,
    concurrency: int = DEFAULT_CONCURRENCY,
    checkpoint: dict[int, Verdict] | None = None,
    output_path: Path | None = None,
) -> dict[int, Verdict]:
    """Analyze finding groups, return verdicts keyed by original finding index."""
    cfg = get_config()
    stage_timeout = cfg.stage_timeout
    finding_timeout = cfg.finding_timeout
    grep_max_file_size = cfg.grep_max_file_kb * 1024
    grep_max_bytes = cfg.grep_max_scan_mb * 1024 * 1024
    request_limit = cfg.request_limit

    if checkpoint is None:
        checkpoint = {}

    # Solo groups use single-finding agents, multi-finding groups use group agents
    single_analyzer = build_analyzer()
    single_formatter = build_verdict_formatter()
    single_evaluator = build_evaluator()
    group_analyzer = build_group_analyzer()
    group_formatter = build_group_verdict_formatter()
    group_eval = build_group_evaluator()

    semaphore = asyncio.Semaphore(concurrency)
    groups_done = 0

    async def _bounded(gi: int, group: FindingGroup) -> dict[int, Verdict]:
        nonlocal groups_done
        async with semaphore:
            # Thinking: use highest severity in group
            severities = [b.finding.severity for b in group.bundles]
            sev_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
            highest = min(severities, key=lambda s: sev_order.get(s, 99))
            thinking = cfg.get_thinking_settings(highest)

            # Pick agents based on group size
            if len(group.bundles) == 1:
                az, fm, ev = single_analyzer, single_formatter, single_evaluator
            else:
                az, fm, ev = group_analyzer, group_formatter, group_eval

            # Timeout scales with group size
            group_finding_timeout = finding_timeout + 60 * (len(group.bundles) - 1)

            try:
                result = await asyncio.wait_for(
                    _analyze_one_group(
                        az, fm, group, codebase, gi,
                        stage_timeout=stage_timeout,
                        grep_max_file_size=grep_max_file_size,
                        grep_max_bytes=grep_max_bytes,
                        request_limit=request_limit,
                        thinking_settings=thinking,
                        evaluator=ev,
                    ),
                    timeout=group_finding_timeout,
                )
            except asyncio.TimeoutError:
                log.error("Group %d timed out after %ds", gi, group_finding_timeout)
                result = {idx: _uncertain(f"Group timed out after {group_finding_timeout}s.")
                          for idx in group.original_indices}
            except Exception as exc:
                log.error("Group %d failed: %s", gi, exc)
                result = {idx: _uncertain(f"Group error: {type(exc).__name__}")
                          for idx in group.original_indices}

            # Save incrementally
            checkpoint.update(result)
            groups_done += 1
            if groups_done % 5 == 0:
                _save_checkpoint_sync(output_path, checkpoint)
                log.info("Checkpoint saved: %d findings complete (%d groups)", len(checkpoint), groups_done)
            return result

    tasks = [_bounded(gi, g) for gi, g in enumerate(groups)]
    results = await asyncio.gather(*tasks)

    # Final checkpoint save
    _save_checkpoint_sync(output_path, checkpoint)

    # Merge all group results into a single dict
    merged: dict[int, Verdict] = {}
    for group_result in results:
        merged.update(group_result)
    return merged
