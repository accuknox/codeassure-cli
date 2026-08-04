from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path

import anthropic
from pydantic_ai.usage import UsageLimits

from ..config import get_config
from ..grouping import FindingGroup
from ..prompts import (
    build_evaluator_message,
    build_formatter_message,
    build_group_evaluator_message,
    build_group_formatter_message,
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
from .validator import build_validator

log = logging.getLogger(__name__)

DEFAULT_CONCURRENCY = 7
MAX_GREP_FILE_SIZE_DEFAULT = 512 * 1024
MAX_GREP_BYTES_DEFAULT = 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# Shared primitives (used by both single-finding and group paths)
# ---------------------------------------------------------------------------


# check_id substrings that are categorically NOT security vulnerabilities,
# regardless of what the analyzer says. Match is case-insensitive substring.
# Override only fires for true_positive verdicts; FP/uncertain are unchanged.
_NON_SECURITY_RULE_SUBSTRINGS = (
    "unquoted-variable-expansion",
    "unquoted-command-substitution",
    "useless-cat",
    "useless-if-body",
    "set-pipefail",
    "missing-apk-no-cache",
    "missing-image-version",
    "multiple-entrypoint",
    "dockerfile-source-not-pinned",
)


def _apply_security_overrides(verdict: Verdict, finding_check_id: str) -> None:
    """Force is_security_vulnerability=False for known-correctness rule families.

    Only applies on true_positive verdicts where is_security_vulnerability is
    currently True. Reason text gets a short prefix so downstream consumers
    know the override fired.
    """
    if verdict.verdict != "true_positive" or not verdict.is_security_vulnerability:
        return
    cid = finding_check_id.lower()
    if any(s in cid for s in _NON_SECURITY_RULE_SUBSTRINGS):
        verdict.is_security_vulnerability = False
        verdict.reason = f"[reclassified as correctness/best-practice] {verdict.reason}"

import random

import httpx
from pydantic_ai.exceptions import UnexpectedModelBehavior

# HTTP statuses worth retrying: rate limits, server errors, Anthropic overloaded (529).
_RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}

# Exception class-name fragments that indicate a transient transport/API problem
# even when no HTTP status is attached (provider SDKs wrap httpx errors).
_TRANSIENT_NAME_FRAGMENTS = (
    "ratelimit", "overloaded", "timeout", "connection", "transport",
    "serviceunavailable", "internalserver", "apiconnection",
)


def _transient_status(exc: BaseException) -> int | None:
    """Extract an HTTP status code from an exception (walking the cause chain)."""
    seen = 0
    cur: BaseException | None = exc
    while cur is not None and seen < 5:
        for attr in ("status_code", "status"):
            code = getattr(cur, attr, None)
            if isinstance(code, int):
                return code
        resp = getattr(cur, "response", None)
        code = getattr(resp, "status_code", None)
        if isinstance(code, int):
            return code
        cur = cur.__cause__ or cur.__context__
        seen += 1
    return None


def _is_transient(exc: BaseException) -> bool:
    """True for errors where a retry has a real chance of succeeding."""
    status = _transient_status(exc)
    if status is not None:
        return status in _RETRYABLE_STATUS
    if isinstance(exc, (httpx.TimeoutException, httpx.TransportError)):
        return True
    if isinstance(exc, UnexpectedModelBehavior):
        return True  # e.g. null/empty API response, truncated output
    name = type(exc).__name__.lower()
    return any(frag in name for frag in _TRANSIENT_NAME_FRAGMENTS)


def _retry_after_seconds(exc: BaseException) -> float | None:
    """Honor a Retry-After header when the provider sent one."""
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None)
    if headers is None:
        return None
    try:
        val = headers.get("retry-after")
        return float(val) if val else None
    except (TypeError, ValueError):
        return None


def _error_detail(exc: BaseException) -> str:
    """Short human-readable error label for verdict reasons and logs."""
    status = _transient_status(exc)
    name = type(exc).__name__
    if status is not None:
        return f"{name} (HTTP {status})"
    return name


async def _run_with_retry(agent, message, *, retries: int | None = None,
                          base_delay: float = 2.0, label: str = "", **kwargs):
    """Run an agent call, retrying every transient failure (rate limits, 5xx,
    overloaded, timeouts, connection drops, malformed model output) with
    exponential backoff + jitter. Non-transient errors raise immediately."""
    if retries is None:
        try:
            retries = get_config().retries
        except RuntimeError:
            retries = 4
    attempts = retries + 1
    for attempt in range(attempts):
        try:
            return await agent.run(message, **kwargs)
        except Exception as exc:
            if attempt >= attempts - 1 or not _is_transient(exc):
                raise
            delay = _retry_after_seconds(exc)
            if delay is None:
                delay = min(base_delay * (2 ** attempt), 45.0) * random.uniform(0.6, 1.4)
            log.warning(
                "%s: transient LLM error (attempt %d/%d), retrying in %.1fs: %s",
                label or "agent", attempt + 1, attempts, delay, _error_detail(exc),
            )
            await asyncio.sleep(delay)


def _fix_unquoted_strings(text: str) -> str:
    """Fix JSON with unquoted string values — common with some models.

    Targets the "reason" field specifically, which nemotron often leaves unquoted.
    Uses a greedy match anchored to the last valid JSON delimiter to handle
    reason text that contains } or , characters.
    """
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
    from ..config import get_config
    limits = UsageLimits(request_limit=request_limit)
    run_kwargs: dict = {"deps": deps, "usage_limits": limits}

    try:
        max_tokens = get_config().max_tokens
    except RuntimeError:
        max_tokens = 4096
    model_settings: dict = {}
    if max_tokens is not None:
        model_settings["max_tokens"] = max_tokens
    if thinking_settings:
        model_settings.update(thinking_settings)
        if "extra_body" in thinking_settings:
            mode = "full" if not thinking_settings["extra_body"]["chat_template_kwargs"].get("low_effort") else "low"
            if not thinking_settings["extra_body"]["chat_template_kwargs"]["enable_thinking"]:
                mode = "off"
            if label:
                log.info("%s → thinking=%s", label, mode)

    run_kwargs["model_settings"] = model_settings
    formatter_kwargs: dict = {"model_settings": model_settings}
    return run_kwargs, formatter_kwargs


def _uncertain(reason: str) -> Verdict:
    """Create an uncertain verdict with the given reason."""
    return Verdict(verdict="uncertain", confidence="low", reason=reason)


def _deterministic_fallback(bundle: EvidenceBundle, error: str | None) -> Verdict:
    """Decisive verdict from deterministic signals when the LLM is unavailable.

    An 'uncertain' wall is useless output — the scanner already made a textual
    pattern match, and the context graph (when present) is deterministic
    reachability/taint evidence. Combine the two with the rule-kind gate:

      * taint-class rule + graph shows a tainted reachable path → true_positive
        (the flagged flow demonstrably exists);
      * taint-class rule + non-degraded graph with NO tainted path → false_positive
        (the constitutive source→sink flow was searched for and is absent);
      * pattern-existence rule → true_positive (the scanner's textual match IS the
        pattern; only mitigation/suppression could overturn it, which needs the LLM) —
        is_security_vulnerability from the rule kind;
      * taint-class rule with no usable graph → uncertain (genuinely undecidable
        without reading code).

    Confidence is always low and the reason names the real LLM error, so these
    are auditable and re-runnable (checkpoint resume will not overwrite them,
    but a fresh run with a healthy provider will).
    """
    from ..prompts.rule_policies import is_taint_class, rule_kind_of

    f = bundle.finding
    err = f"LLM analysis unavailable ({error or 'unknown error'})"
    cg = getattr(f, "context_graph", None)
    cg = cg if isinstance(cg, dict) else None
    paths = (cg.get("paths") or []) if cg else []
    degraded = bool(((cg.get("stats") or {}).get("degraded")) if cg else True)
    tainted_reachable = any(
        p.get("tainted") and p.get("reachability") == "reachable" for p in paths
    )
    sink = (cg.get("sink") or {}) if cg else {}
    sink_ev = [f"{sink['file']}:{sink['line']}"] if sink.get("file") and sink.get("line") is not None else []

    if is_taint_class(f.check_id, f):
        if tainted_reachable:
            return Verdict(
                verdict="true_positive", is_security_vulnerability=True,
                severity="medium", confidence="low",
                reason=f"{err}; deterministic context graph shows a tainted, reachable "
                "source→sink path for this data-flow rule, so the flagged flow exists. "
                "Re-run for a full LLM review of mitigations.",
                evidence_locations=sink_ev, taint_flow_verified=True,
            )
        if paths and not degraded:
            return Verdict(
                verdict="false_positive", is_security_vulnerability=False,
                severity="low", confidence="low",
                reason=f"{err}; non-degraded deterministic context graph found no tainted "
                "source→sink path, and a real flow is constitutive of this data-flow rule.",
                evidence_locations=sink_ev, taint_flow_verified=False,
            )
        return _uncertain(
            f"{err}; data-flow rule with no usable context graph — cannot decide without code analysis."
        )

    kind = rule_kind_of(f.check_id, f)
    is_sec = kind in ("security_audit", "security_config")
    return Verdict(
        verdict="true_positive", is_security_vulnerability=is_sec,
        severity="medium" if is_sec else "low", confidence="low",
        reason=f"{err}; pattern-existence rule ({kind}): the scanner's textual match is "
        "the pattern itself, so the finding stands as a detection. Re-run for LLM review "
        "of mitigations/suppressions and exploitability.",
        evidence_locations=sink_ev or [f"{f.path}:{f.line}"],
    )


async def _run_analyzer_stage(
    analyzer,
    message: str,
    run_kwargs: dict,
    stage_timeout: float,
    label: str = "",
) -> str | None:
    """Run analyzer agent. Returns analysis text or None on failure.

    Legacy helper — kept for tests and the unstructured path. The hot path
    uses _run_analyzer_structured() which returns a Verdict directly.
    """
    try:
        result = await asyncio.wait_for(
            _run_with_retry(analyzer, message, label=label, **run_kwargs),
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


async def _run_analyzer_structured(
    analyzer,
    message: str,
    run_kwargs: dict,
    stage_timeout: float,
    label: str = "",
) -> tuple[object | None, str | None]:
    """Run an analyzer agent whose output_type is a structured pydantic model.

    Retries transient provider errors internally. Returns (output, error_detail):
    output is the parsed Verdict/GroupVerdicts or None; error_detail names the
    final failure so callers can surface the REAL cause instead of a generic
    'analyzer failed' string.
    """
    try:
        result = await asyncio.wait_for(
            _run_with_retry(analyzer, message, label=label, **run_kwargs),
            timeout=stage_timeout,
        )
        return result.output, None
    except asyncio.TimeoutError:
        log.warning("%s: analyzer timed out after %ds", label, stage_timeout)
        return None, f"timed out after {stage_timeout:.0f}s"
    except Exception as exc:
        log.error("%s: analyzer failed: %s", label, exc)
        return None, _error_detail(exc)


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
            _run_with_retry(formatter, message, label="formatter", **kwargs),
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


def _graph_files(finding) -> set[str]:
    """Files named by the deterministic context graph — legitimate trace citations
    even without a tool read, since their code is embedded in the prompt."""
    cg = getattr(finding, "context_graph", None)
    if not isinstance(cg, dict):
        return set()
    files = {n.get("file") for n in cg.get("nodes", []) if n.get("file")}
    sink = cg.get("sink") or {}
    if sink.get("file"):
        files.add(sink["file"])
    return files


def _filter_execution_trace(
    trace: list[str],
    accessed_paths: dict[str, list[tuple[int, int]]],
    finding,
) -> list[str]:
    """Drop trace steps that cite files the model never saw (hallucination guard).

    A step is kept when its 'file:line' prefix names the flagged file, a file the
    model read/grepped, or a context-graph node file (whose code was in the prompt).
    Loose on line numbers by design — the trace is narrative, evidence_locations
    stays the strictly-validated field.
    """
    if not trace:
        return []
    allowed = set(accessed_paths) | _graph_files(finding) | {finding.path}
    kept = []
    for step in trace:
        head = step.split("—")[0].split(" - ")[0].strip()
        file_part = head.rsplit(":", 1)[0].strip() if ":" in head else head
        if not file_part or file_part in allowed:
            kept.append(step)
        else:
            log.debug("execution_trace step dropped (file never seen): %s", step[:120])
    return kept


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
            _run_with_retry(evaluator, eval_message, label=label or "evaluator", **formatter_kwargs),
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
    analyzer, bundle, codebase, index,
    stage_timeout, grep_max_file_size, grep_max_bytes,
    request_limit, thinking_settings,
    retry_hint: str | None = None,
):
    """Single generation pass: analyzer returns structured Verdict directly.

    Returns (verdict, evaluator_kwargs, accessed_paths). Any of the first two
    may be None if generation failed.
    """
    label = f"Finding {index}"
    deps = _build_deps(codebase, bundle.finding.path, grep_max_file_size, grep_max_bytes)
    run_kwargs, evaluator_kwargs = _build_run_kwargs(
        deps, request_limit, thinking_settings,
        label=f"{label} [{bundle.finding.severity}]",
    )

    # Build message, optionally with evaluator feedback
    user_message = build_user_message(bundle)
    if retry_hint:
        user_message += f"\n\n## Previous Attempt Feedback\n{retry_hint}"

    # Single stage: structured analyzer returns Verdict directly
    verdict, error = await _run_analyzer_structured(
        analyzer, user_message, run_kwargs, stage_timeout, label,
    )
    accessed_paths = deps.accessed_paths

    if verdict is None:
        return None, error, accessed_paths

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
    verdict.execution_trace = _filter_execution_trace(
        verdict.execution_trace, accessed_paths, bundle.finding,
    )
    return verdict, evaluator_kwargs, accessed_paths


def _validate_group_evidence(
    group: FindingGroup,
    verdicts: dict[str, Verdict],
    accessed_paths: dict[str, list[tuple[int, int]]],
) -> dict[str, Verdict]:
    """Validate evidence_locations for each verdict against what the model was shown.

    Citations checked against shared_evidence (prompt code) + accessed_paths (tool reads).
    """
    # Build valid ranges from shared_evidence
    shared_ranges: dict[str, list[tuple[int, int]]] = {}
    for ev in group.shared_evidence:
        shared_ranges.setdefault(ev.path, []).append((ev.start_line, ev.end_line))

    # Merge with tool-accessed ranges
    all_valid: dict[str, list[tuple[int, int]]] = {}
    for path, ranges in shared_ranges.items():
        all_valid.setdefault(path, []).extend(ranges)
    for path, ranges in accessed_paths.items():
        all_valid.setdefault(path, []).extend(ranges)

    validated: dict[str, Verdict] = {}
    for key, verdict in verdicts.items():
        good_locs = []
        for loc in verdict.evidence_locations:
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

            if file_part not in all_valid:
                continue
            ranges = all_valid[file_part]
            if cited_line is None or any(s <= cited_line <= e for s, e in ranges):
                good_locs.append(loc)

        verdict.evidence_locations = good_locs
        validated[key] = verdict

    return validated


# ---------------------------------------------------------------------------
# Majority voting
# ---------------------------------------------------------------------------

_CONFIDENCE_WEIGHT = {"high": 3, "medium": 2, "low": 1}


# Tie-break priority when votes AND confidence weight are equal. Prefer flagging
# (true_positive) over uncertain over false_positive so a genuine vuln is never
# silently dropped on a coin-flip tie. Fully deterministic — no reliance on the
# (parallel, completion-ordered) input list order.
_VERDICT_TIE_PRIORITY = {"true_positive": 2, "uncertain": 1, "false_positive": 0}


def _majority_verdict(verdicts: list[Verdict]) -> Verdict:
    """Pick verdict with the most votes; break ties deterministically by total
    confidence weight, then by a fixed verdict priority (never by input order)."""
    from collections import Counter
    counts: Counter = Counter(v.verdict for v in verdicts)
    max_votes = max(counts.values())
    candidates = [label for label, n in counts.items() if n == max_votes]

    if len(candidates) == 1:
        winner = candidates[0]
    else:
        weights: dict[str, int] = {}
        for v in verdicts:
            weights[v.verdict] = weights.get(v.verdict, 0) + _CONFIDENCE_WEIGHT.get(v.confidence, 1)
        # weight primary, fixed verdict priority secondary → deterministic winner.
        winner = max(candidates,
                     key=lambda lbl: (weights.get(lbl, 0), _VERDICT_TIE_PRIORITY.get(lbl, 0)))

    winners = [v for v in verdicts if v.verdict == winner]
    # confidence primary, reason text secondary → the SELECTED verdict object (and
    # thus its reason/severity) is reproducible even when confidences tie.
    best = max(winners, key=lambda v: (_CONFIDENCE_WEIGHT.get(v.confidence, 0), v.reason or ""))
    best.voting_tally = dict(counts)
    return best


_SEVERITY_ORDER = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3,
    "LOW": 2, "WARNING": 1, "INFO": 0,
    "INFORMATIONAL": 0, "UNKNOWN": 0, "NOT_AVAILABLE": 0,
}


def _severity_rank(s: str) -> int:
    return _SEVERITY_ORDER.get(s.upper(), 0)


# ---------------------------------------------------------------------------
# Single-finding analysis
# ---------------------------------------------------------------------------

async def _analyze_one_round(
    analyzer,
    bundle: EvidenceBundle,
    codebase: Path,
    index: int,
    stage_timeout: float = 500,
    grep_max_file_size: int = MAX_GREP_FILE_SIZE_DEFAULT,
    grep_max_bytes: int = MAX_GREP_BYTES_DEFAULT,
    request_limit: int = 200,
    thinking_settings: dict | None = None,
    formatter=None,
) -> Verdict:
    """Single analysis pass for one finding. Returns a Verdict (possibly uncertain on failure)."""
    finding_dir = Path(bundle.finding.path).parent
    anchor_root_str = str(finding_dir) if str(finding_dir) != "." else ""
    deps = _build_deps(codebase, bundle.finding.path, grep_max_file_size, grep_max_bytes)

    limits = UsageLimits(request_limit=request_limit)
    run_kwargs: dict = {"deps": deps, "usage_limits": limits}
    if thinking_settings:
        run_kwargs["model_settings"] = thinking_settings

    try:
        result = await asyncio.wait_for(
            _run_with_retry(analyzer, build_user_message(bundle),
                            label=f"Finding {index}", **run_kwargs),
            timeout=stage_timeout,
        )
        analysis = result.output
    except asyncio.TimeoutError:
        log.warning("Analyzer timed out for finding %d", index)
        return _deterministic_fallback(bundle, f"timed out after {stage_timeout:.0f}s")
    except Exception as exc:
        log.error("Analyzer failed for finding %d: %s", index, exc)
        return _deterministic_fallback(bundle, _error_detail(exc))

    accessed_paths = deps.accessed_paths

    # Structured analyzers (PromptedOutput) hand back a Verdict directly; the
    # legacy text path still parses (with formatter repair) for raw-string agents.
    if isinstance(analysis, Verdict):
        verdict = analysis
    else:
        if not analysis.strip():
            log.warning("Empty analysis for finding %d", index)
            return _deterministic_fallback(bundle, "empty model output")

        verdict = None
        try:
            verdict = _parse_verdict(analysis)
        except Exception as exc:
            log.warning("Direct parse failed for finding %d: %s — trying formatter fallback", index, exc)
            if formatter is not None:
                try:
                    fmt_result = await asyncio.wait_for(
                        _run_with_retry(formatter, build_formatter_message(analysis, bundle),
                                        label=f"Finding {index} formatter"),
                        timeout=stage_timeout,
                    )
                    verdict = _parse_verdict(fmt_result.output)
                except Exception as fmt_exc:
                    log.error("Formatter fallback also failed for finding %d: %s", index, fmt_exc)

        if verdict is None:
            return _deterministic_fallback(bundle, "unparseable model output")

    if bundle.evidence:
        ev = bundle.evidence[0]
        finding_start, finding_end = ev.start_line, ev.end_line
    else:
        finding_start, finding_end = bundle.finding.line, bundle.finding.end_line
    verdict.evidence_locations = _validate_evidence(
        verdict.evidence_locations, accessed_paths, bundle.finding.path,
        finding_start, finding_end,
    )
    verdict.execution_trace = _filter_execution_trace(
        verdict.execution_trace, accessed_paths, bundle.finding,
    )
    return verdict


async def _analyze_one_evaluator(
    analyzer,
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
    """Evaluator-pattern analysis for one finding. Returns a Verdict."""
    label = f"Finding {index}"

    retry_hint = None
    verdict = None
    last_error: str | None = None
    for attempt in range(max_attempts):
        result = await _generate_verdict(
            analyzer, bundle, codebase, index,
            stage_timeout, grep_max_file_size, grep_max_bytes,
            request_limit, thinking_settings,
            retry_hint=retry_hint,
        )

        if result is None or result[0] is None:
            last_error = result[1] if result else None
            log.error("%s: generation failed (attempt %d/%d): %s",
                      label, attempt + 1, max_attempts, last_error)
            continue  # transient retries already happened inside; try a fresh attempt

        verdict, evaluator_kwargs, accessed_paths = result

        # Skip evaluator if none provided
        if evaluator is None:
            return verdict

        # Stage 2: Evaluator reviews the verdict (always runs, including last attempt — needed for severity)
        eval_message = build_evaluator_message(bundle, verdict)
        evaluation = await _run_evaluator(
            evaluator, eval_message, evaluator_kwargs, stage_timeout, label,
        )

        # Apply severity from evaluator (always, even on reject)
        if evaluation and "severity" in evaluation:
            sev = evaluation["severity"]
            if sev in ("critical", "high", "medium", "low"):
                verdict.severity = sev

        if evaluation is None or evaluation.get("accept", True) or attempt == max_attempts - 1:
            if evaluation and evaluation.get("accept"):
                log.info("%s: evaluator accepted (attempt %d), severity=%s", label, attempt + 1, verdict.severity)
            return verdict

        # Evaluator rejected — retry with feedback (not on last attempt)
        issues = evaluation.get("issues", [])
        suggestion = evaluation.get("suggestion", "")
        feedback_parts = []
        if issues:
            feedback_parts.append("Issues found: " + "; ".join(issues))
        if suggestion:
            feedback_parts.append(f"Suggestion: {suggestion}")
        retry_hint = " ".join(feedback_parts)
        log.info("%s: evaluator rejected (attempt %d): %s", label, attempt + 1, retry_hint[:100])

    # Safety net: never leave a generic 'uncertain' — fall back to deterministic signals.
    return verdict if verdict else _deterministic_fallback(bundle, last_error)


async def _analyze_one_voting(
    analyzer,
    bundle: EvidenceBundle,
    codebase: Path,
    index: int,
    stage_timeout: float = 500,
    grep_max_file_size: int = MAX_GREP_FILE_SIZE_DEFAULT,
    grep_max_bytes: int = MAX_GREP_BYTES_DEFAULT,
    request_limit: int = 200,
    thinking_settings: dict | None = None,
    formatter=None,
    voting_rounds: int = 3,
) -> Verdict:
    """Voting-based analysis: run multiple rounds and pick the majority verdict."""
    round_kwargs = dict(
        stage_timeout=stage_timeout,
        grep_max_file_size=grep_max_file_size,
        grep_max_bytes=grep_max_bytes,
        request_limit=request_limit,
        thinking_settings=thinking_settings,
        formatter=formatter,
    )
    tasks = [
        _analyze_one_round(analyzer, bundle, codebase, index, **round_kwargs)
        for _ in range(voting_rounds)
    ]
    results = await asyncio.gather(*tasks)
    verdict = _majority_verdict(list(results))
    log.info(
        "Finding %d voting (%d rounds): %s → %s",
        index, voting_rounds, verdict.voting_tally, verdict.verdict,
    )
    return verdict


async def _analyze_one(
    analyzer,
    bundle: EvidenceBundle,
    codebase: Path,
    index: int,
    stage_timeout: float = 500,
    grep_max_file_size: int = MAX_GREP_FILE_SIZE_DEFAULT,
    grep_max_bytes: int = MAX_GREP_BYTES_DEFAULT,
    request_limit: int = 200,
    thinking_settings: dict | None = None,
    formatter=None,
    evaluator=None,
    voting_rounds: int = 1,
    max_attempts: int = 2,
) -> Verdict:
    """Unified entry point for single-finding analysis.

    Dispatches to the appropriate strategy:
    - voting_rounds > 1  → _analyze_one_voting
    - evaluator provided → _analyze_one_evaluator
    - otherwise          → _analyze_one_round (single pass)
    """
    if voting_rounds > 1:
        return await _analyze_one_voting(
            analyzer, bundle, codebase, index,
            stage_timeout=stage_timeout,
            grep_max_file_size=grep_max_file_size,
            grep_max_bytes=grep_max_bytes,
            request_limit=request_limit,
            thinking_settings=thinking_settings,
            formatter=formatter,
            voting_rounds=voting_rounds,
        )
    if evaluator is not None:
        return await _analyze_one_evaluator(
            analyzer, bundle, codebase, index,
            stage_timeout=stage_timeout,
            grep_max_file_size=grep_max_file_size,
            grep_max_bytes=grep_max_bytes,
            request_limit=request_limit,
            thinking_settings=thinking_settings,
            evaluator=evaluator,
            max_attempts=max_attempts,
        )
    return await _analyze_one_round(
        analyzer, bundle, codebase, index,
        stage_timeout=stage_timeout,
        grep_max_file_size=grep_max_file_size,
        grep_max_bytes=grep_max_bytes,
        request_limit=request_limit,
        thinking_settings=thinking_settings,
        formatter=formatter,
    )


# ---------------------------------------------------------------------------
# Group analysis
# ---------------------------------------------------------------------------


def _evidence_windows(group: FindingGroup) -> list[tuple[str, int, int]]:
    """Extract (path, start, end) tuples from a group's shared evidence."""
    return [(ev.path, ev.start_line, ev.end_line) for ev in group.shared_evidence]


async def _analyze_one_group(
    analyzer,
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
            analyzer, group.bundles[0], codebase,
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
    run_kwargs, evaluator_kwargs = _build_run_kwargs(
        deps, request_limit, thinking_settings, label=label,
    )

    # Scale timeout for group size
    group_timeout = stage_timeout + 60 * (n - 1)

    # Single stage: structured group analyzer returns GroupVerdicts directly
    message = build_group_message(group)
    group_output, error = await _run_analyzer_structured(
        analyzer, message, run_kwargs, group_timeout, label,
    )
    accessed_paths = deps.accessed_paths

    if group_output is None:
        return {
            idx: _deterministic_fallback(b, error)
            for idx, b in zip(group.original_indices, group.bundles)
        }

    expected_keys = [str(i) for i in range(n)]
    verdicts_by_key: dict[str, Verdict] = dict(group_output.verdicts)

    # Fill missing keys deterministically (model dropped an entry)
    for k, b in zip(expected_keys, group.bundles):
        if k not in verdicts_by_key:
            log.warning("%s: missing verdict for key '%s' — deterministic fallback", label, k)
            verdicts_by_key[k] = _deterministic_fallback(b, "model omitted this finding from its group answer")

    # Map key→original_index and validate evidence per finding
    windows = _evidence_windows(group)
    result: dict[int, Verdict] = {}
    for i, orig_idx in enumerate(group.original_indices):
        key = str(i)
        verdict = verdicts_by_key[key]
        verdict.evidence_locations = _validate_evidence_against_windows(
            verdict.evidence_locations, windows, accessed_paths,
        )
        verdict.execution_trace = _filter_execution_trace(
            verdict.execution_trace, accessed_paths, group.bundles[i].finding,
        )
        result[orig_idx] = verdict

    # Stage 2: Group evaluator (checks cross-finding consistency + assigns severity)
    if evaluator is not None:
        eval_message = build_group_evaluator_message(group, verdicts_by_key)
        evaluation = await _run_evaluator(
            evaluator, eval_message, evaluator_kwargs, group_timeout, label,
        )

        if evaluation:
            # Apply per-finding severities
            severities = evaluation.get("severities", {})
            for i, orig_idx in enumerate(group.original_indices):
                key = str(i)
                sev = severities.get(key)
                if sev in ("critical", "high", "medium", "low") and orig_idx in result:
                    result[orig_idx].severity = sev

            if not evaluation.get("accept", True):
                issues = evaluation.get("issues", [])
                log.info("%s: group evaluator rejected: %s", label, "; ".join(issues)[:100])

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


async def _validate_verdict(validator, bundle: EvidenceBundle, verdict: Verdict) -> None:
    """Run the validator and write its judgement back onto the verdict in-place.

    Failures are swallowed (logged) — validation is best-effort and must not
    fail the analyzer's output.
    """
    finding = bundle.finding
    user_message = (
        f"Finding:\n"
        f"  check_id: {finding.check_id}\n"
        f"  path: {finding.path}:{finding.line}-{finding.end_line}\n"
        f"  severity: {finding.severity}\n"
        f"  message: {finding.message}\n"
        f"  code snippet:\n{finding.lines}\n\n"
        f"Verdict produced:\n"
        f"  verdict: {verdict.verdict}\n"
        f"  is_security_vulnerability: {verdict.is_security_vulnerability}\n"
        f"  confidence: {verdict.confidence}\n"
        f"  reason: {verdict.reason}\n"
    )
    try:
        result = await validator.run(user_message)
        v = result.output
        verdict.validator_verdict_agrees = bool(v.verdict_agrees)
        verdict.validator_vuln_agrees = bool(v.vuln_agrees)
        verdict.validator_reason = str(v.reason)
    except Exception as exc:
        log.warning("Validator failed for finding %s: %s", finding.fingerprint or "?", exc)


# ---------------------------------------------------------------------------
# Claude validation
# ---------------------------------------------------------------------------

_CLAUDE_VALIDATION_MODEL = "claude-sonnet-4-6"

_CLAUDE_VALIDATOR_SYSTEM = """\
You are a senior security engineer reviewing an automated SAST finding analysis.
Given the finding details and the verdict produced by another model, evaluate independently:
1. Is the verdict (true_positive / false_positive / uncertain) correct?
2. Is the is_security_vulnerability classification correct?
3. Provide a concise reason covering both assessments.

Respond in this exact JSON format (no markdown fences):
{"verdict_agrees": true|false, "vuln_agrees": true|false, "reason": "..."}

- "verdict_agrees": true if the verdict label is correct.
- "vuln_agrees": true if the is_security_vulnerability flag is correct.
- "reason": 1-3 sentences explaining your evaluation of both.
"""


async def _claude_validate(bundle: EvidenceBundle, verdict: Verdict) -> tuple[bool | None, bool | None, str | None]:
    """Call Claude to validate the verdict for a finding. Returns (verdict_agrees, vuln_agrees, reason)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        log.debug("ANTHROPIC_API_KEY not set — skipping Claude validation")
        return None, None, None

    finding = bundle.finding
    user_message = (
        f"Finding:\n"
        f"  check_id: {finding.check_id}\n"
        f"  path: {finding.path}:{finding.line}-{finding.end_line}\n"
        f"  severity: {finding.severity}\n"
        f"  message: {finding.message}\n"
        f"  code snippet:\n{finding.lines}\n\n"
        f"Verdict produced:\n"
        f"  verdict: {verdict.verdict}\n"
        f"  is_security_vulnerability: {verdict.is_security_vulnerability}\n"
        f"  confidence: {verdict.confidence}\n"
        f"  reason: {verdict.reason}\n"
    )

    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=_CLAUDE_VALIDATION_MODEL,
            max_tokens=512,
            system=_CLAUDE_VALIDATOR_SYSTEM,
            messages=[{"role": "user", "content": user_message}],
        )
        raw = response.content[0].text.strip()
        parsed = json.loads(raw)
        print(f"Claude validation parsed response: {parsed}")
        return bool(parsed["verdict_agrees"]), bool(parsed["vuln_agrees"]), str(parsed["reason"])
    except Exception as exc:
        log.warning("Claude validation failed: %s", exc)
        return None, None, None


# ---------------------------------------------------------------------------
# Orchestrators
# ---------------------------------------------------------------------------

def _print_run_summary(verdicts: list[Verdict]) -> None:
    """One-glance outcome: verdict mix + how many fell back to deterministic signals."""
    from collections import Counter
    if not verdicts:
        return
    counts = Counter(v.verdict for v in verdicts)
    fallbacks = sum(1 for v in verdicts if "LLM analysis unavailable" in (v.reason or ""))
    sec = sum(1 for v in verdicts if v.verdict == "true_positive" and v.is_security_vulnerability)
    print(
        f"[summary] {len(verdicts)} analyzed — "
        f"TP {counts.get('true_positive', 0)} ({sec} security) | "
        f"FP {counts.get('false_positive', 0)} | "
        f"uncertain {counts.get('uncertain', 0)} | "
        f"deterministic-fallback {fallbacks}",
        flush=True,
    )
    if fallbacks:
        print(
            f"[summary] ⚠ {fallbacks} finding(s) used the deterministic fallback because the "
            f"LLM was unavailable — re-run the same command to retry them with full analysis.",
            flush=True,
        )


async def analyze_all(
    bundles: list[EvidenceBundle],
    codebase: Path,
    concurrency: int = DEFAULT_CONCURRENCY,
    claude_verification: bool = False,
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
    voting_rounds = cfg.voting_rounds

    if checkpoint is None:
        checkpoint = {}

    analyzer = build_analyzer()
    formatter = build_verdict_formatter()
    evaluator = build_evaluator() if cfg.evaluator else None
    validator = build_validator() if (cfg.validator and cfg.validator.enabled) else None

    semaphore = asyncio.Semaphore(concurrency)
    total = len(bundles)
    completed = 0

    async def _bounded(index: int, bundle: EvidenceBundle) -> Verdict:
        nonlocal completed
        async with semaphore:
            thinking = cfg.get_thinking_settings(bundle.finding.severity)
            t0 = time.perf_counter()
            try:
                verdict = await asyncio.wait_for(
                    _analyze_one(
                        analyzer,
                        bundle, codebase, index,
                        stage_timeout=stage_timeout,
                        grep_max_file_size=grep_max_file_size,
                        grep_max_bytes=grep_max_bytes,
                        request_limit=request_limit,
                        thinking_settings=thinking,
                        formatter=formatter,
                        evaluator=evaluator,
                        voting_rounds=voting_rounds,
                    ),
                    timeout=finding_timeout * voting_rounds,
                )
            except asyncio.TimeoutError:
                log.error("Finding %d timed out after %ds", index, finding_timeout)
                verdict = _deterministic_fallback(bundle, f"finding timed out after {finding_timeout}s")
            except Exception as exc:
                log.error("Finding %d failed: %s", index, exc)
                verdict = _deterministic_fallback(bundle, _error_detail(exc))

            _apply_security_overrides(verdict, bundle.finding.check_id)

            if validator is not None:
                await _validate_verdict(validator, bundle, verdict)

            if claude_verification:
                verdict_agrees, vuln_agrees, claude_reason = await _claude_validate(bundle, verdict)
                verdict.claude_verdict_agrees = verdict_agrees
                verdict.claude_vuln_agrees = vuln_agrees
                verdict.claude_reason = claude_reason
                if verdict_agrees is not None:
                    log.info(
                        "Finding %d Claude validation — verdict_agrees=%s | vuln_agrees=%s | reason=%s",
                        index, verdict_agrees, vuln_agrees, claude_reason,
                    )

            # Save incrementally
            checkpoint[index] = verdict
            completed += 1
            elapsed = time.perf_counter() - t0
            tally_str = f" votes={verdict.voting_tally}" if verdict.voting_tally else ""
            print(
                f"[{completed}/{total}] Finding #{index} — {elapsed:.1f}s{tally_str}",
                flush=True,
            )
            if completed % 5 == 0:
                _save_checkpoint_sync(output_path, checkpoint)
                log.info("Checkpoint saved: %d findings complete", len(checkpoint))
            return verdict

    tasks = [_bounded(i, b) for i, b in enumerate(bundles)]
    results = await asyncio.gather(*tasks)

    # Final checkpoint save
    _save_checkpoint_sync(output_path, checkpoint)

    _print_run_summary(list(results))
    return results


async def analyze_all_grouped(
    groups: list[FindingGroup],
    codebase: Path,
    concurrency: int = DEFAULT_CONCURRENCY,
    claude_verification: bool = False,
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
    voting_rounds = cfg.voting_rounds

    if checkpoint is None:
        checkpoint = {}

    # Solo groups use single-finding agents, multi-finding groups use group agents
    solo_analyzer = build_analyzer()
    solo_formatter = build_verdict_formatter()
    single_evaluator = build_evaluator() if cfg.evaluator else None
    group_analyzer = build_group_analyzer()
    group_formatter = build_group_verdict_formatter()
    group_eval = build_group_evaluator() if cfg.evaluator else None
    validator = build_validator() if (cfg.validator and cfg.validator.enabled) else None

    semaphore = asyncio.Semaphore(concurrency)
    total = len(groups)
    done_counter = [0]

    async def _bounded_group(gi: int, group: FindingGroup) -> dict[int, Verdict]:
        async with semaphore:
            # Thinking: use highest severity in group
            if group.relationship == "solo":
                bundle = group.bundles[0]
                orig_idx = group.original_indices[0]
                thinking = cfg.get_thinking_settings(bundle.finding.severity)
                t0 = time.perf_counter()
                try:
                    verdict = await asyncio.wait_for(
                        _analyze_one(
                            solo_analyzer,
                            bundle, codebase, orig_idx,
                            stage_timeout=stage_timeout,
                            grep_max_file_size=grep_max_file_size,
                            grep_max_bytes=grep_max_bytes,
                            request_limit=request_limit,
                            thinking_settings=thinking,
                            formatter=solo_formatter,
                            evaluator=single_evaluator,
                            voting_rounds=voting_rounds,
                        ),
                        timeout=finding_timeout * voting_rounds,
                    )
                except asyncio.TimeoutError:
                    log.error("Finding %d timed out after %ds", orig_idx, finding_timeout)
                    verdict = _deterministic_fallback(bundle, f"finding timed out after {finding_timeout}s")
                except Exception as exc:
                    log.error("Finding %d failed: %s", orig_idx, exc)
                    verdict = _deterministic_fallback(bundle, _error_detail(exc))

                _apply_security_overrides(verdict, bundle.finding.check_id)

                if validator is not None:
                    await _validate_verdict(validator, bundle, verdict)

                if claude_verification:
                    va, vua, cr = await _claude_validate(bundle, verdict)
                    verdict.claude_verdict_agrees = va
                    verdict.claude_vuln_agrees = vua
                    verdict.claude_reason = cr
                    if va is not None:
                        log.info("Finding %d Claude validation — verdict_agrees=%s | vuln_agrees=%s", orig_idx, va, vua)

                done_counter[0] += 1
                tally_str = f" votes={verdict.voting_tally}" if verdict.voting_tally else ""
                print(
                    f"[{done_counter[0]}/{total}] Finding #{orig_idx} — {time.perf_counter() - t0:.1f}s{tally_str}",
                    flush=True,
                )
                result = {orig_idx: verdict}

            else:
                # Co-located: analyze the whole group together
                max_severity = max(
                    (b.finding.severity for b in group.bundles),
                    key=_severity_rank,
                    default="MEDIUM",
                )
                thinking = cfg.get_thinking_settings(max_severity)
                group_finding_timeout = finding_timeout + 60 * (len(group.bundles) - 1)
                t0 = time.perf_counter()

                try:
                    result = await asyncio.wait_for(
                        _analyze_one_group(
                            group_analyzer,
                            group, codebase, gi,
                            stage_timeout=stage_timeout,
                            grep_max_file_size=grep_max_file_size,
                            grep_max_bytes=grep_max_bytes,
                            request_limit=request_limit,
                            thinking_settings=thinking,
                            evaluator=group_eval,
                        ),
                        timeout=group_finding_timeout,
                    )
                except asyncio.TimeoutError:
                    log.error("Group %s timed out after %ds", group.group_key, group_finding_timeout)
                    result = {
                        idx: _deterministic_fallback(b, f"group timed out after {group_finding_timeout}s")
                        for idx, b in zip(group.original_indices, group.bundles)
                    }
                except Exception as exc:
                    log.error("Group %s failed: %s", group.group_key, exc)
                    result = {
                        idx: _deterministic_fallback(b, _error_detail(exc))
                        for idx, b in zip(group.original_indices, group.bundles)
                    }

                # Apply deterministic correctness-rule reclassification per finding
                bundles_by_idx = dict(zip(group.original_indices, group.bundles))
                for idx, verdict in result.items():
                    if idx in bundles_by_idx:
                        _apply_security_overrides(verdict, bundles_by_idx[idx].finding.check_id)

                if validator is not None:
                    await asyncio.gather(*(
                        _validate_verdict(validator, bundles_by_idx[idx], verdict)
                        for idx, verdict in result.items()
                        if idx in bundles_by_idx
                    ))

                if claude_verification:
                    for i, orig_idx in enumerate(group.original_indices):
                        if orig_idx in result:
                            bundle = group.bundles[i]
                            verdict = result[orig_idx]
                            va, vua, cr = await _claude_validate(bundle, verdict)
                            verdict.claude_verdict_agrees = va
                            verdict.claude_vuln_agrees = vua
                            verdict.claude_reason = cr
                            if va is not None:
                                log.info("Finding %d Claude validation — verdict_agrees=%s | vuln_agrees=%s", orig_idx, va, vua)

                done_counter[0] += 1
                elapsed = time.perf_counter() - t0
                indices_str = ", ".join(f"#{i}" for i in group.original_indices)
                print(
                    f"[{done_counter[0]}/{total}] Group [{indices_str}] — "
                    f"{len(group.bundles)} findings — {elapsed:.1f}s",
                    flush=True,
                )

            # Save incrementally
            checkpoint.update(result)
            if done_counter[0] % 5 == 0:
                _save_checkpoint_sync(output_path, checkpoint)
                log.info("Checkpoint saved: %d findings complete (%d groups)", len(checkpoint), done_counter[0])
            return result

    tasks = [_bounded_group(gi, g) for gi, g in enumerate(groups)]
    partial_results = await asyncio.gather(*tasks)

    # Final checkpoint save
    _save_checkpoint_sync(output_path, checkpoint)

    combined: dict[int, Verdict] = {}
    for r in partial_results:
        combined.update(r)
    _print_run_summary(list(combined.values()))
    return combined
