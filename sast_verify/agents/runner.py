from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

import anthropic
from pydantic_ai.usage import UsageLimits

from ..config import get_config
from ..grouping import FindingGroup
from ..prompts import (
    build_formatter_message,
    build_group_formatter_message,
    build_group_message,
    build_user_message,
)
from ..schema import EvidenceBundle, Verdict
from .analyzer import (
    build_analyzer,
    build_group_analyzer,
    build_group_verdict_formatter,
    build_verdict_formatter,
)
from .deps import AnalyzerDeps

log = logging.getLogger(__name__)

DEFAULT_CONCURRENCY = 4
MAX_GREP_FILE_SIZE_DEFAULT = 512 * 1024
MAX_GREP_BYTES_DEFAULT = 5 * 1024 * 1024


import re

from pydantic_ai.exceptions import UnexpectedModelBehavior


async def _run_with_retry(agent, message, *, retries: int = 3, base_delay: float = 2.0, **kwargs):
    """Run an agent call, retrying on transient UnexpectedModelBehavior (e.g. null API response)."""
    for attempt in range(retries):
        try:
            return await agent.run(message, **kwargs)
        except UnexpectedModelBehavior as exc:
            if attempt < retries - 1:
                delay = base_delay * (2 ** attempt)
                log.warning(
                    "Transient model error (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1, retries, delay, type(exc).__name__,
                )
                await asyncio.sleep(delay)
            else:
                raise


def _fix_unquoted_strings(text: str) -> str:
    """Fix JSON with unquoted string values — common with some models.

    Targets the "reason" field specifically, which nemotron often leaves unquoted.
    Uses a greedy match anchored to the last valid JSON delimiter to handle
    reason text that contains } or , characters.
    """
    pattern = r'("reason")\s*:\s*(?!")(.+?)(?=,\s*"evidence_locations"\s*:|,\s*"verdict"\s*:|,\s*"confidence"\s*:|,\s*"is_security_vulnerability"\s*:|\s*}\s*$)'
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

    if text.startswith("{"):
        try:
            return Verdict.model_validate(json.loads(text))
        except (json.JSONDecodeError, Exception):
            pass

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


def _parse_group_verdicts(text: str, expected_keys: list[str]) -> dict[str, Verdict]:
    """Parse keyed verdicts JSON. Missing keys → 'uncertain'. Extra/unknown keys → ignored + warned."""
    text = text.strip()

    obj: dict | None = None
    decoder = json.JSONDecoder()

    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            pass

    if obj is None:
        idx = 0
        while idx < len(text):
            pos = text.find("{", idx)
            if pos == -1:
                break
            try:
                parsed, end = decoder.raw_decode(text, pos)
                if isinstance(parsed, dict) and "verdicts" in parsed:
                    obj = parsed
                    break
                idx = end
            except json.JSONDecodeError:
                idx = pos + 1

    if obj is None:
        raise ValueError(f"No keyed verdicts JSON found in: {text[:200]}")

    verdicts_raw = obj.get("verdicts", {})

    result: dict[str, Verdict] = {}
    for key in expected_keys:
        if key not in verdicts_raw:
            log.warning("Group verdict missing key %s — using uncertain", key)
            result[key] = Verdict(
                verdict="uncertain",
                confidence="low",
                reason=f"Model did not provide a verdict for finding {key}.",
            )
        else:
            try:
                result[key] = Verdict.model_validate(verdicts_raw[key])
            except Exception as exc:
                log.warning("Group verdict parse error for key %s: %s", key, exc)
                result[key] = Verdict(
                    verdict="uncertain",
                    confidence="low",
                    reason=f"Could not parse verdict for finding {key}: {exc}",
                )

    for key in verdicts_raw:
        if key not in expected_keys:
            log.debug("Group verdict has unknown key %s — ignored", key)

    return result


def _validate_evidence(
    evidence_locations: list[str],
    accessed_paths: dict[str, list[tuple[int, int]]],
    finding_path: str,
    finding_start: int,
    finding_end: int,
) -> list[str]:
    """Filter evidence_locations to only include files+lines actually accessed."""
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

        if file_part == finding_path:
            if cited_line is None or finding_start <= cited_line <= finding_end:
                validated.append(loc)
                continue
            ranges = accessed_paths.get(file_part, [])
            if any(s <= cited_line <= e for s, e in ranges):
                validated.append(loc)
            continue

        if file_part not in accessed_paths:
            continue

        ranges = accessed_paths[file_part]
        if cited_line is None:
            validated.append(loc)
        elif not ranges:
            validated.append(loc)
        elif any(s <= cited_line <= e for s, e in ranges):
            validated.append(loc)

    return validated


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


def _majority_verdict(verdicts: list[Verdict]) -> Verdict:
    """Pick verdict with the most votes; break ties by total confidence weight."""
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
        winner = max(candidates, key=lambda lbl: weights.get(lbl, 0))

    winners = [v for v in verdicts if v.verdict == winner]
    best = max(winners, key=lambda v: _CONFIDENCE_WEIGHT.get(v.confidence, 0))
    best.voting_tally = dict(counts)
    return best


# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------

def _compute_anchor_root(finding_dir: Path) -> str:
    if str(finding_dir) == ".":
        return ""
    elif str(finding_dir.parent) == ".":
        return str(finding_dir)
    else:
        return str(finding_dir.parent)


def _build_deps(
    codebase: Path,
    finding_dir: Path,
    anchor_root: str,
    grep_max_file_size: int,
    grep_max_bytes: int,
) -> AnalyzerDeps:
    return AnalyzerDeps(
        codebase=str(codebase.resolve()),
        finding_dir=str(finding_dir),
        anchor_root=anchor_root,
        accessed_paths={},
        grep_max_file_size=grep_max_file_size,
        grep_max_bytes=grep_max_bytes,
    )


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
    anchor_root = _compute_anchor_root(finding_dir)
    deps = _build_deps(codebase, finding_dir, anchor_root, grep_max_file_size, grep_max_bytes)

    limits = UsageLimits(request_limit=request_limit)
    run_kwargs: dict = {"deps": deps, "usage_limits": limits}
    if thinking_settings:
        run_kwargs["model_settings"] = thinking_settings

    try:
        result = await asyncio.wait_for(
            _run_with_retry(analyzer, build_user_message(bundle), **run_kwargs),
            timeout=stage_timeout,
        )
        analysis = result.output
    except asyncio.TimeoutError:
        log.warning("Analyzer timed out for finding %d", index)
        return Verdict(verdict="uncertain", confidence="low",
                       reason=f"Analyzer stage timed out after {stage_timeout}s.")
    except Exception as exc:
        log.error("Analyzer failed for finding %d: %s", index, exc)
        return Verdict(verdict="uncertain", confidence="low",
                       reason=f"Analyzer error: {type(exc).__name__}")

    if not analysis.strip():
        log.warning("Empty analysis for finding %d", index)
        return Verdict(verdict="uncertain", confidence="low",
                       reason="Analyzer produced no output.")

    accessed_paths = deps.accessed_paths

    verdict = None
    try:
        verdict = _parse_verdict(analysis)
    except Exception as exc:
        log.warning("Direct parse failed for finding %d: %s — trying formatter fallback", index, exc)
        if formatter is not None:
            try:
                fmt_result = await asyncio.wait_for(
                    _run_with_retry(formatter, build_formatter_message(analysis, bundle)),
                    timeout=stage_timeout,
                )
                verdict = _parse_verdict(fmt_result.output)
            except Exception as fmt_exc:
                log.error("Formatter fallback also failed for finding %d: %s", index, fmt_exc)

    if verdict is None:
        return Verdict(verdict="uncertain", confidence="low",
                       reason="Could not extract a valid verdict from LLM output.")

    if bundle.evidence:
        ev = bundle.evidence[0]
        finding_start, finding_end = ev.start_line, ev.end_line
    else:
        finding_start, finding_end = bundle.finding.line, bundle.finding.end_line
    verdict.evidence_locations = _validate_evidence(
        verdict.evidence_locations, accessed_paths, bundle.finding.path,
        finding_start, finding_end,
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
    voting_rounds: int = 1,
) -> Verdict:
    if voting_rounds <= 1:
        return await _analyze_one_round(
            analyzer, bundle, codebase, index,
            stage_timeout=stage_timeout,
            grep_max_file_size=grep_max_file_size,
            grep_max_bytes=grep_max_bytes,
            request_limit=request_limit,
            thinking_settings=thinking_settings,
            formatter=formatter,
        )

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


# ---------------------------------------------------------------------------
# Group analysis
# ---------------------------------------------------------------------------

async def _analyze_one_group(
    analyzer,
    group: FindingGroup,
    codebase: Path,
    stage_timeout: float = 500,
    grep_max_file_size: int = MAX_GREP_FILE_SIZE_DEFAULT,
    grep_max_bytes: int = MAX_GREP_BYTES_DEFAULT,
    request_limit: int = 200,
    thinking_settings: dict | None = None,
    formatter=None,
) -> dict[int, Verdict]:
    """Analyze a co-located group. Returns dict[original_index → Verdict]."""
    finding_dir = Path(group.bundles[0].finding.path).parent
    anchor_root = _compute_anchor_root(finding_dir)
    deps = _build_deps(codebase, finding_dir, anchor_root, grep_max_file_size, grep_max_bytes)

    limits = UsageLimits(request_limit=request_limit)
    run_kwargs: dict = {"deps": deps, "usage_limits": limits}
    if thinking_settings:
        run_kwargs["model_settings"] = thinking_settings

    expected_keys = [str(i) for i in range(len(group.bundles))]

    def _uncertain_all(reason: str) -> dict[int, Verdict]:
        return {idx: Verdict(verdict="uncertain", confidence="low", reason=reason)
                for idx in group.original_indices}

    try:
        result = await asyncio.wait_for(
            _run_with_retry(analyzer, build_group_message(group), **run_kwargs),
            timeout=stage_timeout,
        )
        analysis = result.output
    except asyncio.TimeoutError:
        log.warning("Group analyzer timed out for %s", group.group_key)
        return _uncertain_all(f"Analyzer stage timed out after {stage_timeout}s.")
    except Exception as exc:
        log.error("Group analyzer failed for %s: %s", group.group_key, type(exc).__name__)
        return _uncertain_all(f"Analyzer error: {type(exc).__name__}")

    if not analysis.strip():
        log.warning("Empty group analysis for %s", group.group_key)
        return _uncertain_all("Analyzer produced no output.")

    accessed_paths = deps.accessed_paths

    verdicts = None
    try:
        verdicts = _parse_group_verdicts(analysis, expected_keys)
    except Exception as exc:
        log.warning("Direct group parse failed for %s: %s — trying formatter fallback", group.group_key, exc)
        if formatter is not None:
            try:
                fmt_result = await asyncio.wait_for(
                    _run_with_retry(formatter, build_group_formatter_message(analysis, group)),
                    timeout=stage_timeout,
                )
                verdicts = _parse_group_verdicts(fmt_result.output, expected_keys)
            except Exception as fmt_exc:
                log.error("Formatter fallback also failed for group %s: %s", group.group_key, fmt_exc)

    if verdicts is None:
        return _uncertain_all("Could not extract group verdicts from LLM output.")

    verdicts = _validate_group_evidence(group, verdicts, accessed_paths)

    return {
        orig_idx: verdicts.get(
            str(i),
            Verdict(verdict="uncertain", confidence="low",
                    reason=f"Verdict not found for finding {i}."),
        )
        for i, orig_idx in enumerate(group.original_indices)
    }


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

async def analyze_all(
    bundles: list[EvidenceBundle],
    codebase: Path,
    concurrency: int = DEFAULT_CONCURRENCY,
    claude_verification: bool = False,
) -> list[Verdict]:
    cfg = get_config()
    stage_timeout = cfg.stage_timeout
    finding_timeout = cfg.finding_timeout
    grep_max_file_size = cfg.grep_max_file_kb * 1024
    grep_max_bytes = cfg.grep_max_scan_mb * 1024 * 1024
    request_limit = cfg.request_limit
    voting_rounds = cfg.voting_rounds

    analyzer = build_analyzer()
    formatter = build_verdict_formatter()

    semaphore = asyncio.Semaphore(concurrency)
    total = len(bundles)
    done_counter = [0]

    async def _bounded(index: int, bundle: EvidenceBundle) -> Verdict:
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
                        voting_rounds=voting_rounds,
                    ),
                    timeout=finding_timeout * voting_rounds,
                )
            except asyncio.TimeoutError:
                log.error("Finding %d timed out after %ds", index, finding_timeout)
                return Verdict(verdict="uncertain", confidence="low",
                               reason=f"Analysis timed out after {finding_timeout}s.")
            except Exception as exc:
                log.error("Finding %d failed: %s", index, exc)
                return Verdict(verdict="uncertain", confidence="low",
                               reason=f"Analysis error: {type(exc).__name__}")

            done_counter[0] += 1
            elapsed = time.perf_counter() - t0
            tally_str = f" votes={verdict.voting_tally}" if verdict.voting_tally else ""
            print(
                f"[{done_counter[0]}/{total}] Finding #{index} — {elapsed:.1f}s",
                flush=True,
            )

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
            return verdict

    tasks = [_bounded(i, b) for i, b in enumerate(bundles)]
    return await asyncio.gather(*tasks)


async def analyze_all_grouped(
    groups: list[FindingGroup],
    codebase: Path,
    concurrency: int = DEFAULT_CONCURRENCY,
    claude_verification: bool = False,
) -> dict[int, Verdict]:
    """Semaphore-bounded grouped analysis. Returns dict[original_index → Verdict]."""
    cfg = get_config()
    stage_timeout = cfg.stage_timeout
    finding_timeout = cfg.finding_timeout
    grep_max_file_size = cfg.grep_max_file_kb * 1024
    grep_max_bytes = cfg.grep_max_scan_mb * 1024 * 1024
    request_limit = cfg.request_limit
    voting_rounds = cfg.voting_rounds

    solo_analyzer = build_analyzer()
    solo_formatter = build_verdict_formatter()
    group_analyzer = build_group_analyzer()
    group_formatter = build_group_verdict_formatter()

    semaphore = asyncio.Semaphore(concurrency)
    total = len(groups)
    done_counter = [0]

    async def _bounded_group(group: FindingGroup) -> dict[int, Verdict]:
        async with semaphore:
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
                            voting_rounds=voting_rounds,
                        ),
                        timeout=finding_timeout * voting_rounds,
                    )
                except asyncio.TimeoutError:
                    log.error("Finding %d timed out after %ds", orig_idx, finding_timeout)
                    verdict = Verdict(verdict="uncertain", confidence="low",
                                     reason=f"Analysis timed out after {finding_timeout}s.")
                except Exception as exc:
                    log.error("Finding %d failed: %s", orig_idx, exc)
                    verdict = Verdict(verdict="uncertain", confidence="low",
                                     reason=f"Analysis error: {type(exc).__name__}")

                done_counter[0] += 1
                tally_str = f" votes={verdict.voting_tally}" if verdict.voting_tally else ""
                print(
                    f"[{done_counter[0]}/{total}] Finding #{orig_idx} — {time.perf_counter() - t0:.1f}s",
                    flush=True,
                )

                if claude_verification:
                    va, vua, cr = await _claude_validate(bundle, verdict)
                    verdict.claude_verdict_agrees = va
                    verdict.claude_vuln_agrees = vua
                    verdict.claude_reason = cr
                    if va is not None:
                        log.info("Finding %d Claude validation — verdict_agrees=%s | vuln_agrees=%s", orig_idx, va, vua)
                return {orig_idx: verdict}

            else:
                # Co-located: analyze the whole group together
                max_severity = max(
                    (b.finding.severity for b in group.bundles),
                    key=_severity_rank,
                    default="MEDIUM",
                )
                thinking = cfg.get_thinking_settings(max_severity)
                timeout = finding_timeout + 60 * (len(group.bundles) - 1)
                t0 = time.perf_counter()

                try:
                    result = await asyncio.wait_for(
                        _analyze_one_group(
                            group_analyzer,
                            group, codebase,
                            stage_timeout=stage_timeout,
                            grep_max_file_size=grep_max_file_size,
                            grep_max_bytes=grep_max_bytes,
                            request_limit=request_limit,
                            formatter=group_formatter,
                            thinking_settings=thinking,
                        ),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    log.error("Group %s timed out after %ds", group.group_key, timeout)
                    uncertain = Verdict(verdict="uncertain", confidence="low",
                                       reason=f"Group analysis timed out after {timeout}s.")
                    result = {idx: uncertain for idx in group.original_indices}
                except Exception as exc:
                    log.error("Group %s failed: %s", group.group_key, exc)
                    uncertain = Verdict(verdict="uncertain", confidence="low",
                                       reason=f"Group analysis error: {type(exc).__name__}")
                    result = {idx: uncertain for idx in group.original_indices}

                done_counter[0] += 1
                elapsed = time.perf_counter() - t0
                indices_str = ", ".join(f"#{i}" for i in group.original_indices)
                print(
                    f"[{done_counter[0]}/{total}] Group [{indices_str}] — "
                    f"{len(group.bundles)} findings — {elapsed:.1f}s",
                    flush=True,
                )

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

                return result

    tasks = [_bounded_group(g) for g in groups]
    partial_results = await asyncio.gather(*tasks)

    combined: dict[int, Verdict] = {}
    for r in partial_results:
        combined.update(r)
    return combined
