from __future__ import annotations

from typing import TYPE_CHECKING

from ..schema import EvidenceBundle

if TYPE_CHECKING:
    from ..grouping import FindingGroup


def build_user_message(bundle: EvidenceBundle) -> str:
    f = bundle.finding

    # Code evidence first — model forms its own impression before seeing the claim
    parts = ["## Source Code"]
    for ev in bundle.evidence:
        parts.append(f"### {ev.path} (lines {ev.start_line}–{ev.end_line})")
        parts.append(f"```\n{ev.content}\n```")

    # Scanner claim second — model evaluates it against the code
    parts.append("\n## Scanner Claim")
    parts.append(f"- **check_id**: {f.check_id}")
    parts.append(f"- **path**: {f.path}")
    parts.append(f"- **lines**: {f.line}–{f.end_line}")
    parts.append(f"- **severity**: {f.severity}")
    parts.append(f"- **category**: {f.category}")
    parts.append(f"- **claim**: {f.message}")
    parts.append(f"- **flagged code**: `{f.lines}`")

    if f.cwe:
        parts.append(f"- **cwe**: {', '.join(f.cwe)}")
    if f.taint_source:
        parts.append(f"- **taint_source**: `{f.taint_source}`")
    if f.taint_sink:
        parts.append(f"- **taint_sink**: `{f.taint_sink}`")
    if f.fix:
        parts.append(f"- **suggested_fix**: {f.fix}")

    return "\n".join(parts)


def build_formatter_message(analysis: str, bundle: EvidenceBundle) -> str:
    f = bundle.finding

    parts = [
        "## Analysis Record",
        analysis,
        "\n## Original Finding (cross-reference)",
        f"- **check_id**: {f.check_id}",
        f"- **path**: {f.path}",
        f"- **lines**: {f.line}–{f.end_line}",
        f"- **severity**: {f.severity}",
        f"- **claim**: {f.message}",
    ]

    return "\n".join(parts)


def _short_check_id(check_id: str) -> str:
    return check_id.rsplit(".", 1)[-1]


def _finding_claim_block(index: int, bundle: EvidenceBundle) -> list[str]:
    """Build the scanner claim section for one finding in a group."""
    f = bundle.finding
    parts = [
        f"\n### Finding {index}: {_short_check_id(f.check_id)}",
        f"- **check_id**: {f.check_id}",
        f"- **lines**: {f.line}–{f.end_line}",
        f"- **severity**: {f.severity}",
        f"- **category**: {f.category}",
        f"- **claim**: {f.message}",
        f"- **flagged code**: `{f.lines}`",
    ]
    if f.cwe:
        parts.append(f"- **cwe**: {', '.join(f.cwe)}")
    if f.taint_source:
        parts.append(f"- **taint_source**: `{f.taint_source}`")
    if f.taint_sink:
        parts.append(f"- **taint_sink**: `{f.taint_sink}`")
    if f.fix:
        parts.append(f"- **suggested_fix**: {f.fix}")
    return parts


def build_group_message(group: FindingGroup) -> str:
    """Build prompt for a group of co-located findings.

    Solo groups delegate to build_user_message().
    """
    if len(group.bundles) == 1:
        return build_user_message(group.bundles[0])

    parts = []

    # Shared code evidence (deduplicated — shown once)
    parts.append("## Source Code")
    for ev in group.shared_evidence:
        parts.append(f"### {ev.path} (lines {ev.start_line}–{ev.end_line})")
        parts.append(f"```\n{ev.content}\n```")

    # Coherence note
    if group.coherence_note:
        parts.append(f"\n## Group Context")
        parts.append(group.coherence_note)

    # Numbered scanner claims
    n = len(group.bundles)
    parts.append(f"\n## Scanner Claims ({n} findings)")
    for i, bundle in enumerate(group.bundles):
        parts.extend(_finding_claim_block(i, bundle))

    # Output instruction
    parts.append(f"\n## Output")
    parts.append(
        f"Provide a verdict for EACH of the {n} findings above "
        f"(Finding 0 through Finding {n - 1})."
    )

    return "\n".join(parts)


def build_group_formatter_message(analysis: str, group: FindingGroup) -> str:
    """Build formatter message for a group of findings."""
    n = len(group.bundles)

    parts = [
        "## Analysis Record",
        analysis,
        f"\n## Original Findings ({n} findings, cross-reference)",
    ]

    for i, bundle in enumerate(group.bundles):
        f = bundle.finding
        parts.append(f"\n### Finding {i}: {_short_check_id(f.check_id)}")
        parts.append(f"- **check_id**: {f.check_id}")
        parts.append(f"- **path**: {f.path}")
        parts.append(f"- **lines**: {f.line}–{f.end_line}")
        parts.append(f"- **severity**: {f.severity}")
        parts.append(f"- **claim**: {f.message}")

    parts.append(f"\nReturn verdicts for all {n} findings (keys 0 through {n - 1}).")

    return "\n".join(parts)
