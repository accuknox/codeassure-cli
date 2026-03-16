from __future__ import annotations

from ..schema import EvidenceBundle


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
