from __future__ import annotations

from typing import TYPE_CHECKING

from ..schema import EvidenceBundle

if TYPE_CHECKING:
    from ..grouping import FindingGroup


def _get_finding_policy_note() -> str | None:
    """Build a verdict policy note from the active config's finding_policy.

    Returns None if all policy flags are False (security-only mode).
    """
    from ..config import get_config
    try:
        cfg = get_config()
    except RuntimeError:
        return None

    policy = cfg.finding_policy
    tp_types = []
    if policy.best_practice_is_tp:
        tp_types.append("best-practice (missing timeout, missing encoding, mutable defaults, missing error handling)")
    if policy.informational_detection_is_tp:
        tp_types.append("informational detection (library/framework usage detection)")
    if policy.audit_rule_is_tp:
        tp_types.append("audit rules (subprocess usage, pickle usage, shell=True)")

    if not tp_types:
        return None

    joined = "; ".join(tp_types)
    return (
        f"## Verdict Policy\n"
        f"This organization treats the following finding types as **true_positive** "
        f"if the detected pattern exists in the code: {joined}. "
        f"A finding is **false_positive** ONLY if the detected pattern does not "
        f"exist in the code. Do not downgrade a finding to false_positive because "
        f"it is \"merely best practice\" or \"not exploitable\" — if the pattern "
        f"exists, it is true_positive."
    )


_LIFECYCLE_MARKERS = (
    ("test", ("/tests/", "/test/", "test_", "_test.", "/testing/", "conftest")),
    ("fixture/example", ("/fixtures/", "/examples/", "/example/", "/samples/", "/demo/", "/docs/")),
    ("generated", ("_pb2.py", ".pb.go", "/generated/", ".g.dart", ".min.js", "/migrations/")),
    ("vendored/third-party", ("/vendor/", "/node_modules/", "/third_party/", "/site-packages/", "/.venv/")),
)


def _lifecycle_of(path: str) -> str | None:
    p = (path or "").lower()
    for label, markers in _LIFECYCLE_MARKERS:
        if any(m in p for m in markers):
            return label
    return None


def _build_rule_policy_note(finding) -> str | None:
    """Inject the per-rule verdict policy + constraint checklist + the reachability
    gate, so the model knows whether reachability may touch the VERDICT for THIS rule.

    Resurrects the metadata in rule_policies.py (previously dead code).
    """
    from .rule_policies import lookup_policy, get_constraints, is_taint_class, rule_kind_of

    check_id = finding.check_id
    policy = lookup_policy(check_id)
    taint = is_taint_class(check_id, finding)
    kind = rule_kind_of(check_id, finding)

    lines = ["## Rule-Specific Verdict Guidance", f"- **rule_kind**: {kind}"]
    if policy and policy.get("verdict_policy"):
        lines.append(f"- **verdict_policy**: {policy['verdict_policy']}")
    constraints = get_constraints(check_id)
    if constraints:
        lines.append("- **verify before deciding**:")
        lines.extend(f"  - {c}" for c in constraints)
    if taint:
        lines.append(
            "- **Reachability gate — OPEN.** This is a data-flow / injection rule: a real "
            "source→sink flow is part of the pattern, so reachability/taint legitimately "
            "bears on the VERDICT. But absence of a proven flow is NOT proof of safety — "
            "confirm or refute with the code before ruling false_positive."
        )
    else:
        lines.append(
            "- **Reachability gate — CLOSED.** This is a pattern-existence rule: the VERDICT "
            "is decided solely by whether the flagged construct is present at the site. "
            "Deadcode / unreachability does NOT make it false_positive — it may only set "
            "is_security_vulnerability=false or lower severity. Reserve false_positive for "
            "the pattern being genuinely absent, mitigated at the same site, or suppressed."
        )
    return "\n".join(lines)


def _build_context_triage_note(finding) -> str | None:
    """Source-trust + code-lifecycle reminders. These move is_security_vulnerability /
    severity only — never the verdict (a present pattern in a test file is still a
    true_positive; it is just usually not an exploitable vulnerability)."""
    lifecycle = _lifecycle_of(getattr(finding, "path", ""))
    lines = ["## Context Triage (affects security/severity, NOT the verdict)"]
    if lifecycle:
        lines.append(
            f"- This file looks like **{lifecycle}** code. If so, a real pattern here is "
            "still `true_positive`, but is usually not a deployable vulnerability — lean "
            "`is_security_vulnerability=false` / lower severity unless it ships to production."
        )
    lines.append(
        "- **Source trust**: classify what reaches the sink — attacker-controlled "
        "(request/CLI/upload) vs hardcoded constant vs operator env/config vs internal. "
        "A reachable, graph-'tainted' sink fed only by a constant/config value is not an "
        "attack (graph 'tainted' means structural flow, not attacker-controlled)."
    )
    return "\n".join(lines)


def _build_context_graph_section(finding, max_paths: int = 8, max_code: int = 900) -> str | None:
    """Render the deterministic source→sink context graph as prompt grounding.

    The model is handed the real flow (source → intermediates → sink) with each
    function's exact code, plus deterministic reachability/protection hints — so
    it rules on complete evidence instead of guessing via grep.
    """
    cg = getattr(finding, "context_graph", None)
    if not cg or not isinstance(cg, dict):
        return None
    nodes = {n.get("id"): n for n in cg.get("nodes", [])}
    paths = cg.get("paths", []) or []
    if not nodes:
        return None

    stats = cg.get("stats", {})
    parts = ["\n## Context Graph (deterministic source→sink analysis)"]
    coverage = ""
    if stats.get("degraded"):
        reason = stats.get("degrade_reason") or "coverage incomplete"
        coverage = (
            f"  ⚠ partial coverage ({reason}) — nodes/paths shown are real; "
            "absences are unproven, verify them with tools"
        )
    parts.append(
        f"- engine: {cg.get('engine', '?')} | language: {cg.get('language', '?')} | "
        f"paths: {len(paths)}" + coverage
    )
    sink = cg.get("sink", {})
    parts.append(f"- sink: {sink.get('file')}:{sink.get('line')}")

    # Trace targets — where the Execution Trace Protocol should start. Sources
    # first; if the engine found none, fall back to each path's first hop; a
    # sink-only graph gets an explicit "verify no callers were missed" target.
    trace_targets: list[str] = []
    _seen_t: set = set()
    def _fmt_target(n: dict) -> str:
        fn = n.get("function") or n.get("label") or "?"
        return f"{fn} ({n.get('file')}:{n.get('line')})"
    for n in cg.get("nodes", []):
        if n.get("kind") in ("source", "route") and n.get("id") not in _seen_t:
            _seen_t.add(n.get("id"))
            trace_targets.append(_fmt_target(n))
    if not trace_targets:
        for p in paths:
            nids = p.get("nodes") or []
            if nids and nids[0] not in _seen_t and nids[0] in nodes:
                _seen_t.add(nids[0])
                n0 = nodes[nids[0]]
                if n0.get("kind") != "sink":
                    trace_targets.append(_fmt_target(n0))
    if trace_targets:
        parts.append("- **trace targets** (start the Execution Trace Protocol here): "
                     + "; ".join(trace_targets[:5]))
    else:
        fn = (nodes.get(sink.get("node_id"), {}) or {}).get("function") or ""
        parts.append(
            "- **trace targets**: none — static analysis found no caller reaching the sink. "
            + (f"Independently verify with trace_callers('{fn}') that the enclosing function "
               "truly has no production callers before relying on unreachability."
               if fn else
               "Independently verify with trace_callers on the enclosing function that it "
               "truly has no production callers before relying on unreachability.")
        )

    for p in paths[:max_paths]:
        prot = p.get("protection", {}) or {}
        flags = []
        if prot.get("has_sanitizer"):
            flags.append("sanitizer-on-path")
        if prot.get("has_guard"):
            flags.append("guard-on-path")
        flag_str = ", ".join(flags) if flags else "no protection detected"
        parts.append(
            f"\n**Path {p.get('id')}** [{p.get('reachability', '?')}, "
            f"{'tainted' if p.get('tainted') else 'structural'}, {flag_str}]:"
        )
        chain = []
        for nid in p.get("nodes", []):
            n = nodes.get(nid, {})
            label = f"{n.get('function') or n.get('label')} ({n.get('file')}:{n.get('line')})"
            if n.get("kind") == "sink":
                label += " [SINK]"
            elif n.get("kind") == "source":
                label += f" [SOURCE:{n.get('role', '')}]"
            elif n.get("kind") == "sanitizer":
                label += " [SANITIZER]"
            chain.append(label)
        parts.append("  " + " → ".join(chain))

    # Unique function bodies referenced by the shown paths, in first-appearance
    # (flow) order — a set here made the prompt text vary run-to-run for an
    # identical graph, perturbing the LLM; ordered dedup keeps it deterministic.
    shown_ids: list = []
    _seen_ids: set = set()
    for p in paths[:max_paths]:
        for nid in p.get("nodes", []):
            if nid not in _seen_ids:
                _seen_ids.add(nid)
                shown_ids.append(nid)
    seen_fns: set = set()
    parts.append("\n### Node source")
    for nid in shown_ids:
        n = nodes.get(nid, {})
        code = (n.get("code") or "").strip()
        key = (n.get("file"), n.get("function"))
        if not code or key in seen_fns:
            continue
        seen_fns.add(key)
        parts.append(f"#### {n.get('function') or n.get('label')} — {n.get('file')}:{n.get('line')}")
        parts.append(f"```\n{code[:max_code]}\n```")

    return "\n".join(parts)


def build_user_message(bundle: EvidenceBundle) -> str:
    f = bundle.finding

    # Code evidence first — model forms its own impression before seeing the claim
    parts = []
    if bundle.evidence:
        parts.append("## Source Code")
        for ev in bundle.evidence:
            parts.append(f"### {ev.path} (lines {ev.start_line}–{ev.end_line})")
            parts.append(f"```\n{ev.content}\n```")
    else:
        # finding_only mode: only the scanner-captured snippet is available
        parts.append("## Flagged Code Snippet")
        parts.append(f"### {f.path} (lines {f.line}–{f.end_line})")
        parts.append(f"```\n{f.lines}\n```")

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

    graph_section = _build_context_graph_section(f)
    if graph_section:
        parts.append(graph_section)

    rule_note = _build_rule_policy_note(f)
    if rule_note:
        parts.append(f"\n{rule_note}")

    triage_note = _build_context_triage_note(f)
    if triage_note:
        parts.append(f"\n{triage_note}")

    policy_note = _get_finding_policy_note()
    if policy_note:
        parts.append(f"\n{policy_note}")

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
    graph_section = _build_context_graph_section(f)
    if graph_section:
        parts.append(graph_section)
    rule_note = _build_rule_policy_note(f)
    if rule_note:
        parts.append(rule_note)
    triage_note = _build_context_triage_note(f)
    if triage_note:
        parts.append(triage_note)
    return parts


def build_group_message(group: "FindingGroup") -> str:
    """Build prompt for a group of co-located findings.

    Solo groups delegate to build_user_message().
    """
    if len(group.bundles) == 1:
        return build_user_message(group.bundles[0])

    parts = []

    # Shared code evidence (deduplicated — shown once)
    if group.shared_evidence:
        parts.append("## Source Code")
        for ev in group.shared_evidence:
            parts.append(f"### {ev.path} (lines {ev.start_line}–{ev.end_line})")
            parts.append(f"```\n{ev.content}\n```")
    else:
        # finding_only mode: show each finding's scanner-captured snippet individually
        parts.append("## Flagged Code Snippets")
        for i, bundle in enumerate(group.bundles):
            f = bundle.finding
            parts.append(f"### Finding {i}: {f.path} (lines {f.line}–{f.end_line})")
            parts.append(f"```\n{f.lines}\n```")

    # Coherence note
    if group.coherence_note:
        parts.append(f"\n## Group Context")
        parts.append(group.coherence_note)

    # Numbered scanner claims
    n = len(group.bundles)
    parts.append(f"\n## Scanner Claims ({n} findings)")
    for i, bundle in enumerate(group.bundles):
        parts.extend(_finding_claim_block(i, bundle))

    # Verdict policy
    policy_note = _get_finding_policy_note()
    if policy_note:
        parts.append(f"\n{policy_note}")

    # Output instruction
    parts.append(f"\n## Output")
    parts.append(
        f"Provide a verdict for EACH of the {n} findings above "
        f"(Finding 0 through Finding {n - 1})."
    )

    return "\n".join(parts)


def build_group_formatter_message(analysis: str, group: "FindingGroup") -> str:
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


# ---------------------------------------------------------------------------
# Evaluator message builders
# ---------------------------------------------------------------------------


def build_evaluator_message(
    bundle: EvidenceBundle,
    verdict: "Verdict",
) -> str:
    """Build message for the evaluator to review a single verdict."""
    from ..schema import Verdict as _V  # avoid circular at module level

    f = bundle.finding
    parts = []

    # Source code
    parts.append("## Source Code")
    for ev in bundle.evidence:
        parts.append(f"### {ev.path} (lines {ev.start_line}–{ev.end_line})")
        parts.append(f"```\n{ev.content}\n```")

    # Scanner claim
    parts.append("\n## Scanner Claim")
    parts.append(f"- **check_id**: {f.check_id}")
    parts.append(f"- **path**: {f.path}:{f.line}")
    parts.append(f"- **claim**: {f.message}")
    parts.append(f"- **flagged code**: `{f.lines}`")

    # Verdict policy (if active)
    policy_note = _get_finding_policy_note()
    if policy_note:
        parts.append(f"\n{policy_note}")

    # Verdict to review
    parts.append("\n## Verdict to Review")
    parts.append(f"- **verdict**: {verdict.verdict}")
    parts.append(f"- **is_security_vulnerability**: {verdict.is_security_vulnerability}")
    parts.append(f"- **confidence**: {verdict.confidence}")
    parts.append(f"- **reason**: {verdict.reason}")
    parts.append(f"- **evidence_locations**: {verdict.evidence_locations}")

    return "\n".join(parts)


def build_group_evaluator_message(
    group: "FindingGroup",
    verdicts: dict[str, "Verdict"],
) -> str:
    """Build message for the evaluator to review grouped verdicts."""
    parts = []

    # Shared code
    parts.append("## Source Code")
    for ev in group.shared_evidence:
        parts.append(f"### {ev.path} (lines {ev.start_line}–{ev.end_line})")
        parts.append(f"```\n{ev.content}\n```")

    # Scanner claims
    n = len(group.bundles)
    parts.append(f"\n## Scanner Claims ({n} findings)")
    for i, bundle in enumerate(group.bundles):
        parts.extend(_finding_claim_block(i, bundle))

    # Verdict policy
    policy_note = _get_finding_policy_note()
    if policy_note:
        parts.append(f"\n{policy_note}")

    # Verdicts to review
    parts.append(f"\n## Verdicts to Review")
    for i in range(n):
        key = str(i)
        v = verdicts.get(key)
        if v is None:
            continue
        parts.append(f"\n### Finding {i}")
        parts.append(f"- **verdict**: {v.verdict}")
        parts.append(f"- **is_security_vulnerability**: {v.is_security_vulnerability}")
        parts.append(f"- **confidence**: {v.confidence}")
        parts.append(f"- **reason**: {v.reason}")
        parts.append(f"- **evidence_locations**: {v.evidence_locations}")

    return "\n".join(parts)
