"""Enrichment pass prompts.

Runs AFTER the verdict. Reasons over the deterministic context graph (and may
tool-call for more) to produce the UI-facing rationale, business context,
developer explanation, and a paste-ready remediation with an exact paste target.
"""

from __future__ import annotations

from ..schema import EvidenceBundle, Verdict
from . import build_user_message

ENRICH_INSTRUCTION = """\
You are a senior application-security engineer writing the FINAL, developer-facing
explanation of a SAST finding whose verdict has already been decided. You are given
the flagged code, the scanner claim, the decided verdict, and — when available — a
DETERMINISTIC context graph: every source→sink path with each function's exact code
and deterministic reachability / protection hints.

Produce, as structured output:

1. **rationale** — the security reasoning behind the verdict, grounded in the graph
   and the code: which entry point feeds the sink, what trust the data carries,
   which protection (if any) decides the outcome. For an `uncertain` verdict,
   state exactly which fact could not be established and what a human should check.
2. **business_logic** — what this code does functionally and its role in the
   application, in plain language a developer or PM would understand.
3. **explanation** — an enriched, developer-facing description of the finding: how
   untrusted data reaches the sink (name the entry point and the hops), and the impact.
4. **remediation** — a genuinely COPY-PASTE fix:
   - `code_patch` MUST be the COMPLETE corrected code block (the whole affected
     statement/function region as it should look AFTER the fix), in the finding's
     language, ready to paste over the current code — not a prose description, not
     a fragment, not a diff with `...` elisions.
   - `file`, `start_line`, `end_line` MUST name the exact paste target: the
     repo-relative file and the 1-indexed inclusive line range that `code_patch`
     replaces. Choose the smallest region that fully contains the fix.
   - `original_code` MUST quote the current code of exactly that region, verbatim,
     so the developer (or a tool) can locate and diff it.
   - Preserve the function's exact signature and surrounding business logic; keep
     imports/variable names consistent with the shown code; use the idiomatic
     secure API for THIS sink (parameterized query / prepared statement, shell-arg
     array instead of shell=True, explicit TLS MinVersion, least-privilege file
     mode, boundary validation, etc.).
   - `summary` is a one-line description; put any extra import or config change in
     `notes`. Set preserves_logic=false ONLY if a behavior change is unavoidable,
     and explain it in `notes`.
   - For a **false_positive** verdict, remediation is the hardening improvement a
     careful team would still make (or, when the code is already ideal, summary
     "No change required" with an empty code_patch and notes explaining why).

Rules:
- Use the graph's deterministic hints (reachability, has_sanitizer, has_guard) as ground
  truth for STRUCTURE; reason over them in prose. Do not re-litigate the verdict.
- You MAY call read_file / grep_code / trace_callers to inspect a validator, confirm
  the exact paste region, or check a node's callees before writing the patch. Read the
  real region you are patching before quoting original_code.
- If no context graph is present, still produce rationale, business_logic, explanation,
  remediation from the code evidence.
- The graph COLORS are computed deterministically downstream — leave `coloring` empty.
"""


def build_enrich_message(bundle: EvidenceBundle, verdict: Verdict) -> str:
    f = bundle.finding
    parts = [
        build_user_message(bundle),  # source + claim + context graph (grounding)
        "\n## Verdict (already decided — do not re-litigate)",
        f"- **verdict**: {verdict.verdict}",
        f"- **is_security_vulnerability**: {verdict.is_security_vulnerability}",
        f"- **severity**: {verdict.severity}",
        f"- **reason**: {verdict.reason}",
    ]
    if verdict.source_trust:
        parts.append(f"- **source_trust**: {verdict.source_trust}")
    if verdict.execution_trace:
        parts.append("- **verified execution trace**:")
        parts.extend(f"  - {step}" for step in verdict.execution_trace)
    if verdict.attack_scenario:
        parts.append(f"- **attack_scenario**: {verdict.attack_scenario}")
    parts += [
        "\n## Your Task",
        "Produce rationale, business_logic, explanation, and a copy-paste remediation "
        f"with an exact paste target in `{f.path}` (file + start_line + end_line + "
        "original_code). Graph colors are computed automatically — leave coloring "
        "empty and put path-safety reasoning into rationale/explanation.",
    ]
    return "\n".join(parts)
