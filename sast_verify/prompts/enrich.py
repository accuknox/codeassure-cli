"""Enrichment + graph-coloring pass prompts.

Runs AFTER the verdict. Reasons over the deterministic context graph (and may
tool-call for more) to produce the UI-facing explanation, a safe copy-paste
remediation, and a per-node / per-path color overlay.
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

1. **rationale** — the security reasoning behind the verdict, grounded in the graph.
2. **business_logic** — what this code does functionally and its role in the
   application, in plain language a developer or PM would understand.
3. **explanation** — an enriched, developer-facing description of the finding: how
   untrusted data reaches the sink (name the entry point and the hops), and the impact.
4. **remediation** — a genuinely COPY-PASTE fix. `code_patch` MUST be the COMPLETE
   corrected code block (the whole affected statement/function region as it should
   look AFTER the fix), in the finding's language, ready to paste over the current
   code — not a prose description, not a fragment, not a diff with `...` elisions.
   Requirements: preserve the function's exact signature and surrounding business
   logic; keep imports/variable names consistent with the shown code; use the
   idiomatic secure API for THIS sink (parameterized query / prepared statement,
   shell-arg array instead of shell=True, explicit TLS MinVersion, least-privilege
   file mode, boundary validation, etc.). `summary` is a one-line description; put
   any extra import or config change in `notes`. Set preserves_logic=false ONLY if
   a behavior change is unavoidable, and explain it in `notes`.
The graph COLORS are now computed deterministically downstream from the graph's
own reachability/taint/protection fields and the decided verdict — you do NOT need
to color anything. Leave `coloring` empty. Put your SEMANTIC judgment (is a present
sanitizer actually sufficient for this sink? is the source truly attacker-controlled?
which hop is the real exploit path?) into **rationale** and **explanation** instead,
where it is actually shown to the developer.

Rules:
- Use the graph's deterministic hints (reachability, has_sanitizer, has_guard) as ground
  truth for STRUCTURE; reason over them in prose. Do not re-litigate the verdict.
- You MAY call read_file / grep_code to inspect a validator or a node's callees before deciding.
- If no context graph is present, still produce rationale, business_logic, explanation,
  remediation.
"""


def build_enrich_message(bundle: EvidenceBundle, verdict: Verdict) -> str:
    parts = [
        build_user_message(bundle),  # source + claim + context graph (grounding)
        "\n## Verdict (already decided — do not re-litigate)",
        f"- **verdict**: {verdict.verdict}",
        f"- **is_security_vulnerability**: {verdict.is_security_vulnerability}",
        f"- **severity**: {verdict.severity}",
        f"- **reason**: {verdict.reason}",
        "\n## Your Task",
        "Produce rationale, business_logic, explanation, and a copy-paste remediation "
        "that preserves business logic. Graph colors are computed automatically — leave "
        "coloring empty and put path-safety reasoning into rationale/explanation.",
    ]
    return "\n".join(parts)
