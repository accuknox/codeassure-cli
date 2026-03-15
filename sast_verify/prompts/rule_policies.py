"""Deterministic verdict policies for known SAST rule families.

Each entry maps a check_id short name (last segment after the last dot)
to a policy dict with:
  - verdict_policy: str — when the finding is TP vs FP (detection only)
  - rule_kind: str — informational | best_practice | security_audit | security_config
    Used as weak guidance for the model, not a forced security label.
"""
from __future__ import annotations

RULE_POLICIES: dict[str, dict] = {
    "dockerfile-source-not-pinned": {
        "verdict_policy": (
            "true_positive if the FROM image uses a tag (e.g. :latest, :3.11) "
            "without a digest pin (@sha256:...). false_positive only if the "
            "image is pinned to a specific digest."
        ),
        "rule_kind": "security_config",
    },
    "dangerous-subprocess-use-audit": {
        "verdict_policy": (
            "true_positive if a subprocess/os.system/os.popen call uses a "
            "non-static (dynamic/variable) string argument at the flagged line. "
            "false_positive if the flagged call only uses static/hardcoded "
            "string literals. The finding is about dynamic arguments in "
            "subprocess calls, not mere subprocess presence — but if a dynamic "
            "argument IS used, the finding is true_positive regardless of "
            "whether the input appears trusted."
        ),
        "rule_kind": "security_audit",
    },
    "subprocess-shell-true": {
        "verdict_policy": (
            "true_positive if shell=True is passed to a subprocess call. The "
            "finding flags the use of shell=True itself, not just exploitability."
        ),
        "rule_kind": "security_audit",
    },
    "use-raise-for-status": {
        "verdict_policy": (
            "true_positive if an HTTP response is used without calling "
            ".raise_for_status(). The finding flags the absence of "
            "raise_for_status() itself — alternative status checking does NOT "
            "make this a false_positive. false_positive only if "
            "raise_for_status() is actually called on the response."
        ),
        "rule_kind": "best_practice",
    },
    "unspecified-open-encoding": {
        "verdict_policy": (
            "true_positive if open() is called without an explicit encoding "
            "parameter. false_positive only if encoding is specified."
        ),
        "rule_kind": "best_practice",
    },
    "default-mutable-dict": {
        "verdict_policy": (
            "true_positive if a mutable default argument (dict, list, set) is "
            "used in a function signature. This is a code quality finding."
        ),
        "rule_kind": "best_practice",
    },
    "detect-generic-ai-oai": {
        "verdict_policy": (
            "true_positive if OpenAI library usage is detected in the code. "
            "This is an informational/detection finding."
        ),
        "rule_kind": "informational",
    },
    "detect-generic-ai-anthprop": {
        "verdict_policy": (
            "true_positive if Anthropic library usage is detected in the code. "
            "This is an informational/detection finding."
        ),
        "rule_kind": "informational",
    },
    "missing-user-entrypoint": {
        "verdict_policy": (
            "true_positive if the Dockerfile does not contain a USER instruction "
            "before the ENTRYPOINT/CMD. false_positive if USER is set."
        ),
        "rule_kind": "security_config",
    },
    "avoid-pickle": {
        "verdict_policy": (
            "true_positive if pickle.load/loads/Unpickler is used. The finding "
            "flags unsafe deserialization regardless of input source."
        ),
        "rule_kind": "security_audit",
    },
    "use-timeout": {
        "verdict_policy": (
            "true_positive if a requests call (get/post/put/delete/patch/head/"
            "options/request) is made without an explicit timeout parameter. "
            "false_positive only if a timeout is actually set on the call."
        ),
        "rule_kind": "best_practice",
    },
}


def get_rule_short_name(check_id: str) -> str:
    """Extract short name from check_id (last segment after last dot)."""
    # check_ids look like: rules.default-rules.python.lang.security.audit.subprocess-shell-true
    # We want: subprocess-shell-true
    parts = check_id.rsplit(".", 1)
    return parts[-1] if parts else check_id


def lookup_policy(check_id: str) -> dict | None:
    """Look up the policy for a check_id. Returns None if no match."""
    short_name = get_rule_short_name(check_id)
    return RULE_POLICIES.get(short_name)
