"""Deterministic verdict policies and verdict constraints for known SAST rule families.

Each entry maps a check_id short name to:
  - verdict_policy: str — when the finding is TP vs FP
  - rule_kind: str — informational | best_practice | security_audit | security_config
  - constraints: list[str] — checklist of facts the analyzer MUST verify before deciding
"""
from __future__ import annotations

RULE_POLICIES: dict[str, dict] = {
    "dangerous-subprocess-use-audit": {
        "verdict_policy": (
            "true_positive if a subprocess/os.system/os.popen call uses a "
            "non-static (dynamic/variable) string argument at the flagged line. "
            "false_positive if the flagged call only uses static/hardcoded "
            "string literals."
        ),
        "rule_kind": "security_audit",
        "constraints": [
            "Is there a subprocess/os.system/os.popen call at the flagged line?",
            "Is the command argument a static string literal, or does it include variables/f-strings/format()?",
            "If dynamic: what is the source of the variable? (user input, env var, API response, hardcoded config)",
            "Is shell=True used?",
            "Is any sanitization applied (shlex.quote, allowlist, etc.)?",
            "VERDICT: TP if dynamic argument exists, regardless of input trust. FP only if fully static.",
        ],
    },
    "subprocess-shell-true": {
        "verdict_policy": (
            "true_positive if shell=True is passed to a subprocess call. "
            "The finding flags the use of shell=True itself."
        ),
        "rule_kind": "security_audit",
        "constraints": [
            "Is shell=True passed to the subprocess call at the flagged line?",
            "VERDICT: TP if shell=True is present. FP only if shell=True is NOT present.",
        ],
    },
    "use-raise-for-status": {
        "verdict_policy": (
            "true_positive if an HTTP response is used without calling "
            ".raise_for_status(). false_positive only if raise_for_status() "
            "is actually called on the response."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            "Is there an HTTP request (requests.get/post/etc.) at the flagged line?",
            "Is .raise_for_status() called on the response object?",
            "VERDICT: TP if raise_for_status() is NOT called. FP only if it IS called.",
            "NOTE: Alternative status checking (if response.status_code) does NOT make this FP — it may affect is_security_vulnerability but not the verdict.",
        ],
    },
    "use-timeout": {
        "verdict_policy": (
            "true_positive if a requests call is made without an explicit timeout parameter. "
            "false_positive only if a timeout is actually set."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            "Is there a requests.get/post/put/delete/patch/head/options call at the flagged line?",
            "Does the call include a timeout= parameter?",
            "VERDICT: TP if no timeout parameter. FP only if timeout is explicitly set.",
        ],
    },
    "disabled-cert-validation": {
        "verdict_policy": (
            "true_positive if verify=False is passed to a requests call. "
            "false_positive only if verify is True or not set (defaults to True)."
        ),
        "rule_kind": "security_config",
        "constraints": [
            "Is there a requests call at the flagged line?",
            "Is verify=False explicitly passed?",
            "VERDICT: TP if verify=False. FP only if verify is True or omitted.",
        ],
    },
    "unspecified-open-encoding": {
        "verdict_policy": (
            "true_positive if open() is called without an explicit encoding parameter. "
            "false_positive only if encoding is specified."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            "Is there an open() call at the flagged line?",
            "Does the call include an encoding= parameter?",
            "VERDICT: TP if no encoding parameter. FP only if encoding is explicitly set.",
        ],
    },
    "default-mutable-dict": {
        "verdict_policy": (
            "true_positive if a mutable default argument (dict, list, set) is "
            "used in a function signature."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            "Is there a function definition at the flagged line?",
            "Does any parameter have a mutable default value (dict(), list(), set(), {}, [], etc.)?",
            "VERDICT: TP if mutable default exists. FP only if no mutable default.",
        ],
    },
    "detect-generic-ai-oai": {
        "verdict_policy": (
            "true_positive if OpenAI library usage is detected in the code."
        ),
        "rule_kind": "informational",
        "constraints": [
            "Is there an import, reference, or usage of OpenAI/openai at the flagged location?",
            "VERDICT: TP if OpenAI usage exists. FP only if no OpenAI reference found.",
        ],
    },
    "detect-generic-ai-anthprop": {
        "verdict_policy": (
            "true_positive if Anthropic library usage is detected in the code."
        ),
        "rule_kind": "informational",
        "constraints": [
            "Is there an import, reference, or usage of Anthropic/anthropic at the flagged location?",
            "VERDICT: TP if Anthropic usage exists. FP only if no reference found.",
        ],
    },
    "detect-generic-ai-api": {
        "verdict_policy": (
            "true_positive if AI API HTTP request usage is detected in the code."
        ),
        "rule_kind": "informational",
        "constraints": [
            "Is there an HTTP request to an AI service API at the flagged location?",
            "VERDICT: TP if AI API call exists. FP only if no such call found.",
        ],
    },
    "detect-openai": {
        "verdict_policy": (
            "true_positive if OpenAI SDK usage is detected in the code."
        ),
        "rule_kind": "informational",
        "constraints": [
            "Is there OpenAI SDK usage at the flagged location?",
            "VERDICT: TP if usage exists. FP only if no reference found.",
        ],
    },
    "missing-user-entrypoint": {
        "verdict_policy": (
            "true_positive if the Dockerfile does not contain a USER instruction "
            "before the ENTRYPOINT/CMD. false_positive if USER is set."
        ),
        "rule_kind": "security_config",
        "constraints": [
            "Is there a USER instruction in the Dockerfile before ENTRYPOINT/CMD?",
            "VERDICT: TP if no USER instruction. FP only if USER is set.",
        ],
    },
    "dockerfile-source-not-pinned": {
        "verdict_policy": (
            "true_positive if the FROM image uses a tag without a digest pin (@sha256:...). "
            "false_positive only if pinned to a specific digest."
        ),
        "rule_kind": "security_config",
        "constraints": [
            "Does the FROM instruction use a tag (e.g., :latest, :3.11)?",
            "Does it include a digest pin (@sha256:...)?",
            "VERDICT: TP if no digest pin. FP only if @sha256: digest is present.",
        ],
    },
    "avoid-pickle": {
        "verdict_policy": (
            "true_positive if pickle.load/loads/Unpickler is used."
        ),
        "rule_kind": "security_audit",
        "constraints": [
            "Is pickle.load, pickle.loads, or pickle.Unpickler called at the flagged line?",
            "VERDICT: TP if pickle deserialization exists. FP only if no pickle call found.",
        ],
    },
    "hardcoded-tmp-path": {
        "verdict_policy": (
            "true_positive if a hardcoded /tmp path is used instead of tempfile."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            "Is there a hardcoded /tmp path at the flagged line?",
            "Is tempfile.mkdtemp/NamedTemporaryFile used instead?",
            "VERDICT: TP if hardcoded /tmp. FP only if tempfile is used.",
        ],
    },
    "arbitrary-sleep": {
        "verdict_policy": (
            "true_positive if time.sleep() is called."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            "Is there a time.sleep() call at the flagged line?",
            "VERDICT: TP if sleep exists. FP only if no sleep call found.",
        ],
    },
}


# Generic constraints for unknown rules
GENERIC_CONSTRAINTS = [
    "Does the pattern described in the scanner's claim exist at the flagged line?",
    "If the pattern exists, are there any mitigations that fully neutralize it?",
    "VERDICT: TP if the pattern exists (per the finding policy). FP only if the pattern does not exist.",
]


def get_rule_short_name(check_id: str) -> str:
    """Extract short name from check_id (last segment after last dot)."""
    parts = check_id.rsplit(".", 1)
    return parts[-1] if parts else check_id


def lookup_policy(check_id: str) -> dict | None:
    """Look up the policy for a check_id. Returns None if no match."""
    short_name = get_rule_short_name(check_id)
    return RULE_POLICIES.get(short_name)


def get_constraints(check_id: str) -> list[str]:
    """Get the verdict constraint checklist for a check_id.

    Returns rule-specific constraints if known, otherwise generic constraints.
    """
    policy = lookup_policy(check_id)
    if policy and "constraints" in policy:
        return policy["constraints"]
    return GENERIC_CONSTRAINTS
