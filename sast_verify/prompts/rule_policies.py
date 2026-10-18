"""Deterministic verdict policies and verdict constraints for known SAST rule families.

Each entry maps a check_id short name to:
  - verdict_policy: str — when the finding is TP vs FP
  - rule_kind: str — informational | best_practice | correctness_lint | security_audit | security_config
  - heuristic: bool — True when the scanner's match does NOT by itself establish the defect, so a
    textual hit is not a true positive. Such rules never fall back to "pattern exists → TP".
  - constraints: list[str] — checklist of facts the analyzer MUST verify before deciding
"""
from __future__ import annotations

# These rules are loose keyword matches that exist to inventory *AI usage*. A mention of the
# vendor's name is not usage, so the checklist asks about the role of the match, not its presence.
def _ai_usage_constraints(vendor: str) -> list[str]:
    return [
        "Read the flagged line and its file: is it executable code, a manifest/config, or prose/comment text?",
        f"Is it an import/require of the {vendor} SDK, construction or call of its client, a request to its "
        "API, or a dependency/provider declaration that wires it in?",
        "Is the match only inside a comment, docstring, description field, changelog/README text, or a string "
        "or constant that merely names an internal package or export path?",
        "In a package manifest only a dependency key (dependencies, devDependencies, peerDependencies, "
        f"optionalDependencies, peerDependenciesMeta) naming the {vendor} SDK counts. A description, keywords, "
        "scripts entry, or an `exports`/`bin`/`files` path that merely contains the vendor name does not. In a "
        "build or tooling config, an entry that names this project's own module does not count.",
        "Judge the flagged line/span itself. A dependency declared elsewhere in the same file does not turn "
        "a description, prose or path line into usage; only the matched line's own role counts.",
        "Do not claim another file imports, constructs or calls the SDK unless you opened it and can quote that "
        "line; a doc comment saying the package has NO runtime dependency on the SDK means it is not used.",
        f"VERDICT: TP only if {vendor} is actually used or declared as a dependency. FP if the word appears "
        "only as text (comment, prose, name of a package this project publishes, file or directory name).",
    ]


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
        "heuristic": True,
        "verdict_policy": (
            "true_positive only if the flagged line is real OpenAI usage: an import/require of the "
            "OpenAI SDK, constructing or calling its client, a request to the OpenAI API, or a "
            "dependency/provider declaration that wires it in. false_positive if the match is only "
            "the word in a comment, docstring, prose, a description field, or a string/constant "
            "that names a package or path."
        ),
        "rule_kind": "informational",
        "constraints": _ai_usage_constraints("OpenAI/openai"),
    },
    "detect-generic-ai-anthprop": {
        "heuristic": True,
        "verdict_policy": (
            "true_positive only if the flagged line is real Anthropic usage: an import/require of the "
            "Anthropic SDK, constructing or calling its client, a request to the Anthropic API, or a "
            "dependency/provider declaration that wires it in. false_positive if the match is only "
            "the word in a comment, docstring, prose, a description field, or a string/constant "
            "that names a package or path."
        ),
        "rule_kind": "informational",
        "constraints": _ai_usage_constraints("Anthropic/anthropic"),
    },
    "detect-generic-ai-api": {
        "heuristic": True,
        "verdict_policy": (
            "true_positive only if the flagged line makes or configures a real HTTP request to an AI "
            "service API. false_positive if it is only a mention in a comment, docstring, prose or a "
            "string that is not used as a request target."
        ),
        "rule_kind": "informational",
        "constraints": _ai_usage_constraints("an AI service"),
    },
    "detect-openai": {
        "heuristic": True,
        "verdict_policy": (
            "true_positive only if the flagged line is real OpenAI SDK usage (import, client "
            "construction/call, or a dependency declaration). false_positive if it is only the word "
            "in a comment, docstring, prose or a string/constant that names a package or path."
        ),
        "rule_kind": "informational",
        "constraints": _ai_usage_constraints("OpenAI/openai"),
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
    "missing-template-string-indicator": {
        "heuristic": True,
        "verdict_policy": (
            "true_positive only if the matched `{...}` is meant to be interpolated: it sits in a template "
            "literal as `{name}` / `{expr}` naming something in scope that would otherwise print literally "
            "instead of its value. false_positive if the braces are literal text (set or schema notation "
            "such as `{ ES256, EdDSA }`, JSON/object examples, regex quantifiers, usage/help text, "
            "placeholders) or the `{` already belongs to a `${...}` expression (e.g. an object literal "
            "inside `JSON.stringify({...})`)."
        ),
        "rule_kind": "correctness_lint",
        "constraints": [
            "Read the matched span, not just the line: where exactly do the braces sit within the template literal?",
            "Is the `{` part of an existing `${ ... }` expression (object literal, block) rather than template text?",
            "Would a reader expect the braced text to be replaced by a runtime value, or is it notation "
            "describing a set, schema, or placeholder?",
            "VERDICT: TP only if a `$` is genuinely missing. Literal notation is FP even though the pattern text exists.",
        ],
    },
    "useless-assignment": {
        "heuristic": True,
        "verdict_policy": (
            "true_positive only if the same storage location is written twice with no read in between, "
            "so the first write is lost. false_positive if the writes target different locations "
            "(e.g. `out[oi++] = a; out[oi++] = b;` — the post-increment moves the index) or the first "
            "value is read before the second write."
        ),
        "rule_kind": "correctness_lint",
        "constraints": [
            "Do both assignments name the same location once side effects (`i++`, `++i`, calls) are evaluated?",
            "Is the first assigned value read before the second write?",
            "VERDICT: FP when index/target expressions differ after evaluating side effects.",
        ],
    },
    "useless-ternary": {
        "verdict_policy": (
            "true_positive if both branches of the conditional are the same expression, so the condition "
            "has no effect. false_positive if the branches differ."
        ),
        "rule_kind": "correctness_lint",
        "constraints": [
            "Are the two branches byte-identical expressions?",
            "VERDICT: TP if identical (a copy-paste defect, not a vulnerability). FP if they differ.",
        ],
    },
    "html-in-template-string": {
        "heuristic": True,
        "verdict_policy": (
            "true_positive only if the template literal builds markup that is delivered as HTML (response "
            "body, innerHTML, rendered page, HTML email) with an unescaped interpolation. false_positive "
            "if the angle-bracket text is placeholder notation or the string only goes to a log, CLI "
            "message or stderr, where HTML is never interpreted."
        ),
        "rule_kind": "correctness_lint",
        "constraints": [
            "Is the angle-bracket text a real HTML tag or a placeholder such as `<method>` / `<id>`?",
            "Where does the resulting string go — a browser/HTML consumer, or a log, error or terminal?",
            "VERDICT: FP when the output is never rendered as HTML.",
        ],
    },
    "detected-jwt-token": {
        "heuristic": True,
        "verdict_policy": (
            "true_positive only if the string is a real JWT (base64url JOSE header carrying `alg`, payload, "
            "signature) that works as a credential. false_positive if it is not a JWT at all, is an "
            "obvious placeholder, or is an inert sample in docs or test vectors."
        ),
        "rule_kind": "security_audit",
        "constraints": [
            "Decode the first segment: is it a JOSE header with `alg`?",
            "Is the signature segment real, or a placeholder word?",
            "Is the file a test vector, fixture or documentation sample signed with a public/test key?",
            "VERDICT: FP when not a JWT or an inert placeholder; a real secret in config/source is TP.",
        ],
    },
    "github-actions-mutable-action-tag": {
        "verdict_policy": (
            "true_positive if the step's `uses:` ref is a tag or branch rather than a 40-character commit "
            "SHA. false_positive if it is a full SHA, a local `./` action, or a digest-pinned image."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            "Quote the `uses:` line. Is the part after `@` a 40-hex SHA?",
            "Security flag: only when the action is NOT GitHub-owned AND its job holds secrets or write permissions.",
            "VERDICT: TP for any tag/branch ref; the reason must not claim the workflow is pinned unless the quoted line is.",
        ],
    },
    "third-party-action-not-pinned-to-commit-sha": {
        "verdict_policy": (
            "true_positive if a non-GitHub-owned action is referenced by a tag/branch instead of a "
            "40-character commit SHA. false_positive if pinned to a full SHA."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            "Quote the `uses:` line. Is the part after `@` a 40-hex SHA?",
            "Security flag: only when the job holds secrets or write permissions that the action can abuse.",
            "VERDICT: TP for any tag/branch ref; the reason must not claim the workflow is pinned unless the quoted line is.",
        ],
    },
}

def _supply_chain_setting(setting: str, where: str) -> dict:
    return {
        "verdict_policy": (
            f"true_positive if `{setting}` is absent or too weak in every place the package manager reads "
            f"it ({where}). false_positive if it is set adequately there, or inherited from a preset/extended "
            "config you can read. Either way this is dependency hardening, not an exploitable flaw."
        ),
        "rule_kind": "best_practice",
        "constraints": [
            f"Search the effective configuration for `{setting}` ({where}).",
            "VERDICT: TP if no effective setting exists. Do not mark FP merely because the code is not attacker-reachable.",
        ],
    }


RULE_POLICIES.update({
    "npm-missing-minimum-release-age": _supply_chain_setting("min-release-age", ".npmrc"),
    "pnpm-minimum-release-age": _supply_chain_setting("minimumReleaseAge", "pnpm-workspace.yaml, .npmrc"),
    "pnpm-block-exotic-sub-dependencies": _supply_chain_setting("blockExoticSubdeps", "pnpm-workspace.yaml, .npmrc"),
    "pnpm-trust-policy": _supply_chain_setting("trustPolicy", "pnpm-workspace.yaml, .npmrc"),
    "renovate-missing-minimum-release-age": _supply_chain_setting(
        "minimumReleaseAge", "the flagged packageRules entry, top-level config, or an extended preset"),
})


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


# check_id fragments that mark a data-flow / taint / injection rule. For these,
# a real source→sink flow is *constitutive of the pattern*, so reachability/taint
# legitimately bears on the VERDICT. For every other rule (the pattern-existence
# majority) the verdict is a pure at-site presence check and reachability must
# not decide it — it may only lower is_security_vulnerability / severity.
TAINT_CHECK_ID_SUBSTRINGS = (
    "sql-injection", "sqli", "xss", "cross-site-scripting", "ssrf",
    "path-traversal", "directory-traversal", "command-injection",
    "os-command", "code-injection", "rce", "remote-code-execution",
    "tainted", "taint", "injection", "deserial", "unpickle", "insecure-load",
    "xxe", "xml-external", "open-redirect", "ldap-injection", "nosql",
    "template-injection", "ssti", "log-injection", "header-injection",
)


def is_taint_class(check_id: str, finding=None) -> bool:
    """True when the rule's verdict is a data-flow question (reachability decides it).

    Every family in RULE_POLICIES is pattern-existence, so a known check_id is
    never taint-class. Unknown check_ids are classified by check_id fragment and
    by whether the scanner attached taint metadata / a tainted context-graph path.
    """
    if get_rule_short_name(check_id) in RULE_POLICIES:
        return False
    cid = check_id.lower()
    if any(s in cid for s in TAINT_CHECK_ID_SUBSTRINGS):
        return True
    if finding is not None:
        if getattr(finding, "taint_source", None) or getattr(finding, "taint_sink", None):
            return True
        cg = getattr(finding, "context_graph", None)
        if isinstance(cg, dict) and any(p.get("tainted") for p in (cg.get("paths") or [])):
            return True
    return False


def rule_kind_of(check_id: str, finding=None) -> str:
    """Best-effort rule_kind label for prompt grounding.

    Returns the known RULE_POLICIES kind, else 'taint_class' for data-flow rules,
    else 'pattern_existence'.
    """
    policy = lookup_policy(check_id)
    if policy:
        return policy.get("rule_kind", "pattern_existence")
    return "taint_class" if is_taint_class(check_id, finding) else "pattern_existence"


# Rules that inventory AI usage in *source*. Prose can describe AI but cannot use it, so a match
# in a documentation or ignore file is a false positive without needing a model to read it.
AI_USAGE_RULES = frozenset({
    "detect-generic-ai-oai", "detect-generic-ai-anthprop", "detect-generic-ai-api", "detect-openai",
})
PROSE_SUFFIXES = frozenset({".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc"})


def is_prose_file(path: str) -> bool:
    """Documentation / ignore files: text a reader sees, never code a program runs."""
    name = path.rsplit("/", 1)[-1].lower()
    return name.endswith(tuple(PROSE_SUFFIXES)) or (name.startswith(".") and name.endswith("ignore"))
