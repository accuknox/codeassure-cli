"""Deterministic verdicts for rules whose truth is a mechanical fact about the flagged text.

An LLM adds nothing to "is this `uses:` ref a 40-char SHA?" — and a small model gets it wrong
(a reason that says "all actions are pinned" on an unpinned line, a different security flag for
byte-identical lines). Each checker here returns a decisive Verdict, or None to defer to the model.
They only ever decide on facts read from the source; anything ambiguous returns None.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from .prompts.rule_policies import get_rule_short_name
from .schema import Finding, Verdict

_UNPINNED_ACTION_RULES = frozenset({
    "github-actions-mutable-action-tag",
    "third-party-action-not-pinned-to-commit-sha",
})
_FIRST_PARTY_ACTION_OWNERS = frozenset({"actions", "github"})

_USES = re.compile(r"""\buses\s*:\s*['"]?([^\s'"#]+)""")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_DOCKER_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
_SECRET_REF = re.compile(r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)([A-Za-z0-9_]+)")
_JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$")
_PERM_LINE = re.compile(r"^(\s*)permissions\s*:\s*(\S.*)?$")
_PERM_ENTRY = re.compile(r"^\s*([A-Za-z-]+)\s*:\s*(read|write|none)\b")
# Writing any of these lets code that runs in the job change what the project publishes.
_PUBLISH_SCOPES = frozenset({"id-token", "contents", "packages", "deployments"})


def _source_lines(finding: Finding, codebase: Path) -> list[str] | None:
    try:
        return (codebase / finding.path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None


def _parse_permissions(lines: list[str], start: int, end: int, indent: str) -> dict[str, str] | None:
    """Permissions declared at exactly `indent` within lines[start:end], or None if absent.

    `read-all`/`write-all` expand to a single "*" entry.
    """
    for i in range(start, end):
        m = _PERM_LINE.match(lines[i])
        if not m or m.group(1) != indent:
            continue
        inline = (m.group(2) or "").split("#")[0].strip()
        if inline in ("read-all", "write-all"):
            return {"*": inline.split("-")[0]}
        if inline == "{}":
            return {}
        perms: dict[str, str] = {}
        for nxt in lines[i + 1:end]:
            if nxt.strip() and not nxt.startswith(indent + " "):
                break
            em = _PERM_ENTRY.match(nxt)
            if em:
                perms[em.group(1)] = em.group(2)
        return perms
    return None


def _job_bounds(lines: list[str], idx: int) -> tuple[int, int, str | None]:
    """(start, end, job_id) of the job containing lines[idx]; whole file when not in `jobs:`."""
    jobs_at = next((i for i, ln in enumerate(lines) if ln.rstrip() == "jobs:"), None)
    if jobs_at is None or idx <= jobs_at:
        return 0, len(lines), None
    start, job_id = None, None
    for i in range(idx, jobs_at, -1):
        m = _JOB_HEADER.match(lines[i])
        if m:
            start, job_id = i, m.group(1)
            break
    if start is None:
        return 0, len(lines), None
    end = next((i for i in range(start + 1, len(lines)) if _JOB_HEADER.match(lines[i])), len(lines))
    return start, end, job_id


def _job_privileges(lines: list[str], idx: int) -> dict:
    """What code running in the flagged step's job can touch."""
    start, end, job_id = _job_bounds(lines, idx)
    jobs_at = next((i for i, ln in enumerate(lines) if ln.rstrip() == "jobs:"), len(lines))
    job_perms = _parse_permissions(lines, start, end, "    ") if job_id else None
    top_perms = _parse_permissions(lines, 0, jobs_at, "")
    perms = job_perms if job_perms is not None else top_perms
    scope = f"job '{job_id}'" if job_id else "workflow"

    write_scopes = sorted(k for k, v in (perms or {}).items() if v == "write")
    secrets = sorted(set(_SECRET_REF.findall("\n".join(lines[start:end]))))
    publish = bool(secrets) or "*" in write_scopes or any(s in _PUBLISH_SCOPES for s in write_scopes)
    return {
        "scope": scope,
        "write_scopes": write_scopes,
        "secrets": secrets,
        "permissions_declared": perms is not None,
        "privileged": bool(write_scopes or secrets),
        "publish_grade": publish,
    }


def _describe_privileges(p: dict) -> str:
    bits = []
    if p["write_scopes"]:
        bits.append("write access to " + ", ".join(p["write_scopes"]))
    if p["secrets"]:
        bits.append("repository secrets " + ", ".join(p["secrets"]))
    if not bits:
        bits.append("a read-only token and no secrets" if p["permissions_declared"]
                    else "no declared permissions and no secrets")
    return f"{p['scope']} has " + " and ".join(bits)


def check_unpinned_action(finding: Finding, codebase: Path) -> Verdict | None:
    lines = _source_lines(finding, codebase)
    idx = finding.line - 1
    if lines is None or not (0 <= idx < len(lines)):
        return None
    m = _USES.search(lines[idx])
    if not m:
        return None  # flagged line is not a `uses:` step — let the model look
    ref = m.group(1)
    where = [f"{finding.path}:{finding.line}"]

    def verdict(v: str, reason: str, *, sec: bool = False, sev: str = "low") -> Verdict:
        return Verdict(
            verdict=v, is_security_vulnerability=sec, severity=sev, confidence="high",
            reason=reason, evidence_locations=where,
            source_trust="external_service" if v == "true_positive" else "hardcoded",
            taint_flow_verified=None,
            execution_trace=[f"{where[0]} — `uses: {ref}`"],
        )

    if ref.startswith("./"):
        return verdict("false_positive", f"`{ref}` is a local action from this repository's own "
                       "checkout; there is no external ref to pin.")
    if ref.startswith("docker://"):
        if _DOCKER_DIGEST.search(ref):
            return verdict("false_positive", f"`{ref}` is pinned to an image digest.")
        return verdict("true_positive", f"`{ref}` references a container image by a mutable tag "
                       "instead of a sha256 digest.")
    if "@" not in ref:
        return None
    action, _, version = ref.rpartition("@")
    if _FULL_SHA.match(version):
        return verdict("false_positive", f"`{action}` is pinned to the full commit SHA {version[:12]}…; "
                       "the ref cannot be silently repointed.")

    owner = action.split("/", 1)[0].lower()
    first_party = owner in _FIRST_PARTY_ACTION_OWNERS
    rule = get_rule_short_name(finding.check_id)
    if rule == "third-party-action-not-pinned-to-commit-sha" and first_party:
        return verdict("false_positive", f"`{action}` is published by GitHub itself, not a third party "
                       "as the rule claims.")

    priv = _job_privileges(lines, idx)
    facts = _describe_privileges(priv)
    kind = "GitHub-owned" if first_party else "third-party"
    base = (f"`{action}` ({kind}) is referenced by the movable ref `{version}` instead of a 40-character "
            f"commit SHA, so the publisher can silently change the code that runs here; {facts}.")
    if first_party:
        return verdict("true_positive", base + " Pinning is hardening; GitHub-owned actions are a "
                       "low-probability supply-chain target.")
    if not priv["privileged"]:
        return verdict("true_positive", base + " A retargeted tag could run code on the runner but "
                       "has no secrets or write permissions to abuse, so this is hardening.")
    return verdict(
        "true_positive",
        base + " A retargeted tag would execute attacker code with those privileges (token theft, "
        "tampering with published artifacts).",
        sec=True, sev="medium" if priv["publish_grade"] else "low",
    )


# --- detected-jwt-token ---------------------------------------------------------------------

_JWT_LIKE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*){1,2}")


def _b64url_json(segment: str):
    try:
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, UnicodeDecodeError):
        return None


def check_jwt_token(finding: Finding, codebase: Path) -> Verdict | None:
    """FP when the matched `eyJ…` blob is not a JOSE-headed token (a JWT header must carry `alg`)."""
    text = finding.match_text or finding.lines
    m = _JWT_LIKE.search(text or "")
    if not m:
        return None
    token = m.group(0)
    header = _b64url_json(token.split(".", 1)[0])
    if isinstance(header, dict) and "alg" in header:
        return None  # structurally a JWT — whether it is a live credential needs the model
    shown = json.dumps(header)[:80] if header is not None else "undecodable data"
    return Verdict(
        verdict="false_positive", is_security_vulnerability=False, severity="low", confidence="high",
        reason=f"The `eyJ…` string only looks like a JWT: its first segment decodes to {shown}, which is "
        "not a JOSE header (no `alg`), so this is not a token and exposes no credential.",
        evidence_locations=[f"{finding.path}:{finding.line}"], source_trust="hardcoded",
        execution_trace=[f"{finding.path}:{finding.line} — decoded first token segment: {shown}"],
    )


# --- missing-template-string-indicator ------------------------------------------------------

_BACKWARD_WINDOW = 6000


def _inside_interpolation(source: bytes, pos: int) -> bool:
    """True when `pos` sits inside a `${ … }` expression of the enclosing template literal.

    Scans backwards for an unmatched `{`: if it is directly preceded by `$` the position is in an
    interpolated expression; a bare unmatched `{` (object literal / block) is stepped over. Stops
    at the backtick that opens the template. Used only to prove a false positive.
    """
    depth = 0
    lo = max(0, pos - _BACKWARD_WINDOW)
    for i in range(pos - 1, lo - 1, -1):
        ch = source[i:i + 1]
        if ch == b"}":
            depth += 1
        elif ch == b"{":
            if depth:
                depth -= 1
            elif source[i - 1:i] == b"$":
                return True
        elif ch == b"`" and depth == 0:
            return False
    return False


def _template_literal_segments(source: bytes, open_tick: int) -> list[bytes] | None:
    """Literal (non-`${…}`) text of the template literal opened by the backtick at `open_tick`.

    None when it cannot be parsed with confidence (nested template inside an interpolation, or no
    closing backtick nearby) — the caller then defers to the model.
    """
    segments: list[bytes] = []
    cur = bytearray()
    i, limit = open_tick + 1, min(len(source), open_tick + _BACKWARD_WINDOW)
    while i < limit:
        ch = source[i:i + 1]
        if ch == b"\\":
            cur += source[i:i + 2]
            i += 2
        elif ch == b"`":
            segments.append(bytes(cur))
            return segments
        elif source[i:i + 2] == b"${":
            segments.append(bytes(cur))
            cur = bytearray()
            depth, i = 1, i + 2
            while i < limit and depth:
                c = source[i:i + 1]
                if c == b"`":
                    return None  # nested template: too ambiguous to judge mechanically
                depth += (c == b"{") - (c == b"}")
                i += 1
        else:
            cur += ch
            i += 1
    return None


def check_template_indicator(finding: Finding, codebase: Path) -> Verdict | None:
    """The rule asks "did you forget the `$` before `{…}`?". If the `{` already belongs to a `${…}`
    expression (an object literal inside `JSON.stringify({…})`, or the `${` itself), nothing is missing."""
    if finding.col is None:
        return None
    try:
        raw = (codebase / finding.path).read_bytes()
    except OSError:
        return None
    line_starts = [0]
    for i, b in enumerate(raw):
        if b == 0x0A:
            line_starts.append(i + 1)
    if not (1 <= finding.line <= len(line_starts)):
        return None
    pos = line_starts[finding.line - 1] + finding.col - 1
    if not (0 <= pos < len(raw)):
        return None
    text = finding.match_text or ""
    starts_interp = raw[pos:pos + 2] == b"${"
    inside = starts_interp or _inside_interpolation(raw, pos)
    braces_only_in_code = False
    if not inside and raw[pos:pos + 1] == b"`":
        segments = _template_literal_segments(raw, pos)
        braces_only_in_code = segments is not None and not any(b"{" in seg or b"}" in seg for seg in segments)
    if not (inside or braces_only_in_code):
        return None
    why = ("starts at a `${` that already interpolates" if starts_interp else
           "lies inside a `${ … }` expression, so the braces are code (e.g. an object literal), not template text"
           if inside else
           "covers a template literal whose own text contains no braces — every `{` belongs to a "
           "`${ … }` expression, so none is a forgotten interpolation")
    return Verdict(
        verdict="false_positive", is_security_vulnerability=False, severity="low", confidence="high",
        reason=f"Nothing is missing a `$`: the matched span {why}.",
        evidence_locations=[f"{finding.path}:{finding.line}"], source_trust="hardcoded",
        execution_trace=[f"{finding.path}:{finding.line}:{finding.col} — matched `{text[:60]}` {why}"],
    )


_CHECKERS = {
    **{r: check_unpinned_action for r in _UNPINNED_ACTION_RULES},
    "detected-jwt-token": check_jwt_token,
    "missing-template-string-indicator": check_template_indicator,
}


def decide(finding: Finding, codebase: Path) -> Verdict | None:
    """Deterministic verdict for this finding, or None when the model must decide."""
    checker = _CHECKERS.get(get_rule_short_name(finding.check_id))
    if checker is None:
        return None
    try:
        return checker(finding, codebase)
    except Exception:
        return None  # a checker bug must never lose the finding — defer to the model
