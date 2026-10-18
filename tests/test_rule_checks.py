"""Deterministic rule checks, same-line clustering and the heuristic-rule fallback.

Fixtures mirror real false/true positives from scanning agent-protocol, where identical findings
received contradictory verdicts and a reason that denied the flagged code.
"""
import base64
import json
from pathlib import Path

from sast_verify.agents.runner import _deterministic_fallback
from sast_verify.pipeline import _cluster_same_line
from sast_verify.preprocess import preprocess_data
from sast_verify.rule_checks import decide
from sast_verify.schema import Evidence, EvidenceBundle

SHA = "a" * 40
RULE_MUTABLE = "x.github-actions-mutable-action-tag"
RULE_THIRD = "x.third-party-action-not-pinned-to-commit-sha"

RELEASE = f"""\
name: Release
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: pnpm/action-setup@{SHA}
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
      - env:
          NODE_AUTH_TOKEN: ${{{{ secrets.NPM_TOKEN }}}}
        run: pnpm publish
"""


def _item(rule, path, line, col=1, end_col=2, text="", start_off=0, end_off=0):
    return {
        "check_id": rule, "path": path,
        "start": {"line": line, "col": col, "offset": start_off},
        "end": {"line": line, "col": end_col, "offset": end_off},
        "extra": {"message": "m", "severity": "WARNING", "lines": text},
    }


def _findings(tmp_path, items):
    return preprocess_data({"results": items}, tmp_path)


def _workflow_finding(tmp_path, rule, content, needle, nth=0):
    wf = tmp_path / ".github/workflows/w.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(content)
    line = [i for i, ln in enumerate(content.splitlines(), 1) if needle in ln][nth]
    return _findings(tmp_path, [_item(rule, ".github/workflows/w.yml", line, text=content.splitlines()[line - 1])])[0]


# --- unpinned actions ------------------------------------------------------------------------

def test_full_sha_is_false_positive(tmp_path):
    f = _workflow_finding(tmp_path, RULE_MUTABLE, RELEASE, f"action-setup@{SHA}")
    assert decide(f, tmp_path).verdict == "false_positive"


def test_mutable_tag_is_true_positive_even_when_surrounding_actions_differ(tmp_path):
    f = _workflow_finding(tmp_path, RULE_MUTABLE, RELEASE, "pnpm/action-setup@v4")
    v = decide(f, tmp_path)
    assert v.verdict == "true_positive"
    assert "pnpm/action-setup" in v.reason and "v4" in v.reason


def test_third_party_in_read_only_job_is_hardening_not_security(tmp_path):
    f = _workflow_finding(tmp_path, RULE_THIRD, RELEASE, "pnpm/action-setup@v4", nth=0)
    v = decide(f, tmp_path)
    assert (v.verdict, v.is_security_vulnerability, v.severity) == ("true_positive", False, "low")
    assert "read-only token" in v.reason


def test_privilege_is_resolved_per_job_not_per_file(tmp_path):
    # Same action, same file: only the job that holds id-token/contents write and NPM_TOKEN is a risk.
    build = _workflow_finding(tmp_path, RULE_THIRD, RELEASE, "pnpm/action-setup@v4", nth=0)
    publish = _workflow_finding(tmp_path, RULE_THIRD, RELEASE, "pnpm/action-setup@v4", nth=1)
    assert decide(build, tmp_path).is_security_vulnerability is False
    v = decide(publish, tmp_path)
    assert (v.is_security_vulnerability, v.severity) == (True, "medium")
    assert "NPM_TOKEN" in v.reason and "id-token" in v.reason


def test_github_owned_action_is_never_security_even_in_privileged_job(tmp_path):
    f = _workflow_finding(tmp_path, RULE_MUTABLE, RELEASE, "actions/setup-node@v4")
    v = decide(f, tmp_path)
    assert (v.verdict, v.is_security_vulnerability) == ("true_positive", False)


def test_third_party_rule_does_not_apply_to_github_owned_action(tmp_path):
    f = _workflow_finding(tmp_path, RULE_THIRD, RELEASE, "actions/checkout@v4")
    assert decide(f, tmp_path).verdict == "false_positive"


def test_identical_lines_get_identical_verdicts(tmp_path):
    a = _workflow_finding(tmp_path, RULE_MUTABLE, RELEASE, "pnpm/action-setup@v4", nth=0)
    b = a.model_copy()
    va, vb = decide(a, tmp_path), decide(b, tmp_path)
    assert va.model_dump() == vb.model_dump()


def test_non_uses_line_defers_to_model(tmp_path):
    wf = tmp_path / "w.yml"
    wf.write_text("name: x\n")
    f = _findings(tmp_path, [_item(RULE_MUTABLE, "w.yml", 1, text="name: x")])[0]
    assert decide(f, tmp_path) is None


# --- JWT -------------------------------------------------------------------------------------

def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def test_jwt_shaped_blob_without_jose_header_is_false_positive(tmp_path):
    blob = f"{_b64({'idx': [1, 2, 3], 'iat': 1})}.PLACEHOLDER_AWAITING_GENERATOR"
    f = _findings(tmp_path, [_item("x.detected-jwt-token", "v.jsonld", 3, text=f'"x": "{blob}"')])[0]
    v = decide(f, tmp_path)
    assert v.verdict == "false_positive" and "JOSE" in v.reason


def test_real_jwt_structure_defers_to_model(tmp_path):
    jwt = f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': '1'})}.c2lnbmF0dXJl"
    f = _findings(tmp_path, [_item("x.detected-jwt-token", "c.ts", 3, text=f'const t = "{jwt}"')])[0]
    assert decide(f, tmp_path) is None


# --- missing-template-string-indicator -------------------------------------------------------

RULE_TPL = "x.missing-template-string-indicator"


def _tpl_finding(tmp_path, source, needle, rule=RULE_TPL):
    p = tmp_path / "m.ts"
    p.write_text(source)
    raw = source.encode()
    start = raw.index(needle.encode())
    line = raw[:start].count(b"\n") + 1
    col = start - (raw.rfind(b"\n", 0, start) + 1) + 1
    item = _item(rule, "m.ts", line, col=col, end_col=col + len(needle), text=source.splitlines()[line - 1],
                 start_off=start, end_off=start + len(needle))
    return _findings(tmp_path, [item])[0]


def test_object_literal_inside_interpolation_is_false_positive(tmp_path):
    src = "const s = `${JSON.stringify({\n  ok: false,\n  e: { code: 1 },\n})}\\n`;\n"
    f = _tpl_finding(tmp_path, src, "{\n  ok: false")
    assert decide(f, tmp_path).verdict == "false_positive"


def test_match_starting_at_dollar_brace_is_false_positive(tmp_path):
    f = _tpl_finding(tmp_path, "const s = `${a} and ${b}`;\n", "${b}")
    assert decide(f, tmp_path).verdict == "false_positive"


def test_literal_braces_in_template_text_defer_to_model(tmp_path):
    src = "const m = `alg ${alg} not in set { ES256, EdDSA }`;\n"
    f = _tpl_finding(tmp_path, src, "{ ES256, EdDSA }")
    assert decide(f, tmp_path) is None  # notation vs. forgotten `$` is a judgement call


# --- match span plumbing ---------------------------------------------------------------------

def test_match_text_is_sliced_from_scanner_offsets(tmp_path):
    src = "const m = `x { ES256 } y`;\n"
    f = _tpl_finding(tmp_path, src, "{ ES256 }")
    assert f.match_text == "{ ES256 }" and f.col is not None


def test_match_text_dropped_when_checkout_disagrees_with_scan(tmp_path):
    (tmp_path / "m.ts").write_text("totally different content here\n")
    item = _item(RULE_TPL, "m.ts", 1, text="const m = `x { ES256 } y`;", start_off=14, end_off=23)
    assert _findings(tmp_path, [item])[0].match_text is None


# --- same-line clustering --------------------------------------------------------------------

def _bundles(tmp_path, items):
    return [(i, EvidenceBundle(finding=f, evidence=[])) for i, f in enumerate(_findings(tmp_path, items))]


def test_same_rule_same_line_matches_collapse_to_one_analysis(tmp_path):
    line = "msg = `a { X } b ${c} { Y }`"
    items = [_item(RULE_TPL, "m.ts", 5, col=c, end_col=c + 5, text=line) for c in (9, 25)]
    items.append(_item(RULE_TPL, "m.ts", 6, text="other"))
    kept, siblings = _cluster_same_line(_bundles(tmp_path, items))
    assert [i for i, _ in kept] == [0, 2] and siblings == {1: 0}
    assert len(kept[0][1].finding.sibling_spans) == 1


def test_different_rules_on_one_line_are_not_merged(tmp_path):
    items = [_item(f"x.{r}", "m.ts", 5, text="t") for r in ("rule-a", "rule-b")]
    kept, siblings = _cluster_same_line(_bundles(tmp_path, items))
    assert len(kept) == 2 and not siblings


# --- fallback --------------------------------------------------------------------------------

def _fb_bundle(tmp_path, rule):
    f = _findings(tmp_path, [_item(rule, "m.ts", 1, text="t")])[0]
    return EvidenceBundle(finding=f, evidence=[Evidence(path="m.ts", start_line=1, end_line=1, content="1: t")])


def test_heuristic_rule_never_falls_back_to_true_positive(tmp_path):
    for rule in ("x.missing-template-string-indicator", "x.detect-generic-ai-oai", "x.html-in-template-string"):
        v = _deterministic_fallback(_fb_bundle(tmp_path, rule), "timed out after 120s")
        assert v.verdict == "uncertain" and "timed out" in v.reason


def test_non_heuristic_pattern_rule_still_falls_back_to_true_positive(tmp_path):
    v = _deterministic_fallback(_fb_bundle(tmp_path, "x.use-timeout"), "timed out")
    assert v.verdict == "true_positive"


# --- garbled model output --------------------------------------------------------------------

def test_garbled_reason_is_detected():
    from sast_verify.agents.runner import _is_garbled
    from sast_verify.schema import Verdict

    def v(reason):
        return Verdict(verdict="true_positive", confidence="high", reason=reason)

    assert _is_garbled(v("The flag is absent. ██Because the pai 终端 fimbul"))
    assert _is_garbled(v("在 ci.yml:23 处确认了被标记的模式：这是一个第三方动作，未固定为完整的 commit SHA"))
    assert _is_garbled(v("pin " * 60))
    assert not _is_garbled(v("`pnpm/action-setup@v4` is referenced by a tag — see ci.yml:23 (em dash — fine)."))
    assert not _is_garbled(v(""))


def test_non_answer_reason_is_unusable():
    from sast_verify.agents.runner import _is_garbled
    from sast_verify.schema import Verdict

    for reason in ("I will read the surrounding files before deciding.", "Let me check the manifest first.", "ok"):
        assert _is_garbled(Verdict(verdict="true_positive", confidence="high", reason=reason))
    assert not _is_garbled(Verdict(verdict="true_positive", confidence="high",
                                   reason="Line 4 is a description string; no SDK is imported or declared there."))


def test_verdict_schema_puts_reasoning_before_the_verdict():
    from sast_verify.schema import Verdict

    props = list(Verdict.model_json_schema()["properties"])
    assert props.index("reason") < props.index("verdict")
    assert props.index("execution_trace") < props.index("verdict")


def test_whole_template_whose_text_has_no_braces_is_false_positive(tmp_path):
    # the scanner also reports the span of the entire template around an interpolated JSON.stringify({…})
    src = "w(`${JSON.stringify({ ok: true, e: { a: 1 } })}\\n`);\n"
    f = _tpl_finding(tmp_path, src, "`${JSON.stringify({ ok: true, e: { a: 1 } })}\\n`")
    assert decide(f, tmp_path).verdict == "false_positive"


def test_whole_template_with_literal_braces_still_defers(tmp_path):
    src = "const HELP = `usage --output {json,text} ${x}`;\n"
    f = _tpl_finding(tmp_path, src, "`usage --output {json,text} ${x}`")
    assert decide(f, tmp_path) is None
