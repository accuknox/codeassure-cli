import json
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

from sast_verify.cli import main
from sast_verify.schema import Verdict


def test_cli_builds_real_graph_before_ai_and_preserves_report(tmp_path):
    (tmp_path / "app.py").write_text("import subprocess\ndef run(command):\n    subprocess.run(command, shell=True)\n")
    finding = {"check_id": "python.command-injection", "path": "app.py",
               "start": {"line": 3}, "end": {"line": 3},
               "extra": {"lines": "subprocess.run(command, shell=True)", "severity": "ERROR", "metadata": {"impact": "HIGH"}}}
    report = tmp_path / "results.json"
    report.write_text(json.dumps({"results": [finding], "repo_url": "https://example.test/repo", "sha": "new-revision"}))
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"model": {"provider": "openai", "name": "test"}, "enrichment": False}))
    async def analyze(bundles, **kwargs):
        assert bundles[0].finding.context_graph["nodes"]
        assert bundles[0].evidence
        return [Verdict(verdict="true_positive", is_security_vulnerability=True,
                        confidence="high", severity="high", reason="Attacker-controlled command reaches the shell.")]
    with patch.object(sys, "argv", ["codeassure", "--codebase", str(tmp_path), "--findings", str(report), "--output", str(report), "--config", str(config), "--graph-no-joern"]), patch("sast_verify.pipeline.analyze_all", side_effect=analyze):
        main()
    result = json.loads(report.read_text())
    assert result["sha"] == "new-revision"
    assert result["graph_analysis"]["generated"] == 1
    assert result["results"][0]["verification"]["analysis_status"] == "completed"
    assert result["results"][0]["context_graph"]["sink"]["file"] == "app.py"
    assert any(n.get("function") == "run" for n in result["results"][0]["context_graph"]["nodes"])
    assert result["ai_sast"]["analyzed"] == 1


def test_write_output_distinguishes_skipped_and_provider_fallback(tmp_path):
    from sast_verify.pipeline import _write_output
    path = tmp_path / "results.json"
    path.write_text(json.dumps({"results": [{"check_id": "a"}, {"check_id": "b"}]}))
    verdict = Verdict(verdict="false_positive", confidence="low", reason="LLM analysis unavailable (timeout)")
    _write_output(path, path, [verdict, verdict], analysis_statuses={0: "fallback", 1: "skipped"})
    document = json.loads(path.read_text())
    assert document["ai_sast"]["status"] == "partial"
    assert document["ai_analysis"] is False
    assert "verification" not in document["results"][1]
    assert document["results"][0]["verification"]["analysis_status"] == "fallback"


def test_model_config_env_refs_and_fallback(monkeypatch, tmp_path):
    from sast_verify import config as cfg

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CODEASSURE_MODEL_NAME", "m1")
    monkeypatch.setenv("CODEASSURE_MODEL_PROVIDER", "anthropic")
    monkeypatch.setenv("CODEASSURE_API_KEY", "k")
    loaded = cfg.load_config(None)
    assert (loaded.model.provider, loaded.model.name, loaded._resolve_api_key()) == ("anthropic", "m1", "k")

    monkeypatch.setenv("MY_MODEL", "m2")
    assert cfg.ModelConfig(provider="openai", name="$MY_MODEL").name == "m2"


def test_openai_client_drops_unknown_service_tier():
    import asyncio, json, httpx
    from sast_verify.config import _openai_http_client

    def handler(request):
        return httpx.Response(200, json={"id": "x", "service_tier": "asap", "choices": []})

    async def run():
        client = _openai_http_client()
        client._transport = httpx.MockTransport(handler)
        r = await client.post("http://t/v1/chat/completions", json={})
        return r.json()

    assert "service_tier" not in asyncio.run(run())


def _v(verdict, sec=True, reason="r"):
    from sast_verify.schema import Verdict
    return Verdict(verdict=verdict, is_security_vulnerability=sec, confidence="high", reason=reason)


def test_wants_enrichment_matrix():
    from sast_verify.pipeline import _wants_enrichment as w
    tp_sec, tp_best = _v("true_positive", True), _v("true_positive", False)
    fp, unc = _v("false_positive", False), _v("uncertain", True)
    fallback = _v("true_positive", True, "LLM analysis unavailable: x")
    assert [w("tp", v) for v in (tp_sec, tp_best, fp, unc, fallback)] == [True, True, False, False, False]
    assert [w("security", v) for v in (tp_sec, tp_best, fp, unc, fallback)] == [True, False, False, False, False]
    assert all(w("all", v) for v in (tp_sec, tp_best, fp, unc, fallback))


def test_enrich_mode_env_overrides_config(monkeypatch):
    import pytest
    from sast_verify.config import Config, ModelConfig
    cfg = Config(model=ModelConfig(provider="openai", name="m"))
    monkeypatch.delenv("CODEASSURE_ENRICH", raising=False)
    assert cfg.enrich_mode == "security"                 # default
    assert Config(model=cfg.model, enrich="tp").enrich_mode == "tp"
    assert Config(model=cfg.model, enrichment=False).enrich_mode == "off"
    monkeypatch.setenv("CODEASSURE_ENRICH", "ALL")
    assert Config(model=cfg.model, enrichment=False).enrich_mode == "all"
    monkeypatch.setenv("CODEASSURE_ENRICH", "bogus")
    with pytest.raises(ValueError):
        cfg.enrich_mode


def test_policy_skipped_enrichment_is_labelled(tmp_path):
    import json
    from sast_verify.agents.enrich import fallback_enrichment
    from sast_verify.pipeline import _write_output
    from sast_verify.schema import EvidenceBundle
    from sast_verify.preprocess import preprocess_data
    raw = {"results": [{"check_id": "r", "path": "a.py", "start": {"line": 1}, "end": {"line": 1},
                        "extra": {"message": "m", "lines": "x", "metadata": {"impact": "HIGH"}}}]}
    src, dst = tmp_path / "in.json", tmp_path / "out.json"
    src.write_text(json.dumps(raw))
    findings = preprocess_data(raw, codebase=tmp_path)
    v = _v("false_positive", False)
    fb = lambda i, verdict: fallback_enrichment(EvidenceBundle(finding=findings[i], evidence=[]), verdict,
                                                skipped="not requested for this verdict (CODEASSURE_ENRICH=security)")
    _write_output(src, dst, [v], findings=findings, codebase=tmp_path, enrich_fallback=fb)
    ver = json.loads(dst.read_text())["results"][0]["verification"]
    assert ver["enrichment_status"] == "skipped"
    assert "not requested" in ver["remediation"]["notes"]
