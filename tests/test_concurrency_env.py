import pytest

from sast_verify import config


def _load(monkeypatch, tmp_path, **env):
    monkeypatch.chdir(tmp_path)
    for key in ("CODEASSURE_CONCURRENCY", "CODEASSURE_MODEL_NAME"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return config.load_config()


def test_env_config_defaults_to_higher_concurrency(monkeypatch, tmp_path):
    cfg = _load(monkeypatch, tmp_path, CODEASSURE_MODEL_NAME="m")
    assert cfg.effective_concurrency == 24


def test_concurrency_env_overrides_config(monkeypatch, tmp_path):
    cfg = _load(monkeypatch, tmp_path, CODEASSURE_MODEL_NAME="m", CODEASSURE_CONCURRENCY="40")
    assert cfg.effective_concurrency == 40


def test_concurrency_env_overrides_config_file(monkeypatch, tmp_path):
    (tmp_path / "codeassure.json").write_text('{"model": {"provider": "openai", "name": "m"}, "concurrency": 3}')
    cfg = _load(monkeypatch, tmp_path, CODEASSURE_CONCURRENCY="12")
    assert cfg.effective_concurrency == 12


@pytest.mark.parametrize("bad", ["0", "-2", "many"])
def test_invalid_concurrency_env_rejected(monkeypatch, tmp_path, bad):
    cfg = _load(monkeypatch, tmp_path, CODEASSURE_MODEL_NAME="m", CODEASSURE_CONCURRENCY=bad)
    with pytest.raises(ValueError):
        cfg.effective_concurrency
