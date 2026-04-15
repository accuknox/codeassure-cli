from __future__ import annotations

import json
import os
from pathlib import Path

from typing import Any, Literal

from pydantic import BaseModel, Field


_OPENAI_COMPATIBLE_PROVIDERS = frozenset({"openai", "openai-compatible"})
_ANTHROPIC_PROVIDERS = frozenset({"anthropic"})
_GOOGLE_PROVIDERS = frozenset({"google", "gemini"})
_ALL_SUPPORTED_PROVIDERS = _OPENAI_COMPATIBLE_PROVIDERS | _ANTHROPIC_PROVIDERS | _GOOGLE_PROVIDERS

ThinkingMode = Literal["full", "low", "off"]

# Default severity → thinking-effort mapping for reasoning models
_DEFAULT_THINKING_MAP: dict[str, ThinkingMode] = {
    "ERROR": "full",
    "WARNING": "low",
    "INFO": "off",
}


def thinking_model_settings(mode: ThinkingMode) -> dict[str, Any]:
    """Build PydanticAI model_settings with extra_body for Nemotron thinking control."""
    if mode == "full":
        return {"extra_body": {"chat_template_kwargs": {"enable_thinking": True}}}
    elif mode == "low":
        return {"extra_body": {"chat_template_kwargs": {"enable_thinking": True, "low_effort": True}}}
    else:  # off
        return {"extra_body": {"chat_template_kwargs": {"enable_thinking": False}}}


class ModelConfig(BaseModel):
    provider: str = Field(description="Provider: 'openai', 'openai-compatible', 'anthropic', 'google', or 'gemini'")
    name: str = Field(description="Model name as known by the provider")
    api_base: str | None = Field(default=None, description="API base URL (for self-hosted endpoints)")
    api_key: str | None = Field(default=None, description="API key (overrides env vars; supports $VAR_NAME syntax for env var references)")
    tool_calling: bool = Field(default=True, description="Set to false for models that don't support tool/function calling")


class Config(BaseModel):
    model: ModelConfig
    concurrency: int = Field(default=4, ge=1)
    stage_timeout: int = Field(default=120, ge=10, description="Seconds per LLM stage (analyzer or formatter)")
    finding_timeout: int = Field(default=300, ge=30, description="Seconds for the entire finding (both stages + repair)")
    grep_max_file_kb: int = Field(default=512, ge=1, description="Skip files larger than this in grep (KB)")
    grep_max_scan_mb: int = Field(default=5, ge=1, description="Stop grep scanning after this many MB read")
    request_limit: int = Field(default=200, ge=1, description="Max requests per agent.run() call (reasoning models need more)")
    thinking_map: dict[str, ThinkingMode] | None = Field(
        # default_factory=lambda: dict(_DEFAULT_THINKING_MAP),
        default=None,
        description="Severity → thinking effort mapping (e.g. {\"ERROR\": \"full\", \"WARNING\": \"low\", \"INFO\": \"off\"}). "
        "Set to null/omit to disable (no extra_body sent).",
    )

    def get_thinking_settings(self, severity: str) -> dict[str, Any] | None:
        """Return model_settings dict for the given severity, or None if thinking control is disabled."""
        if self.thinking_map is None:
            return None
        mode = self.thinking_map.get(severity.upper(), "low")  # default to low for unknown severities
        return thinking_model_settings(mode)

    @property
    def litellm_model(self) -> str:
        return f"{self.model.provider}/{self.model.name}"

    def _resolve_api_key(self) -> str | None:
        """Resolve API key from config.

        - Literal value: ``"api_key": "sk-abc123"``
        - Env var reference: ``"api_key": "$OPENROUTER_API_KEY"``
        """
        raw = self.model.api_key
        if raw is None:
            return None
        if raw.startswith("$"):
            return os.environ.get(raw[1:])
        return raw
    
    def build_model(self):
        if self.model.provider not in _ALL_SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unsupported provider {self.model.provider!r}. "
                f"Supported: {sorted(_ALL_SUPPORTED_PROVIDERS)}"
            )

        api_key = self._resolve_api_key()

        if self.model.provider in _OPENAI_COMPATIBLE_PROVIDERS:
            from pydantic_ai.models.openai import OpenAIChatModel
            from pydantic_ai.providers.openai import OpenAIProvider
            kwargs: dict = {}
            if self.model.api_base:
                base = self.model.api_base.rstrip("/")
                kwargs["base_url"] = base if base.endswith("/v1") else f"{base}/v1"
            if api_key is not None:
                kwargs["api_key"] = api_key
            return OpenAIChatModel(self.model.name, provider=OpenAIProvider(**kwargs))

        if self.model.provider in _ANTHROPIC_PROVIDERS:
            from pydantic_ai.models.anthropic import AnthropicModel
            from pydantic_ai.providers.anthropic import AnthropicProvider
            kwargs = {}
            if self.model.api_base:
                base = self.model.api_base.rstrip("/")
                kwargs["base_url"] = base[:-3] if base.endswith("/v1") else base
            if api_key is not None:
                kwargs["api_key"] = api_key
            return AnthropicModel(self.model.name, provider=AnthropicProvider(**kwargs))

        # google / gemini
        from pydantic_ai.models.google import GoogleModel
        from pydantic_ai.providers.google import GoogleProvider
        kwargs = {}
        if self.model.api_base:
            kwargs["base_url"] = self.model.api_base
        if api_key is not None:
            kwargs["api_key"] = api_key
        return GoogleModel(self.model.name, provider=GoogleProvider(**kwargs))

    def apply(self) -> None:
        """Set LiteLLM env vars from config. API keys come from .env / environment."""
        if self.model.api_base:
            prefix = self.model.provider.upper()
            os.environ.setdefault(f"{prefix}_API_BASE", self.model.api_base)


_active: Config | None = None


def load_config(path: Path | None = None) -> Config:
    global _active
    search = [path] if path else []
    search.append(Path("codeassure.json"))

    for p in search:
        if p and p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            _active = Config.model_validate(data)
            _active.apply()
            return _active

    raise FileNotFoundError(
        "No codeassure.json found. Create one or pass --config <path>."
    )


def get_config() -> Config:
    if _active is None:
        raise RuntimeError("Config not loaded. Call load_config() first.")
    return _active
