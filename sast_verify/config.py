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
    temperature: float | None = Field(default=0.0, description="Sampling temperature (0.0 = deterministic; recommended default so verdicts are stable run-to-run). Raise (e.g. 0.5) only with voting_rounds>1, which needs sampling diversity. Set null to use model default.")


class ValidatorConfig(BaseModel):
    """Second-opinion validator. Skipped entirely when enabled=False."""
    enabled: bool = Field(default=False, description="Run validator after each verdict")
    provider: str = Field(default="google-vertex", description="'google-vertex', 'google-gla', 'openai', or 'openai-compatible'")
    name: str = Field(description="Validator model name, e.g. 'gemini-3.1-pro-preview'")
    project: str | None = Field(default=None, description="GCP project for Vertex (else uses GOOGLE_CLOUD_PROJECT env)")
    location: str | None = Field(default=None, description="Vertex location, e.g. 'global' (else GOOGLE_CLOUD_LOCATION)")
    api_key: str | None = Field(default=None, description="API key for non-Vertex providers")
    api_base: str | None = Field(default=None, description="Override base URL (OpenAI-compatible only)")


class FindingPolicy(BaseModel):
    """Controls what the model considers a true positive."""
    best_practice_is_tp: bool = Field(
        default=True,
        description="Treat best-practice findings (missing timeout, missing encoding, mutable defaults) as TP if the pattern exists",
    )
    informational_detection_is_tp: bool = Field(
        default=True,
        description="Treat informational detection findings (detect-openai, detect-anthropic) as TP if the library is used",
    )
    audit_rule_is_tp: bool = Field(
        default=True,
        description="Treat audit-rule findings (subprocess usage, pickle usage) as TP if the call exists, regardless of input trust",
    )


class Config(BaseModel):
    model: ModelConfig
    concurrency: int = Field(default=7, ge=1)
    stage_timeout: int = Field(default=120, ge=10, description="Seconds per LLM stage (analyzer or formatter)")
    finding_timeout: int = Field(default=300, ge=30, description="Seconds for the entire finding (both stages + repair)")
    grep_max_file_kb: int = Field(default=512, ge=1, description="Skip files larger than this in grep (KB)")
    grep_max_scan_mb: int = Field(default=5, ge=1, description="Stop grep scanning after this many MB read")
    request_limit: int = Field(default=200, ge=1, description="Max requests per agent.run() call (reasoning models need more)")
    retries: int = Field(default=4, ge=0, description="Retries per LLM call on transient errors (rate limits, 5xx, timeouts, connection drops) with exponential backoff")
    evaluator: bool = Field(default=False, description="Run a second evaluator LLM pass on each verdict (consistency check + severity review). Doubles LLM calls; the structured analyzer already assigns severity, so keep off unless using a weak local model.")
    voting_rounds: int = Field(default=1, ge=1, description="Run each finding N times and take majority verdict (3 recommended for non-deterministic local models)")
    max_tokens: int | None = Field(default=4096, description="Max completion tokens per LLM call. Set to null for uncapped.")
    finding_policy: FindingPolicy = Field(default_factory=FindingPolicy, description="Controls what counts as true_positive")
    validator: ValidatorConfig | None = Field(default=None, description="Optional second-opinion validator (e.g. Gemini via Vertex)")
    findings_analysis: bool = Field(
        default=False,
        description="Set to true for finding_only mode: LLM sees only the scanner-captured snippet, no file reads or tools.",
    )
    enrichment: bool = Field(
        default=True,
        description="Run the enrichment + graph-coloring pass after each verdict "
        "(rationale, business logic, explanation, copy-paste remediation, colored context graph). "
        "One extra LLM call per decided finding.",
    )
    thinking_map: dict[str, ThinkingMode] | None = Field(
        # default_factory=lambda: dict(_DEFAULT_THINKING_MAP),
        default=None,
        description="Severity → thinking effort mapping (e.g. {\"ERROR\": \"full\", \"WARNING\": \"low\", \"INFO\": \"off\"}). "
        "Set to null/omit to disable (no extra_body sent).",
    )

    def base_model_settings(self) -> dict[str, Any] | None:
        """Return base model_settings with temperature, or None if nothing to set."""
        if self.model.temperature is None:
            return None
        return {"temperature": self.model.temperature}

    def get_thinking_settings(self, severity: str) -> dict[str, Any] | None:
        """Return model_settings dict for the given severity, or None if thinking control is disabled."""
        base = self.base_model_settings() or {}
        if self.thinking_map is None:
            return base or None
        mode = self.thinking_map.get(severity.upper(), "low")  # default to low for unknown severities
        thinking = thinking_model_settings(mode)
        return {**base, **thinking}

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

    def build_validator_model(self):
        """Build a PydanticAI model for the validator. Branches on provider."""
        if self.validator is None:
            raise RuntimeError("validator is not configured")
        v = self.validator
        if v.provider in ("google-vertex", "google-gla"):
            from pydantic_ai.models.google import GoogleModel
            from pydantic_ai.providers.google import GoogleProvider
            kwargs: dict = {}
            if v.provider == "google-vertex":
                kwargs["vertexai"] = True
                if v.project:
                    kwargs["project"] = v.project
                if v.location:
                    kwargs["location"] = v.location
            elif v.api_key:
                kwargs["api_key"] = v.api_key
            return GoogleModel(v.name, provider=GoogleProvider(**kwargs))
        if v.provider in _OPENAI_COMPATIBLE_PROVIDERS:
            from pydantic_ai.models.openai import OpenAIChatModel
            from pydantic_ai.providers.openai import OpenAIProvider
            kwargs = {}
            if v.api_base:
                kwargs["base_url"] = v.api_base
            if v.api_key:
                kwargs["api_key"] = v.api_key
            return OpenAIChatModel(v.name, provider=OpenAIProvider(**kwargs))
        raise ValueError(f"Unsupported validator provider: {v.provider!r}")

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
