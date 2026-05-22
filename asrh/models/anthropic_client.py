"""Anthropic Claude provider client for ASRH.

The client uses Claude as a text generator for ASRH JSON actions. It does not
expose Anthropic tool-use to the model; ASRH keeps all tools simulated and
policy-controlled inside the local sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from asrh.agents.base import ModelConfig, ModelResponse
from asrh.models.base import (
    ACTION_FORMAT_REMINDER,
    ANTHROPIC_ENV_API_KEY,
    DEFAULT_ANTHROPIC_MODEL,
    PROVIDER_ANTHROPIC,
    BaseModelClient,
    MessageInput,
    ModelConfigurationError,
    ProviderAPIError,
    ProviderClientConfig,
    ProviderNotInstalledError,
    append_action_format_reminder,
    env_text,
    finish_reason_from_response,
    messages_for_anthropic,
    require_api_key,
    response_to_raw_mapping,
    token_usage_from_mapping,
)

ANTHROPIC_ENV_MODEL: Final[str] = "ASRH_ANTHROPIC_MODEL"
ANTHROPIC_ENV_STRICT_JSON_PREFILL: Final[str] = "ASRH_ANTHROPIC_JSON_PREFILL"


@dataclass(slots=True)
class AnthropicModelClient(BaseModelClient):
    """Anthropic Messages API client."""

    api_key: str | None = None
    default_model: str | None = None
    timeout_seconds: int | None = None
    json_prefill: bool | None = None

    provider: str = PROVIDER_ANTHROPIC

    def __post_init__(self) -> None:
        default_model = self.default_model or env_text(ANTHROPIC_ENV_MODEL) or DEFAULT_ANTHROPIC_MODEL
        api_key = self.api_key or env_text(ANTHROPIC_ENV_API_KEY)
        self.client_config = ProviderClientConfig(
            provider=self.provider,
            default_model=default_model,
            api_key=api_key,
            timeout_seconds=int(self.timeout_seconds or 60),
        )
        self.default_model = default_model
        self._client = None
        if self.json_prefill is None:
            raw = env_text(ANTHROPIC_ENV_STRICT_JSON_PREFILL, default="true") or "true"
            self.json_prefill = raw.strip().lower() in {"1", "true", "yes", "on"}

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def generate(self, messages: MessageInput, config: ModelConfig) -> ModelResponse:
        model_name = self.resolve_model_name(config, fallback=self.default_model or DEFAULT_ANTHROPIC_MODEL)
        system, anthropic_messages = messages_for_anthropic(messages)
        anthropic_messages = append_action_format_reminder(anthropic_messages, role="user")

        # A small assistant prefill improves JSON compliance without granting tools.
        if self.json_prefill:
            anthropic_messages = [*anthropic_messages, {"role": "assistant", "content": "{"}]

        request: dict[str, Any] = {
            "model": model_name,
            "messages": anthropic_messages,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }
        if system:
            request["system"] = system

        try:
            response = self.client.messages.create(**request)
        except TypeError:
            # Some SDK versions/providers are picky about temperature on certain models.
            request.pop("temperature", None)
            try:
                response = self.client.messages.create(**request)
            except Exception as exc:  # noqa: BLE001
                raise ProviderAPIError(f"Anthropic Messages call failed after retry: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            raise ProviderAPIError(f"Anthropic Messages call failed: {exc}") from exc

        content = extract_anthropic_text(response)
        if self.json_prefill and content and not content.lstrip().startswith("{"):
            content = "{" + content
        usage = getattr(response, "usage", None)
        input_tokens, output_tokens = token_usage_from_mapping(
            usage,
            input_keys=("input_tokens", "prompt_tokens"),
            output_keys=("output_tokens", "completion_tokens"),
        )
        return self.normalize_response(
            content=content,
            raw=response_to_raw_mapping(response),
            config=config,
            model_name=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            finish_reason=finish_reason_from_response(response),
        )

    def _build_client(self) -> Any:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise ProviderNotInstalledError(
                "Install Anthropic support with: pip install -e '.[anthropic]' or pip install anthropic"
            ) from exc
        api_key = require_api_key(self.client_config.api_key, env_name=ANTHROPIC_ENV_API_KEY, provider="Anthropic")
        kwargs: dict[str, Any] = {"api_key": api_key, "timeout": self.client_config.timeout_seconds}
        return anthropic.Anthropic(**kwargs)


def extract_anthropic_text(response: Any) -> str:
    """Extract text blocks from a Claude Messages response."""
    parts: list[str] = []
    content = getattr(response, "content", None)
    if content is not None:
        for block in content:
            block_type = getattr(block, "type", None)
            text = getattr(block, "text", None)
            if text is not None and (block_type is None or str(block_type) == "text"):
                parts.append(str(text))
    if parts:
        return "\n".join(parts).strip()

    raw = response_to_raw_mapping(response)
    for block in raw.get("content", []) if isinstance(raw.get("content"), list) else []:
        if isinstance(block, dict) and block.get("text"):
            parts.append(str(block["text"]))
    if parts:
        return "\n".join(parts).strip()
    if raw.get("text"):
        return str(raw["text"]).strip()
    raise ModelConfigurationError("Anthropic response did not contain text content")


def build_anthropic_model_client(model: str | None = None, **kwargs: Any) -> AnthropicModelClient:
    default_model = None
    if model:
        default_model = str(model).split("/", 1)[1] if "/" in str(model) else str(model)
    return AnthropicModelClient(default_model=default_model or DEFAULT_ANTHROPIC_MODEL, **kwargs)


ClaudeModelClient = AnthropicModelClient
AnthropicClient = AnthropicModelClient

__all__: Final[tuple[str, ...]] = (
    "AnthropicClient",
    "AnthropicModelClient",
    "ClaudeModelClient",
    "build_anthropic_model_client",
    "extract_anthropic_text",
)
