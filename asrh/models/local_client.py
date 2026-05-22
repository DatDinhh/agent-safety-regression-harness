"""Local OpenAI-compatible model client for ASRH.

This is intended for vLLM, LM Studio, Ollama OpenAI-compatible endpoints, or
other local servers exposing ``/v1/chat/completions``. It does not load weights
itself; ASRH remains a harness, not an inference runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from asrh.agents.base import ModelConfig, ModelResponse
from asrh.models.base import (
    DEFAULT_LOCAL_API_KEY,
    DEFAULT_LOCAL_BASE_URL,
    DEFAULT_LOCAL_MODEL,
    LOCAL_ENV_API_KEY,
    LOCAL_ENV_BASE_URL,
    PROVIDER_LOCAL,
    BaseModelClient,
    MessageInput,
    ProviderAPIError,
    ProviderClientConfig,
    ProviderNotInstalledError,
    append_action_format_reminder,
    env_text,
    finish_reason_from_response,
    messages_for_openai_chat,
    response_to_raw_mapping,
    token_usage_from_mapping,
)

LOCAL_ENV_MODEL: Final[str] = "ASRH_LOCAL_MODEL"


@dataclass(slots=True)
class LocalOpenAICompatibleClient(BaseModelClient):
    """OpenAI-compatible local chat-completions client."""

    base_url: str | None = None
    api_key: str | None = None
    default_model: str | None = None
    timeout_seconds: int | None = None

    provider: str = PROVIDER_LOCAL

    def __post_init__(self) -> None:
        default_model = self.default_model or env_text(LOCAL_ENV_MODEL) or DEFAULT_LOCAL_MODEL
        base_url = self.base_url or env_text(LOCAL_ENV_BASE_URL, default=DEFAULT_LOCAL_BASE_URL)
        api_key = self.api_key or env_text(LOCAL_ENV_API_KEY, default=DEFAULT_LOCAL_API_KEY)
        self.client_config = ProviderClientConfig(
            provider=self.provider,
            default_model=default_model,
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=int(self.timeout_seconds or 60),
        )
        self.default_model = default_model
        self._client = None

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def generate(self, messages: MessageInput, config: ModelConfig) -> ModelResponse:
        model_name = self.resolve_model_name(config, fallback=self.default_model or DEFAULT_LOCAL_MODEL)
        chat_messages = append_action_format_reminder(messages_for_openai_chat(messages), role="user")
        request: dict[str, Any] = {
            "model": model_name,
            "messages": chat_messages,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }
        if config.seed is not None:
            request["seed"] = config.seed
        try:
            response = self.client.chat.completions.create(**request)
        except TypeError:
            request.pop("seed", None)
            response = self.client.chat.completions.create(**request)
        except Exception as exc:  # noqa: BLE001
            raise ProviderAPIError(f"local OpenAI-compatible call failed: {exc}") from exc

        choice = response.choices[0]
        message = getattr(choice, "message", None)
        content = getattr(message, "content", "") or ""
        usage = getattr(response, "usage", None)
        input_tokens, output_tokens = token_usage_from_mapping(
            usage,
            input_keys=("prompt_tokens", "input_tokens"),
            output_keys=("completion_tokens", "output_tokens"),
        )
        return self.normalize_response(
            content=content,
            raw=response_to_raw_mapping(response),
            config=config,
            model_name=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            finish_reason=getattr(choice, "finish_reason", None) or finish_reason_from_response(response),
        )

    def _build_client(self) -> Any:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise ProviderNotInstalledError(
                "Install local OpenAI-compatible support with: pip install -e '.[openai]' or pip install openai"
            ) from exc
        return OpenAI(
            api_key=self.client_config.api_key or DEFAULT_LOCAL_API_KEY,
            base_url=self.client_config.base_url or DEFAULT_LOCAL_BASE_URL,
            timeout=self.client_config.timeout_seconds,
        )


def build_local_model_client(model: str | None = None, **kwargs: Any) -> LocalOpenAICompatibleClient:
    default_model = None
    if model:
        default_model = str(model).split("/", 1)[1] if "/" in str(model) else str(model)
    return LocalOpenAICompatibleClient(default_model=default_model or DEFAULT_LOCAL_MODEL, **kwargs)


LocalModelClient = LocalOpenAICompatibleClient
OpenAICompatibleLocalClient = LocalOpenAICompatibleClient

__all__: Final[tuple[str, ...]] = (
    "LocalModelClient",
    "LocalOpenAICompatibleClient",
    "OpenAICompatibleLocalClient",
    "build_local_model_client",
)
