"""OpenAI provider client for ASRH.

This client asks OpenAI models for the next ASRH JSON action. It does not give
OpenAI any real external tools; ASRH still executes all tools through its local
sandbox and policy layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from asrh.agents.base import ModelConfig, ModelResponse
from asrh.models.base import (
    DEFAULT_OPENAI_MODEL,
    OPENAI_ENV_API_KEY,
    OPENAI_ENV_BASE_URL,
    OPENAI_TEXT_JSON_SCHEMA_FORMAT,
    PROVIDER_OPENAI,
    ACTION_FORMAT_REMINDER,
    BaseModelClient,
    MessageInput,
    ModelConfigurationError,
    ProviderAPIError,
    ProviderClientConfig,
    ProviderNotInstalledError,
    append_action_format_reminder,
    bool_from_env,
    env_text,
    finish_reason_from_response,
    json_safe,
    messages_for_openai_chat,
    messages_for_openai_responses,
    require_api_key,
    response_to_raw_mapping,
    token_usage_from_mapping,
)

DEFAULT_STRUCTURED_OUTPUTS: Final[bool] = True
OPENAI_ENV_STRUCTURED_OUTPUTS: Final[str] = "ASRH_OPENAI_STRUCTURED_OUTPUTS"
OPENAI_ENV_STRUCTURED_FALLBACK: Final[str] = "ASRH_OPENAI_STRUCTURED_FALLBACK"
OPENAI_ENV_STORE: Final[str] = "ASRH_OPENAI_STORE"
OPENAI_ENV_USE_RESPONSES_API: Final[str] = "ASRH_OPENAI_USE_RESPONSES_API"


@dataclass(slots=True)
class OpenAIModelClient(BaseModelClient):
    """OpenAI Responses API client with Chat Completions fallback."""

    api_key: str | None = None
    base_url: str | None = None
    default_model: str = DEFAULT_OPENAI_MODEL
    timeout_seconds: int | None = None
    structured_outputs: bool | None = None
    allow_structured_fallback: bool | None = None
    use_responses_api: bool | None = None
    store: bool | None = None

    provider: str = PROVIDER_OPENAI

    def __post_init__(self) -> None:
        structured = bool_from_env(OPENAI_ENV_STRUCTURED_OUTPUTS, default=DEFAULT_STRUCTURED_OUTPUTS) if self.structured_outputs is None else bool(self.structured_outputs)
        fallback = bool_from_env(OPENAI_ENV_STRUCTURED_FALLBACK, default=True) if self.allow_structured_fallback is None else bool(self.allow_structured_fallback)
        timeout = int(self.timeout_seconds or 60)
        api_key = self.api_key or env_text(OPENAI_ENV_API_KEY)
        base_url = self.base_url or env_text(OPENAI_ENV_BASE_URL)
        self.client_config = ProviderClientConfig(
            provider=self.provider,
            default_model=self.default_model,
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=timeout,
            structured_outputs=structured,
            allow_structured_fallback=fallback,
        )
        self.default_model = self.default_model or DEFAULT_OPENAI_MODEL
        self._client = None
        self.use_responses_api = bool_from_env(OPENAI_ENV_USE_RESPONSES_API, default=True) if self.use_responses_api is None else bool(self.use_responses_api)
        self.store = bool_from_env(OPENAI_ENV_STORE, default=False) if self.store is None else bool(self.store)

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def generate(self, messages: MessageInput, config: ModelConfig) -> ModelResponse:
        model_name = self.resolve_model_name(config, fallback=self.default_model)
        if self.use_responses_api and hasattr(self.client, "responses"):
            return self._generate_responses_api(messages, config, model_name=model_name)
        return self._generate_chat_completions(messages, config, model_name=model_name)

    def _build_client(self) -> Any:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise ProviderNotInstalledError("Install OpenAI support with: pip install -e '.[openai]' or pip install openai") from exc

        api_key = require_api_key(self.client_config.api_key, env_name=OPENAI_ENV_API_KEY, provider="OpenAI")
        kwargs: dict[str, Any] = {"api_key": api_key, "timeout": self.client_config.timeout_seconds}
        if self.client_config.base_url:
            kwargs["base_url"] = self.client_config.base_url
        return OpenAI(**kwargs)

    def _generate_responses_api(self, messages: MessageInput, config: ModelConfig, *, model_name: str) -> ModelResponse:
        instructions, input_messages = messages_for_openai_responses(messages)
        input_messages = append_action_format_reminder(input_messages, role="user")
        request: dict[str, Any] = {
            "model": model_name,
            "input": input_messages,
            "temperature": config.temperature,
            "max_output_tokens": config.max_tokens,
            "store": self.store,
        }
        if instructions:
            request["instructions"] = instructions
        if config.seed is not None:
            request["seed"] = config.seed
        if self.client_config.structured_outputs:
            request["text"] = {"format": OPENAI_TEXT_JSON_SCHEMA_FORMAT}

        try:
            response = self.client.responses.create(**request)
        except TypeError as exc:
            response = self._retry_responses_without_unsupported_kwargs(request, exc)
        except Exception as exc:  # noqa: BLE001
            if self.client_config.structured_outputs and self.client_config.allow_structured_fallback:
                request.pop("text", None)
                try:
                    response = self.client.responses.create(**request)
                except Exception as fallback_exc:  # noqa: BLE001
                    raise ProviderAPIError(f"OpenAI Responses API call failed after structured-output fallback: {fallback_exc}") from fallback_exc
            else:
                raise ProviderAPIError(f"OpenAI Responses API call failed: {exc}") from exc

        content = extract_openai_responses_text(response)
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

    def _retry_responses_without_unsupported_kwargs(self, request: dict[str, Any], original: TypeError) -> Any:
        retry = dict(request)
        for key in ("seed", "store", "text"):
            retry.pop(key, None)
        try:
            return self.client.responses.create(**retry)
        except Exception as exc:  # noqa: BLE001
            raise ProviderAPIError(f"OpenAI Responses API call failed: {original}; retry failed: {exc}") from exc

    def _generate_chat_completions(self, messages: MessageInput, config: ModelConfig, *, model_name: str) -> ModelResponse:
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
            raise ProviderAPIError(f"OpenAI Chat Completions call failed: {exc}") from exc

        choice = response.choices[0]
        message = getattr(choice, "message", None)
        content = getattr(message, "content", "") or ""
        usage = getattr(response, "usage", None)
        input_tokens, output_tokens = token_usage_from_mapping(
            usage,
            input_keys=("prompt_tokens", "input_tokens"),
            output_keys=("completion_tokens", "output_tokens"),
        )
        finish_reason = getattr(choice, "finish_reason", None) or finish_reason_from_response(response)
        return self.normalize_response(
            content=content,
            raw=response_to_raw_mapping(response),
            config=config,
            model_name=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            finish_reason=None if finish_reason is None else str(finish_reason),
        )


def extract_openai_responses_text(response: Any) -> str:
    """Extract assistant text from an OpenAI Responses object."""
    output_text = getattr(response, "output_text", None)
    if output_text:
        return str(output_text).strip()

    raw = response_to_raw_mapping(response)
    if raw.get("output_text"):
        return str(raw["output_text"]).strip()

    parts: list[str] = []
    output = raw.get("output") or []
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content") or []
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text") or block.get("content")
                        if text:
                            parts.append(str(text))
            elif isinstance(content, str):
                parts.append(content)
    if parts:
        return "\n".join(parts).strip()

    # Last resort: preserve enough raw structure for parser debugging.
    if raw:
        return str(json_safe(raw.get("text", raw.get("message", "")))).strip()
    raise ModelConfigurationError("OpenAI response did not contain output_text or message content")


def build_openai_model_client(model: str | None = None, **kwargs: Any) -> OpenAIModelClient:
    default_model = None
    if model:
        default_model = str(model).split("/", 1)[1] if "/" in str(model) else str(model)
    return OpenAIModelClient(default_model=default_model or DEFAULT_OPENAI_MODEL, **kwargs)


OpenAIClient = OpenAIModelClient

__all__: Final[tuple[str, ...]] = (
    "OpenAIClient",
    "OpenAIModelClient",
    "build_openai_model_client",
    "extract_openai_responses_text",
)
