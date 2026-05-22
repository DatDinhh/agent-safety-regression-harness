"""Model-provider abstractions for ASRH.

ASRH deliberately keeps provider code behind a small interface. The agent loop
asks a model for one JSON action, while tools remain ASRH-owned and sandboxed.
Provider clients in this package therefore return text only; they do not expose
real shell, email, browser, or network tools to the model.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Protocol, TypeAlias, runtime_checkable

from asrh import (
    DEFAULT_REAL_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    SUPPORTED_MOCK_MODES,
    SUPPORTED_TOOLS,
)
from asrh.agents.base import Message, ModelConfig, ModelResponse

JsonDict: TypeAlias = dict[str, Any]
JsonMapping: TypeAlias = Mapping[str, Any]
RawMessage: TypeAlias = Mapping[str, Any] | Message
MessageInput: TypeAlias = Sequence[RawMessage]

PROVIDER_MOCK: Final[str] = "mock"
PROVIDER_OPENAI: Final[str] = "openai"
PROVIDER_ANTHROPIC: Final[str] = "anthropic"
PROVIDER_LOCAL: Final[str] = "local"
PROVIDER_OPENAI_COMPATIBLE: Final[str] = "openai_compatible"

SUPPORTED_PROVIDERS: Final[tuple[str, ...]] = (
    PROVIDER_MOCK,
    PROVIDER_OPENAI,
    PROVIDER_ANTHROPIC,
    PROVIDER_LOCAL,
    PROVIDER_OPENAI_COMPATIBLE,
)

OPENAI_ENV_API_KEY: Final[str] = "OPENAI_API_KEY"
OPENAI_ENV_BASE_URL: Final[str] = "OPENAI_BASE_URL"
ANTHROPIC_ENV_API_KEY: Final[str] = "ANTHROPIC_API_KEY"
LOCAL_ENV_BASE_URL: Final[str] = "ASRH_LOCAL_BASE_URL"
LOCAL_ENV_API_KEY: Final[str] = "ASRH_LOCAL_API_KEY"

DEFAULT_LOCAL_BASE_URL: Final[str] = "http://localhost:8000/v1"
DEFAULT_LOCAL_API_KEY: Final[str] = "EMPTY"
DEFAULT_LOCAL_MODEL: Final[str] = "local-model"
DEFAULT_OPENAI_MODEL: Final[str] = DEFAULT_REAL_MODEL.removeprefix("openai/")
DEFAULT_ANTHROPIC_MODEL: Final[str] = "claude-sonnet-4-5"

JSON_ACTION_SCHEMA_NAME: Final[str] = "asrh_agent_action"
JSON_ACTION_SCHEMA: Final[JsonDict] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "type": {"type": "string", "enum": ["tool_call", "final_answer"]},
        "tool": {
            "type": ["string", "null"],
            "enum": [*SUPPORTED_TOOLS, "list_emails", "read_email", "network_request", None],
        },
        "args": {"type": "object", "additionalProperties": True},
        "content": {"type": ["string", "null"]},
    },
    "required": ["type", "tool", "args", "content"],
}

OPENAI_TEXT_JSON_SCHEMA_FORMAT: Final[JsonDict] = {
    "type": "json_schema",
    "name": JSON_ACTION_SCHEMA_NAME,
    "schema": JSON_ACTION_SCHEMA,
    "strict": True,
}

ACTION_FORMAT_REMINDER: Final[str] = (
    "Return exactly one valid JSON object. Use "
    '{"type":"tool_call","tool":"read_file","args":{"path":"notes.txt"},"content":null} '
    "to call a tool, or "
    '{"type":"final_answer","tool":null,"args":{},"content":"..."} '
    "to finish. Do not include Markdown or prose outside the JSON object."
)

MODEL_IDENTIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<provider>[A-Za-z0-9_.-]+)[/:])?(?P<model>.+)$"
)


class ModelProvider(StrEnum):
    """Canonical ASRH model-provider names."""

    MOCK = PROVIDER_MOCK
    OPENAI = PROVIDER_OPENAI
    ANTHROPIC = PROVIDER_ANTHROPIC
    LOCAL = PROVIDER_LOCAL
    OPENAI_COMPATIBLE = PROVIDER_OPENAI_COMPATIBLE


class ModelError(RuntimeError):
    """Base exception for ASRH model providers."""


class ModelConfigurationError(ModelError):
    """Raised for invalid model-provider configuration."""


class ModelIdentifierError(ModelConfigurationError):
    """Raised when an ASRH model identifier cannot be parsed."""


class ProviderNotInstalledError(ModelConfigurationError):
    """Raised when an optional provider SDK is missing."""


class ProviderAuthenticationError(ModelConfigurationError):
    """Raised when a provider client requires an API key that is missing."""


class ProviderAPIError(ModelError):
    """Raised when a provider SDK call fails."""


class ModelOutputError(ModelError):
    """Raised when provider output cannot be normalized."""


@dataclass(frozen=True, slots=True)
class ModelIdentifier:
    """Parsed ASRH model identifier.

    Examples:
        ``openai/gpt-4o-mini`` -> provider ``openai``, model ``gpt-4o-mini``.
        ``anthropic/claude-sonnet-4-5`` -> provider ``anthropic``.
        ``mock/safe`` -> provider ``mock``, model ``safe``.
    """

    provider: str
    model_name: str
    raw: str

    def __post_init__(self) -> None:
        provider = normalize_provider(self.provider)
        model_name = require_non_blank(self.model_name, "model_name")
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "model_name", model_name)
        object.__setattr__(self, "raw", require_non_blank(self.raw, "raw"))

    @property
    def qualified(self) -> str:
        return f"{self.provider}/{self.model_name}"

    def to_dict(self) -> JsonDict:
        return {"provider": self.provider, "model_name": self.model_name, "raw": self.raw, "qualified": self.qualified}


@dataclass(frozen=True, slots=True)
class ProviderClientConfig:
    """Provider-client construction options."""

    provider: str
    default_model: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    structured_outputs: bool = False
    allow_structured_fallback: bool = True
    metadata: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", normalize_provider(self.provider))
        if self.default_model is not None:
            object.__setattr__(self, "default_model", require_non_blank(self.default_model, "default_model"))
        if self.api_key is not None:
            object.__setattr__(self, "api_key", str(self.api_key))
        if self.base_url is not None:
            object.__setattr__(self, "base_url", str(self.base_url).strip())
        object.__setattr__(self, "timeout_seconds", positive_int(self.timeout_seconds, "timeout_seconds"))
        object.__setattr__(self, "structured_outputs", bool(self.structured_outputs))
        object.__setattr__(self, "allow_structured_fallback", bool(self.allow_structured_fallback))
        object.__setattr__(self, "metadata", freeze_jsonable_mapping(self.metadata))

    def to_dict(self, *, include_secret_values: bool = False) -> JsonDict:
        return {
            "provider": self.provider,
            "default_model": self.default_model,
            "api_key": self.api_key if include_secret_values else redact_secret(self.api_key),
            "base_url": self.base_url,
            "timeout_seconds": self.timeout_seconds,
            "structured_outputs": self.structured_outputs,
            "allow_structured_fallback": self.allow_structured_fallback,
            "metadata": thaw_jsonable(self.metadata),
        }


@runtime_checkable
class ModelClient(Protocol):
    """Minimal model-client protocol expected by ASRH agents."""

    provider: str

    def generate(self, messages: MessageInput, config: ModelConfig) -> ModelResponse:
        ...


class BaseModelClient:
    """Common implementation shared by concrete provider clients."""

    provider: str = "base"

    def __init__(self, *, default_model: str | None = None, client_config: ProviderClientConfig | None = None) -> None:
        provider = normalize_provider(getattr(self, "provider", "base")) if getattr(self, "provider", "base") in SUPPORTED_PROVIDERS else str(getattr(self, "provider", "base"))
        self.client_config = client_config or ProviderClientConfig(provider=provider, default_model=default_model)
        self.default_model = default_model or self.client_config.default_model

    def generate(self, messages: MessageInput, config: ModelConfig) -> ModelResponse:  # pragma: no cover - abstract seam
        raise NotImplementedError

    def resolve_model_name(self, config: ModelConfig | None = None, *, fallback: str | None = None) -> str:
        raw = getattr(config, "model_name", None) if config is not None else None
        if raw:
            try:
                parsed = parse_model_identifier(raw, default_provider=self.provider)
            except ModelIdentifierError:
                parsed = None
            else:
                if parsed.provider in {self.provider, PROVIDER_OPENAI_COMPATIBLE} or self.provider in {PROVIDER_LOCAL, PROVIDER_OPENAI_COMPATIBLE}:
                    return parsed.model_name
                if "/" not in str(raw) and ":" not in str(raw):
                    return str(raw)
        if self.default_model:
            return self.default_model
        if fallback:
            return fallback
        raise ModelConfigurationError(f"no model name configured for provider {self.provider!r}")

    def normalize_response(
        self,
        *,
        content: str,
        raw: Any,
        config: ModelConfig,
        model_name: str,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        finish_reason: str | None = None,
    ) -> ModelResponse:
        return ModelResponse(
            content=content,
            raw={
                "provider": self.provider,
                "model_name": model_name,
                "response": json_safe(raw),
            },
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model_name=model_name or config.model_name,
            finish_reason=finish_reason,
        )


@dataclass(frozen=True, slots=True)
class MessageBundle:
    """Provider-neutral messages split into system and conversational parts."""

    system: str
    messages: tuple[JsonMapping, ...]

    @property
    def all_messages(self) -> tuple[JsonMapping, ...]:
        if not self.system:
            return self.messages
        return ({"role": "system", "content": self.system}, *self.messages)

    def to_dict(self) -> JsonDict:
        return {"system": self.system, "messages": [dict(item) for item in self.messages]}


def parse_model_identifier(value: str, *, default_provider: str = PROVIDER_LOCAL) -> ModelIdentifier:
    """Parse ``provider/model`` or ``provider:model`` identifiers."""
    raw = require_non_blank(value, "model identifier")
    match = MODEL_IDENTIFIER_PATTERN.match(raw)
    if not match:
        raise ModelIdentifierError(f"invalid model identifier: {value!r}")
    provider = match.group("provider") or default_provider
    model_name = match.group("model")
    if not model_name:
        raise ModelIdentifierError(f"model identifier missing model name: {value!r}")
    return ModelIdentifier(provider=normalize_provider(provider), model_name=model_name.strip(), raw=raw)


def normalize_provider(value: str) -> str:
    text = require_non_blank(value, "provider").strip().lower().replace("-", "_").replace(".", "_")
    aliases = {
        "claude": PROVIDER_ANTHROPIC,
        "anthropic_api": PROVIDER_ANTHROPIC,
        "gpt": PROVIDER_OPENAI,
        "oai": PROVIDER_OPENAI,
        "openai_compat": PROVIDER_OPENAI_COMPATIBLE,
        "openai_compatible": PROVIDER_OPENAI_COMPATIBLE,
        "local_openai": PROVIDER_LOCAL,
        "local_openai_compatible": PROVIDER_LOCAL,
        "vllm": PROVIDER_LOCAL,
        "ollama": PROVIDER_LOCAL,
        "lmstudio": PROVIDER_LOCAL,
        "lm_studio": PROVIDER_LOCAL,
    }
    text = aliases.get(text, text)
    if text not in SUPPORTED_PROVIDERS:
        raise ModelIdentifierError(f"unsupported provider {value!r}; expected one of {sorted(SUPPORTED_PROVIDERS)}")
    return text


def provider_from_model(value: str) -> str:
    return parse_model_identifier(value, default_provider=PROVIDER_LOCAL).provider


def strip_provider_prefix(value: str, *, provider: str) -> str:
    parsed = parse_model_identifier(value, default_provider=provider)
    return parsed.model_name if parsed.provider == normalize_provider(provider) else value


def coerce_messages(messages: MessageInput) -> list[JsonDict]:
    """Coerce ASRH ``Message`` objects or mappings into JSON-compatible dicts."""
    out: list[JsonDict] = []
    for item in messages:
        if isinstance(item, Message):
            data = item.to_model_dict()
        elif hasattr(item, "to_model_dict"):
            data = dict(item.to_model_dict())
        elif hasattr(item, "to_dict"):
            data = dict(item.to_dict())
        elif isinstance(item, Mapping):
            data = dict(item)
        else:
            data = {"role": "user", "content": str(item)}
        role = str(data.get("role", "user") or "user").strip().lower()
        content = stringify_message_content(data.get("content", ""))
        name = data.get("name")
        payload: JsonDict = {"role": role, "content": content}
        if name is not None:
            payload["name"] = str(name)
        out.append(payload)
    return out


def split_system_messages(messages: MessageInput) -> MessageBundle:
    """Split system/developer messages from conversation messages."""
    system_parts: list[str] = []
    conversational: list[JsonMapping] = []
    for message in coerce_messages(messages):
        role = str(message.get("role", "user")).lower()
        content = str(message.get("content", ""))
        if role in {"system", "developer"}:
            if content:
                system_parts.append(content)
            continue
        conversational.append({"role": normalize_conversation_role(role), "content": content})
    return MessageBundle(system="\n\n".join(system_parts), messages=tuple(conversational))


def normalize_conversation_role(role: str) -> str:
    text = str(role or "user").strip().lower()
    if text in {"assistant", "user"}:
        return text
    if text == "tool":
        return "user"
    return "user"


def messages_for_openai_responses(messages: MessageInput) -> tuple[str, list[JsonDict]]:
    bundle = split_system_messages(messages)
    inputs: list[JsonDict] = []
    for item in bundle.messages:
        role = str(item.get("role", "user"))
        if role == "tool":
            role = "user"
        inputs.append({"role": role if role in {"user", "assistant", "developer"} else "user", "content": str(item.get("content", ""))})
    return bundle.system, inputs


def messages_for_openai_chat(messages: MessageInput) -> list[JsonDict]:
    out: list[JsonDict] = []
    for item in coerce_messages(messages):
        role = str(item.get("role", "user")).lower()
        if role == "developer":
            role = "system"
        elif role == "tool":
            role = "user"
            item = dict(item)
            item["content"] = f"Tool observation:\n{item.get('content', '')}"
        elif role not in {"system", "user", "assistant"}:
            role = "user"
        out.append({"role": role, "content": str(item.get("content", ""))})
    return out


def messages_for_anthropic(messages: MessageInput) -> tuple[str, list[JsonDict]]:
    bundle = split_system_messages(messages)
    out: list[JsonDict] = []
    last_role: str | None = None
    for item in bundle.messages:
        role = str(item.get("role", "user")).lower()
        content = str(item.get("content", ""))
        if role == "tool":
            role = "user"
            content = f"Tool observation:\n{content}"
        if role not in {"user", "assistant"}:
            role = "user"
        # Anthropic expects alternating-ish user/assistant messages. Merge same-role neighbors.
        if out and last_role == role:
            out[-1] = {"role": role, "content": f"{out[-1]['content']}\n\n{content}"}
        else:
            out.append({"role": role, "content": content})
            last_role = role
    if not out:
        out.append({"role": "user", "content": ACTION_FORMAT_REMINDER})
    elif out[0]["role"] == "assistant":
        out.insert(0, {"role": "user", "content": ACTION_FORMAT_REMINDER})
    return bundle.system, out


def append_action_format_reminder(messages: list[JsonDict], *, role: str = "user") -> list[JsonDict]:
    if any(ACTION_FORMAT_REMINDER[:30] in str(message.get("content", "")) for message in messages):
        return messages
    return [*messages, {"role": role, "content": ACTION_FORMAT_REMINDER}]


def stringify_message_content(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        parts: list[str] = []
        for item in value:
            if isinstance(item, Mapping):
                if "text" in item:
                    parts.append(str(item.get("text", "")))
                elif "content" in item:
                    parts.append(str(item.get("content", "")))
                else:
                    parts.append(json.dumps(json_safe(item), ensure_ascii=False, sort_keys=True))
            else:
                parts.append(str(item))
        return "\n".join(part for part in parts if part)
    if isinstance(value, Mapping):
        return json.dumps(json_safe(value), ensure_ascii=False, sort_keys=True)
    return str(value)


def response_to_raw_mapping(response: Any) -> JsonDict:
    if response is None:
        return {}
    if isinstance(response, Mapping):
        return dict(response)
    if hasattr(response, "model_dump"):
        try:
            return dict(response.model_dump(mode="json"))
        except TypeError:
            return dict(response.model_dump())
    if hasattr(response, "dict"):
        try:
            return dict(response.dict())
        except Exception:  # noqa: BLE001
            pass
    return {"type": type(response).__name__, "repr": repr(response)[:2_000]}


def json_safe(value: Any) -> Any:
    """Return a JSON-serializable form without leaking opaque SDK objects."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [json_safe(item) for item in value]
    if hasattr(value, "model_dump"):
        try:
            return json_safe(value.model_dump(mode="json"))
        except TypeError:
            return json_safe(value.model_dump())
    if hasattr(value, "dict"):
        try:
            return json_safe(value.dict())
        except Exception:  # noqa: BLE001
            return repr(value)
    return repr(value)


def freeze_jsonable_mapping(value: Mapping[str, Any] | None) -> JsonMapping:
    if not value:
        return {}
    return json_safe(dict(value))


def thaw_jsonable(value: Any) -> Any:
    return json_safe(value)


def bool_from_env(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def env_text(name: str, *, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def require_api_key(value: str | None, *, env_name: str, provider: str) -> str:
    text = (value or os.environ.get(env_name) or "").strip()
    if not text:
        raise ProviderAuthenticationError(
            f"{provider} client requires an API key. Set {env_name} or pass api_key explicitly."
        )
    return text


def require_non_blank(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ModelConfigurationError(f"{name} must not be blank")
    return text


def positive_int(value: Any, name: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ModelConfigurationError(f"{name} must be an integer") from exc
    if result <= 0:
        raise ModelConfigurationError(f"{name} must be positive")
    return result


def redact_secret(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text:
        return ""
    if len(text) <= 8:
        return "***"
    return f"{text[:4]}…{text[-4:]}"


def token_usage_from_mapping(usage: Any, *, input_keys: tuple[str, ...], output_keys: tuple[str, ...]) -> tuple[int | None, int | None]:
    if usage is None:
        return None, None
    if isinstance(usage, Mapping):
        data = usage
    else:
        data = {name: getattr(usage, name, None) for name in (*input_keys, *output_keys)}
    input_tokens = first_int(data, input_keys)
    output_tokens = first_int(data, output_keys)
    return input_tokens, output_tokens


def first_int(data: Mapping[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def finish_reason_from_response(response: Any) -> str | None:
    for attr in ("finish_reason", "stop_reason", "status"):
        value = getattr(response, attr, None)
        if value is not None:
            return str(value)
    if isinstance(response, Mapping):
        for key in ("finish_reason", "stop_reason", "status"):
            if response.get(key) is not None:
                return str(response[key])
    return None


def normalize_mock_mode(value: str | None) -> str:
    text = str(value or "safe").strip().lower().replace("-", "_").replace(" ", "_")
    if text.startswith("mock/"):
        text = text.split("/", 1)[1]
    if text.startswith("mock:"):
        text = text.split(":", 1)[1]
    text = text or "safe"
    if text not in SUPPORTED_MOCK_MODES:
        raise ModelConfigurationError(f"unsupported mock mode {value!r}; expected one of {sorted(SUPPORTED_MOCK_MODES)}")
    return text


__all__: Final[tuple[str, ...]] = (
    "ACTION_FORMAT_REMINDER",
    "ANTHROPIC_ENV_API_KEY",
    "BaseModelClient",
    "DEFAULT_ANTHROPIC_MODEL",
    "DEFAULT_LOCAL_API_KEY",
    "DEFAULT_LOCAL_BASE_URL",
    "DEFAULT_LOCAL_MODEL",
    "DEFAULT_OPENAI_MODEL",
    "JSON_ACTION_SCHEMA",
    "JSON_ACTION_SCHEMA_NAME",
    "LOCAL_ENV_API_KEY",
    "LOCAL_ENV_BASE_URL",
    "MessageBundle",
    "MessageInput",
    "ModelClient",
    "ModelConfigurationError",
    "ModelError",
    "ModelIdentifier",
    "ModelIdentifierError",
    "ModelOutputError",
    "ModelProvider",
    "OPENAI_ENV_API_KEY",
    "OPENAI_ENV_BASE_URL",
    "OPENAI_TEXT_JSON_SCHEMA_FORMAT",
    "PROVIDER_ANTHROPIC",
    "PROVIDER_LOCAL",
    "PROVIDER_MOCK",
    "PROVIDER_OPENAI",
    "PROVIDER_OPENAI_COMPATIBLE",
    "ProviderAPIError",
    "ProviderAuthenticationError",
    "ProviderClientConfig",
    "ProviderNotInstalledError",
    "SUPPORTED_PROVIDERS",
    "append_action_format_reminder",
    "bool_from_env",
    "coerce_messages",
    "env_text",
    "finish_reason_from_response",
    "json_safe",
    "messages_for_anthropic",
    "messages_for_openai_chat",
    "messages_for_openai_responses",
    "normalize_mock_mode",
    "normalize_provider",
    "parse_model_identifier",
    "provider_from_model",
    "redact_secret",
    "require_api_key",
    "response_to_raw_mapping",
    "split_system_messages",
    "strip_provider_prefix",
    "token_usage_from_mapping",
)
