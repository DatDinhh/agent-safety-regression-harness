"""ASRH model-provider clients.

Public entrypoint for constructing model clients from ASRH model identifiers:

    mock/safe
    openai/gpt-4o-mini
    anthropic/claude-sonnet-4-5
    local/qwen2.5-coder

Provider clients only produce ASRH JSON actions. Tool execution remains local,
sandboxed, and policy-controlled by ASRH.
"""

from __future__ import annotations

from typing import Any, Final

from asrh import DEFAULT_MODEL, DEFAULT_REAL_MODEL
from asrh.models.base import (
    ACTION_FORMAT_REMINDER,
    ANTHROPIC_ENV_API_KEY,
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_LOCAL_API_KEY,
    DEFAULT_LOCAL_BASE_URL,
    DEFAULT_LOCAL_MODEL,
    DEFAULT_OPENAI_MODEL,
    JSON_ACTION_SCHEMA,
    JSON_ACTION_SCHEMA_NAME,
    LOCAL_ENV_API_KEY,
    LOCAL_ENV_BASE_URL,
    MessageBundle,
    ModelClient,
    ModelConfigurationError,
    ModelError,
    ModelIdentifier,
    ModelIdentifierError,
    ModelOutputError,
    ModelProvider,
    OPENAI_ENV_API_KEY,
    OPENAI_ENV_BASE_URL,
    OPENAI_TEXT_JSON_SCHEMA_FORMAT,
    PROVIDER_ANTHROPIC,
    PROVIDER_LOCAL,
    PROVIDER_MOCK,
    PROVIDER_OPENAI,
    PROVIDER_OPENAI_COMPATIBLE,
    ProviderAPIError,
    ProviderAuthenticationError,
    ProviderClientConfig,
    ProviderNotInstalledError,
    SUPPORTED_PROVIDERS,
    append_action_format_reminder,
    coerce_messages,
    messages_for_anthropic,
    messages_for_openai_chat,
    messages_for_openai_responses,
    normalize_provider,
    parse_model_identifier,
    provider_from_model,
)
from asrh.models.mock import MockModelClient, build_mock_model_client

MODEL_PACKAGE_NAME: Final[str] = "asrh.models"


class ModelFactoryError(ModelConfigurationError):
    """Raised when a model identifier cannot be resolved into a client."""


def build_model_client(model: str = DEFAULT_MODEL, **kwargs: Any) -> ModelClient:
    """Build a model client from an ASRH model identifier.

    Args:
        model: Identifier such as ``mock/safe``, ``openai/gpt-4o-mini``,
            ``anthropic/claude-sonnet-4-5``, or ``local/model-name``.
        **kwargs: Provider-specific construction options such as ``api_key`` or
            ``base_url``. Unknown kwargs are passed to the selected client.
    """
    identifier = parse_model_identifier(model or DEFAULT_MODEL, default_provider=PROVIDER_LOCAL)
    provider = identifier.provider
    if provider == PROVIDER_MOCK:
        return build_mock_model_client(identifier.qualified, **kwargs)
    if provider == PROVIDER_OPENAI:
        from asrh.models.openai_client import build_openai_model_client

        return build_openai_model_client(identifier.qualified, **kwargs)
    if provider == PROVIDER_ANTHROPIC:
        from asrh.models.anthropic_client import build_anthropic_model_client

        return build_anthropic_model_client(identifier.qualified, **kwargs)
    if provider in {PROVIDER_LOCAL, PROVIDER_OPENAI_COMPATIBLE}:
        from asrh.models.local_client import build_local_model_client

        return build_local_model_client(identifier.qualified, **kwargs)
    raise ModelFactoryError(f"unsupported model provider {provider!r} for {model!r}")


def get_model_client(model: str = DEFAULT_MODEL, **kwargs: Any) -> ModelClient:
    return build_model_client(model, **kwargs)


def create_model_client(model: str = DEFAULT_MODEL, **kwargs: Any) -> ModelClient:
    return build_model_client(model, **kwargs)


def resolve_model_client(model: str = DEFAULT_MODEL, **kwargs: Any) -> ModelClient:
    return build_model_client(model, **kwargs)


def supported_model_identifiers() -> tuple[str, ...]:
    """Return representative identifiers for documentation and smoke tests."""
    return (
        DEFAULT_MODEL,
        "mock/unsafe_leaker",
        DEFAULT_REAL_MODEL,
        f"anthropic/{DEFAULT_ANTHROPIC_MODEL}",
        f"local/{DEFAULT_LOCAL_MODEL}",
    )


def model_provider_summary() -> dict[str, Any]:
    """Return a JSON-compatible summary of available provider families."""
    return {
        "package": MODEL_PACKAGE_NAME,
        "providers": list(SUPPORTED_PROVIDERS),
        "examples": list(supported_model_identifiers()),
        "api_key_env": {
            PROVIDER_OPENAI: OPENAI_ENV_API_KEY,
            PROVIDER_ANTHROPIC: ANTHROPIC_ENV_API_KEY,
            PROVIDER_LOCAL: LOCAL_ENV_API_KEY,
        },
        "local_base_url_env": LOCAL_ENV_BASE_URL,
        "action_schema": JSON_ACTION_SCHEMA_NAME,
    }


__all__: Final[tuple[str, ...]] = (
    "ACTION_FORMAT_REMINDER",
    "ANTHROPIC_ENV_API_KEY",
    "DEFAULT_ANTHROPIC_MODEL",
    "DEFAULT_LOCAL_API_KEY",
    "DEFAULT_LOCAL_BASE_URL",
    "DEFAULT_LOCAL_MODEL",
    "DEFAULT_OPENAI_MODEL",
    "JSON_ACTION_SCHEMA",
    "JSON_ACTION_SCHEMA_NAME",
    "LOCAL_ENV_API_KEY",
    "LOCAL_ENV_BASE_URL",
    "MODEL_PACKAGE_NAME",
    "MessageBundle",
    "MockModelClient",
    "ModelClient",
    "ModelConfigurationError",
    "ModelError",
    "ModelFactoryError",
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
    "build_mock_model_client",
    "build_model_client",
    "coerce_messages",
    "create_model_client",
    "get_model_client",
    "messages_for_anthropic",
    "messages_for_openai_chat",
    "messages_for_openai_responses",
    "model_provider_summary",
    "normalize_provider",
    "parse_model_identifier",
    "provider_from_model",
    "resolve_model_client",
    "supported_model_identifiers",
)
