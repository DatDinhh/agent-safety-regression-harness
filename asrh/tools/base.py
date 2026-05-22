"""Core tool interfaces for ASRH.

The tool layer exposes model-facing descriptors and thin sandbox-backed adapters.
It deliberately does not own filesystem state, email state, shell execution,
network execution, or policy enforcement. Those responsibilities live in
``asrh.envs.SandboxEnv`` so every tool call follows one trace path.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Final, Protocol, TypeAlias, runtime_checkable

from asrh.envs.sandbox import (
    DEFAULT_TOOL_OUTPUT_CONTENT_TYPE,
    SandboxEnv,
    SandboxError,
    SandboxToolResult,
)

JsonSchema: TypeAlias = Mapping[str, Any]
JsonObject: TypeAlias = Mapping[str, Any]
ToolArgs: TypeAlias = Mapping[str, Any]

TOOL_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]*$")
JSON_SCHEMA_DRAFT: Final[str] = "https://json-schema.org/draft/2020-12/schema"
JSON_TOOL_CONTENT_TYPE: Final[str] = "application/json"
TEXT_TOOL_CONTENT_TYPE: Final[str] = DEFAULT_TOOL_OUTPUT_CONTENT_TYPE
JSON_MIME_TYPE: Final[str] = JSON_TOOL_CONTENT_TYPE
TEXT_MIME_TYPE: Final[str] = TEXT_TOOL_CONTENT_TYPE
DEFAULT_TOOL_CONTENT_TYPE: Final[str] = TEXT_TOOL_CONTENT_TYPE
DEFAULT_TOOL_RESULT_CONTENT_TYPE: Final[str] = TEXT_TOOL_CONTENT_TYPE
MAX_TOOL_PATH_CHARS: Final[int] = 512

EMPTY_JSON_SCHEMA: Final[JsonSchema] = {
    "$schema": JSON_SCHEMA_DRAFT,
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
EMPTY_OBJECT_SCHEMA: Final[JsonSchema] = EMPTY_JSON_SCHEMA


class ToolError(Exception):
    """Base exception for tool definition, validation, and dispatch failures."""


class ToolArgumentError(ToolError):
    """Raised when model-provided tool arguments are malformed."""


class ToolInputError(ToolArgumentError):
    """Backward-compatible alias for malformed tool input errors."""


class ToolConfigurationError(ToolError):
    """Raised when a tool definition or registry is internally inconsistent."""


class ToolRegistrationError(ToolConfigurationError):
    """Backward-compatible alias for tool registration/configuration errors."""


class ToolCallError(ToolError):
    """Raised for unrecoverable tool-call failures."""


class ToolExecutionError(ToolCallError):
    """Backward-compatible alias for unrecoverable tool execution failures."""


class ToolRiskLevel(StrEnum):
    """Risk labels used in tool descriptors and reports."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Provider-neutral metadata for one model-facing tool."""

    name: str
    description: str
    schema: JsonSchema = field(default_factory=lambda: dict(EMPTY_JSON_SCHEMA))
    risk_level: str = ToolRiskLevel.MEDIUM.value
    side_effect_free: bool = True
    simulated: bool = True
    mvp_required: bool = True
    aliases: tuple[str, ...] = field(default_factory=tuple)
    safety_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", normalize_tool_name(self.name))
        object.__setattr__(self, "description", require_non_blank(self.description, "description"))
        object.__setattr__(self, "schema", freeze_jsonable_mapping(self.schema))
        object.__setattr__(self, "risk_level", normalize_risk_level(self.risk_level))
        object.__setattr__(self, "aliases", dedupe_strings(self.aliases))
        object.__setattr__(self, "safety_notes", dedupe_strings(self.safety_notes))

    @property
    def input_schema(self) -> JsonSchema:
        """Compatibility alias used by model-provider clients."""
        return self.schema

    @property
    def tags(self) -> tuple[str, ...]:
        """Return lightweight tags derived from descriptor metadata."""
        tags = ["mvp" if self.mvp_required else "optional", self.risk_level]
        if self.simulated:
            tags.append("simulated")
        if not self.side_effect_free:
            tags.append("side_effect")
        return tuple(tags)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable descriptor."""
        schema = thaw_jsonable(self.schema)
        return {
            "name": self.name,
            "description": self.description,
            "schema": schema,
            "input_schema": schema,
            "risk_level": self.risk_level,
            "side_effect_free": self.side_effect_free,
            "simulated": self.simulated,
            "mvp_required": self.mvp_required,
            "aliases": list(self.aliases),
            "safety_notes": list(self.safety_notes),
            "tags": list(self.tags),
        }

    def to_model_spec(self) -> dict[str, Any]:
        """Return the provider-neutral tool spec expected by ASRH agents."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": thaw_jsonable(self.schema),
        }

    def to_openai_function_spec(self) -> dict[str, Any]:
        """Return an OpenAI-compatible function-tool descriptor."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": thaw_jsonable(self.schema),
            },
        }


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Normalized result returned by every ASRH tool wrapper."""

    tool_name: str
    args: ToolArgs
    output: str
    error: str | None
    allowed: bool
    policy_violation: bool
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: JsonObject = field(default_factory=dict)
    content_type: str = TEXT_TOOL_CONTENT_TYPE

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool_name", normalize_tool_name(self.tool_name))
        object.__setattr__(self, "args", freeze_jsonable_mapping(dict(self.args)))
        object.__setattr__(self, "output", str(self.output))
        object.__setattr__(self, "labels", dedupe_strings(self.labels))
        object.__setattr__(self, "metadata", freeze_jsonable_mapping(dict(self.metadata)))
        object.__setattr__(self, "content_type", str(self.content_type).strip() or TEXT_TOOL_CONTENT_TYPE)

    @property
    def succeeded(self) -> bool:
        """Return whether the call was allowed and returned no execution error."""
        return self.allowed and self.error is None

    @property
    def failed(self) -> bool:
        """Return whether the call was denied or errored."""
        return not self.succeeded

    @classmethod
    def from_sandbox_result(cls, result: SandboxToolResult) -> ToolResult:
        """Convert a sandbox-native result into a stable tool-layer result."""
        return cls(
            tool_name=result.tool_name,
            args=dict(result.args),
            output=result.output,
            error=result.error,
            allowed=result.allowed,
            policy_violation=result.policy_violation,
            labels=tuple(result.labels),
            metadata=dict(result.metadata),
            content_type=result.content_type,
        )

    @classmethod
    def denied(
        cls,
        tool_name: str,
        *,
        args: Mapping[str, Any] | None = None,
        error: str,
        policy_violation: bool = False,
        labels: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
        content_type: str = TEXT_TOOL_CONTENT_TYPE,
    ) -> ToolResult:
        """Build a blocked or invalid-call result."""
        return cls(
            tool_name=tool_name,
            args=args or {},
            output="",
            error=error,
            allowed=False,
            policy_violation=policy_violation,
            labels=tuple(labels),
            metadata=metadata or {},
            content_type=content_type,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable result object."""
        return {
            "tool_name": self.tool_name,
            "args": thaw_jsonable(self.args),
            "output": self.output,
            "error": self.error,
            "allowed": self.allowed,
            "policy_violation": self.policy_violation,
            "labels": list(self.labels),
            "metadata": thaw_jsonable(self.metadata),
            "content_type": self.content_type,
        }


@dataclass(frozen=True, slots=True)
class ToolCall:
    """Normalized model-emitted tool call."""

    tool_name: str
    args: ToolArgs = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool_name", normalize_tool_name(self.tool_name))
        object.__setattr__(self, "args", freeze_jsonable_mapping(dict(self.args)))

    @classmethod
    def from_action(cls, action: Mapping[str, Any]) -> ToolCall:
        """Parse the JSON-action format used by the MVP agent loop."""
        if str(action.get("type", "")).strip() != "tool_call":
            raise ToolArgumentError("action is not a tool_call")
        return cls(tool_name=require_string_arg(action, "tool"), args=expect_object_args(action.get("args", {})))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {"tool_name": self.tool_name, "args": thaw_jsonable(self.args)}


@runtime_checkable
class Tool(Protocol):
    """Runtime-checkable protocol implemented by ASRH tools."""

    name: str
    description: str
    schema: JsonSchema
    risk_level: str
    side_effect_free: bool
    simulated: bool
    mvp_required: bool
    aliases: tuple[str, ...]
    safety_notes: tuple[str, ...]

    def definition(self) -> ToolDefinition:
        """Return model-facing metadata."""
        ...

    def normalize_args(self, args: Mapping[str, Any] | None) -> dict[str, Any]:
        """Validate and normalize model-provided arguments."""
        ...

    def call(self, args: Mapping[str, Any] | None, env: SandboxEnv) -> ToolResult:
        """Execute the tool through a synthetic sandbox."""
        ...

    def to_descriptor(self) -> dict[str, Any]:
        """Return descriptor metadata as a plain mapping."""
        ...

    def prompt_block(self) -> str:
        """Return a deterministic text block for JSON-action prompts."""
        ...


class SandboxDispatchTool:
    """Base class for tools that delegate execution to ``SandboxEnv.call_tool``."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    schema: ClassVar[JsonSchema] = EMPTY_JSON_SCHEMA
    risk_level: ClassVar[str] = ToolRiskLevel.MEDIUM.value
    side_effect_free: ClassVar[bool] = True
    simulated: ClassVar[bool] = True
    mvp_required: ClassVar[bool] = True
    aliases: ClassVar[tuple[str, ...]] = ()
    safety_notes: ClassVar[tuple[str, ...]] = ()

    def __init__(self) -> None:
        self._definition = ToolDefinition(
            name=self.name,
            description=self.description,
            schema=self.schema,
            risk_level=self.risk_level,
            side_effect_free=self.side_effect_free,
            simulated=self.simulated,
            mvp_required=self.mvp_required,
            aliases=self.aliases,
            safety_notes=self.safety_notes,
        )

    def definition(self) -> ToolDefinition:
        """Return immutable model-facing metadata."""
        return self._definition

    def normalize_args(self, args: Mapping[str, Any] | None) -> dict[str, Any]:
        """Validate default object-like arguments."""
        return expect_object_args(args, tool_name=self._definition.name)

    def call(self, args: Mapping[str, Any] | None, env: SandboxEnv) -> ToolResult:
        """Validate args, dispatch through the sandbox, and normalize the result."""
        raw_args = _raw_args_for_error(args)
        try:
            normalized_args = self.normalize_args(args)
        except ToolArgumentError as exc:
            result = ToolResult.denied(
                self._definition.name,
                args=raw_args,
                error=str(exc),
                metadata={"input_error": True},
            )
            return _record_tool_result_if_possible(env, result)

        try:
            result = env.call_tool(self._definition.name, normalized_args)
        except SandboxError as exc:
            denied = ToolResult.denied(
                self._definition.name,
                args=normalized_args,
                error=str(exc),
                metadata={"sandbox_error": True},
            )
            return _record_tool_result_if_possible(env, denied)
        return ToolResult.from_sandbox_result(result)

    def to_descriptor(self) -> dict[str, Any]:
        """Return model-facing metadata as a plain mapping."""
        return self._definition.to_dict()

    def prompt_block(self) -> str:
        """Return a deterministic text block for JSON-action prompts."""
        return f"{self.name}: {self.description}\nInput schema: {compact_json(self.schema)}"

    def to_dict(self) -> dict[str, Any]:
        """Return the tool definition as a JSON-serializable mapping."""
        return self._definition.to_dict()


BaseTool = SandboxDispatchTool
SandboxTool = SandboxDispatchTool
SandboxDelegatingTool = SandboxDispatchTool
BaseSandboxTool = SandboxDispatchTool
SandboxBackedTool = SandboxDispatchTool


class SimulatedSideEffectTool(SandboxDispatchTool):
    """Base class for high-risk simulated side-effect tools."""

    risk_level: ClassVar[str] = ToolRiskLevel.CRITICAL.value
    side_effect_free: ClassVar[bool] = False
    simulated: ClassVar[bool] = True


class ToolSetMixin:
    """Mixin for modules exposing grouped tools."""

    @classmethod
    def build_tools(cls) -> tuple[Tool, ...]:
        """Return concrete tool instances."""
        raise NotImplementedError


def object_schema(
    properties: Mapping[str, Any] | None = None,
    *,
    required: Sequence[str] = (),
    additional_properties: bool = False,
    title: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Build a compact JSON object schema for tool arguments."""
    schema: dict[str, Any] = {
        "$schema": JSON_SCHEMA_DRAFT,
        "type": "object",
        "properties": dict(properties or {}),
        "required": list(required),
        "additionalProperties": additional_properties,
    }
    if title:
        schema["title"] = title
    if description:
        schema["description"] = description
    return schema


def string_property(
    description: str,
    *,
    min_length: int = 0,
    max_length: int | None = None,
    default: str | None = None,
    enum: Sequence[str] | None = None,
    examples: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a JSON Schema string property."""
    schema: dict[str, Any] = {"type": "string", "description": description}
    if min_length:
        schema["minLength"] = min_length
    if max_length is not None:
        schema["maxLength"] = max_length
    if default is not None:
        schema["default"] = default
    if enum is not None:
        schema["enum"] = list(enum)
    if examples:
        schema["examples"] = list(examples)
    return schema


def boolean_property(description: str, *, default: bool | None = None) -> dict[str, Any]:
    """Build a JSON Schema boolean property."""
    schema: dict[str, Any] = {"type": "boolean", "description": description}
    if default is not None:
        schema["default"] = default
    return schema


def array_property(description: str, *, items: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build a JSON Schema array property."""
    return {"type": "array", "description": description, "items": dict(items or {})}


def expect_object_args(args: Any, *, tool_name: str = "tool") -> dict[str, Any]:
    """Return a copy of object-like tool arguments or raise."""
    if args is None:
        return {}
    if not isinstance(args, Mapping):
        raise ToolArgumentError(f"{tool_name} arguments must be a JSON object")
    return {str(key): value for key, value in args.items()}


def require_string_arg(args: Mapping[str, Any], key: str, *, max_chars: int | None = None) -> str:
    """Read a required non-blank string argument."""
    if key not in args:
        raise ToolArgumentError(f"missing required argument: {key}")
    text = str(args[key]).strip()
    if not text:
        raise ToolArgumentError(f"{key} must not be blank")
    if max_chars is not None and len(text) > max_chars:
        raise ToolArgumentError(f"{key} exceeds maximum length {max_chars}")
    return text


def required_string_arg(args: Mapping[str, Any], key: str, *, tool_name: str = "tool") -> str:
    """Compatibility wrapper around ``require_string_arg``."""
    try:
        return require_string_arg(args, key)
    except ToolArgumentError as exc:
        raise ToolArgumentError(f"{tool_name}: {exc}") from exc


def coerce_string_arg(
    args: Mapping[str, Any],
    key: str,
    *,
    default: str = "",
    strip: bool = True,
) -> str:
    """Read an optional string argument."""
    value = args.get(key, default)
    text = default if value is None else str(value)
    return text.strip() if strip else text


def optional_string_arg(
    args: Mapping[str, Any],
    key: str,
    *,
    default: str = "",
    allow_blank: bool = True,
    max_chars: int | None = None,
) -> str:
    """Compatibility wrapper for optional string arguments."""
    text = coerce_string_arg(args, key, default=default)
    if not allow_blank and not text:
        raise ToolArgumentError(f"{key} must not be blank")
    if max_chars is not None and len(text) > max_chars:
        raise ToolArgumentError(f"{key} exceeds maximum length {max_chars}")
    return text


def coerce_bool_arg(args: Mapping[str, Any], key: str, *, default: bool = False) -> bool:
    """Read a permissive optional boolean argument."""
    value = args.get(key, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "t", "yes", "y", "on"}:
            return True
        if normalized in {"", "0", "false", "f", "no", "n", "off"}:
            return False
    return bool(value)


def optional_bool_arg(args: Mapping[str, Any], key: str, *, default: bool = False) -> bool:
    """Compatibility wrapper for optional boolean arguments."""
    return coerce_bool_arg(args, key, default=default)


def coerce_args_mapping(args: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compatibility alias for argument-object validation."""
    return expect_object_args(args)


def coerce_tool_args(args: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compatibility alias for argument-object validation."""
    return expect_object_args(args)


def ensure_args_mapping(args: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compatibility alias for argument-object validation."""
    return expect_object_args(args)


def reject_unknown_args(args: Mapping[str, Any], *, allowed: Iterable[str]) -> None:
    """Raise if ``args`` contains keys outside ``allowed``."""
    allowed_set = set(allowed)
    unknown = sorted(str(key) for key in args if str(key) not in allowed_set)
    if unknown:
        raise ToolArgumentError(f"unknown argument(s): {', '.join(unknown)}")


def normalize_tool_name(value: str) -> str:
    """Normalize and validate a tool name or alias."""
    normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    normalized = normalized.strip("_")
    if not normalized:
        raise ToolConfigurationError("tool name must not be blank")
    if not TOOL_NAME_PATTERN.match(normalized):
        raise ToolConfigurationError(
            f"invalid tool name {value!r}; expected lowercase snake_case matching {TOOL_NAME_PATTERN.pattern!r}"
        )
    return normalized


def normalize_risk_level(value: str | ToolRiskLevel) -> str:
    """Normalize and validate a tool risk label."""
    text = str(getattr(value, "value", value)).strip().lower()
    allowed = {item.value for item in ToolRiskLevel}
    if text not in allowed:
        raise ToolConfigurationError(f"unsupported tool risk level {value!r}; expected one of {sorted(allowed)}")
    return text


def require_non_blank(value: str, field_name: str) -> str:
    """Return stripped text or raise a tool-configuration error."""
    text = str(value).strip()
    if not text:
        raise ToolConfigurationError(f"{field_name} must not be blank")
    return text


def dedupe_strings(values: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate non-blank strings while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return tuple(result)


def compact_json(value: Any) -> str:
    """Return compact deterministic JSON for prompt snippets and reports."""
    return json.dumps(thaw_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def freeze_jsonable_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Freeze a JSON-like mapping recursively into deterministic containers."""
    return {str(key): freeze_jsonable(item) for key, item in value.items()}


def freeze_jsonable(value: Any) -> Any:
    """Freeze common JSON-like containers into deterministic immutable shapes."""
    if isinstance(value, Mapping):
        return freeze_jsonable_mapping(value)
    if isinstance(value, list | tuple | set | frozenset):
        return tuple(freeze_jsonable(item) for item in value)
    return value


def thaw_jsonable(value: Any) -> Any:
    """Convert frozen containers into JSON-serializable plain containers."""
    if isinstance(value, Mapping):
        return {str(key): thaw_jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [thaw_jsonable(item) for item in value]
    return value


def definitions_to_prompt_dicts(definitions: Iterable[ToolDefinition]) -> list[dict[str, Any]]:
    """Return prompt/provider dictionaries for tool definitions."""
    return [definition.to_model_spec() for definition in definitions]


def definitions_to_prompt_text(definitions: Iterable[ToolDefinition]) -> str:
    """Return a deterministic tool-description text block."""
    return "\n\n".join(
        f"{definition.name}: {definition.description}\nSchema: {compact_json(definition.schema)}"
        for definition in definitions
    )


def record_sandbox_result(env: SandboxEnv, result: SandboxToolResult, *, reason: Any = None) -> SandboxToolResult:
    """Record a prebuilt sandbox result through the sandbox trace path."""
    return env._record_tool_call(result, reason=reason)  # noqa: SLF001


def _record_tool_result_if_possible(env: SandboxEnv, result: ToolResult) -> ToolResult:
    """Record tool-layer denial through sandbox trace when possible."""
    try:
        recorded = env._record_tool_call(  # noqa: SLF001
            SandboxToolResult(
                tool_name=result.tool_name,
                args=dict(result.args),
                output=result.output,
                error=result.error,
                allowed=result.allowed,
                policy_violation=result.policy_violation,
                labels=tuple(result.labels),
                metadata=dict(result.metadata),
                content_type=result.content_type,
            ),
            reason=result.error,
        )
    except Exception:  # noqa: BLE001 - invalid-call logging must not break a run.
        return result
    return ToolResult.from_sandbox_result(recorded)


def _raw_args_for_error(args: Any) -> dict[str, Any]:
    if isinstance(args, Mapping):
        return {str(key): value for key, value in args.items()}
    if args is None:
        return {}
    return {"_raw": repr(args)}


freeze_json_object = freeze_jsonable_mapping
freeze_json_schema = freeze_jsonable_mapping
freeze_json_value = freeze_jsonable
thaw_json_value = thaw_jsonable
thaw_json = thaw_jsonable
jsonable = thaw_jsonable
freeze_json = freeze_jsonable
normalize_args = coerce_args_mapping

__all__: Final[tuple[str, ...]] = tuple(
    name
    for name in globals()
    if not name.startswith("_") and name not in {"annotations", "Any", "ClassVar", "Final", "Protocol", "TypeAlias"}
)
