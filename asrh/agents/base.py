"""Provider-neutral agent primitives for ASRH.

The MVP agent contract is a strict JSON-action protocol: each model response is
either a ``tool_call`` or a ``final_answer``. This module contains the common
message/config dataclasses, parser, model-client protocol, and trace-facing
agent result types used by concrete agent loops.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Protocol, TypeAlias, runtime_checkable

from asrh import (
    DEFAULT_MAX_STEPS,
    DEFAULT_MAX_TOKENS_PER_RESPONSE,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TOTAL_TOKENS,
    DEFAULT_MITIGATION,
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    SUPPORTED_AGENT_MODES,
    SUPPORTED_MITIGATIONS,
)
from asrh.tools.base import ToolCall, ToolResult, thaw_jsonable

JsonDict: TypeAlias = dict[str, Any]
JsonMapping: TypeAlias = Mapping[str, Any]
ProviderMessageList: TypeAlias = Sequence[Mapping[str, Any]]

ROLE_SYSTEM: Final[str] = "system"
ROLE_USER: Final[str] = "user"
ROLE_ASSISTANT: Final[str] = "assistant"
ROLE_TOOL: Final[str] = "tool"
VALID_MESSAGE_ROLES: Final[frozenset[str]] = frozenset({ROLE_SYSTEM, ROLE_USER, ROLE_ASSISTANT, ROLE_TOOL})

ACTION_TOOL_CALL: Final[str] = "tool_call"
ACTION_FINAL_ANSWER: Final[str] = "final_answer"
ACTION_TYPE_TOOL_CALL: Final[str] = ACTION_TOOL_CALL
ACTION_TYPE_FINAL_ANSWER: Final[str] = ACTION_FINAL_ANSWER
VALID_ACTION_TYPES: Final[frozenset[str]] = frozenset({ACTION_TOOL_CALL, ACTION_FINAL_ANSWER})

STOP_FINAL_ANSWER: Final[str] = "final_answer"
STOP_MAX_STEPS: Final[str] = "max_steps"
STOP_MAX_TOOL_CALLS: Final[str] = "max_tool_calls"
STOP_MODEL_ERROR: Final[str] = "model_error"
STOP_INVALID_ACTION: Final[str] = "invalid_action"
STOP_TOOL_ERROR: Final[str] = "tool_error"
STOP_TOKEN_BUDGET: Final[str] = "token_budget"
STOP_TIMEOUT: Final[str] = "timeout"
STOP_POLICY_STOPPED: Final[str] = "policy_stopped"
STOP_INTERRUPTED: Final[str] = "interrupted"
STOP_EMPTY_RESPONSE: Final[str] = "empty_response"

DEFAULT_AGENT_MODE: Final[str] = "tool_agent"
DEFAULT_STRICT_JSON: Final[bool] = True
DEFAULT_MAX_INVALID_ACTIONS: Final[int] = 1
DEFAULT_STOP_ON_TOOL_ERROR: Final[bool] = False
DEFAULT_STOP_ON_POLICY_VIOLATION: Final[bool] = False
DEFAULT_INCLUDE_TOOL_SCHEMAS: Final[bool] = True
MAX_PARSE_SNIPPET_CHARS: Final[int] = 500
MAX_TOOL_RESULT_CHARS: Final[int] = 12_000
FENCED_JSON_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"```(?:json)?\s*(?P<body>\{.*?\})\s*```", flags=re.IGNORECASE | re.DOTALL
)


class AgentError(Exception):
    """Base exception for agent code."""


class AgentConfigurationError(AgentError):
    """Raised for invalid agent configuration."""


class AgentParseError(AgentError):
    """Raised when model output cannot be parsed as an ASRH JSON action."""


class AgentActionParseError(AgentParseError):
    """Raised for JSON-action parser failures."""


class AgentExecutionError(AgentError):
    """Raised for unrecoverable agent-loop failures."""


class AgentStepLimitError(AgentExecutionError):
    """Raised when a configured loop limit is exceeded."""


class ModelClientError(AgentExecutionError):
    """Raised when a supplied model client fails or has the wrong shape."""


class MessageRole(StrEnum):
    """Provider-neutral chat roles."""

    SYSTEM = ROLE_SYSTEM
    USER = ROLE_USER
    ASSISTANT = ROLE_ASSISTANT
    TOOL = ROLE_TOOL


class AgentMode(StrEnum):
    """Agent loop modes defined by the MVP specification."""

    MOCK = "mock"
    SINGLE_TURN = "single_turn"
    TOOL_AGENT = "tool_agent"


class AgentActionType(StrEnum):
    """JSON action types emitted by the model."""

    TOOL_CALL = ACTION_TOOL_CALL
    FINAL_ANSWER = ACTION_FINAL_ANSWER


class AgentStopReason(StrEnum):
    """Terminal reasons for an agent run before checkers run."""

    FINAL_ANSWER = STOP_FINAL_ANSWER
    MAX_STEPS = STOP_MAX_STEPS
    MAX_TOOL_CALLS = STOP_MAX_TOOL_CALLS
    MODEL_ERROR = STOP_MODEL_ERROR
    INVALID_ACTION = STOP_INVALID_ACTION
    TOOL_ERROR = STOP_TOOL_ERROR
    TOKEN_BUDGET = STOP_TOKEN_BUDGET
    MAX_TOTAL_TOKENS = STOP_TOKEN_BUDGET
    TIMEOUT = STOP_TIMEOUT
    POLICY_STOPPED = STOP_POLICY_STOPPED
    POLICY_STOP = STOP_POLICY_STOPPED
    INTERRUPTED = STOP_INTERRUPTED
    EMPTY_RESPONSE = STOP_EMPTY_RESPONSE


AgentRunStatus = AgentStopReason


@dataclass(frozen=True, slots=True)
class Message:
    """Provider-neutral chat message with optional trace metadata."""

    role: str | MessageRole
    content: str
    name: str | None = None
    metadata: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", normalize_message_role(self.role))
        object.__setattr__(self, "content", str(self.content))
        object.__setattr__(self, "name", optional_text(self.name))
        object.__setattr__(self, "metadata", freeze_jsonable_mapping(self.metadata))

    @classmethod
    def system(cls, content: str, metadata: Mapping[str, Any] | None = None, **extra: Any) -> Message:
        return cls(ROLE_SYSTEM, content, metadata=merge_metadata(metadata, extra))

    @classmethod
    def user(cls, content: str, metadata: Mapping[str, Any] | None = None, **extra: Any) -> Message:
        return cls(ROLE_USER, content, metadata=merge_metadata(metadata, extra))

    @classmethod
    def assistant(cls, content: str, metadata: Mapping[str, Any] | None = None, **extra: Any) -> Message:
        return cls(ROLE_ASSISTANT, content, metadata=merge_metadata(metadata, extra))

    @classmethod
    def tool(
        cls,
        content: str,
        *,
        name: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        **extra: Any,
    ) -> Message:
        return cls(ROLE_TOOL, content, name=name, metadata=merge_metadata(metadata, extra))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Message:
        return cls(
            role=str(value.get("role", "")),
            content=str(value.get("content", "")),
            name=None if value.get("name") is None else str(value.get("name")),
            metadata=as_mapping(value.get("metadata", {})),
        )

    def to_model_dict(self) -> JsonDict:
        payload: JsonDict = {"role": self.role, "content": self.content}
        if self.name:
            payload["name"] = self.name
        return payload

    def to_provider_dict(self) -> JsonDict:
        return self.to_model_dict()

    def to_dict(self, *, include_metadata: bool = True) -> JsonDict:
        payload = self.to_model_dict()
        if include_metadata and self.metadata:
            payload["metadata"] = thaw_jsonable(self.metadata)
        return payload


AgentMessage = Message


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """Provider-neutral model generation configuration."""

    model_name: str = DEFAULT_MODEL
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS_PER_RESPONSE
    seed: int | None = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    metadata: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_name", require_non_blank(self.model_name, "model_name"))
        object.__setattr__(self, "temperature", bounded_float(self.temperature, "temperature", 0.0, 2.0))
        object.__setattr__(self, "max_tokens", positive_int(self.max_tokens, "max_tokens"))
        object.__setattr__(self, "timeout_seconds", positive_int(self.timeout_seconds, "timeout_seconds"))
        if self.seed is not None:
            object.__setattr__(self, "seed", int(self.seed))
        object.__setattr__(self, "metadata", freeze_jsonable_mapping(self.metadata))

    def to_dict(self) -> JsonDict:
        return {
            "model_name": self.model_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "seed": self.seed,
            "timeout_seconds": self.timeout_seconds,
            "metadata": thaw_jsonable(self.metadata),
        }


AgentModelConfig = ModelConfig
ModelGenerationConfig = ModelConfig


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """Normalized model response."""

    content: str
    raw: JsonMapping = field(default_factory=dict)
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_estimate_usd: float | None = None
    model_name: str | None = None
    finish_reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", str(self.content))
        object.__setattr__(self, "raw", freeze_jsonable_mapping(self.raw))
        if self.input_tokens is not None:
            object.__setattr__(self, "input_tokens", non_negative_int(self.input_tokens, "input_tokens"))
        if self.output_tokens is not None:
            object.__setattr__(self, "output_tokens", non_negative_int(self.output_tokens, "output_tokens"))
        if self.cost_estimate_usd is not None:
            object.__setattr__(self, "cost_estimate_usd", float(self.cost_estimate_usd))

    @property
    def total_tokens(self) -> int | None:
        if self.input_tokens is None and self.output_tokens is None:
            return None
        return int(self.input_tokens or 0) + int(self.output_tokens or 0)

    def to_dict(self) -> JsonDict:
        return {
            "content": self.content,
            "raw": thaw_jsonable(self.raw),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cost_estimate_usd": self.cost_estimate_usd,
            "model_name": self.model_name,
            "finish_reason": self.finish_reason,
        }


NormalizedModelResponse = ModelResponse


@dataclass(frozen=True, slots=True)
class AgentLimits:
    """Loop limits for one agent run."""

    max_steps: int = DEFAULT_MAX_STEPS
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS
    max_tokens_per_response: int = DEFAULT_MAX_TOKENS_PER_RESPONSE
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_invalid_actions: int = DEFAULT_MAX_INVALID_ACTIONS

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_steps", positive_int(self.max_steps, "max_steps"))
        object.__setattr__(self, "max_tool_calls", positive_int(self.max_tool_calls, "max_tool_calls"))
        object.__setattr__(self, "max_tokens_per_response", positive_int(self.max_tokens_per_response, "max_tokens_per_response"))
        object.__setattr__(self, "max_total_tokens", positive_int(self.max_total_tokens, "max_total_tokens"))
        object.__setattr__(self, "timeout_seconds", positive_int(self.timeout_seconds, "timeout_seconds"))
        object.__setattr__(self, "max_invalid_actions", non_negative_int(self.max_invalid_actions, "max_invalid_actions"))

    def to_dict(self) -> JsonDict:
        return {
            "max_steps": self.max_steps,
            "max_tool_calls": self.max_tool_calls,
            "max_tokens_per_response": self.max_tokens_per_response,
            "max_total_tokens": self.max_total_tokens,
            "timeout_seconds": self.timeout_seconds,
            "max_invalid_actions": self.max_invalid_actions,
        }


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """Complete execution config for one ASRH agent run."""

    model_name: str = DEFAULT_MODEL
    mitigation: str = DEFAULT_MITIGATION
    mode: str = DEFAULT_AGENT_MODE
    temperature: float = DEFAULT_TEMPERATURE
    seed: int | None = None
    max_steps: int = DEFAULT_MAX_STEPS
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS
    max_tokens_per_response: int = DEFAULT_MAX_TOKENS_PER_RESPONSE
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    strict_json: bool = DEFAULT_STRICT_JSON
    fail_fast: bool = False
    max_invalid_actions: int = DEFAULT_MAX_INVALID_ACTIONS
    stop_on_tool_error: bool = DEFAULT_STOP_ON_TOOL_ERROR
    stop_on_policy_violation: bool = DEFAULT_STOP_ON_POLICY_VIOLATION
    include_tool_schemas: bool = DEFAULT_INCLUDE_TOOL_SCHEMAS
    metadata: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_name", require_non_blank(self.model_name, "model_name"))
        object.__setattr__(self, "mitigation", normalize_mitigation(self.mitigation))
        object.__setattr__(self, "mode", normalize_agent_mode(self.mode))
        object.__setattr__(self, "temperature", bounded_float(self.temperature, "temperature", 0.0, 2.0))
        object.__setattr__(self, "max_steps", positive_int(self.max_steps, "max_steps"))
        object.__setattr__(self, "max_tool_calls", positive_int(self.max_tool_calls, "max_tool_calls"))
        object.__setattr__(self, "max_tokens_per_response", positive_int(self.max_tokens_per_response, "max_tokens_per_response"))
        object.__setattr__(self, "max_total_tokens", positive_int(self.max_total_tokens, "max_total_tokens"))
        object.__setattr__(self, "timeout_seconds", positive_int(self.timeout_seconds, "timeout_seconds"))
        object.__setattr__(self, "max_invalid_actions", non_negative_int(self.max_invalid_actions, "max_invalid_actions"))
        if self.seed is not None:
            object.__setattr__(self, "seed", int(self.seed))
        object.__setattr__(self, "metadata", freeze_jsonable_mapping(self.metadata))

    @property
    def limits(self) -> AgentLimits:
        return AgentLimits(
            max_steps=self.max_steps,
            max_tool_calls=self.max_tool_calls,
            max_tokens_per_response=self.max_tokens_per_response,
            max_total_tokens=self.max_total_tokens,
            timeout_seconds=self.timeout_seconds,
            max_invalid_actions=self.max_invalid_actions,
        )

    def with_mode(self, mode: str) -> AgentConfig:
        return replace(self, mode=mode)

    def to_model_config(self) -> ModelConfig:
        return ModelConfig(
            model_name=self.model_name,
            temperature=self.temperature,
            max_tokens=self.max_tokens_per_response,
            seed=self.seed,
            timeout_seconds=self.timeout_seconds,
            metadata=self.metadata,
        )

    @property
    def model_config(self) -> ModelConfig:
        return self.to_model_config()

    def to_dict(self, *, flat: bool = True) -> JsonDict:
        data: JsonDict = {
            "model_name": self.model_name,
            "mitigation": self.mitigation,
            "mode": self.mode,
            "temperature": self.temperature,
            "seed": self.seed,
            "max_steps": self.max_steps,
            "max_tool_calls": self.max_tool_calls,
            "max_tokens_per_response": self.max_tokens_per_response,
            "max_total_tokens": self.max_total_tokens,
            "timeout_seconds": self.timeout_seconds,
            "strict_json": self.strict_json,
            "fail_fast": self.fail_fast,
            "max_invalid_actions": self.max_invalid_actions,
            "stop_on_tool_error": self.stop_on_tool_error,
            "stop_on_policy_violation": self.stop_on_policy_violation,
            "include_tool_schemas": self.include_tool_schemas,
            "metadata": thaw_jsonable(self.metadata),
        }
        if flat:
            return data
        grouped = dict(data)
        for key in self.limits.to_dict():
            grouped.pop(key, None)
        grouped["limits"] = self.limits.to_dict()
        return grouped


AgentRunConfig = AgentConfig


@dataclass(frozen=True, slots=True)
class AgentUsage:
    """Aggregated provider usage for one run."""

    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_estimate_usd: float | None = None
    model_calls: int = 0

    @classmethod
    def empty(cls) -> AgentUsage:
        return cls()

    @property
    def total_tokens(self) -> int | None:
        if self.input_tokens is None and self.output_tokens is None:
            return None
        return int(self.input_tokens or 0) + int(self.output_tokens or 0)

    def add(self, response: ModelResponse) -> AgentUsage:
        return AgentUsage(
            input_tokens=add_optional_ints(self.input_tokens, response.input_tokens),
            output_tokens=add_optional_ints(self.output_tokens, response.output_tokens),
            cost_estimate_usd=add_optional_floats(self.cost_estimate_usd, response.cost_estimate_usd),
            model_calls=self.model_calls + 1,
        )

    def to_dict(self) -> JsonDict:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cost_estimate_usd": self.cost_estimate_usd,
            "model_calls": self.model_calls,
        }


@dataclass(frozen=True, slots=True)
class AgentAction:
    """Parsed JSON action emitted by a model."""

    action_type: str
    content: str | None = None
    tool_name: str | None = None
    args: JsonMapping = field(default_factory=dict)
    raw: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized = str(self.action_type).strip().lower()
        if normalized not in VALID_ACTION_TYPES:
            raise AgentActionParseError(f"unsupported action type: {self.action_type!r}")
        object.__setattr__(self, "action_type", normalized)
        object.__setattr__(self, "args", freeze_jsonable_mapping(self.args))
        object.__setattr__(self, "raw", freeze_jsonable_mapping(self.raw))
        if self.content is not None:
            object.__setattr__(self, "content", str(self.content))
        if self.tool_name is not None:
            object.__setattr__(self, "tool_name", require_non_blank(self.tool_name, "tool"))
        if normalized == ACTION_FINAL_ANSWER and self.content is None:
            raise AgentActionParseError("final_answer action requires content")
        if normalized == ACTION_TOOL_CALL and self.tool_name is None:
            raise AgentActionParseError("tool_call action requires tool")

    @property
    def type(self) -> str:
        return self.action_type

    @property
    def is_tool_call(self) -> bool:
        return self.action_type == ACTION_TOOL_CALL

    @property
    def is_final_answer(self) -> bool:
        return self.action_type == ACTION_FINAL_ANSWER

    @classmethod
    def final_answer(cls, content: str, *, raw: Mapping[str, Any] | None = None) -> AgentAction:
        return cls(ACTION_FINAL_ANSWER, content=str(content), raw=raw or {})

    @classmethod
    def tool_call(cls, tool_name: str, args: Mapping[str, Any] | None = None, *, raw: Mapping[str, Any] | None = None) -> AgentAction:
        return cls(ACTION_TOOL_CALL, tool_name=tool_name, args=args or {}, raw=raw or {})

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> AgentAction:
        action_type = str(value.get("type", "")).strip().lower()
        if action_type == ACTION_FINAL_ANSWER:
            if "content" not in value:
                raise AgentActionParseError("final_answer action requires content")
            return cls.final_answer(str(value.get("content", "")), raw=value)
        if action_type == ACTION_TOOL_CALL:
            tool = str(value.get("tool", value.get("tool_name", ""))).strip()
            args = value.get("args", {})
            if not isinstance(args, Mapping):
                raise AgentActionParseError("tool_call.args must be an object")
            return cls.tool_call(tool, args=dict(args), raw=value)
        raise AgentActionParseError("JSON action field 'type' must be either 'tool_call' or 'final_answer'")

    def to_tool_call(self) -> ToolCall:
        if not self.is_tool_call or self.tool_name is None:
            raise AgentActionParseError("action is not a tool_call")
        return ToolCall(self.tool_name, thaw_jsonable(self.args))

    def to_dict(self) -> JsonDict:
        if self.is_final_answer:
            return {"type": ACTION_FINAL_ANSWER, "content": self.content or ""}
        return {"type": ACTION_TOOL_CALL, "tool": self.tool_name, "args": thaw_jsonable(self.args)}


@dataclass(frozen=True, slots=True)
class AgentStep:
    """One iteration of an agent loop."""

    step: int
    model_output: str = ""
    action: AgentAction | None = None
    tool_result: ToolResult | None = None
    error: str | None = None
    timestamp: str = field(default_factory=lambda: utc_now_iso())

    def __post_init__(self) -> None:
        object.__setattr__(self, "step", positive_int(self.step, "step"))
        object.__setattr__(self, "model_output", str(self.model_output))
        if self.error is not None:
            object.__setattr__(self, "error", str(self.error))

    @property
    def index(self) -> int:
        return self.step

    def to_dict(self) -> JsonDict:
        payload: JsonDict = {"step": self.step, "model_output": self.model_output, "timestamp": self.timestamp}
        if self.action:
            payload["action"] = self.action.to_dict()
        if self.tool_result:
            payload["tool_result"] = self.tool_result.to_dict()
        if self.error:
            payload["error"] = self.error
        return payload


@dataclass(frozen=True, slots=True)
class AgentRunResult:
    """Trace-facing result of one agent run before checkers are applied."""

    case_id: str | None
    model: str
    mitigation: str
    mode: str
    started_at: str
    ended_at: str
    messages: tuple[Message, ...]
    steps: tuple[AgentStep, ...]
    final_answer: str
    stop_reason: str
    completed: bool
    tool_call_count: int
    usage: AgentUsage = field(default_factory=AgentUsage.empty)
    errors: tuple[str, ...] = field(default_factory=tuple)
    metadata: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "model", require_non_blank(self.model, "model"))
        object.__setattr__(self, "mitigation", normalize_mitigation(self.mitigation))
        object.__setattr__(self, "mode", normalize_agent_mode(self.mode))
        object.__setattr__(self, "final_answer", str(self.final_answer))
        object.__setattr__(self, "stop_reason", str(self.stop_reason).strip() or STOP_INTERRUPTED)
        object.__setattr__(self, "tool_call_count", non_negative_int(self.tool_call_count, "tool_call_count"))
        object.__setattr__(self, "errors", tuple(str(item) for item in self.errors if str(item).strip()))
        object.__setattr__(self, "metadata", freeze_jsonable_mapping(self.metadata))

    @property
    def status(self) -> str:
        return self.stop_reason

    @property
    def model_name(self) -> str:
        return self.model

    @property
    def failed(self) -> bool:
        return not self.completed

    @property
    def tool_results(self) -> tuple[ToolResult, ...]:
        return tuple(step.tool_result for step in self.steps if step.tool_result is not None)

    def to_dict(self) -> JsonDict:
        return {
            "case_id": self.case_id,
            "model": self.model,
            "mitigation": self.mitigation,
            "agent_mode": self.mode,
            "mode": self.mode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "messages": [message.to_dict() for message in self.messages],
            "agent_steps": [step.to_dict() for step in self.steps],
            "steps": [step.to_dict() for step in self.steps],
            "final_answer": self.final_answer,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "completed": self.completed,
            "tool_call_count": self.tool_call_count,
            "usage": self.usage.to_dict(),
            "errors": list(self.errors),
            "metadata": thaw_jsonable(self.metadata),
        }


AgentResult = AgentRunResult


@dataclass(frozen=True, slots=True)
class AgentContext:
    """Runtime context passed from runner modules into agents."""

    case: Any
    env: Any
    tool_registry: Any
    config: AgentConfig = field(default_factory=AgentConfig)
    metadata: JsonMapping = field(default_factory=dict)


@runtime_checkable
class ModelClient(Protocol):
    """Minimal protocol expected from model clients."""

    def generate(self, messages: ProviderMessageList | Sequence[Message], config: ModelConfig) -> Any:
        ...


ModelClientProtocol = ModelClient


@runtime_checkable
class Agent(Protocol):
    """Protocol implemented by ASRH agents."""

    name: str
    mode: str

    def run(self, **kwargs: Any) -> AgentRunResult:
        ...


AgentProtocol = Agent


class BaseAgent:
    """Small base class for provider-neutral ASRH agents."""

    name: str = "base_agent"
    mode: str = DEFAULT_AGENT_MODE

    def __init__(self, *, name: str | None = None) -> None:
        if name is not None:
            self.name = require_non_blank(name, "agent name")

    def run(self, **_: Any) -> AgentRunResult:
        raise NotImplementedError


def normalize_message_role(role: str | MessageRole) -> str:
    value = str(getattr(role, "value", role)).strip().lower()
    if value not in VALID_MESSAGE_ROLES:
        raise AgentConfigurationError(f"unsupported message role: {role!r}")
    return value


def normalize_agent_mode(mode: str | AgentMode) -> str:
    value = str(getattr(mode, "value", mode)).strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "tool": "tool_agent",
        "tools": "tool_agent",
        "react": "tool_agent",
        "react_agent": "tool_agent",
        "json_react": "tool_agent",
        "single": "single_turn",
        "no_tool": "single_turn",
        "no_tools": "single_turn",
    }
    value = aliases.get(value, value)
    if value not in SUPPORTED_AGENT_MODES:
        raise AgentConfigurationError(f"unsupported agent mode {mode!r}; expected one of {sorted(SUPPORTED_AGENT_MODES)}")
    return value


def normalize_mitigation(mitigation: str | None = None) -> str:
    value = str(mitigation or DEFAULT_MITIGATION).strip().lower().replace("-", "_").replace(" ", "_")
    value = value or DEFAULT_MITIGATION
    if value == "baseline":
        value = "none"
    if value not in SUPPORTED_MITIGATIONS:
        raise AgentConfigurationError(f"unsupported mitigation {mitigation!r}; expected one of {sorted(SUPPORTED_MITIGATIONS)}")
    return value


def parse_agent_action(content: str, *, strict: bool = True) -> AgentAction:
    """Parse model text into the MVP JSON-action format."""
    text = str(content).strip()
    if not text:
        raise AgentActionParseError("model output was empty")
    try:
        raw_value = json.loads(text)
    except json.JSONDecodeError as exact_error:
        candidate = extract_json_candidate(text)
        if candidate is None:
            raise AgentActionParseError(f"model output is not valid JSON: {exact_error.msg}") from exact_error
        if strict and candidate.strip() != strip_markdown_fences(text).strip():
            raise AgentActionParseError("model output contained extra text around JSON while strict_json is enabled") from exact_error
        try:
            raw_value = json.loads(candidate)
        except json.JSONDecodeError as extracted_error:
            raise AgentActionParseError(f"model output JSON could not be parsed: {extracted_error.msg}") from extracted_error
    if not isinstance(raw_value, Mapping):
        raise AgentActionParseError("JSON action must be an object")
    return AgentAction.from_mapping({str(key): value for key, value in raw_value.items()})


def strip_markdown_fences(text: str) -> str:
    match = FENCED_JSON_PATTERN.fullmatch(str(text).strip())
    if match:
        return match.group("body").strip()
    return str(text).strip()


strip_code_fence = strip_markdown_fences


def extract_json_candidate(text: str) -> str | None:
    stripped = strip_markdown_fences(text)
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    start = stripped.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(stripped[start:], start=start):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return stripped[start : index + 1]
    return None


extract_first_json_object = extract_json_object = extract_json_candidate


def invoke_model(model_client: Any, messages: Sequence[Message], config: ModelConfig) -> ModelResponse:
    """Call a model client and normalize its provider-specific response."""
    payload = [message.to_model_dict() for message in messages]
    try:
        raw = model_client.generate(payload, config)
    except TypeError:
        raw = model_client.generate(messages, config)
    return normalize_model_response(raw)


call_model_generate = invoke_model


def normalize_model_response(response: Any) -> ModelResponse:
    if isinstance(response, ModelResponse):
        return response
    if isinstance(response, str):
        return ModelResponse(content=response, raw={"type": "str"})
    if isinstance(response, Mapping):
        usage = as_mapping(response.get("usage", {}))
        raw_mapping = as_mapping(response.get("raw", response))
        content = response.get("content", response.get("text", response.get("output_text", "")))
        if not content and isinstance(response.get("message"), Mapping):
            content = response["message"].get("content", "")
        return ModelResponse(
            content=str(content),
            raw=raw_mapping,
            input_tokens=optional_int(response.get("input_tokens", usage.get("input_tokens"))),
            output_tokens=optional_int(response.get("output_tokens", usage.get("output_tokens"))),
            cost_estimate_usd=optional_float(response.get("cost_estimate_usd", usage.get("cost_estimate_usd"))),
            model_name=None if response.get("model_name") is None else str(response.get("model_name")),
            finish_reason=None if response.get("finish_reason") is None else str(response.get("finish_reason")),
        )
    content = getattr(response, "content", None)
    if content is None:
        content = getattr(response, "text", None)
    if content is None:
        content = getattr(response, "output_text", None)
    if content is None:
        raise ModelClientError(f"model response has no content/text/output_text field: {type(response)!r}")
    return ModelResponse(
        content=str(content),
        raw=as_mapping(getattr(response, "raw", {})),
        input_tokens=optional_int(getattr(response, "input_tokens", None)),
        output_tokens=optional_int(getattr(response, "output_tokens", None)),
        cost_estimate_usd=optional_float(getattr(response, "cost_estimate_usd", None)),
        model_name=None if getattr(response, "model_name", None) is None else str(getattr(response, "model_name")),
        finish_reason=None if getattr(response, "finish_reason", None) is None else str(getattr(response, "finish_reason")),
    )


def messages_to_model_dicts(messages: Sequence[Message]) -> list[JsonDict]:
    return [message.to_model_dict() for message in messages]


def messages_to_provider_dicts(messages: Sequence[Message]) -> list[JsonDict]:
    return messages_to_model_dicts(messages)


def messages_to_trace_dicts(messages: Sequence[Message]) -> list[JsonDict]:
    return [message.to_dict() for message in messages]


def agent_messages_to_dicts(messages: Sequence[Message]) -> list[JsonDict]:
    return messages_to_trace_dicts(messages)


message_dicts = agent_messages_to_dicts


def aggregate_usage(responses: Sequence[ModelResponse]) -> AgentUsage:
    usage = AgentUsage.empty()
    for response in responses:
        usage = usage.add(response)
    return usage


def compact_json(value: Any) -> str:
    return json.dumps(safe_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compact_action_json(action: AgentAction | Mapping[str, Any]) -> str:
    return compact_json(action.to_dict() if hasattr(action, "to_dict") else action)


def truncate_text(text: str, limit: int) -> str:
    raw = str(text)
    return raw if len(raw) <= limit else raw[: max(0, limit - 24)] + "...[truncated]"


def require_non_blank(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise AgentConfigurationError(f"{name} must not be blank")
    return text


def positive_int(value: int, name: str) -> int:
    integer = int(value)
    if integer <= 0:
        raise AgentConfigurationError(f"{name} must be positive")
    return integer


def non_negative_int(value: int | None, name: str) -> int:
    integer = 0 if value is None else int(value)
    if integer < 0:
        raise AgentConfigurationError(f"{name} must be non-negative")
    return integer


def bounded_float(value: float, name: str, low: float, high: float) -> float:
    number = float(value)
    if not low <= number <= high:
        raise AgentConfigurationError(f"{name} must be between {low} and {high}")
    return number


def safe_jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): safe_jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [safe_jsonable(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted(safe_jsonable(item) for item in value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def freeze_jsonable_mapping(value: Mapping[str, Any]) -> JsonMapping:
    return {str(key): safe_jsonable(item) for key, item in value.items()}


freeze_mapping = freeze_jsonable_mapping
freeze_json_object = freeze_jsonable_mapping
freeze_json = safe_jsonable
object_to_json = safe_jsonable


def thaw_json(value: Any) -> Any:
    return thaw_jsonable(value)


def as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    return {}


def merge_metadata(metadata: Mapping[str, Any] | None, extra: Mapping[str, Any]) -> dict[str, Any]:
    data = dict(metadata or {})
    data.update({str(key): value for key, value in extra.items()})
    return data


def optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def add_optional_ints(left: int | None, right: int | None) -> int | None:
    if left is None and right is None:
        return None
    return int(left or 0) + int(right or 0)


def add_optional_floats(left: float | None, right: float | None) -> float | None:
    if left is None and right is None:
        return None
    return float(left or 0.0) + float(right or 0.0)


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__: Final[tuple[str, ...]] = tuple(
    name
    for name in globals()
    if not name.startswith("_")
    and name
    not in {
        "annotations",
        "Any",
        "Final",
        "Mapping",
        "Protocol",
        "Sequence",
        "TypeAlias",
        "dataclass",
        "field",
        "replace",
        "json",
        "re",
        "datetime",
        "UTC",
    }
)
