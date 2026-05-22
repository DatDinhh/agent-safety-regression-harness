"""Tool-using and single-turn ASRH agents.

The tool agent implements the MVP loop: prompt the model for one JSON action,
parse ``tool_call`` or ``final_answer``, dispatch sandbox-backed tools through a
registry, append the observation, and repeat until a terminal condition.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from time import monotonic
from typing import Any, Final

from asrh import DEFAULT_MITIGATION, DEFAULT_MODEL
from asrh.agents.base import (
    AgentAction,
    AgentActionParseError,
    AgentConfig,
    AgentContext,
    AgentExecutionError,
    AgentResult,
    AgentStep,
    AgentStopReason,
    AgentUsage,
    BaseAgent,
    ModelClient,
    ModelClientError,
    ToolResult,
    invoke_model,
    parse_agent_action,
    utc_now_iso,
)
from asrh.agents.prompts import (
    build_initial_messages,
    build_invalid_action_repair_message,
    build_single_turn_messages,
    tool_result_to_message,
)
from asrh.cases.schema import TestCase
from asrh.envs.sandbox import SandboxEnv, SandboxToolResult, build_sandbox_from_case
from asrh.tools.registry import ToolRegistry, build_case_tool_registry

DEFAULT_TOOL_AGENT_NAME: Final[str] = "tool_agent"
DEFAULT_SINGLE_TURN_AGENT_NAME: Final[str] = "single_turn"
TOOL_AGENT_NAME: Final[str] = DEFAULT_TOOL_AGENT_NAME
SINGLE_TURN_AGENT_NAME: Final[str] = DEFAULT_SINGLE_TURN_AGENT_NAME
MOCK_AGENT_NAME: Final[str] = "mock"


class ToolAgentError(RuntimeError):
    """Base runtime error for concrete agents."""


class ToolDispatchError(ToolAgentError):
    """Raised when a tool call cannot be dispatched."""


class ToolAgent(BaseAgent):
    """ReAct-style JSON-action loop with sandboxed tools."""

    name = DEFAULT_TOOL_AGENT_NAME
    mode = "tool_agent"

    def __init__(
        self,
        *,
        name: str | None = None,
        extra_system_instructions: tuple[str, ...] | list[str] = (),
    ) -> None:
        super().__init__(name=name or DEFAULT_TOOL_AGENT_NAME)
        self.mode = "tool_agent"
        self.extra_system_instructions = tuple(str(item) for item in extra_system_instructions)

    def run(
        self,
        *,
        case: TestCase,
        model: ModelClient | Any | None = None,
        model_client: ModelClient | Any | None = None,
        env: SandboxEnv | None = None,
        sandbox: SandboxEnv | None = None,
        tool_registry: ToolRegistry | None = None,
        registry: ToolRegistry | None = None,
        config: AgentConfig | Mapping[str, Any] | None = None,
        model_name: str | None = None,
        mitigation: str | None = None,
    ) -> AgentResult:
        """Run one parsed case and return a pre-checker trajectory."""
        client = model_client if model_client is not None else model
        if client is None:
            raise ModelClientError("ToolAgent.run requires model or model_client")

        cfg = coerce_agent_config(config, mode="tool_agent", model_name=model_name, mitigation=mitigation)
        sandbox_obj = sandbox or env or build_sandbox_from_case(case, mitigation=cfg.mitigation)
        active_registry = prepare_tool_registry(case, tool_registry or registry)
        messages = list(
            build_initial_messages(
                case,
                tool_registry=active_registry,
                mitigation=cfg.mitigation,
                include_tool_schemas=cfg.include_tool_schemas,
                max_steps=cfg.max_steps,
                max_tool_calls=cfg.max_tool_calls,
                extra_system_instructions=self.extra_system_instructions,
            )
        )

        started_at = utc_now_iso()
        start_time = monotonic()
        steps: list[AgentStep] = []
        errors: list[str] = []
        usage = AgentUsage.empty()
        final_answer = ""
        completed = False
        stop_reason = AgentStopReason.MAX_STEPS.value
        tool_call_count = 0
        invalid_action_count = 0

        for step_number in range(1, cfg.max_steps + 1):
            if _timed_out(start_time, cfg.timeout_seconds):
                stop_reason = AgentStopReason.TIMEOUT.value
                errors.append("agent run timed out")
                break

            try:
                response = invoke_model(client, messages, cfg.to_model_config())
            except Exception as exc:  # noqa: BLE001 - model failure belongs in trace, not process crash.
                error = f"model call failed: {exc}"
                errors.append(error)
                steps.append(AgentStep(step=step_number, error=error))
                stop_reason = AgentStopReason.MODEL_ERROR.value
                break

            usage = usage.add(response)
            messages.append(
                messages[0].assistant(
                    response.content,
                    step=step_number,
                    metadata={"finish_reason": response.finish_reason},
                )
            )

            if not response.content.strip():
                error = "empty model response"
                errors.append(error)
                steps.append(AgentStep(step=step_number, model_output=response.content, error=error))
                stop_reason = AgentStopReason.EMPTY_RESPONSE.value
                break

            try:
                action = parse_agent_action(response.content, strict=cfg.strict_json)
            except AgentActionParseError as exc:
                invalid_action_count += 1
                error = str(exc)
                errors.append(error)
                steps.append(AgentStep(step=step_number, model_output=response.content, error=error))
                if cfg.fail_fast or invalid_action_count > cfg.max_invalid_actions:
                    stop_reason = AgentStopReason.INVALID_ACTION.value
                    break
                messages.append(build_invalid_action_repair_message(error))
                continue

            invalid_action_count = 0
            if action.is_final_answer:
                final_answer = action.content or ""
                completed = True
                stop_reason = AgentStopReason.FINAL_ANSWER.value
                steps.append(AgentStep(step=step_number, model_output=response.content, action=action))
                break

            if not action.is_tool_call:
                error = f"unsupported parsed action: {action.action_type}"
                errors.append(error)
                steps.append(AgentStep(step=step_number, model_output=response.content, action=action, error=error))
                stop_reason = AgentStopReason.INVALID_ACTION.value
                break

            if tool_call_count >= cfg.max_tool_calls:
                error = f"max_tool_calls exceeded before calling {action.tool_name!r}"
                errors.append(error)
                steps.append(AgentStep(step=step_number, model_output=response.content, action=action, error=error))
                stop_reason = AgentStopReason.MAX_TOOL_CALLS.value
                break

            result = dispatch_agent_tool_call(action, env=sandbox_obj, tool_registry=active_registry)
            tool_call_count += 1
            steps.append(
                AgentStep(
                    step=step_number,
                    model_output=response.content,
                    action=action,
                    tool_result=result,
                    error=result.error,
                )
            )
            messages.append(tool_result_to_message(result, step=step_number))

            if cfg.stop_on_policy_violation and result.policy_violation:
                error = result.error or f"policy violation from {result.tool_name}"
                errors.append(error)
                stop_reason = AgentStopReason.POLICY_STOPPED.value
                break
            if cfg.stop_on_tool_error and result.failed:
                error = result.error or f"tool {result.tool_name} failed"
                errors.append(error)
                stop_reason = AgentStopReason.TOOL_ERROR.value
                break
            if usage.total_tokens is not None and usage.total_tokens >= cfg.max_total_tokens:
                stop_reason = AgentStopReason.TOKEN_BUDGET.value
                errors.append("max_total_tokens reached")
                break
        else:
            stop_reason = AgentStopReason.MAX_STEPS.value

        return AgentResult(
            case_id=case.id,
            model=cfg.model_name,
            mitigation=cfg.mitigation,
            mode=self.mode,
            started_at=started_at,
            ended_at=utc_now_iso(),
            messages=tuple(messages),
            steps=tuple(steps),
            final_answer=final_answer,
            stop_reason=stop_reason,
            completed=completed,
            tool_call_count=tool_call_count,
            usage=usage,
            errors=tuple(errors),
            metadata={
                "agent_name": self.name,
                "config": cfg.to_dict(),
                "tool_registry": active_registry.summary().to_dict()
                if hasattr(active_registry, "summary")
                else str(type(active_registry).__name__),
                "sandbox": sandbox_obj.to_dict() if hasattr(sandbox_obj, "to_dict") else None,
            },
        )


class SingleTurnAgent(BaseAgent):
    """No-tool baseline agent."""

    name = DEFAULT_SINGLE_TURN_AGENT_NAME
    mode = "single_turn"

    def __init__(
        self,
        *,
        name: str | None = None,
        extra_system_instructions: tuple[str, ...] | list[str] = (),
    ) -> None:
        super().__init__(name=name or DEFAULT_SINGLE_TURN_AGENT_NAME)
        self.mode = "single_turn"
        self.extra_system_instructions = tuple(str(item) for item in extra_system_instructions)

    def run(
        self,
        *,
        case: TestCase,
        model: ModelClient | Any | None = None,
        model_client: ModelClient | Any | None = None,
        config: AgentConfig | Mapping[str, Any] | None = None,
        model_name: str | None = None,
        mitigation: str | None = None,
        env: SandboxEnv | None = None,
        tool_registry: ToolRegistry | None = None,
        registry: ToolRegistry | None = None,
    ) -> AgentResult:
        """Run one parsed case without exposing tools."""
        del env, tool_registry, registry
        client = model_client if model_client is not None else model
        if client is None:
            raise ModelClientError("SingleTurnAgent.run requires model or model_client")

        cfg = coerce_agent_config(config, mode="single_turn", model_name=model_name, mitigation=mitigation)
        started_at = utc_now_iso()
        messages = list(
            build_single_turn_messages(
                case,
                mitigation=cfg.mitigation,
                extra_system_instructions=self.extra_system_instructions,
            )
        )
        steps: list[AgentStep] = []
        errors: list[str] = []
        final_answer = ""
        completed = False
        stop_reason = AgentStopReason.FINAL_ANSWER.value
        usage = AgentUsage.empty()

        try:
            response = invoke_model(client, messages, cfg.to_model_config())
        except Exception as exc:  # noqa: BLE001 - record model failure in result.
            error = f"model call failed: {exc}"
            errors.append(error)
            steps.append(AgentStep(step=1, error=error))
            return AgentResult(
                case_id=case.id,
                model=cfg.model_name,
                mitigation=cfg.mitigation,
                mode=self.mode,
                started_at=started_at,
                ended_at=utc_now_iso(),
                messages=tuple(messages),
                steps=tuple(steps),
                final_answer="",
                stop_reason=AgentStopReason.MODEL_ERROR.value,
                completed=False,
                tool_call_count=0,
                usage=usage,
                errors=tuple(errors),
                metadata={"agent_name": self.name, "config": cfg.to_dict()},
            )

        usage = usage.add(response)
        messages.append(messages[0].assistant(response.content, step=1))
        try:
            action = parse_agent_action(response.content, strict=cfg.strict_json)
        except AgentActionParseError as exc:
            error = str(exc)
            errors.append(error)
            final_answer = response.content.strip()
            completed = not cfg.strict_json
            stop_reason = AgentStopReason.INVALID_ACTION.value if cfg.strict_json else AgentStopReason.FINAL_ANSWER.value
            steps.append(AgentStep(step=1, model_output=response.content, error=error))
        else:
            if action.is_final_answer:
                final_answer = action.content or ""
                completed = True
                steps.append(AgentStep(step=1, model_output=response.content, action=action))
            else:
                error = "single_turn mode does not allow tool_call actions"
                errors.append(error)
                stop_reason = AgentStopReason.INVALID_ACTION.value
                steps.append(AgentStep(step=1, model_output=response.content, action=action, error=error))

        return AgentResult(
            case_id=case.id,
            model=cfg.model_name,
            mitigation=cfg.mitigation,
            mode=self.mode,
            started_at=started_at,
            ended_at=utc_now_iso(),
            messages=tuple(messages),
            steps=tuple(steps),
            final_answer=final_answer,
            stop_reason=stop_reason,
            completed=completed,
            tool_call_count=0,
            usage=usage,
            errors=tuple(errors),
            metadata={"agent_name": self.name, "config": cfg.to_dict()},
        )


def dispatch_agent_tool_call(action: AgentAction, *, env: SandboxEnv, tool_registry: ToolRegistry) -> ToolResult:
    """Dispatch a parsed tool-call action through registry, falling back to sandbox denial logging."""
    call = action.to_tool_call()
    try:
        result = tool_registry.call_tool_call(call, env)
    except Exception as registry_exc:  # noqa: BLE001
        try:
            sandbox_result = env.call_tool(call.tool_name, call.args)
        except Exception as sandbox_exc:  # noqa: BLE001
            return ToolResult.denied(
                call.tool_name,
                args=call.args,
                error=f"tool dispatch failed: registry={registry_exc}; sandbox={sandbox_exc}",
                metadata={"registry_error": str(registry_exc), "sandbox_error": str(sandbox_exc)},
            )
        return _coerce_tool_result(sandbox_result)
    return _coerce_tool_result(result)


def coerce_agent_config(
    config: AgentConfig | Mapping[str, Any] | None,
    *,
    mode: str,
    model_name: str | None = None,
    mitigation: str | None = None,
) -> AgentConfig:
    """Coerce user-provided config into an immutable AgentConfig."""
    overrides: dict[str, Any] = {"mode": mode}
    if model_name is not None:
        overrides["model_name"] = model_name
    if mitigation is not None:
        overrides["mitigation"] = mitigation

    if config is None:
        data = {"model_name": model_name or DEFAULT_MODEL, "mitigation": mitigation or DEFAULT_MITIGATION, "mode": mode}
        return AgentConfig(**data)
    if isinstance(config, AgentConfig):
        return replace(config, **overrides)
    if isinstance(config, Mapping):
        data = dict(config)
        data.update(overrides)
        return AgentConfig(**data)
    raise TypeError("config must be AgentConfig, mapping, or None")


def prepare_tool_registry(case: TestCase, registry: ToolRegistry | None) -> ToolRegistry:
    """Return a case-filtered registry."""
    if registry is None:
        return build_case_tool_registry(case, strict=False)
    if hasattr(registry, "for_case"):
        return registry.for_case(case, strict=False)
    return registry


build_registry_for_case = prepare_tool_registry


def make_agent_context(
    *,
    case: TestCase,
    env: SandboxEnv | None = None,
    tool_registry: ToolRegistry | None = None,
    config: AgentConfig | Mapping[str, Any] | None = None,
    mitigation: str | None = None,
    model_name: str | None = None,
) -> AgentContext:
    """Build the execution context expected by runner modules."""
    cfg = coerce_agent_config(config, mode="tool_agent", model_name=model_name, mitigation=mitigation)
    sandbox = env or build_sandbox_from_case(case, mitigation=cfg.mitigation)
    registry = prepare_tool_registry(case, tool_registry)
    return AgentContext(case=case, env=sandbox, tool_registry=registry, config=cfg)


def build_tool_agent(**kwargs: Any) -> ToolAgent:
    return ToolAgent(**kwargs)


def build_single_turn_agent(**kwargs: Any) -> SingleTurnAgent:
    return SingleTurnAgent(**kwargs)


def build_agent(mode: str = "tool_agent", **kwargs: Any) -> BaseAgent:
    normalized = str(mode).strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in {"single_turn", "single", "no_tool", "no_tools"}:
        return build_single_turn_agent(**kwargs)
    if normalized in {"tool_agent", "tool", "tools", "mock"}:
        return build_tool_agent(**kwargs)
    if normalized in {"react", "react_agent", "json_react", "json_react_agent"}:
        from asrh.agents.react_agent import ReactAgent

        return ReactAgent(**kwargs)
    raise ValueError(f"unsupported agent mode: {mode!r}")


def run_agent(*, context: AgentContext, model_client: ModelClient | Any) -> AgentResult:
    return ToolAgent().run(
        case=context.case,
        env=context.env,
        model_client=model_client,
        tool_registry=context.tool_registry,
        config=context.config,
    )


def run_tool_agent(
    *,
    case: TestCase,
    model: ModelClient | Any | None = None,
    model_client: ModelClient | Any | None = None,
    env: SandboxEnv | None = None,
    tool_registry: ToolRegistry | None = None,
    config: AgentConfig | Mapping[str, Any] | None = None,
) -> AgentResult:
    return ToolAgent().run(case=case, model=model, model_client=model_client, env=env, tool_registry=tool_registry, config=config)


def run_single_turn_agent(
    *,
    case: TestCase,
    model: ModelClient | Any | None = None,
    model_client: ModelClient | Any | None = None,
    config: AgentConfig | Mapping[str, Any] | None = None,
) -> AgentResult:
    return SingleTurnAgent().run(case=case, model=model, model_client=model_client, config=config)


def _coerce_tool_result(result: ToolResult | SandboxToolResult | Any) -> ToolResult:
    if isinstance(result, ToolResult):
        return result
    if isinstance(result, SandboxToolResult):
        return ToolResult.from_sandbox_result(result)
    if isinstance(result, Mapping):
        return ToolResult(
            tool_name=str(result.get("tool_name") or result.get("tool") or "unknown_tool"),
            args=result.get("args", {}),
            output=str(result.get("output", "")),
            error=None if result.get("error") is None else str(result.get("error")),
            allowed=bool(result.get("allowed", False)),
            policy_violation=bool(result.get("policy_violation", False)),
            labels=tuple(str(item) for item in result.get("labels", ())),
            metadata={"coerced_from_mapping": True},
        )
    return ToolResult.denied("unknown_tool", error=f"unsupported tool result type: {type(result).__name__}")


def _timed_out(start_time: float, timeout_seconds: int) -> bool:
    return monotonic() - start_time > float(timeout_seconds)


ToolUsingAgent = ToolAgent
JsonToolAgent = ToolAgent
JsonActionToolAgent = ToolAgent
MockAgent = ToolAgent
ModelLike = ModelClient

__all__: Final[tuple[str, ...]] = tuple(
    name
    for name in globals()
    if not name.startswith("_")
    and name not in {"annotations", "Any", "Final", "Mapping", "replace", "monotonic"}
)
