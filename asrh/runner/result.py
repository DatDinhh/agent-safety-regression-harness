"""Structured result objects and aggregate metrics for ASRH runners."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from asrh import (
    DEFAULT_MAX_STEPS,
    DEFAULT_MAX_TOKENS_PER_RESPONSE,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TOTAL_TOKENS,
    DEFAULT_MITIGATION,
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
)
from asrh.agents import AgentConfig
from asrh.runner.trace import TraceConfig, TraceRecord, jsonable, utc_now_iso

DEFAULT_AGENT_MODE: Final[str] = "tool_agent"

STATUS_COMPLETED: Final[str] = "completed"
STATUS_ERROR: Final[str] = "error"
STATUS_FAILED: Final[str] = STATUS_ERROR
STATUS_PARTIAL: Final[str] = "partial"
STATUS_SKIPPED: Final[str] = "skipped"

RUNNER_STATUS_COMPLETED: Final[str] = STATUS_COMPLETED
RUNNER_STATUS_ERROR: Final[str] = STATUS_ERROR
RUNNER_STATUS_FAILED: Final[str] = STATUS_FAILED
RUNNER_STATUS_PARTIAL: Final[str] = STATUS_PARTIAL
RUNNER_STATUS_SKIPPED: Final[str] = STATUS_SKIPPED


class RunnerResultError(RuntimeError):
    """Base exception for runner result handling."""


class RunnerConfigurationError(RunnerResultError):
    """Raised when runner configuration is invalid."""


class RunnerExecutionError(RunnerResultError):
    """Raised when a case or suite cannot be executed."""


class CaseExecutionError(RunnerExecutionError):
    """Raised when one case execution fails and fail-fast is enabled."""


class SuiteExecutionError(RunnerExecutionError):
    """Raised when suite execution fails and fail-fast is enabled."""


class ModelResolutionError(RunnerConfigurationError):
    """Raised when a requested model identifier cannot be resolved."""


@dataclass(frozen=True, slots=True)
class RunnerConfig:
    """Configuration shared by case and suite runner backends."""

    model: str = DEFAULT_MODEL
    mitigation: str = DEFAULT_MITIGATION
    agent_mode: str = DEFAULT_AGENT_MODE
    temperature: float = DEFAULT_TEMPERATURE
    seed: int | None = None
    max_steps: int = DEFAULT_MAX_STEPS
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS
    max_tokens_per_response: int = DEFAULT_MAX_TOKENS_PER_RESPONSE
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    fail_fast: bool = False
    append: bool = False
    run_started_at: str | None = None
    strict_json: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def started_at(self) -> str:
        """Return the configured suite/case start timestamp."""
        return self.run_started_at or utc_now_iso()

    def to_agent_config(self) -> AgentConfig:
        """Return the provider-neutral agent configuration."""
        return AgentConfig(
            model_name=self.model,
            mitigation=self.mitigation,
            mode=self.agent_mode,
            temperature=self.temperature,
            seed=self.seed,
            max_steps=self.max_steps,
            max_tool_calls=self.max_tool_calls,
            max_tokens_per_response=self.max_tokens_per_response,
            max_total_tokens=self.max_total_tokens,
            timeout_seconds=self.timeout_seconds,
            strict_json=self.strict_json,
            fail_fast=self.fail_fast,
            metadata=self.metadata,
        )

    def to_trace_config(self) -> TraceConfig:
        """Return the trace configuration snapshot."""
        return TraceConfig(
            model=self.model,
            mitigation=self.mitigation,
            agent_mode=self.agent_mode,
            temperature=self.temperature,
            seed=self.seed,
            max_steps=self.max_steps,
            max_tool_calls=self.max_tool_calls,
            max_tokens_per_response=self.max_tokens_per_response,
            max_total_tokens=self.max_total_tokens,
            timeout_seconds=self.timeout_seconds,
            fail_fast=self.fail_fast,
            strict_json=self.strict_json,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible config mapping."""
        return jsonable(
            {
                "model": self.model,
                "mitigation": self.mitigation,
                "agent_mode": self.agent_mode,
                "temperature": self.temperature,
                "seed": self.seed,
                "max_steps": self.max_steps,
                "max_tool_calls": self.max_tool_calls,
                "max_tokens_per_response": self.max_tokens_per_response,
                "max_total_tokens": self.max_total_tokens,
                "timeout_seconds": self.timeout_seconds,
                "fail_fast": self.fail_fast,
                "append": self.append,
                "run_started_at": self.run_started_at,
                "strict_json": self.strict_json,
                "metadata": self.metadata,
            }
        )


RunConfig = RunnerConfig
ExecutionConfig = RunnerConfig
CaseExecutionConfig = RunnerConfig
SuiteExecutionConfig = RunnerConfig


@dataclass(frozen=True, slots=True)
class CaseRunResult:
    """Summary returned by one case execution."""

    trace: TraceRecord
    status: str = STATUS_COMPLETED
    case_path: Path | None = None
    output_path: Path | None = None
    error: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_trace(
        cls,
        trace: TraceRecord | Mapping[str, Any],
        *,
        status: str | None = None,
        case_path: str | Path | None = None,
        output_path: str | Path | None = None,
        error: str | None = None,
        errors: Sequence[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> CaseRunResult:
        """Build a result from a trace object or JSONL mapping."""
        record = trace if isinstance(trace, TraceRecord) else TraceRecord.from_mapping(trace)
        if errors:
            merged = tuple(str(item) for item in [*record.errors, *errors] if str(item).strip())
            record = TraceRecord.from_mapping({**record.to_dict(), "errors": list(merged)})
        return cls(
            trace=record,
            status=status or record.status,
            case_path=None if case_path is None else Path(case_path).expanduser(),
            output_path=None if output_path is None else Path(output_path).expanduser(),
            error=error,
            metadata=dict(metadata or {}),
        )

    @property
    def run_id(self) -> str:
        return self.trace.run_id

    @property
    def case_id(self) -> str:
        return self.trace.case_id

    @property
    def suite(self) -> str:
        return self.trace.suite

    @property
    def model(self) -> str:
        return self.trace.model

    @property
    def mitigation(self) -> str:
        return self.trace.mitigation

    @property
    def agent_mode(self) -> str:
        return self.trace.agent_mode or str(self.trace.config.get("agent_mode", DEFAULT_AGENT_MODE))

    @property
    def case_count(self) -> int:
        return 1

    @property
    def verdict(self) -> Mapping[str, Any]:
        return self.trace.verdict

    @property
    def overall(self) -> str:
        return str(self.verdict.get("overall", "FAIL"))

    @property
    def utility_pass(self) -> bool:
        return self.verdict.get("utility_pass") is True

    @property
    def safety_pass(self) -> bool:
        return self.verdict.get("safety_pass") is True

    @property
    def attack_success(self) -> bool:
        return self.verdict.get("attack_success") is True

    @property
    def utility_pass_rate(self) -> float:
        return 1.0 if self.utility_pass else 0.0

    @property
    def safety_pass_rate(self) -> float:
        return 1.0 if self.safety_pass else 0.0

    @property
    def attack_success_rate(self) -> float:
        return 1.0 if self.attack_success else 0.0

    @property
    def unsafe_success_rate(self) -> float:
        return 1.0 if self.overall == "UNSAFE_SUCCESS" else 0.0

    @property
    def safe_but_useless_rate(self) -> float:
        return 1.0 if self.overall == "SAFE_BUT_USELESS" else 0.0

    @property
    def over_refusal_rate(self) -> float:
        return 1.0 if has_failure_class(self.trace, "OVER_REFUSAL") else 0.0

    @property
    def average_tool_calls(self) -> float:
        return float(self.tool_call_count)

    @property
    def average_policy_violations(self) -> float:
        return float(self.policy_violation_count)

    @property
    def tool_call_count(self) -> int:
        return len(self.trace.tool_calls)

    @property
    def policy_violation_count(self) -> int:
        return sum(1 for call in self.trace.tool_calls if call.get("policy_violation") is True)

    @property
    def errors(self) -> tuple[str, ...]:
        values = [str(item) for item in self.trace.errors if str(item).strip()]
        if self.error:
            values.append(str(self.error))
        return tuple(values)

    def to_dict(self, *, include_trace: bool = False) -> dict[str, Any]:
        """Return a JSON-compatible summary."""
        payload: dict[str, Any] = {
            "status": self.status,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "suite": self.suite,
            "model": self.model,
            "mitigation": self.mitigation,
            "agent_mode": self.agent_mode,
            "case_path": self.case_path.as_posix() if self.case_path else None,
            "output_path": self.output_path.as_posix() if self.output_path else None,
            "case_count": 1,
            "overall": self.overall,
            "utility_pass": self.utility_pass,
            "safety_pass": self.safety_pass,
            "attack_success": self.attack_success,
            "utility_pass_rate": self.utility_pass_rate,
            "safety_pass_rate": self.safety_pass_rate,
            "attack_success_rate": self.attack_success_rate,
            "unsafe_success_rate": self.unsafe_success_rate,
            "safe_but_useless_rate": self.safe_but_useless_rate,
            "over_refusal_rate": self.over_refusal_rate,
            "average_tool_calls": self.average_tool_calls,
            "average_policy_violations": self.average_policy_violations,
            "tool_call_count": self.tool_call_count,
            "policy_violation_count": self.policy_violation_count,
            "errors": list(self.errors),
            "metadata": jsonable(self.metadata),
        }
        if include_trace:
            payload["trace"] = self.trace.to_dict()
        return payload


RunCaseResult = CaseRunResult
CaseExecutionResult = CaseRunResult
CaseRunSummary = CaseRunResult


@dataclass(frozen=True, slots=True)
class SuiteRunResult:
    """Summary returned by suite execution."""

    run_id: str
    suite_path: Path
    output_path: Path | None
    model: str
    mitigation: str
    agent_mode: str
    results: tuple[CaseRunResult, ...]
    status: str = STATUS_COMPLETED
    started_at: str | None = None
    ended_at: str | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def case_count(self) -> int:
        return len(self.results)

    @property
    def total_cases(self) -> int:
        return self.case_count

    @property
    def completed_case_count(self) -> int:
        return sum(result.status == STATUS_COMPLETED for result in self.results)

    @property
    def failed_case_count(self) -> int:
        return sum(result.status != STATUS_COMPLETED for result in self.results)

    def metrics(self) -> dict[str, Any]:
        return compute_metrics(self.results)

    @property
    def utility_pass_rate(self) -> float:
        return float(self.metrics().get("utility_pass_rate", 0.0))

    @property
    def safety_pass_rate(self) -> float:
        return float(self.metrics().get("safety_pass_rate", 0.0))

    @property
    def attack_success_rate(self) -> float:
        return float(self.metrics().get("attack_success_rate", 0.0))

    @property
    def unsafe_success_rate(self) -> float:
        return float(self.metrics().get("unsafe_success_rate", 0.0))

    @property
    def safe_but_useless_rate(self) -> float:
        return float(self.metrics().get("safe_but_useless_rate", 0.0))

    @property
    def over_refusal_rate(self) -> float:
        return float(self.metrics().get("over_refusal_rate", 0.0))

    @property
    def average_tool_calls(self) -> float:
        return float(self.metrics().get("average_tool_calls", 0.0))

    @property
    def average_policy_violations(self) -> float:
        return float(self.metrics().get("average_policy_violations", 0.0))

    def to_dict(self, *, include_case_results: bool = True) -> dict[str, Any]:
        """Return a JSON-compatible suite summary."""
        payload: dict[str, Any] = {
            "status": self.status,
            "run_id": self.run_id,
            "suite_path": self.suite_path.as_posix(),
            "output_path": self.output_path.as_posix() if self.output_path else None,
            "model": self.model,
            "mitigation": self.mitigation,
            "agent_mode": self.agent_mode,
            "case_count": self.case_count,
            "total_cases": self.total_cases,
            "completed_case_count": self.completed_case_count,
            "failed_case_count": self.failed_case_count,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "errors": list(self.errors),
            "metadata": jsonable(self.metadata),
            **self.metrics(),
        }
        if include_case_results:
            payload["case_results"] = [result.to_dict() for result in self.results]
        return payload


RunSuiteResult = SuiteRunResult
SuiteRunSummary = SuiteRunResult
RunnerSummary = SuiteRunResult
RunSummary = SuiteRunResult


def compute_metrics(results: Sequence[CaseRunResult]) -> dict[str, Any]:
    """Compute aggregate metrics required by the specification."""
    n = len(results)
    if n == 0:
        return empty_metrics()
    utility = sum(result.utility_pass for result in results)
    safety = sum(result.safety_pass for result in results)
    attack = sum(result.attack_success for result in results)
    unsafe = sum(result.overall == "UNSAFE_SUCCESS" for result in results)
    safe_useless = sum(result.overall == "SAFE_BUT_USELESS" for result in results)
    over_refusal = sum(has_failure_class(result.trace, "OVER_REFUSAL") for result in results)
    failures = Counter(cls for result in results for cls in failure_classes(result.trace))
    categories = Counter(str(result.trace.metadata.get("category") or result.suite or "unknown") for result in results)
    severities = Counter(str(result.trace.metadata.get("severity") or "unknown") for result in results)
    return {
        "case_count": n,
        "total_cases": n,
        "utility_pass_count": utility,
        "safety_pass_count": safety,
        "attack_success_count": attack,
        "utility_pass_rate": rate(utility, n),
        "safety_pass_rate": rate(safety, n),
        "attack_success_rate": rate(attack, n),
        "unsafe_success_rate": rate(unsafe, n),
        "safe_but_useless_rate": rate(safe_useless, n),
        "over_refusal_rate": rate(over_refusal, n),
        "average_tool_calls": average([result.tool_call_count for result in results]),
        "average_policy_violations": average([result.policy_violation_count for result in results]),
        "by_failure_class": dict(sorted(failures.items())),
        "by_category": dict(sorted(categories.items())),
        "by_severity": dict(sorted(severities.items())),
    }


def empty_metrics() -> dict[str, Any]:
    """Return aggregate metrics for an empty run."""
    return {
        "case_count": 0,
        "total_cases": 0,
        "utility_pass_count": 0,
        "safety_pass_count": 0,
        "attack_success_count": 0,
        "utility_pass_rate": 0.0,
        "safety_pass_rate": 0.0,
        "attack_success_rate": 0.0,
        "unsafe_success_rate": 0.0,
        "safe_but_useless_rate": 0.0,
        "over_refusal_rate": 0.0,
        "average_tool_calls": 0.0,
        "average_policy_violations": 0.0,
        "by_failure_class": {},
        "by_category": {},
        "by_severity": {},
    }


summarize_records = compute_metrics
summarize_case_results = compute_metrics


def summarize_trace_records(records: Sequence[TraceRecord | Mapping[str, Any]]) -> dict[str, Any]:
    """Compute metrics directly from trace records or JSON mappings."""
    results = [CaseRunResult.from_trace(record) for record in records]
    return compute_metrics(results)


def failure_classes(trace: TraceRecord) -> tuple[str, ...]:
    """Return failed checker failure classes for one trace."""
    classes: list[str] = []
    for result in trace.checker_results:
        failure_class = result.get("failure_class")
        if result.get("passed") is False and failure_class:
            classes.append(str(failure_class))
    return tuple(classes)


def has_failure_class(trace: TraceRecord, failure_class: str) -> bool:
    return failure_class in failure_classes(trace)


def rate(count: int, total: int) -> float:
    """Return a stable ratio in the closed interval [0, 1]."""
    return round(float(count) / float(total), 6) if total else 0.0


def average(values: Sequence[int | float]) -> float:
    """Return a rounded arithmetic mean."""
    return round(float(sum(values)) / float(len(values)), 6) if values else 0.0


__all__: Final[tuple[str, ...]] = (
    "DEFAULT_AGENT_MODE",
    "CaseExecutionConfig",
    "CaseExecutionError",
    "CaseExecutionResult",
    "CaseRunResult",
    "CaseRunSummary",
    "ExecutionConfig",
    "ModelResolutionError",
    "RunCaseResult",
    "RunConfig",
    "RunSummary",
    "RunSuiteResult",
    "RUNNER_STATUS_COMPLETED",
    "RUNNER_STATUS_ERROR",
    "RUNNER_STATUS_FAILED",
    "RUNNER_STATUS_PARTIAL",
    "RUNNER_STATUS_SKIPPED",
    "RunnerConfig",
    "RunnerConfigurationError",
    "RunnerExecutionError",
    "RunnerResultError",
    "RunnerSummary",
    "STATUS_COMPLETED",
    "STATUS_ERROR",
    "STATUS_FAILED",
    "STATUS_PARTIAL",
    "STATUS_SKIPPED",
    "SuiteExecutionConfig",
    "SuiteExecutionError",
    "SuiteRunResult",
    "SuiteRunSummary",
    "average",
    "compute_metrics",
    "empty_metrics",
    "failure_classes",
    "has_failure_class",
    "rate",
    "summarize_case_results",
    "summarize_records",
    "summarize_trace_records",
)

# Compatibility properties used by CLI smoke tests and external scripts.
if not hasattr(SuiteRunResult, "utility_pass_rate"):
    SuiteRunResult.utility_pass_rate = property(lambda self: float(self.metrics().get("utility_pass_rate", 0.0)))  # type: ignore[attr-defined]
if not hasattr(SuiteRunResult, "safety_pass_rate"):
    SuiteRunResult.safety_pass_rate = property(lambda self: float(self.metrics().get("safety_pass_rate", 0.0)))  # type: ignore[attr-defined]
if not hasattr(SuiteRunResult, "attack_success_rate"):
    SuiteRunResult.attack_success_rate = property(lambda self: float(self.metrics().get("attack_success_rate", 0.0)))  # type: ignore[attr-defined]
if not hasattr(SuiteRunResult, "unsafe_success_rate"):
    SuiteRunResult.unsafe_success_rate = property(lambda self: float(self.metrics().get("unsafe_success_rate", 0.0)))  # type: ignore[attr-defined]
if not hasattr(SuiteRunResult, "safe_but_useless_rate"):
    SuiteRunResult.safe_but_useless_rate = property(lambda self: float(self.metrics().get("safe_but_useless_rate", 0.0)))  # type: ignore[attr-defined]
if not hasattr(SuiteRunResult, "over_refusal_rate"):
    SuiteRunResult.over_refusal_rate = property(lambda self: float(self.metrics().get("over_refusal_rate", 0.0)))  # type: ignore[attr-defined]
