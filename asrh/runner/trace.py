"""Trace construction and JSONL persistence for ASRH runner outputs.

Runner traces are the canonical execution artifact: one JSON object per case,
written as JSONL.  The shape intentionally mirrors the MVP specification so the
CLI report module can consume traces without importing runtime code.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Final, TypeAlias

from asrh import (
    DEFAULT_MAX_STEPS,
    DEFAULT_MAX_TOKENS_PER_RESPONSE,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TOTAL_TOKENS,
    DEFAULT_MITIGATION,
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    TRACE_SCHEMA_VERSION,
    get_version,
)

JsonDict: TypeAlias = dict[str, Any]
JsonMapping: TypeAlias = Mapping[str, Any]

DEFAULT_JSONL_ENCODING: Final[str] = "utf-8"
DEFAULT_AGENT_MODE: Final[str] = "tool_agent"
RUN_ID_TIME_FORMAT: Final[str] = "%Y%m%dT%H%M%SZ"
RUN_ID_UNSAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9_.-]+")


class TraceError(RuntimeError):
    """Base exception for trace serialization and persistence."""


class TraceSerializationError(TraceError):
    """Raised when a trace cannot be converted to JSON."""


class TraceIOError(TraceError):
    """Raised when JSONL trace IO fails."""


TraceReadError = TraceIOError
TraceWriteError = TraceIOError


@dataclass(frozen=True, slots=True)
class TraceConfig:
    """Runner configuration fields embedded in every trace record."""

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
    strict_json: bool = True

    def to_dict(self) -> JsonDict:
        return jsonable(asdict(self))


RunnerTraceConfig = TraceConfig
TraceConfigSnapshot = TraceConfig


@dataclass(frozen=True, slots=True)
class TraceRecord:
    """One JSONL-compatible ASRH case execution trace."""

    run_id: str
    case_id: str
    suite: str
    model: str
    mitigation: str
    started_at: str
    ended_at: str
    config: JsonMapping
    messages: tuple[JsonMapping, ...]
    tool_calls: tuple[JsonMapping, ...]
    final_answer: str
    checker_results: tuple[JsonMapping, ...]
    verdict: JsonMapping
    usage: JsonMapping = field(default_factory=dict)
    metadata: JsonMapping = field(default_factory=dict)
    task: JsonMapping = field(default_factory=dict)
    attack: JsonMapping | None = None
    environment: JsonMapping = field(default_factory=dict)
    agent_steps: tuple[JsonMapping, ...] = field(default_factory=tuple)
    sandbox: JsonMapping = field(default_factory=dict)
    trace_schema_version: str = TRACE_SCHEMA_VERSION
    asrh_version: str = field(default_factory=get_version)
    agent_mode: str = DEFAULT_AGENT_MODE
    status: str = "completed"
    errors: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TraceRecord":
        cfg = as_mapping(value.get("config"))
        return cls(
            run_id=str(value.get("run_id", "unknown_run")),
            case_id=str(value.get("case_id", "unknown_case")),
            suite=str(value.get("suite", value.get("category", "unknown"))),
            model=str(value.get("model", cfg.get("model", DEFAULT_MODEL))),
            mitigation=str(value.get("mitigation", cfg.get("mitigation", DEFAULT_MITIGATION))),
            started_at=str(value.get("started_at", "")),
            ended_at=str(value.get("ended_at", "")),
            config=cfg,
            messages=tuple(as_mapping(item) for item in as_sequence(value.get("messages"))),
            tool_calls=tuple(normalize_tool_call(item) for item in as_sequence(value.get("tool_calls"))),
            final_answer=str(value.get("final_answer", "")),
            checker_results=tuple(as_mapping(item) for item in as_sequence(value.get("checker_results"))),
            verdict=as_mapping(value.get("verdict")),
            usage=as_mapping(value.get("usage")),
            metadata=as_mapping(value.get("metadata")),
            task=as_mapping(value.get("task")),
            attack=None if value.get("attack") is None else as_mapping(value.get("attack")),
            environment=as_mapping(value.get("environment")),
            agent_steps=tuple(as_mapping(item) for item in as_sequence(value.get("agent_steps", value.get("steps")))),
            sandbox=as_mapping(value.get("sandbox")),
            trace_schema_version=str(value.get("trace_schema_version", TRACE_SCHEMA_VERSION)),
            asrh_version=str(value.get("asrh_version", get_version())),
            agent_mode=str(value.get("agent_mode", cfg.get("agent_mode", cfg.get("mode", DEFAULT_AGENT_MODE)))),
            status=str(value.get("status", "completed")),
            errors=tuple(str(item) for item in as_sequence(value.get("errors")) if str(item).strip()),
        )

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
    def overall(self) -> str:
        return str(self.verdict.get("overall", "FAIL"))

    def to_dict(self) -> JsonDict:
        payload: JsonDict = {
            "trace_schema_version": self.trace_schema_version,
            "asrh_version": self.asrh_version,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "suite": self.suite,
            "model": self.model,
            "mitigation": self.mitigation,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "config": jsonable(self.config),
            "metadata": jsonable(self.metadata),
            "task": jsonable(self.task),
            "attack": jsonable(self.attack),
            "environment": jsonable(self.environment),
            "messages": [jsonable(item) for item in self.messages],
            "agent_steps": [jsonable(item) for item in self.agent_steps],
            "steps": [jsonable(item) for item in self.agent_steps],
            "tool_calls": [normalize_tool_call(item) for item in self.tool_calls],
            "final_answer": self.final_answer,
            "checker_results": [jsonable(item) for item in self.checker_results],
            "verdict": jsonable(self.verdict),
            "utility_pass": self.utility_pass,
            "safety_pass": self.safety_pass,
            "attack_success": self.attack_success,
            "overall": self.overall,
            "usage": jsonable(self.usage),
            "sandbox": jsonable(self.sandbox),
            "agent_mode": self.agent_mode,
            "status": self.status,
            "errors": list(self.errors),
        }
        return payload

    def to_json(self) -> str:
        return trace_json(self.to_dict())


RunTrace = TraceRecord
RunTraceRecord = TraceRecord
CaseTrace = TraceRecord


@dataclass(frozen=True, slots=True)
class TraceWriteResult:
    """Summary of a JSONL write operation."""

    path: str
    records_written: int
    append: bool

    def to_dict(self) -> JsonDict:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_run_id(*, started_at: str | None = None, model: str = DEFAULT_MODEL, mitigation: str = DEFAULT_MITIGATION, target: str | None = None, suite: str | None = None) -> str:
    raw_time = started_at or utc_now_iso()
    try:
        timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).astimezone(UTC).strftime(RUN_ID_TIME_FORMAT)
    except ValueError:
        timestamp = datetime.now(UTC).strftime(RUN_ID_TIME_FORMAT)
    suffix = target or suite
    parts = [timestamp, safe_id_part(model), safe_id_part(mitigation)]
    if suffix:
        parts.append(safe_id_part(suffix))
    return "_".join(part for part in parts if part)


build_run_id = make_run_id


def build_prechecker_trace_mapping(*, case: Any, suite: str | None, agent_result: Any, env: Any | None = None, metadata: Mapping[str, Any] | None = None) -> JsonDict:
    """Build the checker-facing trace mapping before checker results exist."""
    result = object_to_dict(agent_result)
    return {
        "case_id": str(getattr(case, "id", result.get("case_id", ""))),
        "suite": suite or str(getattr(case, "category", "")),
        "model": str(result.get("model") or result.get("model_name") or DEFAULT_MODEL),
        "mitigation": str(result.get("mitigation") or DEFAULT_MITIGATION),
        "started_at": str(result.get("started_at", "")),
        "ended_at": str(result.get("ended_at", "")),
        "metadata": {**case_metadata(case), **jsonable(metadata or {})},
        "task": case_task(case),
        "attack": case_attack(case),
        "environment": environment_summary(case),
        "messages": messages_to_dicts(result.get("messages", getattr(agent_result, "messages", ()))),
        "agent_steps": sequence_to_dicts(result.get("agent_steps", result.get("steps", getattr(agent_result, "steps", ())))),
        "steps": sequence_to_dicts(result.get("agent_steps", result.get("steps", getattr(agent_result, "steps", ())))),
        "tool_calls": tool_calls_from_env(env) or tuple(normalize_tool_call(item) for item in as_sequence(result.get("tool_calls"))),
        "final_answer": str(result.get("final_answer", getattr(agent_result, "final_answer", ""))),
        "usage": as_mapping(result.get("usage")),
        "sandbox": sandbox_snapshot(env) if env is not None else {},
        "errors": tuple(str(item) for item in as_sequence(result.get("errors")) if str(item).strip()),
    }


build_precheck_trace_mapping = build_prechecker_trace_mapping
build_prechecker_trace = build_prechecker_trace_mapping


def build_run_trace(*, run_id: str, case: Any, suite: str | None, case_path: str | Path | None, config: TraceConfig | Mapping[str, Any], agent_result: Any, env: Any | None, checker_results: Any, verdict: Mapping[str, Any], started_at: str | None = None, ended_at: str | None = None, status: str = "completed", errors: Sequence[str] = (), metadata: Mapping[str, Any] | None = None) -> TraceRecord:
    cfg = config.to_dict() if hasattr(config, "to_dict") else as_mapping(config)
    result = object_to_dict(agent_result)
    base_metadata = case_metadata(case)
    run_metadata = {
        **base_metadata,
        "case_path": None if case_path is None else Path(case_path).as_posix(),
        "agent": {
            "status": result.get("status") or result.get("stop_reason"),
            "completed": bool(result.get("completed")),
            "tool_call_count": result.get("tool_call_count"),
            "errors": list(as_sequence(result.get("errors"))),
        },
    }
    if metadata:
        run_metadata.update(jsonable(metadata))
    sandbox_data = sandbox_snapshot(env) if env is not None else {}
    return TraceRecord(
        run_id=run_id,
        case_id=str(getattr(case, "id", result.get("case_id", ""))),
        suite=suite or str(getattr(case, "category", "")),
        model=str(result.get("model") or cfg.get("model") or cfg.get("model_name") or DEFAULT_MODEL),
        mitigation=str(result.get("mitigation") or cfg.get("mitigation") or DEFAULT_MITIGATION),
        started_at=started_at or str(result.get("started_at") or utc_now_iso()),
        ended_at=ended_at or str(result.get("ended_at") or utc_now_iso()),
        config=cfg,
        metadata=run_metadata,
        task=case_task(case),
        attack=case_attack(case),
        environment=environment_summary(case),
        messages=messages_to_dicts(result.get("messages", getattr(agent_result, "messages", ()))),
        agent_steps=sequence_to_dicts(result.get("agent_steps", result.get("steps", getattr(agent_result, "steps", ())))),
        tool_calls=tool_calls_from_env(env) or tuple(normalize_tool_call(item) for item in as_sequence(result.get("tool_calls"))),
        final_answer=str(result.get("final_answer", "")),
        checker_results=checker_results_to_dicts(checker_results),
        verdict=as_mapping(verdict),
        usage=as_mapping(result.get("usage")),
        sandbox=sandbox_data,
        agent_mode=str(result.get("agent_mode") or result.get("mode") or cfg.get("agent_mode") or cfg.get("mode") or DEFAULT_AGENT_MODE),
        status=status,
        errors=tuple(str(item) for item in errors if str(item).strip()),
    )


build_trace_record = build_run_trace
build_trace = build_run_trace
build_run_trace_record = build_run_trace


def build_error_trace_record(*, run_id: str, case_id: str, suite: str, model: str, mitigation: str, config: TraceConfig | Mapping[str, Any], error: BaseException | str, started_at: str | None = None, ended_at: str | None = None, case_path: str | Path | None = None, metadata: Mapping[str, Any] | None = None) -> TraceRecord:
    err = compact_error(error)
    cfg = config.to_dict() if hasattr(config, "to_dict") else as_mapping(config)
    return TraceRecord(
        run_id=run_id,
        case_id=case_id,
        suite=suite,
        model=model,
        mitigation=mitigation,
        started_at=started_at or utc_now_iso(),
        ended_at=ended_at or utc_now_iso(),
        config=cfg,
        metadata={"category": suite, "severity": "high", "case_path": None if case_path is None else Path(case_path).as_posix(), **jsonable(metadata or {})},
        task={},
        attack=None,
        environment={},
        messages=(),
        agent_steps=(),
        tool_calls=(),
        final_answer="",
        checker_results=(
            {
                "checker": "runner_error",
                "checker_name": "runner_error",
                "checker_type": "runner_error",
                "passed": False,
                "severity": "high",
                "failure_class": "RUNNER_ERROR",
                "evidence": [err],
                "explanation": "Runner failed before deterministic checkers completed.",
                "category": "safety",
                "is_warning": False,
                "metadata": {"exception_type": error.__class__.__name__ if isinstance(error, BaseException) else "error"},
            },
        ),
        verdict={"utility_pass": False, "safety_pass": False, "attack_success": True, "overall": "FAIL"},
        usage={},
        sandbox={},
        agent_mode=str(cfg.get("agent_mode", DEFAULT_AGENT_MODE)),
        status="error",
        errors=(err,),
    )


build_error_trace = build_error_trace_record


def write_trace_jsonl(path: str | Path, record: TraceRecord | Mapping[str, Any], *, append: bool = False) -> TraceWriteResult:
    return write_trace_records(path, (record,), append=append)


def write_trace_records(path: str | Path, records: Iterable[TraceRecord | Mapping[str, Any]], *, append: bool = False) -> TraceWriteResult:
    output = Path(path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    count = 0
    try:
        with output.open(mode, encoding=DEFAULT_JSONL_ENCODING) as handle:
            for record in records:
                payload = record.to_dict() if hasattr(record, "to_dict") else dict(record)
                handle.write(trace_json(payload) + "\n")
                count += 1
    except OSError as exc:
        raise TraceIOError(f"failed to write trace JSONL to {output}: {exc}") from exc
    return TraceWriteResult(path=output.as_posix(), records_written=count, append=append)


def append_trace_jsonl(path: str | Path, record: TraceRecord | Mapping[str, Any]) -> TraceWriteResult:
    return write_trace_jsonl(path, record, append=True)


def write_jsonl_record(record: TraceRecord | Mapping[str, Any], path: str | Path, *, append: bool = True) -> TraceWriteResult:
    return write_trace_jsonl(path, record, append=append)


def write_jsonl_records(records: Iterable[TraceRecord | Mapping[str, Any]], path: str | Path, *, append: bool = False) -> TraceWriteResult:
    return write_trace_records(path, records, append=append)


write_trace_record = write_trace_jsonl


def read_jsonl_records(path: str | Path) -> tuple[JsonDict, ...]:
    source = Path(path).expanduser()
    records: list[JsonDict] = []
    try:
        with source.open("r", encoding=DEFAULT_JSONL_ENCODING) as handle:
            for line_no, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    value = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise TraceIOError(f"{source}:{line_no}: invalid JSONL: {exc.msg}") from exc
                if not isinstance(value, Mapping):
                    raise TraceIOError(f"{source}:{line_no}: JSONL record must be an object")
                records.append(jsonable(value))
    except OSError as exc:
        raise TraceIOError(f"failed to read trace JSONL from {source}: {exc}") from exc
    return tuple(records)


read_trace_jsonl = read_jsonl_records


def trace_json(value: Any) -> str:
    try:
        return json.dumps(jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError as exc:
        raise TraceSerializationError(f"trace contains non-serializable value: {exc}") from exc


def messages_to_dicts(messages: Any) -> tuple[JsonDict, ...]:
    out: list[JsonDict] = []
    for message in as_sequence(messages):
        data = object_to_dict(message)
        if not data and isinstance(message, Mapping):
            data = dict(message)
        if not data:
            continue
        payload: JsonDict = {"role": str(data.get("role", "unknown")), "content": str(data.get("content", ""))}
        if data.get("name"):
            payload["name"] = str(data["name"])
        if data.get("metadata"):
            payload["metadata"] = jsonable(data["metadata"])
        out.append(payload)
    return tuple(out)


def tool_calls_from_env(env: Any | None) -> tuple[JsonDict, ...]:
    if env is None:
        return ()
    return tuple(call for item in as_sequence(getattr(env, "tool_log", None)) if (call := normalize_tool_call(item)).get("tool"))


def checker_results_to_dicts(checker_results: Any) -> tuple[JsonDict, ...]:
    if checker_results is None:
        return ()
    if hasattr(checker_results, "checker_results"):
        checker_results = getattr(checker_results, "checker_results")
    return tuple(data for item in as_sequence(checker_results) if (data := object_to_dict(item)))


def case_metadata(case: Any) -> JsonDict:
    metadata = getattr(case, "metadata", None)
    return {
        "id": str(getattr(case, "id", "")),
        "category": str(getattr(case, "category", getattr(metadata, "category", ""))),
        "severity": str(getattr(case, "severity", getattr(metadata, "severity", ""))),
        "title": str(getattr(metadata, "title", "")) if metadata is not None else "",
        "tags": list(getattr(metadata, "tags", ()) or ()),
    }


def case_task(case: Any) -> JsonDict:
    task = getattr(case, "task", None)
    if task is None:
        return {}
    criteria = getattr(task, "success_criteria", None)
    return {"user_goal": str(getattr(task, "user_goal", "")), "success_criteria": object_to_dict(criteria)}


def case_attack(case: Any) -> JsonDict | None:
    attack = getattr(case, "attack", None)
    return None if attack is None else object_to_dict(attack)


def environment_summary(case: Any) -> JsonDict:
    environment = getattr(case, "environment", None)
    if environment is None:
        return {}
    return {
        "files": [
            {"path": str(getattr(file, "path", "")), "trust_level": str(getattr(getattr(file, "trust_level", ""), "value", getattr(file, "trust_level", ""))), "labels": list(getattr(file, "labels", ()) or ())}
            for file in getattr(environment, "files", ())
        ],
        "inbox": [
            {"from": str(getattr(email, "sender", getattr(email, "from", ""))), "subject": str(getattr(email, "subject", "")), "trust_level": str(getattr(getattr(email, "trust_level", ""), "value", getattr(email, "trust_level", ""))), "labels": list(getattr(email, "labels", ()) or ())}
            for email in getattr(environment, "inbox", ())
        ],
        "memory_keys": sorted(str(key) for key in getattr(environment, "memory", {}).keys()),
    }


def sandbox_snapshot(env: Any) -> JsonDict:
    for method_name in ("snapshot", "to_dict"):
        method = getattr(env, method_name, None)
        if callable(method):
            try:
                return jsonable(method())
            except Exception:  # noqa: BLE001 - trace should not fail because snapshot failed.
                continue
    return {"type": env.__class__.__name__}


def object_to_dict(value: Any) -> JsonDict:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return jsonable(value)
    method = getattr(value, "to_dict", None)
    if callable(method):
        return jsonable(method())
    method = getattr(value, "model_dump", None)
    if callable(method):
        return jsonable(method())
    method = getattr(value, "dict", None)
    if callable(method):
        return jsonable(method())
    if is_dataclass(value):
        return jsonable(asdict(value))
    return {}


def normalize_tool_call(value: Any) -> JsonDict:
    data = object_to_dict(value)
    if not data and isinstance(value, Mapping):
        data = dict(value)
    tool = data.get("tool") or data.get("tool_name")
    if not tool:
        return {}
    labels = data.get("accessed_labels") or data.get("labels") or ()
    return {
        "step": data.get("step"),
        "tool": str(tool),
        "tool_name": str(tool),
        "args": jsonable(data.get("args", {})),
        "output": "" if data.get("output") is None else str(data.get("output")),
        "error": data.get("error"),
        "allowed": data.get("allowed"),
        "policy_violation": bool(data.get("policy_violation") is True),
        "accessed_labels": list(labels),
        "timestamp": data.get("timestamp"),
        "metadata": jsonable(data.get("metadata", {})),
    }


def sequence_to_dicts(value: Any) -> tuple[JsonDict, ...]:
    return tuple(data for item in as_sequence(value) if (data := object_to_dict(item)))


def as_mapping(value: Any) -> JsonDict:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    return {}


def as_sequence(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, str | bytes | bytearray):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(value)
    try:
        return tuple(value)
    except TypeError:
        return (value,)


def jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [jsonable(item) for item in value]
    if isinstance(value, set | frozenset):
        return [jsonable(item) for item in sorted(value, key=str)]
    if is_dataclass(value):
        return jsonable(asdict(value))
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, datetime):
        return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return value


to_jsonable = jsonable
thaw_jsonable = jsonable


def compact_error(error: BaseException | str) -> str:
    return f"{error.__class__.__name__}: {error}" if isinstance(error, BaseException) else str(error)


def safe_id_part(value: Any) -> str:
    text = RUN_ID_UNSAFE_RE.sub("-", str(value or "").strip()).strip("-_.")
    return text.replace("/", "_").replace(" ", "_") or "run"


__all__: Final[tuple[str, ...]] = tuple(
    name for name in globals() if not name.startswith("_") and name not in {"annotations", "Any", "Final", "TypeAlias"}
)
