"""Synthetic sandbox environment for ASRH case execution.

A sandbox is the concrete testbench around one tool-using agent run. It owns the
case-defined file system, inbox, memory store, code-enforced policy, event log,
and tool-call log. The sandbox never performs real shell execution, email
delivery, or network access in the MVP.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from asrh import DEFAULT_MITIGATION
from asrh.cases.schema import TestCase
from asrh.envs.email_box import EmailBox, EmailBoxError, EmailObject
from asrh.envs.file_system import FileNotFound, FileObject, FileSystem, FileSystemError
from asrh.envs.memory_store import MemoryKeyNotFound, MemoryStore, MemoryStoreError
from asrh.envs.policy import (
    EMAIL_TOOL_NAME,
    LIST_FILES_TOOL_NAME,
    READ_FILE_TOOL_NAME,
    SHELL_TOOL_NAME,
    WRITE_FILE_TOOL_NAME,
    Policy,
    ToolPolicyDecision,
)

DEFAULT_TOOL_OUTPUT_CONTENT_TYPE: Final[str] = "text/plain"
SANDBOX_EVENT_CREATED: Final[str] = "sandbox.created"
SANDBOX_EVENT_TOOL_CALL: Final[str] = "tool.call"
SANDBOX_EVENT_POLICY_BLOCK: Final[str] = "policy.block"
SANDBOX_EVENT_ERROR: Final[str] = "sandbox.error"


class SandboxError(Exception):
    """Base exception for sandbox construction and execution."""


class SandboxBuildError(SandboxError):
    """Raised when a sandbox cannot be built from a parsed case."""


class ToolExecutionError(SandboxError):
    """Raised when a synthetic tool call fails before a result can be recorded."""


@dataclass(frozen=True, slots=True)
class Event:
    """Human-inspectable event emitted by the sandbox."""

    step: int
    event_type: str
    message: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "step": self.step,
            "event_type": self.event_type,
            "message": self.message,
            "metadata": _jsonable(self.metadata),
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class SandboxToolResult:
    """Result returned by one sandboxed tool call."""

    tool_name: str
    args: Mapping[str, Any]
    output: str
    error: str | None
    allowed: bool
    policy_violation: bool
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    content_type: str = DEFAULT_TOOL_OUTPUT_CONTENT_TYPE

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation matching trace expectations."""
        return {
            "tool_name": self.tool_name,
            "args": _jsonable(self.args),
            "output": self.output,
            "error": self.error,
            "allowed": self.allowed,
            "policy_violation": self.policy_violation,
            "labels": list(self.labels),
            "metadata": _jsonable(self.metadata),
            "content_type": self.content_type,
        }


@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    """Trace record for a synthetic tool call."""

    step: int
    tool_name: str
    args: Mapping[str, Any]
    output: str
    allowed: bool
    policy_violation: bool
    accessed_labels: tuple[str, ...] = field(default_factory=tuple)
    timestamp: str = field(default_factory=lambda: _utc_now_iso())
    error: str | None = None
    reason: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "step": self.step,
            "tool": self.tool_name,
            "args": _jsonable(self.args),
            "output": self.output,
            "allowed": self.allowed,
            "policy_violation": self.policy_violation,
            "accessed_labels": list(self.accessed_labels),
            "timestamp": self.timestamp,
            "error": self.error,
            "reason": self.reason,
            "metadata": _jsonable(self.metadata),
        }


@dataclass(slots=True)
class SandboxEnv:
    """Concrete synthetic environment for one ASRH case run."""

    files: FileSystem = field(default_factory=FileSystem)
    inbox: EmailBox = field(default_factory=EmailBox)
    memory: MemoryStore = field(default_factory=MemoryStore)
    policy: Policy = field(default_factory=Policy.empty)
    case_id: str | None = None
    suite: str | None = None
    tool_log: list[ToolCallRecord] = field(default_factory=list)
    event_log: list[Event] = field(default_factory=list)
    observed_labels: set[str] = field(default_factory=set)
    _step: int = 0

    @classmethod
    def from_case(cls, case: TestCase, *, mitigation: str = DEFAULT_MITIGATION) -> SandboxEnv:
        """Build a sandbox environment from a parsed YAML case."""
        try:
            sandbox = cls(
                files=FileSystem.from_specs(case.environment.files),
                inbox=EmailBox.from_specs(case.environment.inbox),
                memory=MemoryStore.from_mapping(case.environment.memory),
                policy=Policy.from_case(case, mitigation=mitigation),
                case_id=case.id,
                suite=str(getattr(case.metadata.category, "value", case.metadata.category)),
            )
        except (FileSystemError, EmailBoxError, MemoryStoreError, ValueError) as exc:
            raise SandboxBuildError(f"failed to build sandbox for case {case.id}: {exc}") from exc

        sandbox.log_event(
            SANDBOX_EVENT_CREATED,
            "sandbox created from case",
            metadata={
                "case_id": case.id,
                "suite": sandbox.suite,
                "mitigation": mitigation,
                "files": len(sandbox.files),
                "emails": len(sandbox.inbox),
                "memory_items": len(sandbox.memory),
            },
        )
        return sandbox

    @property
    def step(self) -> int:
        """Return current sandbox step counter."""
        return self._step

    @property
    def context_labels(self) -> tuple[str, ...]:
        """Return labels observed by the agent through prior allowed tool outputs."""
        return tuple(sorted(self.observed_labels))

    def reset_logs(self) -> None:
        """Clear event/tool logs and observed labels while keeping environment state."""
        self.tool_log.clear()
        self.event_log.clear()
        self.observed_labels.clear()
        self._step = 0

    def log_event(
        self,
        event_type: str,
        message: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> Event:
        """Append a structured sandbox event."""
        event = Event(
            step=self._step,
            event_type=event_type,
            message=message,
            metadata=metadata or {},
        )
        self.event_log.append(event)
        return event

    def call_tool(self, tool_name: str, args: Mapping[str, Any] | None = None) -> SandboxToolResult:
        """Dispatch a synthetic tool call and record the result.

        ``args`` is copied into a plain ``dict`` so later mutations by a caller
        cannot alter the trace.
        """
        normalized_tool = _normalize_tool_name(tool_name)
        call_args = dict(args or {})
        handlers: dict[str, Callable[[dict[str, Any]], SandboxToolResult]] = {
            LIST_FILES_TOOL_NAME: self._tool_list_files,
            READ_FILE_TOOL_NAME: self._tool_read_file,
            WRITE_FILE_TOOL_NAME: self._tool_write_file,
            EMAIL_TOOL_NAME: self._tool_send_email,
            SHELL_TOOL_NAME: self._tool_run_shell,
            "list_emails": self._tool_list_emails,
            "read_email": self._tool_read_email,
            "read_memory": self._tool_read_memory,
        }
        handler = handlers.get(normalized_tool)
        if handler is None:
            decision = self.policy.evaluate_generic_tool(normalized_tool, context_labels=self.context_labels)
            if decision.allowed:
                result = self._result_from_decision(
                    decision,
                    args=call_args,
                    output=_json_dumps({"ok": False, "reason": "no sandbox handler for tool"}),
                    error=f"unknown sandbox tool: {normalized_tool}",
                )
            else:
                result = self._result_from_decision(decision, args=call_args, output="", error=decision.reason)
            return self._record_tool_call(result, reason=decision.reason)

        try:
            result = handler(call_args)
        except Exception as exc:  # noqa: BLE001 - sandbox must record failures instead of crashing traces.
            self.log_event(
                SANDBOX_EVENT_ERROR,
                f"tool handler failed: {normalized_tool}",
                metadata={"error": str(exc), "args": call_args},
            )
            result = SandboxToolResult(
                tool_name=normalized_tool,
                args=call_args,
                output="",
                error=str(exc),
                allowed=False,
                policy_violation=False,
                labels=(),
                metadata={"handler_error": True},
            )
        return self._record_tool_call(result, reason=result.metadata.get("policy_reason"))

    def list_files(self) -> SandboxToolResult:
        """Convenience wrapper for ``list_files``."""
        return self.call_tool(LIST_FILES_TOOL_NAME, {})

    def read_file(self, path: str) -> SandboxToolResult:
        """Convenience wrapper for ``read_file``."""
        return self.call_tool(READ_FILE_TOOL_NAME, {"path": path})

    def write_file(self, path: str, content: str) -> SandboxToolResult:
        """Convenience wrapper for ``write_file``."""
        return self.call_tool(WRITE_FILE_TOOL_NAME, {"path": path, "content": content})

    def send_email(self, to: str, subject: str, body: str) -> SandboxToolResult:
        """Convenience wrapper for ``send_email``."""
        return self.call_tool(EMAIL_TOOL_NAME, {"to": to, "subject": subject, "body": body})

    def run_shell(self, command: str) -> SandboxToolResult:
        """Convenience wrapper for simulated ``run_shell``."""
        return self.call_tool(SHELL_TOOL_NAME, {"command": command})

    def snapshot(
        self,
        *,
        include_file_content: bool = False,
        include_email_body: bool = False,
        include_memory_values: bool = False,
    ) -> dict[str, Any]:
        """Return a JSON-serializable snapshot of the sandbox state."""
        return {
            "case_id": self.case_id,
            "suite": self.suite,
            "step": self._step,
            "policy": self.policy.to_dict(),
            "files": self.files.snapshot(include_content=include_file_content),
            "emails": self.inbox.snapshot(include_body=include_email_body),
            "memory": self.memory.snapshot(include_values=include_memory_values),
            "observed_labels": sorted(self.observed_labels),
            "tool_log": [record.to_dict() for record in self.tool_log],
            "event_log": [event.to_dict() for event in self.event_log],
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a redacted snapshot suitable for logs and reports."""
        return self.snapshot()

    def _tool_list_files(self, args: dict[str, Any]) -> SandboxToolResult:
        decision = self.policy.evaluate_list_files()
        if not decision.allowed:
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)

        paths = tuple(
            path
            for path in self.files.paths(include_sensitive=True)
            if self.policy.should_list_file(path, self.files.get(path).trust_level)
        )
        output = _json_dumps({"files": list(paths)})
        return self._result_from_decision(
            decision,
            args=args,
            output=output,
            metadata={"file_count": len(paths)},
        )

    def _tool_read_file(self, args: dict[str, Any]) -> SandboxToolResult:
        path = str(args.get("path", "")).strip()
        if not path:
            decision = ToolPolicyDecision.deny(
                READ_FILE_TOOL_NAME,
                reason="read_file.path must not be blank",
                policy_violation=False,
            )
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)

        file_object: FileObject | None = None
        labels: tuple[str, ...] = ()
        trust_level: str | None = None
        try:
            file_object = self.files.get_optional(path)
            if file_object is not None:
                labels = file_object.access_labels
                trust_level = file_object.trust_level
        except FileSystemError as exc:
            decision = ToolPolicyDecision.deny(
                READ_FILE_TOOL_NAME,
                reason=str(exc),
                policy_violation=False,
            )
            return self._result_from_decision(decision, args=args, output="", error=str(exc))

        decision = self.policy.evaluate_read_file(path, trust_level=trust_level, labels=labels)
        if not decision.allowed:
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)

        if file_object is None:
            error = f"file not found: {path}"
            return self._result_from_decision(
                decision,
                args=args,
                output="",
                error=error,
                metadata={"not_found": True},
            )

        return self._result_from_decision(
            decision,
            args=args,
            output=file_object.content,
            labels=file_object.access_labels,
            metadata={"path": file_object.path, "trust_level": file_object.trust_level},
        )

    def _tool_write_file(self, args: dict[str, Any]) -> SandboxToolResult:
        path = str(args.get("path", "")).strip()
        content = str(args.get("content", ""))
        if not path:
            decision = ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason="write_file.path must not be blank",
                policy_violation=False,
            )
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)

        existing_trust_level: str | None = None
        try:
            existing = self.files.get_optional(path)
            existing_trust_level = existing.trust_level if existing is not None else None
        except FileSystemError as exc:
            decision = ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason=str(exc),
                policy_violation=False,
            )
            return self._result_from_decision(decision, args=args, output="", error=str(exc))

        decision = self.policy.evaluate_write_file(
            path,
            content=content,
            existing_trust_level=existing_trust_level,
            context_labels=self.context_labels,
        )
        if not decision.allowed:
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)

        try:
            write_result = self.files.write(
                path,
                content,
                labels=("source:tool:write_file",),
                overwrite=True,
            )
        except FileSystemError as exc:
            return self._result_from_decision(
                decision,
                args=args,
                output="",
                error=str(exc),
                metadata={"write_error": True},
            )

        return self._result_from_decision(
            decision,
            args=args,
            output=_json_dumps(write_result.to_dict()),
            labels=write_result.labels,
            metadata=write_result.to_dict(),
            content_type="application/json",
        )

    def _tool_send_email(self, args: dict[str, Any]) -> SandboxToolResult:
        to = str(args.get("to", "")).strip()
        subject = str(args.get("subject", ""))
        body = str(args.get("body", ""))
        decision = self.policy.evaluate_send_email(
            to=to,
            subject=subject,
            body=body,
            context_labels=self.context_labels,
        )
        record = self.inbox.record_send(
            to=to or "unknown@example.invalid",
            subject=subject,
            body=body,
            allowed=decision.allowed,
            reason=None if decision.allowed else decision.reason,
            labels=decision.labels,
        )
        output = _json_dumps({"sent": record.sent, "simulated": True, "reason": record.reason})
        return self._result_from_decision(
            decision,
            args=args,
            output=output,
            error=None if decision.allowed else decision.reason,
            labels=decision.labels,
            metadata={"email_record": record.to_dict(include_body=False)},
            content_type="application/json",
        )

    def _tool_run_shell(self, args: dict[str, Any]) -> SandboxToolResult:
        command = str(args.get("command", ""))
        decision = self.policy.evaluate_run_shell(command=command, context_labels=self.context_labels)
        reason = "shell execution is simulated and disabled in MVP"
        output = _json_dumps({"executed": False, "reason": reason})
        return self._result_from_decision(
            decision,
            args=args,
            output=output,
            error=None if decision.allowed else decision.reason,
            labels=decision.labels,
            metadata={"simulated": True, "policy_reason": decision.reason},
            content_type="application/json",
        )

    def _tool_list_emails(self, args: dict[str, Any]) -> SandboxToolResult:
        decision = self.policy.evaluate_generic_tool("list_emails", context_labels=self.context_labels)
        if not decision.allowed:
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)
        unread_only = _as_bool(args.get("unread_only"), default=False)
        messages = [
            message.to_dict(include_body=False) for message in self.inbox.list_messages(unread_only=unread_only)
        ]
        return self._result_from_decision(
            decision,
            args=args,
            output=_json_dumps({"emails": messages}),
            metadata={"email_count": len(messages)},
            content_type="application/json",
        )

    def _tool_read_email(self, args: dict[str, Any]) -> SandboxToolResult:
        decision = self.policy.evaluate_generic_tool("read_email", context_labels=self.context_labels)
        if not decision.allowed:
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)

        message_id = str(args.get("message_id", "")).strip()
        message: EmailObject | None
        if message_id:
            try:
                message = self.inbox.read(message_id)
            except EmailBoxError as exc:
                return self._result_from_decision(
                    decision,
                    args=args,
                    output="",
                    error=str(exc),
                    metadata={"not_found": True},
                )
        else:
            message = self.inbox.first_unread()
            if message is not None:
                message = self.inbox.read(message.message_id)

        if message is None:
            return self._result_from_decision(
                decision,
                args=args,
                output=_json_dumps({"email": None}),
                error="no unread email found",
                metadata={"not_found": True},
                content_type="application/json",
            )

        return self._result_from_decision(
            decision,
            args=args,
            output=_json_dumps(message.to_dict(include_body=True)),
            labels=message.access_labels,
            metadata={"message_id": message.message_id, "trust_level": message.trust_level},
            content_type="application/json",
        )

    def _tool_read_memory(self, args: dict[str, Any]) -> SandboxToolResult:
        key = str(args.get("key", "")).strip()
        if not key:
            decision = ToolPolicyDecision.deny(
                "read_memory",
                reason="read_memory.key must not be blank",
                policy_violation=False,
            )
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)
        try:
            item = self.memory.get(key)
        except MemoryKeyNotFound as exc:
            decision = self.policy.evaluate_memory_read(key)
            return self._result_from_decision(
                decision,
                args=args,
                output="",
                error=str(exc),
                metadata={"not_found": True},
            )
        decision = self.policy.evaluate_memory_read(
            key,
            trust_level=item.trust_level,
            labels=item.access_labels,
        )
        if not decision.allowed:
            return self._result_from_decision(decision, args=args, output="", error=decision.reason)
        return self._result_from_decision(
            decision,
            args=args,
            output=item.value_text(),
            labels=item.access_labels,
            metadata={"key": item.key, "trust_level": item.trust_level},
        )

    def _result_from_decision(
        self,
        decision: ToolPolicyDecision,
        *,
        args: Mapping[str, Any],
        output: str,
        error: str | None = None,
        labels: Iterable[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
        content_type: str = DEFAULT_TOOL_OUTPUT_CONTENT_TYPE,
    ) -> SandboxToolResult:
        result_labels = tuple(labels if labels is not None else decision.labels)
        merged_metadata: dict[str, Any] = dict(metadata or {})
        merged_metadata.setdefault("policy_reason", decision.reason)
        if decision.metadata:
            merged_metadata.setdefault("policy_metadata", dict(decision.metadata))
        return SandboxToolResult(
            tool_name=decision.tool_name,
            args=dict(args),
            output=output,
            error=error,
            allowed=decision.allowed,
            policy_violation=decision.policy_violation,
            labels=_dedupe(result_labels),
            metadata=merged_metadata,
            content_type=content_type,
        )

    def _record_tool_call(self, result: SandboxToolResult, *, reason: Any = None) -> SandboxToolResult:
        self._step += 1
        record = ToolCallRecord(
            step=self._step,
            tool_name=result.tool_name,
            args=dict(result.args),
            output=result.output,
            allowed=result.allowed,
            policy_violation=result.policy_violation,
            accessed_labels=result.labels,
            error=result.error,
            reason=str(reason) if reason else None,
            metadata=result.metadata,
        )
        self.tool_log.append(record)
        if result.allowed:
            self.observed_labels.update(result.labels)
        event_type = SANDBOX_EVENT_TOOL_CALL if result.allowed else SANDBOX_EVENT_POLICY_BLOCK
        self.log_event(
            event_type,
            f"{result.tool_name} {'allowed' if result.allowed else 'blocked'}",
            metadata=record.to_dict(),
        )
        return result


def build_sandbox_from_case(case: TestCase, *, mitigation: str = DEFAULT_MITIGATION) -> SandboxEnv:
    """Build a ``SandboxEnv`` from a parsed case.

    This helper is the stable import point expected by runner modules.
    """
    return SandboxEnv.from_case(case, mitigation=mitigation)


def _normalize_tool_name(value: str) -> str:
    """Normalize tool names from model JSON actions."""
    text = str(value).strip().lower().replace("-", "_")
    if not text:
        raise ToolExecutionError("tool_name must not be blank")
    return text


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate non-blank labels while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return tuple(result)


def _json_dumps(value: Any) -> str:
    """Serialize a compact JSON object for tool output."""
    return json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _jsonable(value: Any) -> Any:
    """Convert common Python values into JSON-serializable containers."""
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [_jsonable(item) for item in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    return value


def _as_bool(value: Any, *, default: bool) -> bool:
    """Parse a permissive boolean argument for optional tools."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", ""}:
            return False
    return default


def _utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(UTC).isoformat(timespec="seconds")


__all__: Final[tuple[str, ...]] = (
    "DEFAULT_TOOL_OUTPUT_CONTENT_TYPE",
    "Event",
    "SANDBOX_EVENT_CREATED",
    "SANDBOX_EVENT_ERROR",
    "SANDBOX_EVENT_POLICY_BLOCK",
    "SANDBOX_EVENT_TOOL_CALL",
    "SandboxBuildError",
    "SandboxEnv",
    "SandboxError",
    "SandboxToolResult",
    "ToolCallRecord",
    "ToolExecutionError",
    "build_sandbox_from_case",
)
