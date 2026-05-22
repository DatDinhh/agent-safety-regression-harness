"""Policy primitives for ASRH synthetic environments.

The policy layer is intentionally independent from concrete tool classes. It
answers one question for the sandbox and future ``asrh.tools`` package: should a
requested operation be allowed, blocked, or logged as a policy violation?

The MVP contract is deliberately conservative:

- all tools are simulated unless a later non-MVP extension explicitly enables
  real side effects;
- sensitive files require explicit authorization before read access;
- shell execution, network access, and real email delivery are disabled by
  default;
- high-risk actions can be blocked by code-enforced mitigations instead of
  relying only on prompt instructions.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Final

from asrh import DEFAULT_MITIGATION, SUPPORTED_MITIGATIONS
from asrh.cases.schema import CheckerSpec, TestCase, validate_case_relative_path

SHELL_TOOL_NAME: Final[str] = "run_shell"
EMAIL_TOOL_NAME: Final[str] = "send_email"
NETWORK_TOOL_NAME: Final[str] = "network_request"
READ_FILE_TOOL_NAME: Final[str] = "read_file"
LIST_FILES_TOOL_NAME: Final[str] = "list_files"
WRITE_FILE_TOOL_NAME: Final[str] = "write_file"

HIGH_RISK_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        EMAIL_TOOL_NAME,
        SHELL_TOOL_NAME,
        NETWORK_TOOL_NAME,
        "delete_file",
    }
)
"""Tool names whose use should be treated as safety-relevant by default."""

EXECUTABLE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".bat",
        ".bash",
        ".cmd",
        ".com",
        ".dll",
        ".dylib",
        ".exe",
        ".fish",
        ".ps1",
        ".sh",
        ".so",
        ".zsh",
    }
)
"""File suffixes that are blocked by ``write_file`` in the MVP sandbox."""

FALSE_VALUES: Final[frozenset[str]] = frozenset({"", "0", "false", "f", "no", "n", "off"})
TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "t", "yes", "y", "on"})

FORBIDDEN_PATTERN_CHECKER_TYPE: Final[str] = "no_secret_leak"
SENSITIVE_TRUST_LEVEL: Final[str] = "sensitive"
UNTRUSTED_TRUST_LEVEL: Final[str] = "untrusted"

SUPPORTED_MITIGATION_SET: Final[frozenset[str]] = frozenset(SUPPORTED_MITIGATIONS)


class PolicyError(Exception):
    """Base exception for policy construction and evaluation failures."""


class PolicyConfigurationError(PolicyError):
    """Raised when a policy configuration is internally inconsistent."""


class PolicyOutcome(StrEnum):
    """Decision outcome for a tool or data-access request."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class ToolPolicyDecision:
    """Policy decision returned before a sandbox operation is executed."""

    tool_name: str
    allowed: bool
    reason: str
    policy_violation: bool = False
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def outcome(self) -> PolicyOutcome:
        """Return the normalized decision outcome."""
        return PolicyOutcome.ALLOW if self.allowed else PolicyOutcome.DENY

    @classmethod
    def allow(
        cls,
        tool_name: str,
        *,
        reason: str = "allowed by policy",
        labels: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolPolicyDecision:
        """Build an allow decision."""
        return cls(
            tool_name=tool_name,
            allowed=True,
            reason=reason,
            policy_violation=False,
            labels=_dedupe(labels),
            metadata=_freeze_mapping(metadata or {}),
        )

    @classmethod
    def deny(
        cls,
        tool_name: str,
        *,
        reason: str,
        policy_violation: bool = True,
        labels: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> ToolPolicyDecision:
        """Build a deny decision."""
        return cls(
            tool_name=tool_name,
            allowed=False,
            reason=reason,
            policy_violation=policy_violation,
            labels=_dedupe(labels),
            metadata=_freeze_mapping(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "tool_name": self.tool_name,
            "allowed": self.allowed,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "policy_violation": self.policy_violation,
            "labels": list(self.labels),
            "metadata": _thaw(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class Policy:
    """Code-enforced policy for one synthetic sandbox environment.

    ``Policy`` is immutable after construction. It can be shared between tool
    wrappers and the sandbox without accidental mutation of the case-defined
    configuration.
    """

    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    tool_policies: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    mitigation: str = DEFAULT_MITIGATION
    forbidden_patterns: tuple[str, ...] = field(default_factory=tuple)
    allow_real_shell: bool = False
    allow_real_email: bool = False
    allow_real_network: bool = False

    def __post_init__(self) -> None:
        """Normalize and validate policy fields."""
        normalized_mitigation = self.mitigation.strip() or DEFAULT_MITIGATION
        if normalized_mitigation not in SUPPORTED_MITIGATION_SET:
            raise PolicyConfigurationError(
                f"unsupported mitigation {self.mitigation!r}; expected one of "
                f"{sorted(SUPPORTED_MITIGATION_SET)}"
            )

        object.__setattr__(self, "allowed_tools", frozenset(_normalize_name(tool) for tool in self.allowed_tools))
        object.__setattr__(self, "tool_policies", _freeze_policy_map(self.tool_policies))
        object.__setattr__(self, "mitigation", normalized_mitigation)
        object.__setattr__(self, "forbidden_patterns", _dedupe(self.forbidden_patterns))
        object.__setattr__(self, "allow_real_shell", bool(self.allow_real_shell))
        object.__setattr__(self, "allow_real_email", bool(self.allow_real_email))
        object.__setattr__(self, "allow_real_network", bool(self.allow_real_network))

    @classmethod
    def from_case(
        cls,
        case: TestCase,
        *,
        mitigation: str = DEFAULT_MITIGATION,
        allow_real_shell: bool | None = None,
        allow_real_email: bool | None = None,
        allow_real_network: bool | None = None,
    ) -> Policy:
        """Build a policy from a parsed ASRH test case."""
        return cls(
            allowed_tools=frozenset(case.tools.allowed),
            tool_policies=case.tools.tool_policies,
            mitigation=mitigation,
            forbidden_patterns=extract_forbidden_patterns(case.checkers),
            allow_real_shell=env_flag("ASRH_ALLOW_REAL_SHELL") if allow_real_shell is None else allow_real_shell,
            allow_real_email=env_flag("ASRH_ALLOW_REAL_EMAIL") if allow_real_email is None else allow_real_email,
            allow_real_network=env_flag("ASRH_ALLOW_REAL_NETWORK")
            if allow_real_network is None
            else allow_real_network,
        )

    @classmethod
    def empty(cls) -> Policy:
        """Return a policy that denies every tool."""
        return cls(allowed_tools=frozenset())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "allowed_tools": sorted(self.allowed_tools),
            "tool_policies": _thaw(self.tool_policies),
            "mitigation": self.mitigation,
            "forbidden_patterns": list(self.forbidden_patterns),
            "allow_real_shell": self.allow_real_shell,
            "allow_real_email": self.allow_real_email,
            "allow_real_network": self.allow_real_network,
        }

    def is_tool_allowed_by_case(self, tool_name: str) -> bool:
        """Return whether the case configuration exposes this tool."""
        return _normalize_name(tool_name) in self.allowed_tools

    def evaluate_generic_tool(
        self,
        tool_name: str,
        *,
        context_labels: Iterable[str] = (),
    ) -> ToolPolicyDecision:
        """Evaluate a generic non-specialized tool call.

        Specialized operations such as file reads and email sends should use the
        dedicated evaluators below. This method is useful for optional future
        tools such as ``read_email`` that are not part of the strict MVP tool
        list but may appear during experimentation.
        """
        normalized = _normalize_name(tool_name)
        base = self._base_tool_decision(normalized)
        if base is not None:
            return base
        if normalized in HIGH_RISK_TOOL_NAMES and self._requires_human_approval(normalized):
            return ToolPolicyDecision.deny(
                normalized,
                reason="human approval required by mitigation",
                labels=context_labels,
            )
        return ToolPolicyDecision.allow(normalized, labels=context_labels)

    def evaluate_list_files(self) -> ToolPolicyDecision:
        """Evaluate a ``list_files`` request."""
        base = self._base_tool_decision(LIST_FILES_TOOL_NAME)
        if base is not None:
            return base
        return ToolPolicyDecision.allow(LIST_FILES_TOOL_NAME)

    def should_list_file(self, path: str, trust_level: str) -> bool:
        """Return whether ``list_files`` should reveal a file path."""
        normalized_path = validate_case_relative_path(path, field_name="file path")
        normalized_trust = _normalize_name(trust_level)
        list_policy = self._tool_config(LIST_FILES_TOOL_NAME)
        read_policy = self._tool_config(READ_FILE_TOOL_NAME)

        if normalized_path in _string_tuple(list_policy.get("denied_paths")):
            return False
        if normalized_path in _string_tuple(read_policy.get("denied_paths")):
            return False

        include_sensitive = _bool_setting(list_policy, "include_sensitive", default=False)
        if normalized_trust == SENSITIVE_TRUST_LEVEL and not include_sensitive:
            return self._is_sensitive_path_explicitly_authorized(normalized_path)
        return True

    def evaluate_read_file(
        self,
        path: str,
        *,
        trust_level: str | None = None,
        labels: Iterable[str] = (),
    ) -> ToolPolicyDecision:
        """Evaluate a ``read_file`` request."""
        base = self._base_tool_decision(READ_FILE_TOOL_NAME)
        if base is not None:
            return base

        try:
            normalized_path = validate_case_relative_path(path, field_name="read_file.path")
        except ValueError as exc:
            return ToolPolicyDecision.deny(
                READ_FILE_TOOL_NAME,
                reason=f"unsafe file path: {exc}",
                labels=labels,
            )

        policy = self._tool_config(READ_FILE_TOOL_NAME)
        if self._path_matches_policy_list(normalized_path, policy.get("denied_paths")):
            return ToolPolicyDecision.deny(
                READ_FILE_TOOL_NAME,
                reason=f"read_file path is denied by policy: {normalized_path}",
                labels=labels,
            )

        allowed_paths = _string_tuple(policy.get("allowed_paths"))
        if allowed_paths and not self._path_matches_policy_list(normalized_path, allowed_paths):
            return ToolPolicyDecision.deny(
                READ_FILE_TOOL_NAME,
                reason=f"read_file path is outside allowed_paths: {normalized_path}",
                labels=labels,
            )

        if _normalize_name(trust_level or "") == SENSITIVE_TRUST_LEVEL:
            require_sensitive_auth = (
                self.mitigation in {"tool_policy_guard", "taint_tracking_guard", "human_approval_guard"}
                or _bool_setting(policy, "require_sensitive_authorization", default=False)
            )
            if require_sensitive_auth and not self._is_sensitive_path_explicitly_authorized(normalized_path):
                return ToolPolicyDecision.deny(
                    READ_FILE_TOOL_NAME,
                    reason=f"sensitive file access requires explicit authorization: {normalized_path}",
                    labels=labels,
                )

        return ToolPolicyDecision.allow(READ_FILE_TOOL_NAME, labels=labels)

    def evaluate_write_file(
        self,
        path: str,
        *,
        content: str = "",
        existing_trust_level: str | None = None,
        context_labels: Iterable[str] = (),
    ) -> ToolPolicyDecision:
        """Evaluate a ``write_file`` request."""
        base = self._base_tool_decision(WRITE_FILE_TOOL_NAME)
        if base is not None:
            return base

        try:
            normalized_path = validate_case_relative_path(path, field_name="write_file.path")
        except ValueError as exc:
            return ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason=f"unsafe file path: {exc}",
                labels=context_labels,
            )

        policy = self._tool_config(WRITE_FILE_TOOL_NAME)
        if self._path_matches_policy_list(normalized_path, policy.get("denied_paths")):
            return ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason=f"write_file path is denied by policy: {normalized_path}",
                labels=context_labels,
            )

        allowed_paths = _string_tuple(policy.get("allowed_paths"))
        if allowed_paths and not self._path_matches_policy_list(normalized_path, allowed_paths):
            return ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason=f"write_file path is outside allowed_paths: {normalized_path}",
                labels=context_labels,
            )

        if _normalize_name(existing_trust_level or "") == SENSITIVE_TRUST_LEVEL:
            return ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason=f"cannot overwrite sensitive file: {normalized_path}",
                labels=context_labels,
            )

        suffix = PurePosixPath(normalized_path).suffix.lower()
        if suffix in EXECUTABLE_SUFFIXES:
            return ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason=f"writing executable-like file is disabled in MVP: {normalized_path}",
                labels=context_labels,
            )

        if self._tainted_high_risk_block(WRITE_FILE_TOOL_NAME, context_labels):
            return ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason="write_file blocked after reading untrusted content by taint_tracking_guard",
                labels=context_labels,
            )

        forbidden = _first_forbidden_match(content, self.forbidden_patterns)
        if forbidden is not None and not _bool_setting(policy, "allow_sensitive_content", default=False):
            return ToolPolicyDecision.deny(
                WRITE_FILE_TOOL_NAME,
                reason="write_file content contains a forbidden sensitive pattern",
                labels=context_labels,
                metadata={"matched_pattern": forbidden},
            )

        return ToolPolicyDecision.allow(WRITE_FILE_TOOL_NAME, labels=context_labels)

    def evaluate_send_email(
        self,
        *,
        to: str,
        subject: str = "",
        body: str = "",
        context_labels: Iterable[str] = (),
    ) -> ToolPolicyDecision:
        """Evaluate a simulated ``send_email`` request."""
        base = self._base_tool_decision(EMAIL_TOOL_NAME)
        if base is not None:
            return base

        policy = self._tool_config(EMAIL_TOOL_NAME)
        recipient = to.strip()
        if not recipient:
            return ToolPolicyDecision.deny(
                EMAIL_TOOL_NAME,
                reason="send_email.to must not be blank",
                policy_violation=False,
                labels=context_labels,
            )

        if _bool_setting(policy, "enabled", default=True) is False:
            return ToolPolicyDecision.deny(
                EMAIL_TOOL_NAME,
                reason="send_email is disabled by tool policy",
                labels=context_labels,
            )

        if self._requires_human_approval(EMAIL_TOOL_NAME) and not _bool_setting(
            policy, "human_approved", default=False
        ):
            return ToolPolicyDecision.deny(
                EMAIL_TOOL_NAME,
                reason="human approval required by mitigation",
                labels=context_labels,
            )

        if _bool_setting(policy, "requires_authorization", default=False) and not _bool_setting(
            policy, "user_authorized", default=False
        ):
            return ToolPolicyDecision.deny(
                EMAIL_TOOL_NAME,
                reason="send_email requires explicit user authorization",
                labels=context_labels,
            )

        allowed_recipients = _string_tuple(policy.get("allowed_recipients"))
        if allowed_recipients and recipient.lower() not in {item.lower() for item in allowed_recipients}:
            return ToolPolicyDecision.deny(
                EMAIL_TOOL_NAME,
                reason=f"recipient is outside allowed_recipients: {recipient}",
                labels=context_labels,
            )

        if self._tainted_high_risk_block(EMAIL_TOOL_NAME, context_labels):
            return ToolPolicyDecision.deny(
                EMAIL_TOOL_NAME,
                reason="send_email blocked after reading untrusted content by taint_tracking_guard",
                labels=context_labels,
            )

        combined_text = f"{subject}\n{body}"
        forbidden = _first_forbidden_match(combined_text, self.forbidden_patterns)
        if forbidden is not None and not _bool_setting(policy, "allow_sensitive_content", default=False):
            return ToolPolicyDecision.deny(
                EMAIL_TOOL_NAME,
                reason="send_email body contains a forbidden sensitive pattern",
                labels=context_labels,
                metadata={"matched_pattern": forbidden},
            )

        return ToolPolicyDecision.allow(
            EMAIL_TOOL_NAME,
            labels=context_labels,
            metadata={"simulated_delivery": not self.allow_real_email},
        )

    def evaluate_run_shell(
        self,
        *,
        command: str,
        context_labels: Iterable[str] = (),
    ) -> ToolPolicyDecision:
        """Evaluate a simulated ``run_shell`` request."""
        base = self._base_tool_decision(SHELL_TOOL_NAME)
        if base is not None:
            return base

        policy = self._tool_config(SHELL_TOOL_NAME)
        if not _bool_setting(policy, "enabled", default=False):
            return ToolPolicyDecision.deny(
                SHELL_TOOL_NAME,
                reason="run_shell is disabled by tool policy",
                labels=context_labels,
            )

        if self._requires_human_approval(SHELL_TOOL_NAME) and not _bool_setting(
            policy, "human_approved", default=False
        ):
            return ToolPolicyDecision.deny(
                SHELL_TOOL_NAME,
                reason="human approval required by mitigation",
                labels=context_labels,
            )

        if self._tainted_high_risk_block(SHELL_TOOL_NAME, context_labels):
            return ToolPolicyDecision.deny(
                SHELL_TOOL_NAME,
                reason="run_shell blocked after reading untrusted content by taint_tracking_guard",
                labels=context_labels,
            )

        forbidden = _first_forbidden_match(command, self.forbidden_patterns)
        if forbidden is not None:
            return ToolPolicyDecision.deny(
                SHELL_TOOL_NAME,
                reason="run_shell command contains a forbidden sensitive pattern",
                labels=context_labels,
                metadata={"matched_pattern": forbidden},
            )

        return ToolPolicyDecision.allow(
            SHELL_TOOL_NAME,
            labels=context_labels,
            metadata={"simulated_execution": not self.allow_real_shell},
        )

    def evaluate_network_request(
        self,
        *,
        url: str,
        context_labels: Iterable[str] = (),
    ) -> ToolPolicyDecision:
        """Evaluate a future simulated network request."""
        base = self._base_tool_decision(NETWORK_TOOL_NAME)
        if base is not None:
            return base

        policy = self._tool_config(NETWORK_TOOL_NAME)
        if not _bool_setting(policy, "enabled", default=False):
            return ToolPolicyDecision.deny(
                NETWORK_TOOL_NAME,
                reason="network_request is disabled by tool policy",
                labels=context_labels,
            )
        if self._requires_human_approval(NETWORK_TOOL_NAME):
            return ToolPolicyDecision.deny(
                NETWORK_TOOL_NAME,
                reason="human approval required by mitigation",
                labels=context_labels,
            )
        if self._tainted_high_risk_block(NETWORK_TOOL_NAME, context_labels):
            return ToolPolicyDecision.deny(
                NETWORK_TOOL_NAME,
                reason="network_request blocked after reading untrusted content by taint_tracking_guard",
                labels=context_labels,
            )
        return ToolPolicyDecision.allow(
            NETWORK_TOOL_NAME,
            labels=context_labels,
            metadata={"simulated_request": not self.allow_real_network, "url": url},
        )

    def evaluate_memory_read(
        self,
        key: str,
        *,
        trust_level: str | None = None,
        labels: Iterable[str] = (),
    ) -> ToolPolicyDecision:
        """Evaluate a memory read operation.

        Memory access is not a required MVP tool, but the sandbox exposes this
        evaluator so future memory tools can reuse the same sensitive-data rule.
        """
        if _normalize_name(trust_level or "") == SENSITIVE_TRUST_LEVEL:
            policy = self._tool_config("read_memory")
            allowed_keys = _string_tuple(policy.get("allowed_keys"))
            allow_sensitive = _bool_setting(policy, "allow_sensitive", default=False)
            if not allow_sensitive and key not in allowed_keys:
                return ToolPolicyDecision.deny(
                    "read_memory",
                    reason=f"sensitive memory access requires explicit authorization: {key}",
                    labels=labels,
                )
        return ToolPolicyDecision.allow("read_memory", labels=labels)

    def _base_tool_decision(self, tool_name: str) -> ToolPolicyDecision | None:
        """Return a base allow-list denial, or ``None`` when further checks are needed."""
        normalized = _normalize_name(tool_name)
        if normalized not in self.allowed_tools:
            return ToolPolicyDecision.deny(
                normalized,
                reason=f"tool is not exposed by this case: {normalized}",
            )
        return None

    def _tool_config(self, tool_name: str) -> Mapping[str, Any]:
        """Return normalized config for a tool."""
        return self.tool_policies.get(_normalize_name(tool_name), MappingProxyType({}))

    def _requires_human_approval(self, tool_name: str) -> bool:
        """Return whether a mitigation requires explicit human approval."""
        normalized = _normalize_name(tool_name)
        if self.mitigation == "human_approval_guard" and normalized in HIGH_RISK_TOOL_NAMES:
            return True
        if self.mitigation == "tool_policy_guard" and normalized in {SHELL_TOOL_NAME, NETWORK_TOOL_NAME}:
            return True
        return False

    def _tainted_high_risk_block(self, tool_name: str, context_labels: Iterable[str]) -> bool:
        """Return whether taint-tracking guard blocks the requested operation."""
        normalized = _normalize_name(tool_name)
        if self.mitigation != "taint_tracking_guard":
            return False
        if normalized not in HIGH_RISK_TOOL_NAMES and normalized != WRITE_FILE_TOOL_NAME:
            return False
        labels = set(context_labels)
        if f"trust:{UNTRUSTED_TRUST_LEVEL}" not in labels:
            return False
        policy = self._tool_config(normalized)
        return not _bool_setting(policy, "allow_after_untrusted", default=False)

    def _is_sensitive_path_explicitly_authorized(self, path: str) -> bool:
        """Return whether a sensitive file path is explicitly authorized."""
        policy = self._tool_config(READ_FILE_TOOL_NAME)
        if _bool_setting(policy, "allow_sensitive", default=False):
            return True
        if self._path_matches_policy_list(path, policy.get("allow_sensitive_paths")):
            return True
        allowed_paths = _string_tuple(policy.get("allowed_paths"))
        allowed_paths_authorize_sensitive = _bool_setting(
            policy,
            "allowed_paths_authorize_sensitive",
            default=True,
        )
        return bool(allowed_paths and allowed_paths_authorize_sensitive and path in allowed_paths)

    @staticmethod
    def _path_matches_policy_list(path: str, configured_paths: Any) -> bool:
        """Return whether ``path`` matches a configured exact or prefix path list."""
        normalized = validate_case_relative_path(path, field_name="policy path")
        for configured in _string_tuple(configured_paths):
            if configured.endswith("/"):
                if normalized.startswith(configured):
                    return True
            elif normalized == configured:
                return True
        return False


def extract_forbidden_patterns(checkers: Sequence[CheckerSpec]) -> tuple[str, ...]:
    """Extract no-secret-leak patterns from checker declarations."""
    patterns: list[str] = []
    for checker in checkers:
        checker_type = _enum_value(checker.type)
        if checker_type != FORBIDDEN_PATTERN_CHECKER_TYPE:
            continue
        patterns.extend(checker.forbidden_patterns or [])
    return _dedupe(patterns)


def env_flag(name: str, *, default: bool = False) -> bool:
    """Return a boolean environment flag.

    Unknown or blank values fall back to ``default``. The accepted values are
    intentionally explicit so setting ``ASRH_ALLOW_REAL_SHELL=maybe`` does not
    accidentally enable side effects.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    return default


def _normalize_name(value: str) -> str:
    """Normalize a tool or policy name."""
    return value.strip().lower().replace("-", "_")


def _enum_value(value: Any) -> str:
    """Return enum value or string representation for Pydantic enum fields."""
    return str(getattr(value, "value", value))


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate non-blank strings while preserving order."""
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return tuple(normalized)


def _string_tuple(value: Any) -> tuple[str, ...]:
    """Normalize scalar/list/tuple policy values into a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        return _dedupe((value,))
    if isinstance(value, Iterable):
        return _dedupe(str(item) for item in value)
    return _dedupe((str(value),))


def _bool_setting(mapping: Mapping[str, Any], key: str, *, default: bool) -> bool:
    """Read a boolean setting from a policy mapping."""
    if key not in mapping:
        return default
    value = mapping[key]
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in TRUE_VALUES:
            return True
        if normalized in FALSE_VALUES:
            return False
    return default


def _first_forbidden_match(text: str, patterns: Sequence[str]) -> str | None:
    """Return the first forbidden pattern contained in ``text``."""
    if not text:
        return None
    for pattern in patterns:
        if pattern and pattern in text:
            return pattern
    return None


def _freeze_policy_map(value: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Mapping[str, Any]]:
    """Return an immutable normalized tool-policy mapping."""
    frozen: dict[str, Mapping[str, Any]] = {}
    for tool_name, config in value.items():
        normalized_tool = _normalize_name(str(tool_name))
        if not isinstance(config, Mapping):
            raise PolicyConfigurationError(f"tool policy for {tool_name!r} must be a mapping")
        frozen[normalized_tool] = _freeze_mapping(config)
    return MappingProxyType(frozen)


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Recursively freeze a mapping into ``MappingProxyType`` and tuples."""
    frozen: dict[str, Any] = {}
    for key, item in value.items():
        frozen[str(key)] = _freeze_value(item)
    return MappingProxyType(frozen)


def _freeze_value(value: Any) -> Any:
    """Recursively freeze common container values."""
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, list | tuple | set | frozenset):
        return tuple(_freeze_value(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    """Convert frozen containers into JSON-serializable Python containers."""
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [_thaw(item) for item in value]
    return value


__all__: Final[tuple[str, ...]] = (
    "EMAIL_TOOL_NAME",
    "EXECUTABLE_SUFFIXES",
    "HIGH_RISK_TOOL_NAMES",
    "LIST_FILES_TOOL_NAME",
    "NETWORK_TOOL_NAME",
    "Policy",
    "PolicyConfigurationError",
    "PolicyError",
    "PolicyOutcome",
    "READ_FILE_TOOL_NAME",
    "SHELL_TOOL_NAME",
    "SENSITIVE_TRUST_LEVEL",
    "ToolPolicyDecision",
    "UNTRUSTED_TRUST_LEVEL",
    "WRITE_FILE_TOOL_NAME",
    "env_flag",
    "extract_forbidden_patterns",
)
