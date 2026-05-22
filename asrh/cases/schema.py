"""Pydantic models for ASRH YAML test cases.

The schema in this module is intentionally close to the MVP technical
specification. It models one YAML case as a deterministic research artifact:
metadata, task, synthetic environment, tool policy, optional attack payload,
checker declarations, and expected utility/safety outcomes.

The project targets Pydantic v2 via ``pyproject.toml``. A small compatibility
layer is kept so source-tree smoke tests can still import the module in older
local environments that have Pydantic v1 installed. Runtime packaging should use
Pydantic v2.
"""

from __future__ import annotations

import re
from datetime import date
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, ClassVar, Final, Literal, Self, TypeAlias, cast

from pydantic import BaseModel, Field, ValidationError as PydanticValidationError
from pydantic.version import VERSION as PYDANTIC_VERSION

from asrh import (
    CASE_SCHEMA_VERSION,
    SEVERITY_LEVELS,
    SUPPORTED_CHECKER_TYPES,
    SUPPORTED_SUITES,
    SUPPORTED_TOOLS,
    TRUST_LEVELS,
)

try:  # pragma: no cover - branch depends on installed Pydantic major version.
    from pydantic import ConfigDict, field_validator, model_validator

    PYDANTIC_V2: Final[bool] = int(PYDANTIC_VERSION.split(".", 1)[0]) >= 2
except ImportError:  # pragma: no cover - exercised only on Pydantic v1.
    from pydantic import root_validator, validator

    PYDANTIC_V2 = False


CASE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*_[0-9]{3,}$")
"""Canonical ASRH case-id pattern, for example ``secret_exfiltration_001``."""

CASE_FILE_SUFFIXES: Final[tuple[str, ...]] = (".yaml", ".yml")
"""File suffixes accepted by case discovery."""

REQUIRED_MVP_CASE_COUNT: Final[int] = 50
"""Minimum case count for the MVP benchmark catalog."""

REQUIRED_CASES_PER_MVP_SUITE: Final[int] = 10
"""Minimum case count expected in each of the five MVP suites."""

SUPPORTED_CATEGORY_SET: Final[frozenset[str]] = frozenset(SUPPORTED_SUITES)
SUPPORTED_TOOL_SET: Final[frozenset[str]] = frozenset(SUPPORTED_TOOLS)
SUPPORTED_CHECKER_TYPE_SET: Final[frozenset[str]] = frozenset(SUPPORTED_CHECKER_TYPES)
TRUST_LEVEL_SET: Final[frozenset[str]] = frozenset(TRUST_LEVELS)
SEVERITY_LEVEL_SET: Final[frozenset[str]] = frozenset(SEVERITY_LEVELS)

UTILITY_CHECKER_TYPES: Final[frozenset[str]] = frozenset({"task_completion", "over_refusal"})
"""Checker types that primarily contribute to utility evaluation."""

SAFETY_CHECKER_TYPES: Final[frozenset[str]] = frozenset(
    {
        "no_secret_leak",
        "no_sensitive_file_access",
        "no_forbidden_tool_call",
        "instruction_hierarchy",
        "tool_minimality",
        "data_flow",
    }
)
"""Checker types that primarily contribute to safety evaluation."""

HIGH_RISK_TOOLS: Final[frozenset[str]] = frozenset(
    {"send_email", "run_shell", "network_request", "delete_file"}
)
"""Tool names treated as high risk by validation and later policy layers."""

SENSITIVE_CHECKER_TYPES: Final[frozenset[str]] = frozenset(
    {"no_secret_leak", "no_sensitive_file_access", "data_flow"}
)
"""Checker types expected when a case contains sensitive assets."""

PATH_TRAVERSAL_TOKEN: Final[str] = ".."
WINDOWS_DRIVE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:")
CONTROL_CHAR_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

RawCaseDocument: TypeAlias = dict[str, Any]
"""Raw mapping loaded from a YAML case file before schema validation."""

ExpectedUtility: TypeAlias = Literal["pass", "fail", "unknown"]
ExpectedSafety: TypeAlias = Literal["pass", "fail"]
Difficulty: TypeAlias = Literal["easy", "medium", "hard"]


def _major_pydantic_version() -> int:
    """Return the installed Pydantic major version."""
    try:
        return int(PYDANTIC_VERSION.split(".", 1)[0])
    except ValueError:
        return 0


def _field_validator(*fields: str, mode: str = "after") -> Any:
    """Return a field-validator decorator for Pydantic v1 or v2."""
    if PYDANTIC_V2:
        return field_validator(*fields, mode=mode)  # type: ignore[name-defined]
    return validator(*fields, pre=(mode == "before"), allow_reuse=True)  # type: ignore[name-defined]


class TrustLevel(StrEnum):
    """Trust labels for content in the synthetic environment."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    SENSITIVE = "sensitive"


class EmailTrustLevel(StrEnum):
    """Trust labels accepted by email items."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class SeverityLevel(StrEnum):
    """Ordered severity labels used by cases and checker results."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseCategory(StrEnum):
    """MVP suite categories."""

    PROMPT_INJECTION = "prompt_injection"
    SECRET_EXFILTRATION = "secret_exfiltration"
    TOOL_MISUSE = "tool_misuse"
    INSTRUCTION_CONFLICT = "instruction_conflict"
    REWARD_HACKING = "reward_hacking"


class AttackType(StrEnum):
    """Attack types represented in the case schema."""

    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_MISUSE = "tool_misuse"
    INSTRUCTION_CONFLICT = "instruction_conflict"
    REWARD_HACKING = "reward_hacking"


class PayloadLocation(StrEnum):
    """Locations where attacker-controlled payloads can appear."""

    USER_PROMPT = "user_prompt"
    FILE = "file"
    EMAIL = "email"
    MEMORY = "memory"
    TOOL_OUTPUT = "tool_output"


class CheckerType(StrEnum):
    """Checker identifiers accepted by ASRH YAML cases."""

    NO_SECRET_LEAK = "no_secret_leak"
    NO_SENSITIVE_FILE_ACCESS = "no_sensitive_file_access"
    NO_FORBIDDEN_TOOL_CALL = "no_forbidden_tool_call"
    TASK_COMPLETION = "task_completion"
    INSTRUCTION_HIERARCHY = "instruction_hierarchy"
    OVER_REFUSAL = "over_refusal"
    TOOL_MINIMALITY = "tool_minimality"
    DATA_FLOW = "data_flow"


class CaseBaseModel(BaseModel):
    """Base model shared by ASRH case-schema objects."""

    if PYDANTIC_V2:
        model_config: ClassVar[Any] = ConfigDict(  # type: ignore[name-defined]
            extra="forbid",
            frozen=True,
            populate_by_name=True,
            str_strip_whitespace=True,
            validate_assignment=False,
        )
    else:  # pragma: no cover - compatibility branch for Pydantic v1.

        class Config:
            """Pydantic v1 compatibility config."""

            extra = "forbid"
            allow_mutation = False
            allow_population_by_field_name = True
            anystr_strip_whitespace = True


class Metadata(CaseBaseModel):
    """Human-readable metadata for one test case."""

    title: str
    category: CaseCategory
    severity: SeverityLevel
    subcategory: str | None = None
    tags: list[str] = Field(default_factory=list)
    author: str | None = None
    created_at: date | None = None
    expected_difficulty: Difficulty | None = None

    @_field_validator("title")
    @classmethod
    def _title_must_not_be_blank(cls, value: str) -> str:
        return _require_non_blank(value, field_name="metadata.title")

    @_field_validator("subcategory", "author")
    @classmethod
    def _optional_text_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _require_non_blank(value, field_name="optional metadata text")

    @_field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        return _deduplicate_non_blank_strings(value, field_name="metadata.tags")


class ThreatModelSpec(CaseBaseModel):
    """Optional threat-model block for a case."""

    attacker_capability: str
    attacker_goal: str
    trusted_context: str
    untrusted_context: str
    security_property: str

    @_field_validator(
        "attacker_capability",
        "attacker_goal",
        "trusted_context",
        "untrusted_context",
        "security_property",
    )
    @classmethod
    def _threat_model_fields_must_not_be_blank(cls, value: str) -> str:
        return _require_non_blank(value, field_name="threat_model")


class TaskSuccessCriteria(CaseBaseModel):
    """Optional deterministic utility criteria embedded in the task block."""

    must_contain: list[str] = Field(default_factory=list)
    must_not_contain: list[str] = Field(default_factory=list)
    expected_tool_calls: list[str] = Field(default_factory=list)
    forbidden_tool_calls: list[str] = Field(default_factory=list)

    @_field_validator("must_contain", "must_not_contain", "expected_tool_calls", "forbidden_tool_calls")
    @classmethod
    def _normalize_string_lists(cls, value: list[str]) -> list[str]:
        return _deduplicate_non_blank_strings(value, field_name="task.success_criteria")


class TaskSpec(CaseBaseModel):
    """Trusted user task for the agent under test."""

    user_goal: str
    success_criteria: TaskSuccessCriteria = Field(default_factory=TaskSuccessCriteria)

    @_field_validator("user_goal")
    @classmethod
    def _user_goal_must_not_be_blank(cls, value: str) -> str:
        return _require_non_blank(value, field_name="task.user_goal")


class FileSpec(CaseBaseModel):
    """Synthetic file available in the sandbox environment."""

    path: str
    content: str
    trust_level: TrustLevel
    labels: list[str] = Field(default_factory=list)

    @_field_validator("path")
    @classmethod
    def _path_must_be_safe(cls, value: str) -> str:
        return validate_case_relative_path(value, field_name="environment.files[].path")

    @_field_validator("labels")
    @classmethod
    def _normalize_labels(cls, value: list[str]) -> list[str]:
        return _deduplicate_non_blank_strings(value, field_name="environment.files[].labels")


class EmailSpec(CaseBaseModel):
    """Synthetic email available in the sandbox environment."""

    sender: str = Field(alias="from")
    subject: str
    body: str
    trust_level: EmailTrustLevel
    labels: list[str] = Field(default_factory=list)

    @_field_validator("sender", "subject")
    @classmethod
    def _email_text_must_not_be_blank(cls, value: str) -> str:
        return _require_non_blank(value, field_name="environment.inbox[]")

    @_field_validator("labels")
    @classmethod
    def _normalize_labels(cls, value: list[str]) -> list[str]:
        return _deduplicate_non_blank_strings(value, field_name="environment.inbox[].labels")


class EnvironmentSpec(CaseBaseModel):
    """Synthetic environment for a case."""

    files: list[FileSpec] = Field(default_factory=list)
    inbox: list[EmailSpec] = Field(default_factory=list)
    memory: dict[str, Any] = Field(default_factory=dict)

    if PYDANTIC_V2:

        @model_validator(mode="after")  # type: ignore[name-defined]
        def _validate_environment(self) -> Self:
            _ensure_unique_file_paths(self.files)
            _ensure_memory_keys_are_safe(self.memory)
            return self

    else:  # pragma: no cover - compatibility branch for Pydantic v1.

        @root_validator(allow_reuse=True)  # type: ignore[name-defined]
        def _validate_environment_v1(cls, values: dict[str, Any]) -> dict[str, Any]:
            files = cast(list[FileSpec], values.get("files") or [])
            memory = cast(dict[str, Any], values.get("memory") or {})
            _ensure_unique_file_paths(files)
            _ensure_memory_keys_are_safe(memory)
            return values

    @property
    def sensitive_file_paths(self) -> tuple[str, ...]:
        """Return paths of files marked as sensitive."""
        return tuple(file.path for file in self.files if file.trust_level == TrustLevel.SENSITIVE)

    @property
    def untrusted_file_paths(self) -> tuple[str, ...]:
        """Return paths of files marked as untrusted."""
        return tuple(file.path for file in self.files if file.trust_level == TrustLevel.UNTRUSTED)


class ToolSpec(CaseBaseModel):
    """Allowed tools and per-tool policy configuration for a case."""

    allowed: list[str]
    tool_policies: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @_field_validator("allowed")
    @classmethod
    def _allowed_tools_must_not_be_empty(cls, value: list[str]) -> list[str]:
        normalized = _deduplicate_non_blank_strings(value, field_name="tools.allowed")
        if not normalized:
            raise ValueError("tools.allowed must include at least one tool")
        return normalized

    @_field_validator("tool_policies")
    @classmethod
    def _tool_policy_keys_must_not_be_blank(
        cls, value: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        for key, policy in value.items():
            _require_non_blank(key, field_name="tools.tool_policies key")
            if not isinstance(policy, dict):
                raise TypeError(f"tools.tool_policies.{key} must be a mapping")
        return value


class AttackSpec(CaseBaseModel):
    """Attacker payload embedded in the case."""

    type: AttackType
    payload_location: PayloadLocation
    payload: str
    expected_attack_behavior: str | None = None

    @_field_validator("payload")
    @classmethod
    def _payload_must_not_be_blank(cls, value: str) -> str:
        return _require_non_blank(value, field_name="attack.payload")

    @_field_validator("expected_attack_behavior")
    @classmethod
    def _expected_behavior_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _require_non_blank(value, field_name="attack.expected_attack_behavior")


class CheckerSpec(CaseBaseModel):
    """Configuration for one deterministic checker."""

    type: CheckerType
    forbidden_patterns: list[str] | None = None
    tools: list[str] | None = None
    paths: list[str] | None = None
    required_evidence: list[str] | None = None
    higher_priority_instruction: str | None = None
    lower_priority_conflict: str | None = None
    must_contain: list[str] | None = None
    must_not_contain: list[str] | None = None
    severity: SeverityLevel | None = None

    @_field_validator("forbidden_patterns", "tools", "required_evidence", "must_contain", "must_not_contain")
    @classmethod
    def _optional_string_lists_must_be_clean(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return _deduplicate_non_blank_strings(value, field_name="checker string list")

    @_field_validator("paths")
    @classmethod
    def _optional_paths_must_be_safe(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized = _deduplicate_non_blank_strings(value, field_name="checker paths")
        return [validate_case_relative_path(path, field_name="checker.paths") for path in normalized]

    @_field_validator("higher_priority_instruction", "lower_priority_conflict")
    @classmethod
    def _optional_text_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _require_non_blank(value, field_name="checker text")

    if PYDANTIC_V2:

        @model_validator(mode="after")  # type: ignore[name-defined]
        def _validate_checker_config(self) -> Self:
            _validate_checker_requirements(self)
            return self

    else:  # pragma: no cover - compatibility branch for Pydantic v1.

        @root_validator(allow_reuse=True)  # type: ignore[name-defined]
        def _validate_checker_config_v1(cls, values: dict[str, Any]) -> dict[str, Any]:
            checker = CheckerSpec.construct(**values)
            _validate_checker_requirements(checker)
            return values

    @property
    def is_utility_checker(self) -> bool:
        """Return whether this checker primarily measures utility."""
        return self.type.value in UTILITY_CHECKER_TYPES

    @property
    def is_safety_checker(self) -> bool:
        """Return whether this checker primarily measures safety."""
        return self.type.value in SAFETY_CHECKER_TYPES


class ExpectedSpec(CaseBaseModel):
    """Expected utility and safety outcomes for a case."""

    utility: ExpectedUtility
    safety: ExpectedSafety
    notes: str | None = None

    @_field_validator("notes")
    @classmethod
    def _notes_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _require_non_blank(value, field_name="expected.notes")


class TestCase(CaseBaseModel):
    """A complete ASRH YAML test case."""

    id: str
    version: str
    metadata: Metadata
    task: TaskSpec
    environment: EnvironmentSpec
    tools: ToolSpec
    attack: AttackSpec | None = None
    checkers: list[CheckerSpec]
    expected: ExpectedSpec
    threat_model: ThreatModelSpec | None = None

    @_field_validator("id")
    @classmethod
    def _case_id_must_be_valid(cls, value: str) -> str:
        normalized = _require_non_blank(value, field_name="id")
        if not CASE_ID_PATTERN.fullmatch(normalized):
            raise ValueError(
                "id must match '<category>_<number>', for example 'secret_exfiltration_001'"
            )
        return normalized

    @_field_validator("version")
    @classmethod
    def _version_must_match_schema(cls, value: str) -> str:
        normalized = _require_non_blank(value, field_name="version")
        if normalized != CASE_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported case schema version {normalized!r}; expected {CASE_SCHEMA_VERSION!r}"
            )
        return normalized

    @_field_validator("checkers")
    @classmethod
    def _checkers_must_not_be_empty(cls, value: list[CheckerSpec]) -> list[CheckerSpec]:
        if not value:
            raise ValueError("checkers must include at least one checker")
        return value

    if PYDANTIC_V2:

        @model_validator(mode="after")  # type: ignore[name-defined]
        def _validate_case_consistency(self) -> Self:
            _validate_case_consistency(self)
            return self

    else:  # pragma: no cover - compatibility branch for Pydantic v1.

        @root_validator(allow_reuse=True)  # type: ignore[name-defined]
        def _validate_case_consistency_v1(cls, values: dict[str, Any]) -> dict[str, Any]:
            case = TestCase.construct(**values)
            _validate_case_consistency(case)
            return values

    @property
    def category(self) -> str:
        """Return the case category as a string."""
        return self.metadata.category.value

    @property
    def severity(self) -> str:
        """Return the case severity as a string."""
        return self.metadata.severity.value

    @property
    def checker_types(self) -> tuple[str, ...]:
        """Return configured checker type names."""
        return tuple(checker.type.value for checker in self.checkers)

    @property
    def allowed_tools(self) -> tuple[str, ...]:
        """Return allowed tool names."""
        return tuple(self.tools.allowed)

    @property
    def sensitive_file_paths(self) -> tuple[str, ...]:
        """Return paths of sensitive files in this case."""
        return self.environment.sensitive_file_paths

    @property
    def has_utility_checker(self) -> bool:
        """Return whether the case has at least one utility checker."""
        return any(checker.is_utility_checker for checker in self.checkers)

    @property
    def has_safety_checker(self) -> bool:
        """Return whether the case has at least one safety checker."""
        return any(checker.is_safety_checker for checker in self.checkers)

    def has_checker(self, checker_type: str | CheckerType) -> bool:
        """Return whether the case contains a checker of ``checker_type``."""
        wanted = checker_type.value if isinstance(checker_type, CheckerType) else checker_type
        return wanted in self.checker_types

    def to_mapping(self, *, by_alias: bool = True, exclude_none: bool = True) -> dict[str, Any]:
        """Return a plain Python mapping suitable for YAML or JSON serialization."""
        if PYDANTIC_V2:
            return cast(
                dict[str, Any],
                self.model_dump(by_alias=by_alias, exclude_none=exclude_none, mode="python"),
            )
        return cast(dict[str, Any], self.dict(by_alias=by_alias, exclude_none=exclude_none))


class CaseSchemaError(ValueError):
    """Raised by convenience schema helpers when case validation fails."""


# Backward-compatible aliases that mirror the naming in the technical spec.
FileTrustLevel: TypeAlias = TrustLevel
CaseSeverity: TypeAlias = SeverityLevel
ToolSpecModel: TypeAlias = ToolSpec


def validate_case_relative_path(value: str, *, field_name: str = "path") -> str:
    """Validate a case-local POSIX-style relative path.

    Paths in test cases describe synthetic sandbox objects, not host paths. The
    loader and later sandbox must therefore reject absolute paths, traversal, and
    control characters early.
    """
    path_text = _require_non_blank(value, field_name=field_name)
    if "\\" in path_text:
        raise ValueError(f"{field_name} must use POSIX-style '/' separators, not backslashes")
    if WINDOWS_DRIVE_PATTERN.match(path_text):
        raise ValueError(f"{field_name} must not include a Windows drive prefix")
    if CONTROL_CHAR_PATTERN.search(path_text):
        raise ValueError(f"{field_name} must not contain control characters")

    path = PurePosixPath(path_text)
    if path.is_absolute():
        raise ValueError(f"{field_name} must be relative, not absolute")
    if PATH_TRAVERSAL_TOKEN in path.parts:
        raise ValueError(f"{field_name} must not contain '..' traversal segments")
    if any(part == "" for part in path.parts):
        raise ValueError(f"{field_name} must not contain empty path segments")
    return path_text


def parse_case_document(document: RawCaseDocument) -> TestCase:
    """Validate a raw YAML mapping and return a ``TestCase`` model."""
    if not isinstance(document, dict):
        raise CaseSchemaError("case document must be a YAML mapping/object")
    try:
        if PYDANTIC_V2:
            return TestCase.model_validate(document)
        return TestCase.parse_obj(document)
    except PydanticValidationError as exc:
        raise CaseSchemaError(str(exc)) from exc


def is_utility_checker_type(checker_type: str | CheckerType) -> bool:
    """Return whether a checker type contributes to utility metrics."""
    value = checker_type.value if isinstance(checker_type, CheckerType) else checker_type
    return value in UTILITY_CHECKER_TYPES


def is_safety_checker_type(checker_type: str | CheckerType) -> bool:
    """Return whether a checker type contributes to safety metrics."""
    value = checker_type.value if isinstance(checker_type, CheckerType) else checker_type
    return value in SAFETY_CHECKER_TYPES


def category_from_case_id(case_id: str) -> str:
    """Return the category prefix from a canonical case id."""
    _require_non_blank(case_id, field_name="case_id")
    if "_" not in case_id:
        return case_id
    return case_id.rsplit("_", 1)[0]


def _validate_checker_requirements(checker: CheckerSpec) -> None:
    checker_type = checker.type.value
    if checker_type == "no_secret_leak" and not checker.forbidden_patterns:
        raise ValueError("no_secret_leak checker requires forbidden_patterns")
    if checker_type == "no_sensitive_file_access" and not checker.paths:
        raise ValueError("no_sensitive_file_access checker requires paths")
    if checker_type == "no_forbidden_tool_call" and not checker.tools:
        raise ValueError("no_forbidden_tool_call checker requires tools")
    if checker_type == "task_completion" and not checker.required_evidence:
        raise ValueError("task_completion checker requires required_evidence")
    if checker_type == "instruction_hierarchy":
        has_conflict = bool(checker.lower_priority_conflict)
        has_forbidden_text = bool(checker.must_not_contain)
        if not has_conflict and not has_forbidden_text:
            raise ValueError(
                "instruction_hierarchy checker requires lower_priority_conflict or must_not_contain"
            )


def _validate_case_consistency(case: TestCase) -> None:
    case_category = case.metadata.category.value
    id_category = category_from_case_id(case.id)
    if case_category not in SUPPORTED_CATEGORY_SET:
        raise ValueError(f"metadata.category must be one of {sorted(SUPPORTED_CATEGORY_SET)}")
    if id_category != case_category:
        raise ValueError(
            f"case id prefix {id_category!r} must match metadata.category {case_category!r}"
        )

    checker_types = case.checker_types
    if not any(is_utility_checker_type(checker_type) for checker_type in checker_types):
        raise ValueError("case must include at least one utility checker")
    if not any(is_safety_checker_type(checker_type) for checker_type in checker_types):
        raise ValueError("case must include at least one safety checker")

    sensitive_paths = set(case.sensitive_file_paths)
    if sensitive_paths and not any(
        checker_type in SENSITIVE_CHECKER_TYPES for checker_type in checker_types
    ):
        raise ValueError(
            "cases containing sensitive files must include a sensitive-data safety checker"
        )


def _ensure_unique_file_paths(files: list[FileSpec]) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for file_spec in files:
        if file_spec.path in seen:
            duplicates.add(file_spec.path)
        seen.add(file_spec.path)
    if duplicates:
        duplicate_text = ", ".join(sorted(duplicates))
        raise ValueError(f"environment.files contains duplicate path(s): {duplicate_text}")


def _ensure_memory_keys_are_safe(memory: dict[str, Any]) -> None:
    for key in memory:
        _require_non_blank(key, field_name="environment.memory key")
        if CONTROL_CHAR_PATTERN.search(key):
            raise ValueError("environment.memory keys must not contain control characters")


def _deduplicate_non_blank_strings(values: list[str], *, field_name: str) -> list[str]:
    if not isinstance(values, list):
        raise TypeError(f"{field_name} must be a list")

    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _require_non_blank(value, field_name=field_name)
        if text not in seen:
            normalized.append(text)
            seen.add(text)
    return normalized


def _require_non_blank(value: str, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be blank")
    return normalized


__all__: Final[tuple[str, ...]] = (
    "AttackSpec",
    "AttackType",
    "CASE_FILE_SUFFIXES",
    "CASE_ID_PATTERN",
    "CaseBaseModel",
    "CaseCategory",
    "CaseSchemaError",
    "CaseSeverity",
    "CheckerSpec",
    "CheckerType",
    "Difficulty",
    "EmailSpec",
    "EmailTrustLevel",
    "EnvironmentSpec",
    "ExpectedSafety",
    "ExpectedSpec",
    "ExpectedUtility",
    "FileSpec",
    "FileTrustLevel",
    "HIGH_RISK_TOOLS",
    "Metadata",
    "PYDANTIC_V2",
    "PayloadLocation",
    "REQUIRED_CASES_PER_MVP_SUITE",
    "REQUIRED_MVP_CASE_COUNT",
    "RawCaseDocument",
    "SAFETY_CHECKER_TYPES",
    "SENSITIVE_CHECKER_TYPES",
    "SUPPORTED_CATEGORY_SET",
    "SUPPORTED_CHECKER_TYPE_SET",
    "SUPPORTED_TOOL_SET",
    "SEVERITY_LEVEL_SET",
    "TaskSpec",
    "TaskSuccessCriteria",
    "TestCase",
    "ThreatModelSpec",
    "ToolSpec",
    "ToolSpecModel",
    "TrustLevel",
    "UTILITY_CHECKER_TYPES",
    "category_from_case_id",
    "is_safety_checker_type",
    "is_utility_checker_type",
    "parse_case_document",
    "validate_case_relative_path",
)
