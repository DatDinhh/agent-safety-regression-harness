"""Mitigation strategy primitives for ASRH.

The mitigation layer is the orchestration seam between prompts, sandbox policy,
tool registries, and later runner/checker code. It deliberately does not execute
model calls. Instead, it provides deterministic transformations and metadata so
runner modules can apply a mitigation consistently before each case run.

The MVP mitigation modes match the technical specification:

- ``none``: no extra mitigation beyond the case's base sandbox policy;
- ``system_prompt_guard``: guarded prompt variant only;
- ``tool_policy_guard``: code-enforced tool-policy hardening;
- ``taint_tracking_guard``: code-enforced high-risk blocking after untrusted data;
- ``human_approval_guard``: simulated approval gates for risky actions.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field, is_dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final, Protocol, TypeAlias, runtime_checkable

from asrh import DEFAULT_MITIGATION, SUPPORTED_MITIGATIONS
from asrh.cases.schema import TestCase, parse_case_document, validate_case_relative_path
from asrh.envs.policy import HIGH_RISK_TOOL_NAMES
from asrh.envs.sandbox import SandboxEnv, build_sandbox_from_case
from asrh.tools.registry import ToolRegistry, build_case_tool_registry

JsonDict: TypeAlias = dict[str, Any]
JsonMapping: TypeAlias = Mapping[str, Any]
ToolPolicyPatch: TypeAlias = Mapping[str, Mapping[str, Any]]

MITIGATION_NONE: Final[str] = "none"
MITIGATION_SYSTEM_PROMPT_GUARD: Final[str] = "system_prompt_guard"
MITIGATION_TOOL_POLICY_GUARD: Final[str] = "tool_policy_guard"
MITIGATION_TAINT_TRACKING_GUARD: Final[str] = "taint_tracking_guard"
MITIGATION_HUMAN_APPROVAL_GUARD: Final[str] = "human_approval_guard"

PROMPT_VARIANT_BASELINE: Final[str] = "baseline"
PROMPT_VARIANT_GUARDED: Final[str] = "guarded"

READ_FILE_TOOL_NAME: Final[str] = "read_file"
LIST_FILES_TOOL_NAME: Final[str] = "list_files"
WRITE_FILE_TOOL_NAME: Final[str] = "write_file"
SEND_EMAIL_TOOL_NAME: Final[str] = "send_email"
RUN_SHELL_TOOL_NAME: Final[str] = "run_shell"
NETWORK_REQUEST_TOOL_NAME: Final[str] = "network_request"
READ_MEMORY_TOOL_NAME: Final[str] = "read_memory"

SENSITIVE_TRUST_LEVEL: Final[str] = "sensitive"
UNTRUSTED_TRUST_LEVEL: Final[str] = "untrusted"

FORBIDDEN_PATTERN_CHECKER_TYPE: Final[str] = "no_secret_leak"
SENSITIVE_ACCESS_CHECKER_TYPE: Final[str] = "no_sensitive_file_access"

DEFAULT_LIST_MERGE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "allowed_paths",
        "denied_paths",
        "allow_sensitive_paths",
        "allowed_recipients",
        "denied_recipients",
        "allowed_commands",
        "denied_commands",
        "allowed_urls",
        "denied_urls",
        "allowed_keys",
        "denied_keys",
    }
)

MITIGATION_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "baseline": MITIGATION_NONE,
        "no_mitigation": MITIGATION_NONE,
        "no_guard": MITIGATION_NONE,
        "prompt_guard": MITIGATION_SYSTEM_PROMPT_GUARD,
        "system_guard": MITIGATION_SYSTEM_PROMPT_GUARD,
        "instruction_hierarchy_guard": MITIGATION_SYSTEM_PROMPT_GUARD,
        "policy_guard": MITIGATION_TOOL_POLICY_GUARD,
        "tool_guard": MITIGATION_TOOL_POLICY_GUARD,
        "code_policy_guard": MITIGATION_TOOL_POLICY_GUARD,
        "taint_guard": MITIGATION_TAINT_TRACKING_GUARD,
        "taint_guarded": MITIGATION_TAINT_TRACKING_GUARD,
        "approval_guard": MITIGATION_HUMAN_APPROVAL_GUARD,
        "human_guard": MITIGATION_HUMAN_APPROVAL_GUARD,
    }
)
SUPPORTED_MITIGATION_SET: Final[frozenset[str]] = frozenset(SUPPORTED_MITIGATIONS)


class MitigationError(Exception):
    """Base exception for mitigation lookup, configuration, and application."""


class MitigationConfigurationError(MitigationError):
    """Raised when a mitigation strategy is malformed or unsupported."""


class MitigationApplicationError(MitigationError):
    """Raised when a mitigation cannot be applied to a case or config."""


class MitigationName(StrEnum):
    """Canonical mitigation names defined by the MVP specification."""

    NONE = MITIGATION_NONE
    SYSTEM_PROMPT_GUARD = MITIGATION_SYSTEM_PROMPT_GUARD
    TOOL_POLICY_GUARD = MITIGATION_TOOL_POLICY_GUARD
    TAINT_TRACKING_GUARD = MITIGATION_TAINT_TRACKING_GUARD
    HUMAN_APPROVAL_GUARD = MITIGATION_HUMAN_APPROVAL_GUARD


class MitigationPromptVariant(StrEnum):
    """Prompt variants understood by ``asrh.agents.prompts``."""

    BASELINE = PROMPT_VARIANT_BASELINE
    GUARDED = PROMPT_VARIANT_GUARDED


class MitigationCapability(StrEnum):
    """Capability tags advertised by mitigation strategies."""

    PROMPT_GUARD = "prompt_guard"
    CODE_ENFORCED_POLICY = "code_enforced_policy"
    TAINT_TRACKING = "taint_tracking"
    HUMAN_APPROVAL = "human_approval"
    FINAL_OUTPUT_SCAN = "final_output_scan"


@dataclass(frozen=True, slots=True)
class MitigationDecision:
    """A normalized mitigation hook decision.

    This is intentionally similar to ``ToolPolicyDecision`` but independent of
    the sandbox policy layer so runner code can use it for pre/post hooks and
    final-answer scans without coupling to tool internals.
    """

    allowed: bool
    reason: str
    mitigation: str
    policy_violation: bool = False
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: JsonMapping = field(default_factory=dict)

    @classmethod
    def allow(
        cls,
        mitigation: str,
        *,
        reason: str = "allowed by mitigation",
        labels: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> MitigationDecision:
        """Return an allow decision."""
        return cls(
            allowed=True,
            reason=reason,
            mitigation=normalize_mitigation_name(mitigation),
            policy_violation=False,
            labels=dedupe_strings(labels),
            metadata=freeze_jsonable_mapping(metadata or {}),
        )

    @classmethod
    def deny(
        cls,
        mitigation: str,
        *,
        reason: str,
        policy_violation: bool = True,
        labels: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> MitigationDecision:
        """Return a deny decision."""
        return cls(
            allowed=False,
            reason=str(reason),
            mitigation=normalize_mitigation_name(mitigation),
            policy_violation=policy_violation,
            labels=dedupe_strings(labels),
            metadata=freeze_jsonable_mapping(metadata or {}),
        )

    def to_dict(self) -> JsonDict:
        """Return a JSON-serializable representation."""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "mitigation": self.mitigation,
            "policy_violation": self.policy_violation,
            "labels": list(self.labels),
            "metadata": thaw_jsonable(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class FinalAnswerScanResult:
    """Result of a mitigation-level final-answer safety scan."""

    passed: bool
    mitigation: str
    matched_patterns: tuple[str, ...] = field(default_factory=tuple)
    failure_class: str | None = None
    severity: str | None = None
    explanation: str = ""
    metadata: JsonMapping = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        """Return whether the scan found a mitigation-level violation."""
        return not self.passed

    def to_decision(self) -> MitigationDecision:
        """Convert this scan result into a runner-facing decision."""
        if self.passed:
            return MitigationDecision.allow(
                self.mitigation,
                reason=self.explanation or "final answer passed mitigation scan",
                metadata=self.to_dict(),
            )
        return MitigationDecision.deny(
            self.mitigation,
            reason=self.explanation or "final answer failed mitigation scan",
            labels=(self.failure_class or "FINAL_OUTPUT_SCAN_FAILURE",),
            metadata=self.to_dict(),
        )

    def to_dict(self) -> JsonDict:
        """Return a JSON-serializable representation."""
        return {
            "passed": self.passed,
            "mitigation": self.mitigation,
            "matched_patterns": list(self.matched_patterns),
            "failure_class": self.failure_class,
            "severity": self.severity,
            "explanation": self.explanation,
            "metadata": thaw_jsonable(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class MitigationApplication:
    """Summary of a mitigation applied to a case before execution."""

    mitigation: str
    original_case_id: str
    case: TestCase
    prompt_variant: str
    extra_system_instructions: tuple[str, ...] = field(default_factory=tuple)
    metadata: JsonMapping = field(default_factory=dict)

    @property
    def case_id(self) -> str:
        """Return the case id after mitigation application."""
        return self.case.id

    def to_dict(self) -> JsonDict:
        """Return a JSON-serializable summary without embedding full case content."""
        return {
            "mitigation": self.mitigation,
            "original_case_id": self.original_case_id,
            "case_id": self.case.id,
            "prompt_variant": self.prompt_variant,
            "extra_system_instructions": list(self.extra_system_instructions),
            "metadata": thaw_jsonable(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class MitigationContext:
    """Runtime context supplied to optional mitigation hooks."""

    case: TestCase
    mitigation: str = DEFAULT_MITIGATION
    env: SandboxEnv | None = None
    config: Any = None
    metadata: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "mitigation", normalize_mitigation_name(self.mitigation))
        object.__setattr__(self, "metadata", freeze_jsonable_mapping(self.metadata))

    def to_dict(self) -> JsonDict:
        """Return a compact JSON-serializable context summary."""
        return {
            "case_id": self.case.id,
            "category": self.case.category,
            "mitigation": self.mitigation,
            "has_env": self.env is not None,
            "metadata": thaw_jsonable(self.metadata),
        }


@runtime_checkable
class MitigationStrategy(Protocol):
    """Protocol implemented by concrete mitigation strategies."""

    name: str
    description: str
    prompt_guard: bool
    code_enforced: bool
    taint_tracking: bool
    human_approval: bool
    final_output_scan: bool

    @property
    def prompt_variant(self) -> str:
        """Return ``baseline`` or ``guarded`` prompt variant."""
        ...

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return capability tags for reporting."""
        ...

    def apply_case(self, case: TestCase) -> TestCase:
        """Return a case transformed for this mitigation."""
        ...

    def extra_system_instructions(self, case: TestCase | None = None) -> tuple[str, ...]:
        """Return optional extra instructions for agent prompt builders."""
        ...

    def build_sandbox(self, case: TestCase) -> SandboxEnv:
        """Build a sandbox configured for this mitigation."""
        ...

    def build_tool_registry(self, case: TestCase, *, strict: bool = False) -> ToolRegistry:
        """Build the tool registry for a mitigated case."""
        ...

    def scan_final_answer(self, final_answer: str, case: TestCase) -> FinalAnswerScanResult:
        """Run mitigation-level final-answer scan, if any."""
        ...

    def to_dict(self) -> JsonDict:
        """Return a JSON-serializable descriptor."""
        ...


class BaseMitigationStrategy:
    """Base class for deterministic ASRH mitigation strategies.

    Concrete strategies should override declarative class attributes and, when
    needed, ``policy_patches`` or ``apply_case``. Prompt code already switches to
    a guarded system prompt when the mitigation name is not ``none``; this class
    exposes the same prompt-variant metadata for runner/report code.
    """

    name: str = "base"
    description: str = "Base mitigation strategy."
    prompt_guard: bool = False
    code_enforced: bool = False
    taint_tracking: bool = False
    human_approval: bool = False
    final_output_scan: bool = False
    terminal_on_policy_violation: bool = False

    def __init__(self) -> None:
        self.validate_strategy_definition()

    @property
    def prompt_variant(self) -> str:
        """Return the prompt variant expected by ``asrh.agents.prompts``."""
        return PROMPT_VARIANT_GUARDED if self.prompt_guard else PROMPT_VARIANT_BASELINE

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return capability tags used by reports and trace metadata."""
        capabilities: list[str] = []
        if self.prompt_guard:
            capabilities.append(MitigationCapability.PROMPT_GUARD.value)
        if self.code_enforced:
            capabilities.append(MitigationCapability.CODE_ENFORCED_POLICY.value)
        if self.taint_tracking:
            capabilities.append(MitigationCapability.TAINT_TRACKING.value)
        if self.human_approval:
            capabilities.append(MitigationCapability.HUMAN_APPROVAL.value)
        if self.final_output_scan:
            capabilities.append(MitigationCapability.FINAL_OUTPUT_SCAN.value)
        return tuple(capabilities)

    def validate_strategy_definition(self) -> None:
        """Validate static fields at construction time."""
        if normalize_mitigation_name(self.name) != self.name:
            raise MitigationConfigurationError(f"strategy name must be canonical: {self.name!r}")
        if self.name not in SUPPORTED_MITIGATION_SET:
            raise MitigationConfigurationError(
                f"unsupported mitigation strategy name: {self.name!r}"
            )
        if not str(self.description).strip():
            raise MitigationConfigurationError(f"strategy {self.name!r} has a blank description")

    def policy_patches(self, case: TestCase) -> ToolPolicyPatch:
        """Return per-tool policy patches for ``case``.

        Subclasses should prefer overriding this method over rewriting
        ``apply_case`` when they only need to modify ``tools.tool_policies``.
        """
        del case
        return {}

    def apply_case(self, case: TestCase) -> TestCase:
        """Return a case transformed for this mitigation."""
        patches = self.policy_patches(case)
        return patch_case_tool_policies(case, patches) if patches else case

    def apply(self, case: TestCase) -> MitigationApplication:
        """Apply the mitigation and return a structured summary."""
        mitigated_case = self.apply_case(case)
        return MitigationApplication(
            mitigation=self.name,
            original_case_id=case.id,
            case=mitigated_case,
            prompt_variant=self.prompt_variant,
            extra_system_instructions=self.extra_system_instructions(mitigated_case),
            metadata={
                "capabilities": list(self.capabilities),
                "code_enforced": self.code_enforced,
                "taint_tracking": self.taint_tracking,
                "human_approval": self.human_approval,
            },
        )

    def apply_agent_config(self, config: Any) -> Any:
        """Return ``config`` with this mitigation name applied when possible."""
        if config is None:
            return {"mitigation": self.name}
        if isinstance(config, Mapping):
            data = dict(config)
            data["mitigation"] = self.name
            if self.terminal_on_policy_violation:
                data.setdefault("stop_on_policy_violation", True)
            return data
        if is_dataclass(config):
            updates: dict[str, Any] = {"mitigation": self.name}
            if self.terminal_on_policy_violation and hasattr(config, "stop_on_policy_violation"):
                updates["stop_on_policy_violation"] = True
            try:
                return replace(config, **updates)
            except TypeError as exc:
                raise MitigationApplicationError(
                    f"could not apply mitigation to config: {exc}"
                ) from exc
        if hasattr(config, "mitigation"):
            try:
                setattr(config, "mitigation", self.name)
                return config
            except Exception as exc:  # noqa: BLE001 - config objects are external to this module.
                raise MitigationApplicationError(f"could not set config.mitigation: {exc}") from exc
        return config

    def extra_system_instructions(self, case: TestCase | None = None) -> tuple[str, ...]:
        """Return optional extra system instructions for agent constructors.

        The default returns an empty tuple because prompt builders already select
        guarded text based on the mitigation name. Concrete strategies can add
        short non-oracle instructions here.
        """
        del case
        return ()

    def build_sandbox(self, case: TestCase) -> SandboxEnv:
        """Build a sandbox configured for this mitigation."""
        return build_sandbox_from_case(self.apply_case(case), mitigation=self.name)

    def build_tool_registry(self, case: TestCase, *, strict: bool = False) -> ToolRegistry:
        """Build a case-filtered tool registry for the mitigated case."""
        return build_case_tool_registry(self.apply_case(case), strict=strict)

    def before_tool_call(
        self,
        *,
        tool_name: str,
        args: Mapping[str, Any] | None,
        context: MitigationContext,
    ) -> MitigationDecision:
        """Optional pre-tool hook for future runner implementations."""
        del tool_name, args, context
        return MitigationDecision.allow(self.name, reason="no mitigation pre-tool block")

    def after_tool_result(
        self,
        *,
        tool_result: Any,
        context: MitigationContext,
    ) -> MitigationDecision:
        """Optional post-tool hook for future runner implementations."""
        del tool_result, context
        return MitigationDecision.allow(self.name, reason="no mitigation post-tool block")

    def scan_final_answer(self, final_answer: str, case: TestCase) -> FinalAnswerScanResult:
        """Run mitigation-level final-answer checks.

        Checker modules remain the source of truth for verdicts. This hook exists
        so ``taint_tracking_guard`` can contribute an auditable exact-match scan
        without requiring LLM-as-judge.
        """
        del final_answer, case
        return FinalAnswerScanResult(
            passed=True,
            mitigation=self.name,
            explanation="mitigation has no final-answer scan",
        )

    def to_dict(self) -> JsonDict:
        """Return a JSON-serializable descriptor."""
        return {
            "name": self.name,
            "description": self.description,
            "prompt_guard": self.prompt_guard,
            "prompt_variant": self.prompt_variant,
            "code_enforced": self.code_enforced,
            "taint_tracking": self.taint_tracking,
            "human_approval": self.human_approval,
            "final_output_scan": self.final_output_scan,
            "terminal_on_policy_violation": self.terminal_on_policy_violation,
            "capabilities": list(self.capabilities),
        }

    def __repr__(self) -> str:
        """Return concise strategy representation."""
        return f"{type(self).__name__}(name={self.name!r})"


class MitigationRegistry:
    """Immutable registry of mitigation strategies."""

    def __init__(self, strategies: Iterable[MitigationStrategy]) -> None:
        by_name: dict[str, MitigationStrategy] = {}
        for strategy in strategies:
            name = normalize_mitigation_name(strategy.name)
            if name in by_name:
                raise MitigationConfigurationError(f"duplicate mitigation strategy: {name}")
            by_name[name] = strategy
        missing = SUPPORTED_MITIGATION_SET - set(by_name)
        if missing:
            raise MitigationConfigurationError(f"missing mitigation strategies: {sorted(missing)}")
        self._by_name = MappingProxyType(by_name)

    def __contains__(self, name: object) -> bool:
        return (
            isinstance(name, str)
            and normalize_mitigation_name(name, validate=False) in self._by_name
        )

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._by_name.values())

    def __len__(self) -> int:
        return len(self._by_name)

    @property
    def names(self) -> tuple[str, ...]:
        """Return registered strategy names in deterministic order."""
        return tuple(name for name in SUPPORTED_MITIGATIONS if name in self._by_name)

    def get(self, name: str | None = None) -> MitigationStrategy:
        """Return a strategy by canonical name or alias."""
        normalized = normalize_mitigation_name(name)
        try:
            return self._by_name[normalized]
        except KeyError as exc:
            raise MitigationConfigurationError(f"unsupported mitigation: {name!r}") from exc

    def to_dict(self) -> JsonDict:
        """Return JSON-serializable registry metadata."""
        return {name: self._by_name[name].to_dict() for name in self.names}


# ---------------------------------------------------------------------------
# Case-policy patch helpers
# ---------------------------------------------------------------------------


def normalize_mitigation_name(name: str | None = None, *, validate: bool = True) -> str:
    """Normalize a mitigation identifier into its canonical ASRH name."""
    raw = DEFAULT_MITIGATION if name is None else str(name)
    normalized = raw.strip().lower().replace("-", "_").replace(" ", "_") or DEFAULT_MITIGATION
    normalized = MITIGATION_ALIASES.get(normalized, normalized)
    if validate and normalized not in SUPPORTED_MITIGATION_SET:
        raise MitigationConfigurationError(
            f"unsupported mitigation {name!r}; expected one of {sorted(SUPPORTED_MITIGATION_SET)}"
        )
    return normalized


canonicalize_mitigation_name = normalize_mitigation_name
resolve_mitigation_name = normalize_mitigation_name


def is_supported_mitigation(name: str | None) -> bool:
    """Return whether ``name`` resolves to a supported mitigation."""
    try:
        normalize_mitigation_name(name)
    except MitigationConfigurationError:
        return False
    return True


def case_to_mutable_mapping(case: TestCase) -> JsonDict:
    """Return a deep-ish mutable mapping for a parsed case."""
    if hasattr(case, "to_mapping"):
        return thaw_jsonable(case.to_mapping(by_alias=True, exclude_none=True))
    if hasattr(case, "model_dump"):
        return thaw_jsonable(case.model_dump(by_alias=True, exclude_none=True, mode="python"))
    if hasattr(case, "dict"):
        return thaw_jsonable(case.dict(by_alias=True, exclude_none=True))
    raise MitigationApplicationError(f"unsupported case object: {type(case).__name__}")


def parse_mutable_case_mapping(document: Mapping[str, Any]) -> TestCase:
    """Validate a mutated case mapping and return ``TestCase``."""
    try:
        return parse_case_document(dict(document))
    except Exception as exc:  # noqa: BLE001 - preserve pydantic details inside wrapper.
        raise MitigationApplicationError(f"mitigated case failed validation: {exc}") from exc


def patch_case_tool_policies(
    case: TestCase,
    patches: ToolPolicyPatch,
    *,
    overwrite: bool = True,
    list_merge_keys: Iterable[str] = DEFAULT_LIST_MERGE_KEYS,
) -> TestCase:
    """Return ``case`` with merged ``tools.tool_policies`` patches."""
    if not patches:
        return case
    document = case_to_mutable_mapping(case)
    tools_doc = ensure_mapping(document.setdefault("tools", {}), field_name="tools")
    raw_policies = tools_doc.get("tool_policies") or {}
    if not isinstance(raw_policies, Mapping):
        raise MitigationApplicationError("tools.tool_policies must be a mapping")
    tool_policies: JsonDict = {
        str(key): thaw_jsonable(value) for key, value in raw_policies.items()
    }
    merge_keys = frozenset(str(key) for key in list_merge_keys)

    for raw_tool_name, patch in patches.items():
        tool_name = normalize_policy_name(raw_tool_name)
        if not isinstance(patch, Mapping):
            raise MitigationApplicationError(f"policy patch for {tool_name!r} must be a mapping")
        existing = ensure_mutable_mapping(
            tool_policies.get(tool_name, {}),
            field_name=f"policy:{tool_name}",
        )
        tool_policies[tool_name] = merge_policy_mappings(
            existing,
            patch,
            overwrite=overwrite,
            list_merge_keys=merge_keys,
        )

    tools_doc["tool_policies"] = tool_policies
    document["tools"] = tools_doc
    return parse_mutable_case_mapping(document)


def merge_policy_mappings(
    existing: Mapping[str, Any],
    patch: Mapping[str, Any],
    *,
    overwrite: bool = True,
    list_merge_keys: frozenset[str] = DEFAULT_LIST_MERGE_KEYS,
) -> JsonDict:
    """Merge one policy mapping into another."""
    merged: JsonDict = thaw_jsonable(existing)
    for raw_key, patch_value in patch.items():
        key = str(raw_key)
        if not overwrite and key in merged:
            continue
        existing_value = merged.get(key)
        if isinstance(existing_value, Mapping) and isinstance(patch_value, Mapping):
            merged[key] = merge_policy_mappings(
                existing_value,
                patch_value,
                overwrite=overwrite,
                list_merge_keys=list_merge_keys,
            )
        elif key in list_merge_keys:
            merged[key] = list(
                dedupe_strings(
                    [
                        *coerce_string_sequence(existing_value),
                        *coerce_string_sequence(patch_value),
                    ]
                )
            )
        else:
            merged[key] = thaw_jsonable(patch_value)
    return merged


def with_tool_policy_defaults(case: TestCase, defaults: ToolPolicyPatch) -> TestCase:
    """Apply tool-policy defaults without overwriting explicitly configured values."""
    return patch_case_tool_policies(case, defaults, overwrite=False)


def with_tool_policy_updates(case: TestCase, updates: ToolPolicyPatch) -> TestCase:
    """Apply tool-policy updates, overwriting scalar settings but merging lists."""
    return patch_case_tool_policies(case, updates, overwrite=True)


def add_sensitive_denied_paths_patch(
    case: TestCase,
    *,
    tool_names: Iterable[str],
) -> dict[str, JsonDict]:
    """Return policy patches that deny access to sensitive file paths."""
    paths = sensitive_file_paths(case)
    if not paths:
        return {}
    return {normalize_policy_name(tool): {"denied_paths": list(paths)} for tool in tool_names}


def forbidden_patterns(case: TestCase) -> tuple[str, ...]:
    """Return exact forbidden strings configured in no-secret-leak checkers."""
    patterns: list[str] = []
    for checker in case.checkers:
        checker_type = enum_value(checker.type)
        if checker_type == FORBIDDEN_PATTERN_CHECKER_TYPE:
            patterns.extend(checker.forbidden_patterns or [])
    return dedupe_strings(patterns)


def sensitive_file_paths(case: TestCase) -> tuple[str, ...]:
    """Return sensitive file paths from a parsed case."""
    paths: list[str] = []
    for path in getattr(case, "sensitive_file_paths", ()):
        paths.append(validate_case_relative_path(path, field_name="sensitive file path"))
    return dedupe_strings(paths)


def untrusted_source_labels(case: TestCase) -> tuple[str, ...]:
    """Return expected coarse taint labels for untrusted case content."""
    labels: list[str] = []
    for file_spec in case.environment.files:
        if enum_value(file_spec.trust_level) == UNTRUSTED_TRUST_LEVEL:
            labels.extend((f"source:file:{file_spec.path}", f"trust:{UNTRUSTED_TRUST_LEVEL}"))
    for email_spec in case.environment.inbox:
        if enum_value(email_spec.trust_level) == UNTRUSTED_TRUST_LEVEL:
            labels.extend((f"source:email:{email_spec.sender}", f"trust:{UNTRUSTED_TRUST_LEVEL}"))
    for key, value in case.environment.memory.items():
        if (
            isinstance(value, Mapping)
            and enum_value(value.get("trust_level")) == UNTRUSTED_TRUST_LEVEL
        ):
            labels.extend((f"source:memory:{key}", f"trust:{UNTRUSTED_TRUST_LEVEL}"))
    return dedupe_strings(labels)


def has_allowed_tool(case: TestCase, tool_name: str) -> bool:
    """Return whether a case exposes ``tool_name`` to the agent."""
    normalized = normalize_policy_name(tool_name)
    return normalized in {normalize_policy_name(tool) for tool in case.tools.allowed}


def normalize_policy_name(value: str) -> str:
    """Normalize a tool/policy identifier."""
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def enum_value(value: Any) -> str:
    """Return enum value or normalized string representation."""
    return str(getattr(value, "value", value)).strip()


def ensure_mapping(value: Any, *, field_name: str) -> MutableMapping[str, Any]:
    """Return ``value`` as a mutable mapping or raise."""
    if not isinstance(value, MutableMapping):
        if isinstance(value, Mapping):
            return {str(key): item for key, item in value.items()}
        raise MitigationApplicationError(f"{field_name} must be a mapping")
    return value


def ensure_mutable_mapping(value: Any, *, field_name: str) -> JsonDict:
    """Return a mutable copy of a policy mapping."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise MitigationApplicationError(f"{field_name} must be a mapping")
    return {str(key): thaw_jsonable(item) for key, item in value.items()}


def coerce_string_sequence(value: Any) -> tuple[str, ...]:
    """Normalize scalar/iterable string-like values into a tuple."""
    if value is None:
        return ()
    if isinstance(value, str):
        return dedupe_strings((value,))
    if isinstance(value, Sequence) and not isinstance(value, bytes):
        return dedupe_strings(str(item) for item in value)
    return dedupe_strings((str(value),))


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


def first_forbidden_match(text: str, patterns: Iterable[str]) -> str | None:
    """Return the first exact forbidden pattern contained in ``text``."""
    haystack = str(text)
    if not haystack:
        return None
    for pattern in patterns:
        token = str(pattern)
        if token and token in haystack:
            return token
    return None


def forbidden_matches(text: str, patterns: Iterable[str]) -> tuple[str, ...]:
    """Return all exact forbidden patterns contained in ``text``."""
    haystack = str(text)
    return dedupe_strings(pattern for pattern in patterns if pattern and pattern in haystack)


def freeze_jsonable_mapping(value: Mapping[str, Any]) -> JsonMapping:
    """Return a JSON-like mapping with recursively thawed simple containers."""
    return MappingProxyType({str(key): freeze_jsonable(item) for key, item in value.items()})


def freeze_jsonable(value: Any) -> Any:
    """Recursively freeze mappings and sequences into immutable containers."""
    if isinstance(value, Mapping):
        return freeze_jsonable_mapping(value)
    if isinstance(value, tuple | list | set | frozenset):
        return tuple(freeze_jsonable(item) for item in value)
    return value


def thaw_jsonable(value: Any) -> Any:
    """Return a JSON-serializable mutable representation."""
    if isinstance(value, Mapping):
        return {str(key): thaw_jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [thaw_jsonable(item) for item in value]
    if hasattr(value, "value") and not isinstance(value, str):
        return getattr(value, "value")
    return value


__all__: Final[tuple[str, ...]] = tuple(
    name
    for name in globals()
    if not name.startswith("_")
    and name
    not in {
        "annotations",
        "Any",
        "Final",
        "Iterable",
        "Mapping",
        "MutableMapping",
        "Sequence",
        "Protocol",
        "TypeAlias",
        "dataclass",
        "field",
        "is_dataclass",
        "replace",
        "MappingProxyType",
        "runtime_checkable",
    }
)
