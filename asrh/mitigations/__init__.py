"""ASRH mitigation strategies.

This package exposes the public mitigation registry used by future runner code
and report metadata. Strategies are deterministic: they transform case policy,
select prompt variants, build sandbox/tool-registry objects, and optionally scan
final answers. They do not call models and do not perform real side effects.
"""

from __future__ import annotations

from typing import Any, Final

from asrh.cases.schema import TestCase
from asrh.envs.sandbox import SandboxEnv
from asrh.mitigations.base import (
    MITIGATION_HUMAN_APPROVAL_GUARD,
    MITIGATION_NONE,
    MITIGATION_SYSTEM_PROMPT_GUARD,
    MITIGATION_TAINT_TRACKING_GUARD,
    MITIGATION_TOOL_POLICY_GUARD,
    BaseMitigationStrategy,
    FinalAnswerScanResult,
    MitigationApplication,
    MitigationApplicationError,
    MitigationCapability,
    MitigationConfigurationError,
    MitigationContext,
    MitigationDecision,
    MitigationError,
    MitigationName,
    MitigationPromptVariant,
    MitigationRegistry,
    MitigationStrategy,
    canonicalize_mitigation_name,
    is_supported_mitigation,
    normalize_mitigation_name,
)
from asrh.mitigations.human_approval_guard import (
    HUMAN_APPROVAL_GUARD,
    HumanApprovalGuard,
    HumanApprovalGuardStrategy,
)
from asrh.mitigations.none import NONE_MITIGATION, NoMitigation, NoMitigationStrategy
from asrh.mitigations.system_prompt_guard import (
    SYSTEM_PROMPT_GUARD,
    SystemPromptGuard,
    SystemPromptGuardStrategy,
)
from asrh.mitigations.taint_tracking_guard import (
    TAINT_TRACKING_GUARD,
    TaintTrackingGuard,
    TaintTrackingGuardStrategy,
)
from asrh.mitigations.tool_policy_guard import (
    TOOL_POLICY_GUARD,
    ToolPolicyGuard,
    ToolPolicyGuardStrategy,
)
from asrh.tools.registry import ToolRegistry

DEFAULT_MITIGATION_REGISTRY: Final[MitigationRegistry] = MitigationRegistry(
    (
        NONE_MITIGATION,
        SYSTEM_PROMPT_GUARD,
        TOOL_POLICY_GUARD,
        TAINT_TRACKING_GUARD,
        HUMAN_APPROVAL_GUARD,
    )
)
"""Immutable registry containing all MVP mitigation strategies."""

MITIGATION_STRATEGIES: Final[dict[str, MitigationStrategy]] = {
    name: DEFAULT_MITIGATION_REGISTRY.get(name) for name in DEFAULT_MITIGATION_REGISTRY.names
}
"""Convenience mapping of canonical mitigation name to singleton strategy."""

DEFAULT_STRATEGY: Final[MitigationStrategy] = NONE_MITIGATION
"""Default baseline mitigation strategy."""


def get_mitigation_strategy(name: str | None = None) -> MitigationStrategy:
    """Return a mitigation strategy by canonical name or alias."""
    return DEFAULT_MITIGATION_REGISTRY.get(name)


resolve_mitigation = get_mitigation_strategy
strategy_for_mitigation = get_mitigation_strategy


def list_mitigation_names() -> tuple[str, ...]:
    """Return canonical mitigation names in stable spec order."""
    return DEFAULT_MITIGATION_REGISTRY.names


def list_mitigation_strategies() -> tuple[MitigationStrategy, ...]:
    """Return mitigation strategies in stable spec order."""
    return tuple(
        DEFAULT_MITIGATION_REGISTRY.get(name)
        for name in DEFAULT_MITIGATION_REGISTRY.names
    )


def apply_mitigation_to_case(case: TestCase, mitigation: str | None = None) -> TestCase:
    """Return ``case`` transformed by ``mitigation``."""
    return get_mitigation_strategy(mitigation).apply_case(case)


mitigate_case = apply_mitigation_to_case
build_mitigated_case = apply_mitigation_to_case


def apply_mitigation(case: TestCase, mitigation: str | None = None) -> MitigationApplication:
    """Apply ``mitigation`` and return a structured application summary."""
    return get_mitigation_strategy(mitigation).apply(case)


def apply_mitigation_to_config(config: Any, mitigation: str | None = None) -> Any:
    """Return an agent config or config mapping with mitigation metadata applied."""
    return get_mitigation_strategy(mitigation).apply_agent_config(config)


def build_mitigated_sandbox(case: TestCase, mitigation: str | None = None) -> SandboxEnv:
    """Build a sandbox for a mitigated case."""
    return get_mitigation_strategy(mitigation).build_sandbox(case)


def build_mitigated_tool_registry(
    case: TestCase,
    mitigation: str | None = None,
    *,
    strict: bool = False,
) -> ToolRegistry:
    """Build a case-filtered tool registry after mitigation application."""
    return get_mitigation_strategy(mitigation).build_tool_registry(case, strict=strict)


def mitigation_extra_system_instructions(
    mitigation: str | None = None,
    case: TestCase | None = None,
) -> tuple[str, ...]:
    """Return optional extra prompt instructions for a mitigation."""
    return get_mitigation_strategy(mitigation).extra_system_instructions(case)


def mitigation_prompt_variant(mitigation: str | None = None) -> str:
    """Return ``baseline`` or ``guarded`` for the mitigation."""
    return get_mitigation_strategy(mitigation).prompt_variant


def scan_final_answer_with_mitigation(
    final_answer: str,
    case: TestCase,
    mitigation: str | None = None,
) -> FinalAnswerScanResult:
    """Run the mitigation-level final-answer scan."""
    return get_mitigation_strategy(mitigation).scan_final_answer(final_answer, case)


def mitigation_registry_summary() -> dict[str, Any]:
    """Return JSON-serializable mitigation registry metadata."""
    return DEFAULT_MITIGATION_REGISTRY.to_dict()


__all__: Final[tuple[str, ...]] = (
    "DEFAULT_MITIGATION_REGISTRY",
    "DEFAULT_STRATEGY",
    "HUMAN_APPROVAL_GUARD",
    "MITIGATION_HUMAN_APPROVAL_GUARD",
    "MITIGATION_NONE",
    "MITIGATION_STRATEGIES",
    "MITIGATION_SYSTEM_PROMPT_GUARD",
    "MITIGATION_TAINT_TRACKING_GUARD",
    "MITIGATION_TOOL_POLICY_GUARD",
    "NONE_MITIGATION",
    "SYSTEM_PROMPT_GUARD",
    "TAINT_TRACKING_GUARD",
    "TOOL_POLICY_GUARD",
    "BaseMitigationStrategy",
    "FinalAnswerScanResult",
    "HumanApprovalGuard",
    "HumanApprovalGuardStrategy",
    "MitigationApplication",
    "MitigationApplicationError",
    "MitigationCapability",
    "MitigationConfigurationError",
    "MitigationContext",
    "MitigationDecision",
    "MitigationError",
    "MitigationName",
    "MitigationPromptVariant",
    "MitigationRegistry",
    "MitigationStrategy",
    "NoMitigation",
    "NoMitigationStrategy",
    "SystemPromptGuard",
    "SystemPromptGuardStrategy",
    "TaintTrackingGuard",
    "TaintTrackingGuardStrategy",
    "ToolPolicyGuard",
    "ToolPolicyGuardStrategy",
    "apply_mitigation",
    "apply_mitigation_to_case",
    "apply_mitigation_to_config",
    "build_mitigated_case",
    "build_mitigated_sandbox",
    "build_mitigated_tool_registry",
    "canonicalize_mitigation_name",
    "get_mitigation_strategy",
    "is_supported_mitigation",
    "list_mitigation_names",
    "list_mitigation_strategies",
    "mitigate_case",
    "mitigation_extra_system_instructions",
    "mitigation_prompt_variant",
    "mitigation_registry_summary",
    "normalize_mitigation_name",
    "resolve_mitigation",
    "scan_final_answer_with_mitigation",
    "strategy_for_mitigation",
)
