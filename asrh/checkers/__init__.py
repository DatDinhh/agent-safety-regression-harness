"""Deterministic checker package for ASRH.

The checkers implement the assertion layer described in the ASRH technical
specification: exact secret-leak detection, sensitive-access detection,
forbidden-tool detection, task-completion evidence, instruction hierarchy,
coarse data-flow, and over-refusal.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Final

from asrh.cases.schema import CheckerSpec, TestCase
from asrh.checkers.base import *  # noqa: F403 - package re-export surface is intentional.
from asrh.checkers.base import CheckerRegistry, CheckerRunResult, CheckResult, TraceLike, results_to_dicts, run_checkers as _run_checkers_with_registry
from asrh.checkers.data_flow import DataFlowChecker, FlowChecker, NoSensitiveFileAccessChecker, NoUnsafeDataFlowChecker, SensitiveAccessChecker, SensitiveDataFlowChecker, SensitiveFileAccessChecker, SourceToSinkChecker
from asrh.checkers.instruction_hierarchy import HierarchyChecker, InstructionConflictChecker, InstructionHierarchyChecker, SystemPromptLeakChecker, UntrustedInstructionChecker
from asrh.checkers.over_refusal import DEFAULT_REFUSAL_PATTERNS, DEFAULT_REFUSAL_PHRASES, NoOverRefusalChecker, OverRefusalChecker, RefusalChecker
from asrh.checkers.secret_leak import NoForbiddenPatternChecker, NoSecretLeakChecker, SecretLeakChecker
from asrh.checkers.task_completion import CompletionChecker, RequiredEvidenceChecker, TaskCompletionChecker, UtilityChecker
from asrh.checkers.tool_policy import ForbiddenToolCallChecker, NoForbiddenToolCallChecker, NoSensitiveFileAccessChecker as _ToolPolicySensitiveAlias, NoUnsafeToolCallChecker, SensitiveFileAccessChecker as _ToolPolicySensitiveFileAlias, ToolMinimalityChecker, UnauthorizedToolCallChecker

CHECKER_PACKAGE_NAME: Final[str] = "asrh.checkers"
DEFAULT_CHECKER_REGISTRY_NAMES: Final[tuple[str, ...]] = (
    CHECKER_NO_SECRET_LEAK,
    CHECKER_NO_SENSITIVE_FILE_ACCESS,
    CHECKER_NO_FORBIDDEN_TOOL_CALL,
    CHECKER_TASK_COMPLETION,
    CHECKER_INSTRUCTION_HIERARCHY,
    CHECKER_OVER_REFUSAL,
    CHECKER_TOOL_MINIMALITY,
    CHECKER_DATA_FLOW,
)


def get_default_checker_registry() -> CheckerRegistry:
    """Return a fresh default checker registry."""
    registry = CheckerRegistry()
    registry.register(CHECKER_NO_SECRET_LEAK, NoSecretLeakChecker)
    registry.register(CHECKER_NO_SENSITIVE_FILE_ACCESS, NoSensitiveFileAccessChecker)
    registry.register(CHECKER_NO_FORBIDDEN_TOOL_CALL, NoForbiddenToolCallChecker)
    registry.register(CHECKER_TASK_COMPLETION, TaskCompletionChecker)
    registry.register(CHECKER_INSTRUCTION_HIERARCHY, InstructionHierarchyChecker)
    registry.register(CHECKER_OVER_REFUSAL, OverRefusalChecker)
    registry.register(CHECKER_TOOL_MINIMALITY, ToolMinimalityChecker)
    registry.register(CHECKER_DATA_FLOW, DataFlowChecker)
    return registry


build_default_checker_registry = get_default_checker_registry
default_checker_registry = get_default_checker_registry


def build_checker(spec: CheckerSpec | dict[str, Any] | str):
    """Build one checker from a checker spec, mapping, or checker type."""
    return get_default_checker_registry().create(spec)


def run_checkers(trace: TraceLike, case: TestCase, *, checker_specs: Iterable[CheckerSpec | dict[str, Any]] | None = None, registry: CheckerRegistry | None = None) -> CheckerRunResult:
    """Run configured checkers and return checker results plus verdict."""
    active_registry = registry or get_default_checker_registry()
    return _run_checkers_with_registry(trace, case, registry=active_registry, checker_specs=tuple(checker_specs or case.checkers))


def run_checkers_as_dicts(trace: TraceLike, case: TestCase, *, checker_specs: Iterable[CheckerSpec | dict[str, Any]] | None = None, registry: CheckerRegistry | None = None) -> list[dict[str, Any]]:
    """Run checkers and return JSONL-compatible checker dictionaries."""
    return results_to_dicts(run_checkers(trace, case, checker_specs=checker_specs, registry=registry).checker_results)


def evaluate_trace(trace: TraceLike, case: TestCase, *, checker_specs: Iterable[CheckerSpec | dict[str, Any]] | None = None, registry: CheckerRegistry | None = None) -> tuple[tuple[CheckResult, ...], dict[str, Any]]:
    """Run checkers and return ``(results, verdict)``."""
    result = run_checkers(trace, case, checker_specs=checker_specs, registry=registry)
    return result.checker_results, dict(result.verdict)


def evaluate_trace_as_dict(trace: TraceLike, case: TestCase, *, checker_specs: Iterable[CheckerSpec | dict[str, Any]] | None = None, registry: CheckerRegistry | None = None) -> dict[str, Any]:
    """Return checker results and verdict fields as a JSONL-compatible mapping."""
    result = run_checkers(trace, case, checker_specs=checker_specs, registry=registry)
    verdict = dict(result.verdict)
    return {
        "checker_results": results_to_dicts(result.checker_results),
        "verdict": verdict,
        "utility_pass": bool(verdict.get("utility_pass")),
        "safety_pass": bool(verdict.get("safety_pass")),
        "attack_success": bool(verdict.get("attack_success")),
        "overall": str(verdict.get("overall")),
    }


def checker_registry_summary(registry: CheckerRegistry | None = None) -> dict[str, Any]:
    """Return registered checker types as a JSON-compatible summary."""
    return (registry or get_default_checker_registry()).to_dict()


__all__ = tuple(name for name in globals() if not name.startswith("_") and name != "annotations")
