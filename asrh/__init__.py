"""ASRH package root.

ASRH (Agent Safety Regression Harness) is a verification-style evaluation
framework for testing whether tool-using LLM agents preserve safety constraints
under adversarial conditions.

The package root is intentionally lightweight. It exposes stable project
metadata and shared MVP constants without importing CLI, provider, runner,
checker, or tool modules. Keeping import-time behavior minimal prevents optional
provider SDKs, API clients, filesystem setup, and logging configuration from
running when a user simply executes ``import asrh``.
"""

from __future__ import annotations

from importlib import metadata
from typing import Final

DISTRIBUTION_NAME: Final[str] = "agent-safety-regression-harness"
"""Installed distribution name declared in ``pyproject.toml``."""

PACKAGE_NAME: Final[str] = "asrh"
"""Python import package name."""

PROJECT_NAME: Final[str] = "ASRH"
"""Short project name used in CLI output, run metadata, and reports."""

PROJECT_TITLE: Final[str] = "Agent Safety Regression Harness"
"""Human-readable project title without the acronym prefix."""

PROJECT_FULL_TITLE: Final[str] = "ASRH: Agent Safety Regression Harness"
"""Human-readable project title with the acronym prefix."""

PROJECT_DESCRIPTION: Final[str] = (
    "Verification-style regression testing for tool-using LLM agents under "
    "adversarial conditions."
)
"""One-line project description used by package metadata and documentation."""

DEFAULT_VERSION: Final[str] = "0.1.0"
"""Fallback version used when imported from an uninstalled source tree."""

SPEC_VERSION: Final[str] = "0.1"
"""Technical specification version targeted by this package."""

CASE_SCHEMA_VERSION: Final[str] = "0.1"
"""Current YAML test-case schema version."""

TRACE_SCHEMA_VERSION: Final[str] = "0.1"
"""Current JSONL trace/result schema version."""

DEFAULT_MODEL: Final[str] = "mock/safe"
"""Default deterministic model for local smoke tests."""

DEFAULT_UNSAFE_MODEL: Final[str] = "mock/unsafe_leaker"
"""Default deterministic unsafe model for baseline-vs-guard demonstrations."""

DEFAULT_REAL_MODEL: Final[str] = "openai/gpt-4o-mini"
"""Default external model identifier used by documented MVP commands."""

DEFAULT_MITIGATION: Final[str] = "none"
"""Default mitigation mode for baseline runs."""

DEFAULT_GUARD: Final[str] = "tool_policy_guard"
"""Default code-enforced guard for comparison runs."""

DEFAULT_MAX_STEPS: Final[int] = 8
"""Default maximum number of agent loop steps per case."""

DEFAULT_MAX_TOOL_CALLS: Final[int] = 6
"""Default maximum number of tool calls per case."""

DEFAULT_MAX_TOKENS_PER_RESPONSE: Final[int] = 800
"""Default maximum output tokens per model response."""

DEFAULT_MAX_TOTAL_TOKENS: Final[int] = 6_000
"""Default total token budget per case."""

DEFAULT_TIMEOUT_SECONDS: Final[int] = 60
"""Default timeout per case run."""

DEFAULT_TEMPERATURE: Final[float] = 0.0
"""Default deterministic decoding temperature for provider-backed runs."""

SUPPORTED_AGENT_MODES: Final[tuple[str, ...]] = (
    "mock",
    "single_turn",
    "tool_agent",
)
"""Agent execution modes defined by the MVP specification."""

SUPPORTED_MOCK_MODES: Final[tuple[str, ...]] = (
    "safe",
    "unsafe_leaker",
    "tool_abuser",
    "refuser",
    "json_invalid",
    "looping",
)
"""Deterministic mock modes used for tests and report demos."""

SUPPORTED_MITIGATIONS: Final[tuple[str, ...]] = (
    "none",
    "system_prompt_guard",
    "tool_policy_guard",
    "taint_tracking_guard",
    "human_approval_guard",
)
"""Mitigation modes in the MVP contract."""

SUPPORTED_TOOLS: Final[tuple[str, ...]] = (
    "list_files",
    "read_file",
    "write_file",
    "send_email",
    "run_shell",
)
"""Required MVP tools. All are simulated unless explicitly marked sandbox-safe."""

SUPPORTED_SUITES: Final[tuple[str, ...]] = (
    "prompt_injection",
    "secret_exfiltration",
    "tool_misuse",
    "instruction_conflict",
    "reward_hacking",
)
"""MVP test suites expected under the repository's ``suites/`` directory."""

SUPPORTED_CHECKER_TYPES: Final[tuple[str, ...]] = (
    "no_secret_leak",
    "no_sensitive_file_access",
    "no_forbidden_tool_call",
    "task_completion",
    "instruction_hierarchy",
    "over_refusal",
    "tool_minimality",
    "data_flow",
)
"""Checker identifiers accepted by YAML cases and checker registries."""

TRUST_LEVELS: Final[tuple[str, ...]] = (
    "trusted",
    "untrusted",
    "sensitive",
)
"""Trust labels for files, emails, memory, and tool outputs."""

SEVERITY_LEVELS: Final[tuple[str, ...]] = (
    "low",
    "medium",
    "high",
    "critical",
)
"""Ordered severity labels used by cases, checker results, and reports."""

VERDICTS: Final[tuple[str, ...]] = (
    "PASS",
    "UNSAFE_SUCCESS",
    "SAFE_BUT_USELESS",
    "FAIL",
)
"""Per-case verdict labels produced by the runner."""

FAILURE_CLASSES: Final[tuple[str, ...]] = (
    "SECRET_LEAK_FINAL",
    "SECRET_LEAK_TOOL_ARG",
    "SENSITIVE_ACCESS",
    "UNAUTHORIZED_TOOL_CALL",
    "UNTRUSTED_INSTRUCTION_FOLLOWED",
    "SYSTEM_PROMPT_LEAK",
    "TASK_FAILURE",
    "OVER_REFUSAL",
    "POLICY_BYPASS_ATTEMPT",
    "CHECKER_GAMING",
    "TOOL_MINIMALITY_VIOLATION",
)
"""Failure taxonomy labels used by checkers and Markdown reports."""

SIDE_EFFECT_GATES: Final[tuple[str, ...]] = (
    "ASRH_ALLOW_REAL_SHELL",
    "ASRH_ALLOW_REAL_EMAIL",
    "ASRH_ALLOW_REAL_NETWORK",
)
"""Environment gates that must stay false unless a non-MVP tool is explicitly enabled."""

__title__: Final[str] = PROJECT_FULL_TITLE
__description__: Final[str] = PROJECT_DESCRIPTION
__author__: Final[str] = "Dat Dinh"
__license__: Final[str] = "MIT"


def _read_installed_version() -> str:
    """Return the installed distribution version, with a source-tree fallback."""
    try:
        return metadata.version(DISTRIBUTION_NAME)
    except metadata.PackageNotFoundError:
        return DEFAULT_VERSION


def _version_tuple(version: str) -> tuple[int, ...]:
    """Parse the numeric release prefix of a PEP 440-like version string.

    Examples:
        ``"0.1.0"`` -> ``(0, 1, 0)``
        ``"1.2.3.dev4"`` -> ``(1, 2, 3)``
    """
    release = version.split("+", 1)[0].split("-", 1)[0]
    parts: list[int] = []

    for token in release.split("."):
        numeric_prefix = ""
        for character in token:
            if not character.isdigit():
                break
            numeric_prefix += character
        if not numeric_prefix:
            break
        parts.append(int(numeric_prefix))

    return tuple(parts)


__version__: Final[str] = _read_installed_version()
"""Installed ASRH version, falling back to ``DEFAULT_VERSION`` in source-tree imports."""

__version_tuple__: Final[tuple[int, ...]] = _version_tuple(__version__)
"""Numeric tuple parsed from ``__version__`` for simple version comparisons."""


def get_version() -> str:
    """Return the ASRH package version.

    CLI and report modules can use this helper without depending directly on
    ``importlib.metadata``.
    """
    return __version__


__all__: Final[tuple[str, ...]] = (
    "CASE_SCHEMA_VERSION",
    "DEFAULT_GUARD",
    "DEFAULT_MAX_STEPS",
    "DEFAULT_MAX_TOKENS_PER_RESPONSE",
    "DEFAULT_MAX_TOOL_CALLS",
    "DEFAULT_MAX_TOTAL_TOKENS",
    "DEFAULT_MITIGATION",
    "DEFAULT_MODEL",
    "DEFAULT_REAL_MODEL",
    "DEFAULT_TEMPERATURE",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_UNSAFE_MODEL",
    "DEFAULT_VERSION",
    "DISTRIBUTION_NAME",
    "FAILURE_CLASSES",
    "PACKAGE_NAME",
    "PROJECT_DESCRIPTION",
    "PROJECT_FULL_TITLE",
    "PROJECT_NAME",
    "PROJECT_TITLE",
    "SEVERITY_LEVELS",
    "SIDE_EFFECT_GATES",
    "SPEC_VERSION",
    "SUPPORTED_AGENT_MODES",
    "SUPPORTED_CHECKER_TYPES",
    "SUPPORTED_MITIGATIONS",
    "SUPPORTED_MOCK_MODES",
    "SUPPORTED_SUITES",
    "SUPPORTED_TOOLS",
    "TRACE_SCHEMA_VERSION",
    "TRUST_LEVELS",
    "VERDICTS",
    "__author__",
    "__description__",
    "__license__",
    "__title__",
    "__version__",
    "__version_tuple__",
    "get_version",
)
