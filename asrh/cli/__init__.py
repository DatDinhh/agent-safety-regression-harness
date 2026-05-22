"""Command-line interface package for ASRH.

The CLI layer exposes the console entry points declared in ``pyproject.toml``:

- ``asrh`` for the root command group;
- ``asrh-run`` for running one case or suite;
- ``asrh-report`` for generating Markdown reports;
- ``asrh-list-cases`` for inspecting YAML case inventories;
- ``asrh-validate-cases`` for schema validation.

This package initializer is intentionally lightweight. It defines shared CLI
constants, defaults, exit codes, and small helper utilities, but it does not
import command modules such as ``asrh.cli.run`` or ``asrh.cli.report``. Avoiding
those imports keeps ``import asrh.cli`` side-effect-free and prevents optional
provider clients, filesystem checks, or Typer/Rich application construction from
running before a specific command is invoked.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import MappingProxyType
from typing import Final

from asrh import (
    DEFAULT_GUARD,
    DEFAULT_MAX_STEPS,
    DEFAULT_MAX_TOKENS_PER_RESPONSE,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TOTAL_TOKENS,
    DEFAULT_MITIGATION,
    DEFAULT_MODEL,
    DEFAULT_REAL_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_UNSAFE_MODEL,
    PROJECT_DESCRIPTION,
    PROJECT_FULL_TITLE,
    PROJECT_NAME,
    get_version,
)

CLI_PACKAGE_NAME: Final[str] = "asrh.cli"
"""Python package containing ASRH command modules."""

ROOT_COMMAND_NAME: Final[str] = "asrh"
"""Primary console script name for the root command group."""

RUN_COMMAND_NAME: Final[str] = "run"
"""Subcommand name for executing cases or suites."""

REPORT_COMMAND_NAME: Final[str] = "report"
"""Subcommand name for generating single-run and comparison reports."""

LIST_CASES_COMMAND_NAME: Final[str] = "list-cases"
"""Subcommand name for listing discovered YAML cases."""

VALIDATE_CASES_COMMAND_NAME: Final[str] = "validate-cases"
"""Subcommand name for validating YAML cases against the schema."""

SUBCOMMAND_NAMES: Final[tuple[str, ...]] = (
    RUN_COMMAND_NAME,
    REPORT_COMMAND_NAME,
    LIST_CASES_COMMAND_NAME,
    VALIDATE_CASES_COMMAND_NAME,
)
"""Root CLI subcommands expected by the MVP contract."""

COMMAND_MODULES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "main": "asrh.cli.main",
        RUN_COMMAND_NAME: "asrh.cli.run",
        REPORT_COMMAND_NAME: "asrh.cli.report",
        LIST_CASES_COMMAND_NAME: "asrh.cli.list_cases",
        VALIDATE_CASES_COMMAND_NAME: "asrh.cli.validate_cases",
    }
)
"""Mapping from public command names to importable command modules."""

CONSOLE_SCRIPTS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "asrh": "asrh.cli.main:app",
        "asrh-run": "asrh.cli.run:app",
        "asrh-report": "asrh.cli.report:app",
        "asrh-list-cases": "asrh.cli.list_cases:app",
        "asrh-validate-cases": "asrh.cli.validate_cases:app",
    }
)
"""Console script targets mirrored from ``pyproject.toml``."""

COMMAND_HELP: Final[Mapping[str, str]] = MappingProxyType(
    {
        RUN_COMMAND_NAME: "Run one YAML case or suite and write JSONL traces.",
        REPORT_COMMAND_NAME: "Generate Markdown reports from JSONL run traces.",
        LIST_CASES_COMMAND_NAME: "List discovered YAML cases and suite counts.",
        VALIDATE_CASES_COMMAND_NAME: "Validate YAML cases against the active schema.",
    }
)
"""Short help text for root-command registration."""

DEFAULT_SUITE_DIR: Final[Path] = Path("suites")
"""Default directory containing YAML case suites."""

DEFAULT_RUN_DIR: Final[Path] = Path("runs")
"""Default directory for generated JSONL traces."""

DEFAULT_REPORT_DIR: Final[Path] = Path("reports")
"""Default directory for generated Markdown reports."""

DEFAULT_OUTPUT_ENCODING: Final[str] = "utf-8"
"""Encoding for CLI-created text files."""

DEFAULT_JSONL_SUFFIX: Final[str] = ".jsonl"
"""Expected suffix for run trace files."""

DEFAULT_MARKDOWN_SUFFIX: Final[str] = ".md"
"""Expected suffix for generated reports."""

PROVIDER_KEY_ENV_VARS: Final[tuple[str, ...]] = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)
"""Provider credential variables recognized by provider-backed commands."""

SAFETY_GATE_ENV_VARS: Final[tuple[str, ...]] = (
    "ASRH_ALLOW_REAL_SHELL",
    "ASRH_ALLOW_REAL_EMAIL",
    "ASRH_ALLOW_REAL_NETWORK",
    "ASRH_ALLOW_REAL_CREDENTIALS",
    "ASRH_ALLOW_BROWSER_AUTOMATION",
)
"""Environment gates that must remain false for MVP simulated-tool behavior."""

RUN_CONFIG_ENV_VARS: Final[tuple[str, ...]] = (
    "ASRH_DEFAULT_MODEL",
    "ASRH_DEFAULT_UNSAFE_MODEL",
    "ASRH_DEFAULT_REAL_MODEL",
    "ASRH_DEFAULT_MITIGATION",
    "ASRH_GUARD_MITIGATION",
    "ASRH_SUITE_DIR",
    "ASRH_RUN_DIR",
    "ASRH_REPORT_DIR",
    "ASRH_TEMPERATURE",
    "ASRH_SEED",
    "ASRH_MAX_STEPS",
    "ASRH_MAX_TOOL_CALLS",
    "ASRH_MAX_TOKENS_PER_RESPONSE",
    "ASRH_MAX_TOTAL_TOKENS",
    "ASRH_TIMEOUT_SECONDS",
    "ASRH_FAIL_FAST",
)
"""Environment variables used by run and report commands."""


class ExitCode(IntEnum):
    """Stable process exit codes for ASRH CLI commands.

    The values are deliberately small and conventional where possible. Typer and
    Click commonly use ``2`` for usage errors, while ``0`` indicates success.
    """

    OK = 0
    USAGE = 2
    VALIDATION_ERROR = 3
    CONFIG_ERROR = 4
    RUNTIME_ERROR = 5
    PROVIDER_ERROR = 6
    SAFETY_GATE_ERROR = 7
    INTERNAL_ERROR = 70


@dataclass(frozen=True, slots=True)
class CliDefaults:
    """Default CLI configuration shared across command modules."""

    model: str = DEFAULT_MODEL
    unsafe_model: str = DEFAULT_UNSAFE_MODEL
    real_model: str = DEFAULT_REAL_MODEL
    mitigation: str = DEFAULT_MITIGATION
    guard_mitigation: str = DEFAULT_GUARD
    suite_dir: Path = DEFAULT_SUITE_DIR
    run_dir: Path = DEFAULT_RUN_DIR
    report_dir: Path = DEFAULT_REPORT_DIR
    temperature: float = DEFAULT_TEMPERATURE
    max_steps: int = DEFAULT_MAX_STEPS
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS
    max_tokens_per_response: int = DEFAULT_MAX_TOKENS_PER_RESPONSE
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


DEFAULTS: Final[CliDefaults] = CliDefaults()
"""Immutable CLI default configuration."""


class CliError(RuntimeError):
    """Base exception for CLI-facing errors.

    Command modules should raise ``CliError`` for errors that should be reported
    as user-facing command failures rather than Python tracebacks. The root
    command can map ``exit_code`` to ``typer.Exit`` or ``SystemExit``.
    """

    def __init__(self, message: str, *, exit_code: ExitCode = ExitCode.RUNTIME_ERROR) -> None:
        super().__init__(message)
        self.exit_code: Final[ExitCode] = exit_code


class UsageError(CliError):
    """Raised when command-line arguments are incomplete or inconsistent."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=ExitCode.USAGE)


class ValidationCliError(CliError):
    """Raised when YAML cases, traces, or reports fail validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=ExitCode.VALIDATION_ERROR)


class SafetyGateError(CliError):
    """Raised when a command attempts to bypass MVP side-effect gates."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=ExitCode.SAFETY_GATE_ERROR)


def normalize_command_name(command: str) -> str:
    """Normalize a command token for lookup.

    Both ``list_cases`` and ``list-cases`` resolve to ``list-cases`` so that
    internal Python names and public CLI names can share one registry.
    """
    return command.strip().lower().replace("_", "-")


def get_command_module(command: str) -> str:
    """Return the import path for a CLI command module.

    Raises:
        UsageError: If ``command`` is not part of the CLI contract.
    """
    normalized = normalize_command_name(command)
    module = COMMAND_MODULES.get(normalized)
    if module is not None:
        return module

    available = ", ".join(SUBCOMMAND_NAMES)
    raise UsageError(f"Unknown ASRH command '{command}'. Available commands: {available}.")


def iter_subcommand_names() -> tuple[str, ...]:
    """Return public root-command subcommand names in display order."""
    return SUBCOMMAND_NAMES


def build_version_banner() -> str:
    """Return a concise CLI version banner."""
    return f"{PROJECT_NAME} {get_version()} — {PROJECT_DESCRIPTION}"


def build_full_title_banner() -> str:
    """Return a full CLI title banner for help screens and reports."""
    return f"{PROJECT_FULL_TITLE} v{get_version()}"


__all__: Final[tuple[str, ...]] = (
    "CLI_PACKAGE_NAME",
    "COMMAND_HELP",
    "COMMAND_MODULES",
    "CONSOLE_SCRIPTS",
    "DEFAULTS",
    "DEFAULT_JSONL_SUFFIX",
    "DEFAULT_MARKDOWN_SUFFIX",
    "DEFAULT_OUTPUT_ENCODING",
    "DEFAULT_REPORT_DIR",
    "DEFAULT_RUN_DIR",
    "DEFAULT_SUITE_DIR",
    "ExitCode",
    "LIST_CASES_COMMAND_NAME",
    "PROVIDER_KEY_ENV_VARS",
    "REPORT_COMMAND_NAME",
    "ROOT_COMMAND_NAME",
    "RUN_COMMAND_NAME",
    "RUN_CONFIG_ENV_VARS",
    "SAFETY_GATE_ENV_VARS",
    "SUBCOMMAND_NAMES",
    "VALIDATE_CASES_COMMAND_NAME",
    "CliDefaults",
    "CliError",
    "SafetyGateError",
    "UsageError",
    "ValidationCliError",
    "build_full_title_banner",
    "build_version_banner",
    "get_command_module",
    "iter_subcommand_names",
    "normalize_command_name",
)
