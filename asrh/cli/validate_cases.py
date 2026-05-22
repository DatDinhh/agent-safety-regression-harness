"""Case-validation command for ASRH.

This module owns the public ``asrh-validate-cases`` console entry point and the
``python -m asrh.cli.validate_cases`` execution path. It validates YAML cases
against the MVP schema and safety-infrastructure expectations from the ASRH
technical specification.

The validator is intentionally implemented in the CLI layer for the skeleton
phase. When ``asrh.cases.schema`` and ``asrh.cases.validator`` are implemented,
this command can delegate to those modules without changing the public command
contract.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, NoReturn

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from asrh import (
    CASE_SCHEMA_VERSION,
    SEVERITY_LEVELS,
    SUPPORTED_CHECKER_TYPES,
    SUPPORTED_SUITES,
    SUPPORTED_TOOLS,
    TRUST_LEVELS,
)
from asrh.cli import (
    DEFAULTS,
    DEFAULT_OUTPUT_ENCODING,
    ExitCode,
    UsageError,
    ValidationCliError,
    build_version_banner,
)

APP_NAME: Final[str] = "asrh-validate-cases"
APP_HELP: Final[str] = "Validate ASRH YAML cases against the active MVP schema."
APP_EPILOG: Final[str] = (
    "Examples:\n"
    "  python -m asrh.cli.validate_cases --suite suites\n"
    "  python -m asrh.cli.validate_cases --case suites/secret_exfiltration/case_001.yaml\n"
    "  python -m asrh.cli.validate_cases --suite suites --strict --fail-on-warnings"
)
DEFAULT_ENV_FILE: Final[Path] = Path(".env")
CASE_SUFFIXES: Final[frozenset[str]] = frozenset({".yaml", ".yml"})
CASE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*_[0-9]{3}$")
FILE_PATH_FORBIDDEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"(^/)|(^[A-Za-z]:)|(^|/)\.\.(/|$)")
UNKNOWN_VALUE: Final[str] = "unknown"

ATTACK_TYPES: Final[frozenset[str]] = frozenset(
    {
        "direct_prompt_injection",
        "indirect_prompt_injection",
        "data_exfiltration",
        "tool_misuse",
        "instruction_conflict",
        "reward_hacking",
    }
)
PAYLOAD_LOCATIONS: Final[frozenset[str]] = frozenset(
    {"user_prompt", "file", "email", "memory", "tool_output"}
)
EXPECTED_UTILITY_VALUES: Final[frozenset[str]] = frozenset({"pass", "fail", "unknown"})
EXPECTED_SAFETY_VALUES: Final[frozenset[str]] = frozenset({"pass", "fail"})
UTILITY_CHECKERS: Final[frozenset[str]] = frozenset({"task_completion", "over_refusal"})
SAFETY_CHECKERS: Final[frozenset[str]] = frozenset(
    {
        "no_secret_leak",
        "no_sensitive_file_access",
        "no_forbidden_tool_call",
        "instruction_hierarchy",
        "data_flow",
        "tool_minimality",
    }
)
OPTIONAL_NON_MVP_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "read_email",
        "list_email",
        "delete_file",
        "network_request",
    }
)

console: Final[Console] = Console(stderr=True)
stdout_console: Final[Console] = Console()


class FindingKind(StrEnum):
    """Severity of a validation finding."""

    ERROR = "error"
    WARNING = "warning"


AddFindingFn = Callable[[FindingKind, str, str], None]
"""Callback signature used by validation helpers to record findings."""


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    """One schema or quality finding."""

    kind: FindingKind
    path: str
    case_id: str
    field: str
    message: str


@dataclass(slots=True)
class CaseValidationResult:
    """Validation output for one case file."""

    path: str
    case_id: str
    category: str
    findings: list[ValidationFinding]

    @property
    def error_count(self) -> int:
        return sum(1 for finding in self.findings if finding.kind is FindingKind.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for finding in self.findings if finding.kind is FindingKind.WARNING)

    @property
    def passed(self) -> bool:
        return self.error_count == 0


@dataclass(frozen=True, slots=True)
class ValidationSummary:
    """Complete validation summary."""

    target: str
    case_count: int
    error_count: int
    warning_count: int
    categories: dict[str, int]
    suites: dict[str, int]
    results: tuple[CaseValidationResult, ...]


app = typer.Typer(
    name=APP_NAME,
    help=APP_HELP,
    epilog=APP_EPILOG,
    no_args_is_help=False,
    rich_markup_mode="rich",
    add_completion=False,
)


@app.command(help=APP_HELP, epilog=APP_EPILOG)
def validate_cases_command(
    case_path: Annotated[
        Path | None,
        typer.Option(
            "--case",
            dir_okay=False,
            file_okay=True,
            resolve_path=False,
            help="Validate one YAML case file. Mutually exclusive with --suite.",
        ),
    ] = None,
    suite_path: Annotated[
        Path | None,
        typer.Option(
            "--suite",
            dir_okay=True,
            file_okay=False,
            resolve_path=False,
            help="Validate a suite directory or the top-level suites directory. Defaults to suites/.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Treat custom categories/tools and quality warnings as schema errors where applicable.",
        ),
    ] = False,
    fail_on_warnings: Annotated[
        bool,
        typer.Option("--fail-on-warnings", help="Exit non-zero when warnings are present."),
    ] = False,
    require_mvp_suites: Annotated[
        bool,
        typer.Option("--require-mvp-suites", help="Require all five MVP suite directories to exist."),
    ] = False,
    include_hidden: Annotated[
        bool,
        typer.Option("--include-hidden", help="Include hidden directories and files in discovery."),
    ] = False,
    max_findings: Annotated[
        int | None,
        typer.Option("--max-findings", min=1, help="Maximum findings to show in human-readable output."),
    ] = None,
    env_file: Annotated[
        Path | None,
        typer.Option(
            "--env-file",
            dir_okay=False,
            file_okay=True,
            resolve_path=False,
            help="Optional .env file to load before resolving defaults.",
        ),
    ] = DEFAULT_ENV_FILE,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print machine-readable validation output to stdout."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress non-error output."),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Show Python tracebacks for internal/runtime errors."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option("--version", help="Print version information and exit."),
    ] = False,
) -> None:
    """Validate one ASRH case file or a directory of cases."""
    if version:
        stdout_console.print(build_version_banner())
        raise typer.Exit(code=int(ExitCode.OK))

    try:
        _load_env_file(env_file)
        target_path, case_files = _resolve_targets(
            case_path=case_path,
            suite_path=suite_path,
            include_hidden=include_hidden,
        )
        summary = validate_case_files(
            case_files=case_files,
            target_path=target_path,
            strict=strict,
            require_mvp_suites=require_mvp_suites,
        )

        if json_output:
            _print_json(_summary_to_mapping(summary))
        elif not quiet:
            _print_summary(summary, max_findings=max_findings)

        if summary.error_count > 0:
            raise typer.Exit(code=int(ExitCode.VALIDATION_ERROR))
        if fail_on_warnings and summary.warning_count > 0:
            raise typer.Exit(code=int(ExitCode.VALIDATION_ERROR))

        raise typer.Exit(code=int(ExitCode.OK))

    except typer.Exit:
        raise
    except (UsageError, ValidationCliError) as exc:
        _exit_with_cli_error(exc, json_output=json_output, debug=debug)
    except Exception as exc:  # noqa: BLE001 - CLI must convert uncaught errors to stable exits.
        if debug:
            raise
        _exit_with_internal_error(exc, json_output=json_output)


def validate_case_files(
    *,
    case_files: Sequence[Path],
    target_path: Path,
    strict: bool,
    require_mvp_suites: bool,
) -> ValidationSummary:
    """Validate discovered case files and compute aggregate summary."""
    results = [
        _validate_one_case(path=path, suite_root=target_path if target_path.is_dir() else None, strict=strict)
        for path in case_files
    ]

    _add_duplicate_id_findings(results)
    if require_mvp_suites and target_path.is_dir():
        _add_missing_mvp_suite_findings(results=results, target_path=target_path)

    categories = Counter(result.category for result in results)
    suites = Counter(_infer_suite(path=Path(result.path), root=target_path) for result in results)
    error_count = sum(result.error_count for result in results)
    warning_count = sum(result.warning_count for result in results)

    return ValidationSummary(
        target=target_path.as_posix(),
        case_count=len(results),
        error_count=error_count,
        warning_count=warning_count,
        categories=dict(sorted(categories.items())),
        suites=dict(sorted(suites.items())),
        results=tuple(results),
    )


def _resolve_targets(
    *, case_path: Path | None, suite_path: Path | None, include_hidden: bool
) -> tuple[Path, tuple[Path, ...]]:
    """Resolve target path and case-file list."""
    if case_path is not None and suite_path is not None:
        raise UsageError("--case and --suite are mutually exclusive.")

    if case_path is not None:
        path = case_path.expanduser()
        if not path.exists():
            raise UsageError(f"Case file does not exist: {path}")
        if not path.is_file():
            raise UsageError(f"--case must point to a YAML file, not a directory: {path}")
        if path.suffix.lower() not in CASE_SUFFIXES:
            raise UsageError(f"Case file must use one of these suffixes: {sorted(CASE_SUFFIXES)}. Got: {path}")
        return path, (path,)

    root = (suite_path or DEFAULTS.suite_dir).expanduser()
    if not root.exists():
        raise UsageError(f"Suite directory does not exist: {root}")
    if not root.is_dir():
        raise UsageError(f"--suite must point to a directory: {root}")

    case_files = _discover_case_files(root, include_hidden=include_hidden)
    if not case_files:
        raise UsageError(f"No YAML case files found under suite directory: {root}")
    return root, case_files


def _discover_case_files(root: Path, *, include_hidden: bool) -> tuple[Path, ...]:
    """Return sorted YAML files under ``root``."""
    candidates: list[Path] = []
    for suffix in CASE_SUFFIXES:
        candidates.extend(root.rglob(f"*{suffix}"))

    def usable(path: Path) -> bool:
        if not path.is_file():
            return False
        if include_hidden:
            return True
        return not any(part.startswith(".") for part in path.parts)

    return tuple(sorted((path for path in candidates if usable(path)), key=lambda item: item.as_posix()))


def _validate_one_case(*, path: Path, suite_root: Path | None, strict: bool) -> CaseValidationResult:
    """Validate one YAML case file."""
    display_path = _relative_path(path)
    findings: list[ValidationFinding] = []

    def add(kind: FindingKind, field: str, message: str, case_id: str = UNKNOWN_VALUE) -> None:
        findings.append(
            ValidationFinding(kind=kind, path=display_path, case_id=case_id, field=field, message=message)
        )

    try:
        raw = yaml.safe_load(path.read_text(encoding=DEFAULT_OUTPUT_ENCODING))
    except (OSError, yaml.YAMLError) as exc:
        add(FindingKind.ERROR, "$", f"YAML parse/read failure: {exc}")
        return CaseValidationResult(
            path=display_path,
            case_id=path.stem,
            category=UNKNOWN_VALUE,
            findings=findings,
        )

    if raw is None:
        add(FindingKind.ERROR, "$", "YAML document is empty")
        return CaseValidationResult(path=display_path, case_id=path.stem, category=UNKNOWN_VALUE, findings=findings)

    if not isinstance(raw, Mapping):
        add(FindingKind.ERROR, "$", "top-level YAML document must be a mapping/object")
        return CaseValidationResult(path=display_path, case_id=path.stem, category=UNKNOWN_VALUE, findings=findings)

    case_id = _string_value(raw.get("id"), fallback=path.stem)
    category = _metadata_category(raw)

    def add_case(kind: FindingKind, field: str, message: str) -> None:
        findings.append(
            ValidationFinding(kind=kind, path=display_path, case_id=case_id, field=field, message=message)
        )

    _validate_root(raw, add=add_case)
    _validate_id_and_version(raw, case_id=case_id, add=add_case)
    _validate_metadata(raw, case_id=case_id, path=path, suite_root=suite_root, strict=strict, add=add_case)
    _validate_task(raw, add=add_case)
    environment_facts = _validate_environment(raw, add=add_case)
    tool_facts = _validate_tools(raw, strict=strict, add=add_case)
    checker_facts = _validate_checkers(raw, add=add_case)
    _validate_attack(raw, strict=strict, add=add_case)
    _validate_expected(raw, add=add_case)
    _validate_cross_field_invariants(
        raw,
        environment_facts=environment_facts,
        tool_facts=tool_facts,
        checker_facts=checker_facts,
        strict=strict,
        add=add_case,
    )

    return CaseValidationResult(
        path=display_path,
        case_id=case_id,
        category=category,
        findings=findings,
    )


def _validate_root(raw: Mapping[str, Any], *, add: AddFindingFn) -> None:
    required = ("id", "version", "metadata", "task", "environment", "tools", "checkers", "expected")
    for key in required:
        if key not in raw:
            add(FindingKind.ERROR, key, f"missing required root field '{key}'")

    mapping_fields = ("metadata", "task", "environment", "tools", "expected")
    for key in mapping_fields:
        if key in raw and not isinstance(raw[key], Mapping):
            add(FindingKind.ERROR, key, f"'{key}' must be a mapping/object")

    if "checkers" in raw and not isinstance(raw["checkers"], list):
        add(FindingKind.ERROR, "checkers", "'checkers' must be a list")


def _validate_id_and_version(raw: Mapping[str, Any], *, case_id: str, add: AddFindingFn) -> None:
    if not isinstance(raw.get("id"), str) or not str(raw.get("id", "")).strip():
        add(FindingKind.ERROR, "id", "case id must be a non-empty string")
    elif not CASE_ID_PATTERN.match(case_id):
        add(
            FindingKind.WARNING,
            "id",
            "case id should be snake_case with a numeric suffix, e.g. secret_exfiltration_001",
        )

    version = raw.get("version")
    if not isinstance(version, str):
        add(FindingKind.ERROR, "version", "version must be a string")
    elif version != CASE_SCHEMA_VERSION:
        add(FindingKind.WARNING, "version", f"expected schema version {CASE_SCHEMA_VERSION!r}, got {version!r}")


def _validate_metadata(
    raw: Mapping[str, Any], *, case_id: str, path: Path, suite_root: Path | None, strict: bool, add: AddFindingFn
) -> None:
    metadata = _mapping(raw.get("metadata"))
    title = metadata.get("title")
    if not isinstance(title, str) or not title.strip():
        add(FindingKind.ERROR, "metadata.title", "metadata.title must be a non-empty string")

    category = metadata.get("category")
    if not isinstance(category, str) or not category.strip():
        add(FindingKind.ERROR, "metadata.category", "metadata.category must be a non-empty string")
    elif category not in SUPPORTED_SUITES:
        add(_warning_or_error(strict), "metadata.category", f"category is not one of MVP suites: {', '.join(SUPPORTED_SUITES)}")
    else:
        if not case_id.startswith(f"{category}_"):
            add(FindingKind.WARNING, "id", f"case id should start with metadata.category prefix '{category}_'")
        inferred_suite = _infer_suite(path=path, root=suite_root) if suite_root is not None else path.parent.name
        if inferred_suite in SUPPORTED_SUITES and inferred_suite != category:
            add(
                FindingKind.WARNING,
                "metadata.category",
                f"metadata.category '{category}' does not match suite directory '{inferred_suite}'",
            )

    severity = metadata.get("severity")
    if severity not in SEVERITY_LEVELS:
        add(FindingKind.ERROR, "metadata.severity", f"metadata.severity must be one of: {', '.join(SEVERITY_LEVELS)}")

    tags = metadata.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
        add(FindingKind.ERROR, "metadata.tags", "metadata.tags must be a list of strings")

    expected_difficulty = metadata.get("expected_difficulty")
    if expected_difficulty is not None and expected_difficulty not in {"easy", "medium", "hard"}:
        add(FindingKind.WARNING, "metadata.expected_difficulty", "expected_difficulty should be easy, medium, or hard")


def _validate_task(raw: Mapping[str, Any], *, add: AddFindingFn) -> None:
    task = _mapping(raw.get("task"))
    user_goal = task.get("user_goal")
    if not isinstance(user_goal, str) or not user_goal.strip():
        add(FindingKind.ERROR, "task.user_goal", "task.user_goal must be a non-empty string")

    success_criteria = task.get("success_criteria")
    if success_criteria is not None and not isinstance(success_criteria, Mapping):
        add(FindingKind.ERROR, "task.success_criteria", "task.success_criteria must be a mapping when present")


@dataclass(frozen=True, slots=True)
class EnvironmentFacts:
    """Facts collected while validating the environment section."""

    sensitive_files: tuple[str, ...]
    untrusted_sources: int


@dataclass(frozen=True, slots=True)
class ToolFacts:
    """Facts collected while validating the tools section."""

    allowed_tools: tuple[str, ...]
    risky_tools: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CheckerFacts:
    """Facts collected while validating the checkers section."""

    checker_types: tuple[str, ...]
    has_utility_checker: bool
    has_safety_checker: bool


def _validate_environment(raw: Mapping[str, Any], *, add: AddFindingFn) -> EnvironmentFacts:
    environment = _mapping(raw.get("environment"))
    sensitive_files: list[str] = []
    untrusted_sources = 0

    files = environment.get("files", [])
    if files is None:
        files = []
    if not isinstance(files, list):
        add(FindingKind.ERROR, "environment.files", "environment.files must be a list when present")
        files = []

    seen_paths: set[str] = set()
    for index, file_spec in enumerate(files):
        field = f"environment.files[{index}]"
        if not isinstance(file_spec, Mapping):
            add(FindingKind.ERROR, field, "file entry must be a mapping")
            continue

        path = file_spec.get("path")
        if not isinstance(path, str) or not path.strip():
            add(FindingKind.ERROR, f"{field}.path", "file path must be a non-empty string")
        else:
            if path in seen_paths:
                add(FindingKind.ERROR, f"{field}.path", f"duplicate file path: {path}")
            seen_paths.add(path)
            if FILE_PATH_FORBIDDEN_PATTERN.search(path):
                add(FindingKind.ERROR, f"{field}.path", "file path must be relative and must not contain '..'")

        content = file_spec.get("content")
        if not isinstance(content, str):
            add(FindingKind.ERROR, f"{field}.content", "file content must be a string")

        trust_level = file_spec.get("trust_level")
        if trust_level not in TRUST_LEVELS:
            add(FindingKind.ERROR, f"{field}.trust_level", f"trust_level must be one of: {', '.join(TRUST_LEVELS)}")
        elif trust_level == "sensitive" and isinstance(path, str):
            sensitive_files.append(path)
        elif trust_level == "untrusted":
            untrusted_sources += 1

        labels = file_spec.get("labels", [])
        if not isinstance(labels, list) or not all(isinstance(item, str) for item in labels):
            add(FindingKind.ERROR, f"{field}.labels", "labels must be a list of strings")

    inbox = environment.get("inbox", [])
    if inbox is None:
        inbox = []
    if not isinstance(inbox, list):
        add(FindingKind.ERROR, "environment.inbox", "environment.inbox must be a list when present")
        inbox = []

    for index, email_spec in enumerate(inbox):
        field = f"environment.inbox[{index}]"
        if not isinstance(email_spec, Mapping):
            add(FindingKind.ERROR, field, "email entry must be a mapping")
            continue
        sender = email_spec.get("from", email_spec.get("sender"))
        if not isinstance(sender, str) or not sender.strip():
            add(FindingKind.ERROR, f"{field}.from", "email sender must be a non-empty string")
        for key in ("subject", "body"):
            if not isinstance(email_spec.get(key), str):
                add(FindingKind.ERROR, f"{field}.{key}", f"email {key} must be a string")
        trust_level = email_spec.get("trust_level")
        if trust_level not in {"trusted", "untrusted"}:
            add(FindingKind.ERROR, f"{field}.trust_level", "email trust_level must be trusted or untrusted")
        elif trust_level == "untrusted":
            untrusted_sources += 1

    memory = environment.get("memory", {})
    if memory is not None and not isinstance(memory, Mapping):
        add(FindingKind.ERROR, "environment.memory", "environment.memory must be a mapping when present")

    return EnvironmentFacts(sensitive_files=tuple(sensitive_files), untrusted_sources=untrusted_sources)


def _validate_tools(raw: Mapping[str, Any], *, strict: bool, add: AddFindingFn) -> ToolFacts:
    tools = _mapping(raw.get("tools"))
    allowed = tools.get("allowed")
    allowed_tools: list[str] = []
    risky_tools: list[str] = []

    if not isinstance(allowed, list) or not allowed:
        add(FindingKind.ERROR, "tools.allowed", "tools.allowed must be a non-empty list of tool names")
    else:
        for index, tool_name in enumerate(allowed):
            field = f"tools.allowed[{index}]"
            if not isinstance(tool_name, str) or not tool_name.strip():
                add(FindingKind.ERROR, field, "tool name must be a non-empty string")
                continue
            allowed_tools.append(tool_name)
            if tool_name not in SUPPORTED_TOOLS:
                if tool_name in OPTIONAL_NON_MVP_TOOLS:
                    add(
                        _warning_or_error(strict),
                        field,
                        f"'{tool_name}' is not a required MVP tool; implement it before relying on it",
                    )
                else:
                    add(_warning_or_error(strict), field, f"unsupported tool name '{tool_name}'")
            if tool_name in {"send_email", "run_shell", "network_request", "delete_file"}:
                risky_tools.append(tool_name)

    policies = tools.get("tool_policies", {})
    if policies is not None and not isinstance(policies, Mapping):
        add(FindingKind.ERROR, "tools.tool_policies", "tool_policies must be a mapping when present")
        return ToolFacts(allowed_tools=tuple(allowed_tools), risky_tools=tuple(risky_tools))

    policies_map = _mapping(policies)
    _validate_read_file_policy(policies_map.get("read_file"), add=add)
    _validate_send_email_policy(policies_map.get("send_email"), add=add)
    _validate_run_shell_policy(policies_map.get("run_shell"), strict=strict, add=add)

    return ToolFacts(allowed_tools=tuple(allowed_tools), risky_tools=tuple(risky_tools))


def _validate_read_file_policy(policy: Any, *, add: AddFindingFn) -> None:
    if policy is None:
        return
    if not isinstance(policy, Mapping):
        add(FindingKind.ERROR, "tools.tool_policies.read_file", "read_file policy must be a mapping")
        return
    for key in ("allowed_paths", "denied_paths"):
        value = policy.get(key)
        if value is not None and (not isinstance(value, list) or not all(isinstance(item, str) for item in value)):
            add(FindingKind.ERROR, f"tools.tool_policies.read_file.{key}", f"{key} must be a list of strings")


def _validate_send_email_policy(policy: Any, *, add: AddFindingFn) -> None:
    if policy is None:
        return
    if not isinstance(policy, Mapping):
        add(FindingKind.ERROR, "tools.tool_policies.send_email", "send_email policy must be a mapping")
        return
    requires_authorization = policy.get("requires_authorization")
    if requires_authorization is not None and not isinstance(requires_authorization, bool):
        add(
            FindingKind.ERROR,
            "tools.tool_policies.send_email.requires_authorization",
            "requires_authorization must be boolean when present",
        )
    allowed_recipients = policy.get("allowed_recipients")
    if allowed_recipients is not None and (
        not isinstance(allowed_recipients, list) or not all(isinstance(item, str) for item in allowed_recipients)
    ):
        add(FindingKind.ERROR, "tools.tool_policies.send_email.allowed_recipients", "allowed_recipients must be a list of strings")


def _validate_run_shell_policy(policy: Any, *, strict: bool, add: AddFindingFn) -> None:
    if policy is None:
        return
    if not isinstance(policy, Mapping):
        add(FindingKind.ERROR, "tools.tool_policies.run_shell", "run_shell policy must be a mapping")
        return
    enabled = policy.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        add(FindingKind.ERROR, "tools.tool_policies.run_shell.enabled", "enabled must be boolean when present")
    if enabled is True:
        add(_warning_or_error(strict), "tools.tool_policies.run_shell.enabled", "MVP run_shell must remain fake/disabled")


def _validate_checkers(raw: Mapping[str, Any], *, add: AddFindingFn) -> CheckerFacts:
    checkers = raw.get("checkers")
    checker_types: list[str] = []
    if not isinstance(checkers, list) or not checkers:
        add(FindingKind.ERROR, "checkers", "checkers must be a non-empty list")
        return CheckerFacts(checker_types=(), has_utility_checker=False, has_safety_checker=False)

    for index, checker in enumerate(checkers):
        field = f"checkers[{index}]"
        if not isinstance(checker, Mapping):
            add(FindingKind.ERROR, field, "checker entry must be a mapping")
            continue
        checker_type = checker.get("type")
        if not isinstance(checker_type, str) or not checker_type.strip():
            add(FindingKind.ERROR, f"{field}.type", "checker type must be a non-empty string")
            continue
        checker_types.append(checker_type)
        if checker_type not in SUPPORTED_CHECKER_TYPES:
            add(FindingKind.ERROR, f"{field}.type", f"unsupported checker type '{checker_type}'")
            continue
        _validate_checker_parameters(checker, field=field, add=add)

    has_utility = any(checker_type in UTILITY_CHECKERS for checker_type in checker_types)
    has_safety = any(checker_type in SAFETY_CHECKERS for checker_type in checker_types)
    if not has_utility:
        add(FindingKind.ERROR, "checkers", "each case should include at least one utility checker, usually task_completion")
    if not has_safety:
        add(FindingKind.ERROR, "checkers", "each case should include at least one safety checker")

    return CheckerFacts(
        checker_types=tuple(checker_types),
        has_utility_checker=has_utility,
        has_safety_checker=has_safety,
    )


def _validate_checker_parameters(checker: Mapping[str, Any], *, field: str, add: AddFindingFn) -> None:
    checker_type = str(checker["type"])
    requirements: dict[str, tuple[str, str]] = {
        "no_secret_leak": ("forbidden_patterns", "list of forbidden secret patterns"),
        "no_sensitive_file_access": ("paths", "list of sensitive paths"),
        "no_forbidden_tool_call": ("tools", "list of forbidden tools"),
        "task_completion": ("required_evidence", "list of required evidence strings"),
    }
    if checker_type in requirements:
        key, description = requirements[checker_type]
        value = checker.get(key)
        if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
            add(FindingKind.ERROR, f"{field}.{key}", f"{checker_type} requires a non-empty {description}")

    if checker_type == "instruction_hierarchy":
        conflict = checker.get("lower_priority_conflict")
        if not isinstance(conflict, str) or not conflict.strip():
            add(FindingKind.ERROR, f"{field}.lower_priority_conflict", "instruction_hierarchy requires lower_priority_conflict")


def _validate_attack(raw: Mapping[str, Any], *, strict: bool, add: AddFindingFn) -> None:
    attack = raw.get("attack")
    if attack is None:
        add(_warning_or_error(strict), "attack", "adversarial MVP cases should include an attack block")
        return
    if not isinstance(attack, Mapping):
        add(FindingKind.ERROR, "attack", "attack must be a mapping when present")
        return

    attack_type = attack.get("type")
    if attack_type not in ATTACK_TYPES:
        add(FindingKind.ERROR, "attack.type", f"attack.type must be one of: {', '.join(sorted(ATTACK_TYPES))}")
    payload_location = attack.get("payload_location")
    if payload_location not in PAYLOAD_LOCATIONS:
        add(
            FindingKind.ERROR,
            "attack.payload_location",
            f"payload_location must be one of: {', '.join(sorted(PAYLOAD_LOCATIONS))}",
        )
    payload = attack.get("payload")
    if not isinstance(payload, str) or not payload.strip():
        add(FindingKind.ERROR, "attack.payload", "attack.payload must be a non-empty string")


def _validate_expected(raw: Mapping[str, Any], *, add: AddFindingFn) -> None:
    expected = _mapping(raw.get("expected"))
    utility = expected.get("utility")
    if utility not in EXPECTED_UTILITY_VALUES:
        add(FindingKind.ERROR, "expected.utility", "expected.utility must be pass, fail, or unknown")
    safety = expected.get("safety")
    if safety not in EXPECTED_SAFETY_VALUES:
        add(FindingKind.ERROR, "expected.safety", "expected.safety must be pass or fail")


def _validate_cross_field_invariants(
    raw: Mapping[str, Any],
    *,
    environment_facts: EnvironmentFacts,
    tool_facts: ToolFacts,
    checker_facts: CheckerFacts,
    strict: bool,
    add: AddFindingFn,
) -> None:
    checker_types = set(checker_facts.checker_types)

    if environment_facts.sensitive_files and not ({"no_secret_leak", "no_sensitive_file_access"} & checker_types):
        add(
            _warning_or_error(strict),
            "checkers",
            "case contains sensitive files but lacks no_secret_leak or no_sensitive_file_access checker",
        )

    if environment_facts.untrusted_sources > 0 and "instruction_hierarchy" not in checker_types:
        add(
            FindingKind.WARNING,
            "checkers",
            "case contains untrusted content but lacks instruction_hierarchy checker",
        )

    if "send_email" in tool_facts.allowed_tools and "no_secret_leak" not in checker_types:
        add(FindingKind.WARNING, "checkers", "send_email is allowed but no_secret_leak checker is absent")

    if "run_shell" in tool_facts.allowed_tools and "no_forbidden_tool_call" not in checker_types:
        add(FindingKind.WARNING, "checkers", "run_shell is allowed but no_forbidden_tool_call checker is absent")

    expected = _mapping(raw.get("expected"))
    if expected.get("safety") == "pass" and not checker_facts.has_safety_checker:
        add(FindingKind.ERROR, "checkers", "expected.safety=pass requires at least one safety checker")


def _add_duplicate_id_findings(results: Sequence[CaseValidationResult]) -> None:
    buckets: dict[str, list[CaseValidationResult]] = defaultdict(list)
    for result in results:
        buckets[result.case_id].append(result)

    for case_id, bucket in buckets.items():
        if case_id == UNKNOWN_VALUE or len(bucket) <= 1:
            continue
        paths = ", ".join(result.path for result in bucket)
        for result in bucket:
            result.findings.append(
                ValidationFinding(
                    kind=FindingKind.ERROR,
                    path=result.path,
                    case_id=case_id,
                    field="id",
                    message=f"duplicate case id across files: {paths}",
                )
            )


def _add_missing_mvp_suite_findings(*, results: Sequence[CaseValidationResult], target_path: Path) -> None:
    if target_path.name != "suites":
        return
    missing = [suite for suite in SUPPORTED_SUITES if not (target_path / suite).is_dir()]
    if not missing or not results:
        return
    anchor = results[0]
    anchor.findings.append(
        ValidationFinding(
            kind=FindingKind.ERROR,
            path=anchor.path,
            case_id=anchor.case_id,
            field="suites",
            message=f"missing required MVP suite directories: {', '.join(missing)}",
        )
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_value(value: Any, *, fallback: str) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _metadata_category(raw: Mapping[str, Any]) -> str:
    metadata = raw.get("metadata")
    if isinstance(metadata, Mapping) and isinstance(metadata.get("category"), str):
        return str(metadata["category"])
    return UNKNOWN_VALUE


def _warning_or_error(strict: bool) -> FindingKind:
    return FindingKind.ERROR if strict else FindingKind.WARNING


def _infer_suite(*, path: Path, root: Path | None) -> str:
    if root is None:
        return path.parent.name
    try:
        relative = path.relative_to(root)
    except ValueError:
        return path.parent.name
    if root.name == "suites" and len(relative.parts) >= 2:
        return relative.parts[0]
    if root.name in SUPPORTED_SUITES:
        return root.name
    if len(relative.parts) >= 2:
        return relative.parts[0]
    return root.name


def _relative_path(path: Path) -> str:
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def _summary_to_mapping(summary: ValidationSummary) -> dict[str, Any]:
    return {
        "target": summary.target,
        "case_count": summary.case_count,
        "error_count": summary.error_count,
        "warning_count": summary.warning_count,
        "categories": summary.categories,
        "suites": summary.suites,
        "results": [
            {
                "path": result.path,
                "case_id": result.case_id,
                "category": result.category,
                "passed": result.passed,
                "error_count": result.error_count,
                "warning_count": result.warning_count,
                "findings": [
                    {
                        "kind": finding.kind.value,
                        "path": finding.path,
                        "case_id": finding.case_id,
                        "field": finding.field,
                        "message": finding.message,
                    }
                    for finding in result.findings
                ],
            }
            for result in summary.results
        ],
    }


def _print_summary(summary: ValidationSummary, *, max_findings: int | None) -> None:
    table = Table(title="ASRH Case Validation Summary", show_header=True, header_style="bold")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("target", summary.target)
    table.add_row("validated_cases", str(summary.case_count))
    table.add_row("errors", str(summary.error_count))
    table.add_row("warnings", str(summary.warning_count))
    table.add_row("categories", _format_counts(summary.categories))
    table.add_row("suites", _format_counts(summary.suites))
    console.print(table)

    findings = [finding for result in summary.results for finding in result.findings]
    if not findings:
        console.print("[green]All discovered cases passed structural validation.[/green]")
        console.print(f"Validated {summary.case_count} cases. Errors: 0. Warnings: 0.")
        return

    _print_findings(findings, max_findings=max_findings)
    console.print(
        f"Validated {summary.case_count} cases. Errors: {summary.error_count}. Warnings: {summary.warning_count}."
    )


def _print_findings(findings: Sequence[ValidationFinding], *, max_findings: int | None) -> None:
    visible = findings if max_findings is None else findings[:max_findings]
    table = Table(title="Validation Findings", show_header=True, header_style="bold")
    table.add_column("Kind")
    table.add_column("Case ID")
    table.add_column("Field")
    table.add_column("Message")
    table.add_column("Path")

    for finding in visible:
        style = "red" if finding.kind is FindingKind.ERROR else "yellow"
        table.add_row(
            f"[{style}]{finding.kind.value}[/{style}]",
            finding.case_id,
            finding.field,
            finding.message,
            finding.path,
        )

    console.print(table)
    if max_findings is not None and len(findings) > max_findings:
        console.print(f"[yellow]Showing {max_findings} of {len(findings)} findings.[/yellow]")


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "-"
    return ", ".join(f"{name}={count}" for name, count in counts.items())


def _load_env_file(env_file: Path | None) -> None:
    if env_file is not None and env_file.exists():
        load_dotenv(dotenv_path=env_file, override=False)


def _print_json(payload: Mapping[str, Any]) -> None:
    stdout_console.print_json(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _exit_with_cli_error(
    exc: UsageError | ValidationCliError, *, json_output: bool, debug: bool
) -> NoReturn:
    if debug:
        raise exc
    payload = {"error": exc.__class__.__name__, "message": str(exc), "exit_code": int(exc.exit_code)}
    if json_output:
        _print_json(payload)
    else:
        console.print(Panel(str(exc), title=exc.__class__.__name__, style="red"))
    raise typer.Exit(code=int(exc.exit_code))


def _exit_with_internal_error(exc: Exception, *, json_output: bool) -> NoReturn:
    payload = {
        "error": exc.__class__.__name__,
        "message": str(exc),
        "exit_code": int(ExitCode.INTERNAL_ERROR),
    }
    if json_output:
        _print_json(payload)
    else:
        console.print(
            Panel(
                f"{exc.__class__.__name__}: {exc}\n\nRerun with --debug for a traceback.",
                title="InternalError",
                style="red",
            )
        )
    raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR))


def main(argv: Sequence[str] | None = None) -> None:
    """Entrypoint for ``python -m asrh.cli.validate_cases`` and tests."""
    if argv is not None:
        original_argv = sys.argv[:]
        sys.argv = [sys.argv[0], *argv]
        try:
            app()
        finally:
            sys.argv = original_argv
        return

    app()


__all__: Final[tuple[str, ...]] = (
    "APP_HELP",
    "APP_NAME",
    "CaseValidationResult",
    "FindingKind",
    "ValidationFinding",
    "ValidationSummary",
    "app",
    "main",
    "validate_case_files",
    "validate_cases_command",
)


if __name__ == "__main__":
    main()
