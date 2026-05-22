"""Run-command implementation for ASRH.

This module owns the public ``asrh-run`` console entry point and the
``python -m asrh.cli.run`` execution path. It is intentionally an orchestration
layer, not the implementation of the agent loop itself.

Runtime contract for the backend modules implemented later in the MVP:

- ``asrh.runner.run_case.run_case`` accepts keyword-only arguments with the
  names emitted by ``_execute_backend`` below and writes exactly one JSON object
  per line to the requested JSONL output path.
- ``asrh.runner.run_suite.run_suite`` accepts the same configuration plus a
  ``suite_path`` and writes one JSON object per case.
- Both functions may return ``None`` or a mapping/dataclass-like object with
  summary fields such as ``case_count``, ``utility_pass_rate``,
  ``safety_pass_rate``, and ``attack_success_rate``.

The CLI performs argument validation, environment loading, safety-gate checks,
output-path handling, and user-facing error reporting. Keeping those concerns in
one place makes the runner modules easier to test and keeps provider/tool code
out of import-time execution.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, NoReturn

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from asrh import (
    DEFAULT_MAX_STEPS,
    DEFAULT_MAX_TOKENS_PER_RESPONSE,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TOTAL_TOKENS,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    SUPPORTED_AGENT_MODES,
    SUPPORTED_MITIGATIONS,
    SUPPORTED_MOCK_MODES,
    SUPPORTED_SUITES,
    get_version,
)
from asrh.cli import (
    DEFAULTS,
    DEFAULT_JSONL_SUFFIX,
    ExitCode,
    SafetyGateError,
    UsageError,
    build_version_banner,
)

APP_NAME: Final[str] = "asrh-run"
APP_HELP: Final[str] = "Run one YAML case or suite and write JSONL traces."
APP_EPILOG: Final[str] = (
    "Examples:\n"
    "  python -m asrh.cli.run --case suites/secret_exfiltration/case_001.yaml "
    "--model mock/safe --mitigation none --out runs/single_case.jsonl\n"
    "  python -m asrh.cli.run --suite suites --model openai/gpt-4o-mini "
    "--mitigation tool_policy_guard --out runs/tool_policy_guard.jsonl"
)

CASE_SUFFIXES: Final[frozenset[str]] = frozenset({".yaml", ".yml"})
CASE_RUNNER_MODULE: Final[str] = "asrh.runner.run_case"
SUITE_RUNNER_MODULE: Final[str] = "asrh.runner.run_suite"
CASE_RUNNER_FUNCTION: Final[str] = "run_case"
SUITE_RUNNER_FUNCTION: Final[str] = "run_suite"
DEFAULT_AGENT_MODE: Final[str] = "tool_agent"
DEFAULT_ENV_FILE: Final[Path] = Path(".env")
TRUTHY_ENV_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "t", "yes", "y", "on"})
FALSY_ENV_VALUES: Final[frozenset[str]] = frozenset({"0", "false", "f", "no", "n", "off", ""})
PROVIDER_RUN_ENV_VAR: Final[str] = "ASRH_ENABLE_PROVIDER_RUNS"
SAFETY_GATE_ENV_VARS: Final[tuple[str, ...]] = (
    "ASRH_ALLOW_REAL_SHELL",
    "ASRH_ALLOW_REAL_EMAIL",
    "ASRH_ALLOW_REAL_NETWORK",
    "ASRH_ALLOW_REAL_CREDENTIALS",
    "ASRH_ALLOW_BROWSER_AUTOMATION",
)

console: Final[Console] = Console(stderr=True)
stdout_console: Final[Console] = Console()


class TargetKind(StrEnum):
    """Kinds of run targets accepted by the CLI."""

    CASE = "case"
    SUITE = "suite"


class ProviderKind(StrEnum):
    """Provider families inferred from ASRH model identifiers."""

    MOCK = "mock"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RunTarget:
    """Validated case or suite target."""

    kind: TargetKind
    path: Path
    case_count: int
    case_files: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class RunCliConfig:
    """Fully resolved command configuration passed to the runner backend."""

    target: RunTarget
    output_path: Path
    model: str
    provider: ProviderKind
    mitigation: str
    agent_mode: str
    temperature: float
    seed: int | None
    max_steps: int
    max_tool_calls: int
    max_tokens_per_response: int
    max_total_tokens: int
    timeout_seconds: int
    fail_fast: bool
    append: bool
    overwrite: bool
    dry_run: bool
    quiet: bool
    debug: bool
    started_at: str


@dataclass(frozen=True, slots=True)
class BackendCallResult:
    """Normalized backend execution summary for CLI display."""

    target_kind: str
    target_path: str
    output_path: str
    model: str
    mitigation: str
    case_count: int
    status: str
    details: Mapping[str, Any]


app = typer.Typer(
    name=APP_NAME,
    help=APP_HELP,
    epilog=APP_EPILOG,
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)


@app.command(help=APP_HELP, epilog=APP_EPILOG, no_args_is_help=True)
def run_command(
    case_path: Annotated[
        Path | None,
        typer.Option(
            "--case",
            dir_okay=False,
            file_okay=True,
            resolve_path=False,
            help="Path to one YAML test case. Mutually exclusive with --suite.",
        ),
    ] = None,
    suite_path: Annotated[
        Path | None,
        typer.Option(
            "--suite",
            dir_okay=True,
            file_okay=False,
            resolve_path=False,
            help="Path to a suite directory or the top-level suites directory.",
        ),
    ] = None,
    output_path: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            dir_okay=False,
            file_okay=True,
            resolve_path=False,
            help="JSONL output path for case traces. Required for non-dry runs.",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            help="Model identifier, e.g. mock/safe, mock/unsafe_leaker, or openai/gpt-4o-mini.",
        ),
    ] = None,
    mitigation: Annotated[
        str | None,
        typer.Option(
            "--mitigation",
            help="Mitigation mode: none, system_prompt_guard, tool_policy_guard, taint_tracking_guard, or human_approval_guard.",
        ),
    ] = None,
    agent_mode: Annotated[
        str | None,
        typer.Option(
            "--agent-mode",
            help="Agent mode: mock, single_turn, or tool_agent. Defaults to tool_agent.",
        ),
    ] = None,
    temperature: Annotated[
        float | None,
        typer.Option("--temperature", min=0.0, max=2.0, help="Sampling temperature."),
    ] = None,
    seed: Annotated[
        int | None,
        typer.Option("--seed", help="Optional deterministic seed passed to model clients and mocks."),
    ] = None,
    max_steps: Annotated[
        int | None,
        typer.Option("--max-steps", min=1, help="Maximum agent loop steps per case."),
    ] = None,
    max_tool_calls: Annotated[
        int | None,
        typer.Option("--max-tool-calls", min=0, help="Maximum tool calls per case."),
    ] = None,
    max_tokens_per_response: Annotated[
        int | None,
        typer.Option(
            "--max-tokens-per-response",
            min=1,
            help="Maximum generated tokens per model response.",
        ),
    ] = None,
    max_total_tokens: Annotated[
        int | None,
        typer.Option("--max-total-tokens", min=1, help="Total token budget per case."),
    ] = None,
    timeout_seconds: Annotated[
        int | None,
        typer.Option("--timeout-seconds", min=1, help="Timeout per case run in seconds."),
    ] = None,
    fail_fast: Annotated[
        bool,
        typer.Option("--fail-fast", help="Stop after the first case-level runtime failure."),
    ] = False,
    append: Annotated[
        bool,
        typer.Option("--append", help="Append to an existing JSONL output file instead of failing."),
    ] = False,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Overwrite an existing JSONL output file."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Validate configuration and print the resolved plan without executing."),
    ] = False,
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
    acknowledge_side_effects: Annotated[
        bool,
        typer.Option(
            "--acknowledge-side-effects",
            help="Allow future non-MVP side-effect gates if explicitly enabled in the environment.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print machine-readable JSON summary to stdout."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress non-error progress output."),
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
    """Run one ASRH case or suite.

    The command writes JSONL traces rather than Markdown. Use ``asrh-report`` or
    ``python -m asrh.cli.report`` later to generate reports from the run file.
    """
    if version:
        stdout_console.print(build_version_banner())
        raise typer.Exit(code=int(ExitCode.OK))

    try:
        _load_env_file(env_file)
        if not acknowledge_side_effects:
            _assert_side_effect_gates_closed()

        config = _resolve_config(
            case_path=case_path,
            suite_path=suite_path,
            output_path=output_path,
            model=model,
            mitigation=mitigation,
            agent_mode=agent_mode,
            temperature=temperature,
            seed=seed,
            max_steps=max_steps,
            max_tool_calls=max_tool_calls,
            max_tokens_per_response=max_tokens_per_response,
            max_total_tokens=max_total_tokens,
            timeout_seconds=timeout_seconds,
            fail_fast=fail_fast,
            append=append,
            overwrite=overwrite,
            dry_run=dry_run,
            quiet=quiet,
            debug=debug,
        )

        if json_output:
            _print_json(_config_to_public_dict(config))
        elif not quiet:
            _print_run_plan(config)

        if dry_run:
            if not json_output and not quiet:
                console.print("[green]Dry run complete. No cases were executed.[/green]")
            raise typer.Exit(code=int(ExitCode.OK))

        result = _execute_backend(config)

        if json_output:
            _print_json(_backend_result_to_mapping(result))
        elif not quiet:
            _print_result_summary(result)

        raise typer.Exit(code=int(ExitCode.OK))

    except typer.Exit:
        raise
    except (UsageError, SafetyGateError) as exc:
        _exit_with_cli_error(exc, json_output=json_output, debug=debug)
    except Exception as exc:  # noqa: BLE001 - CLI must convert uncaught errors to stable exit codes.
        if debug:
            raise
        _exit_with_internal_error(exc, json_output=json_output)


def _load_env_file(env_file: Path | None) -> None:
    """Load a dotenv file if one exists.

    Missing dotenv files are not errors. The repository ships ``.env.example``;
    local users may or may not have copied it to ``.env``.
    """
    if env_file is None:
        return

    if env_file.exists():
        load_dotenv(dotenv_path=env_file, override=False)


def _resolve_config(
    *,
    case_path: Path | None,
    suite_path: Path | None,
    output_path: Path | None,
    model: str | None,
    mitigation: str | None,
    agent_mode: str | None,
    temperature: float | None,
    seed: int | None,
    max_steps: int | None,
    max_tool_calls: int | None,
    max_tokens_per_response: int | None,
    max_total_tokens: int | None,
    timeout_seconds: int | None,
    fail_fast: bool,
    append: bool,
    overwrite: bool,
    dry_run: bool,
    quiet: bool,
    debug: bool,
) -> RunCliConfig:
    """Resolve command-line arguments and environment defaults into one config."""
    target = _resolve_target(case_path=case_path, suite_path=suite_path)
    resolved_output_path = _resolve_output_path(
        output_path=output_path,
        target=target,
        dry_run=dry_run,
        append=append,
        overwrite=overwrite,
    )
    resolved_model = _resolve_string_option(
        explicit_value=model,
        env_var="ASRH_DEFAULT_MODEL",
        fallback=DEFAULTS.model,
    )
    provider = _infer_provider(resolved_model)
    resolved_mitigation = _resolve_string_option(
        explicit_value=mitigation,
        env_var="ASRH_DEFAULT_MITIGATION",
        fallback=DEFAULTS.mitigation,
    )
    resolved_agent_mode = _resolve_string_option(
        explicit_value=agent_mode,
        env_var="ASRH_AGENT_MODE",
        fallback=DEFAULT_AGENT_MODE,
    )
    resolved_temperature = _resolve_float_option(
        explicit_value=temperature,
        env_var="ASRH_TEMPERATURE",
        fallback=DEFAULT_TEMPERATURE,
    )
    resolved_max_steps = _resolve_int_option(
        explicit_value=max_steps,
        env_var="ASRH_MAX_STEPS",
        fallback=DEFAULT_MAX_STEPS,
    )
    resolved_max_tool_calls = _resolve_int_option(
        explicit_value=max_tool_calls,
        env_var="ASRH_MAX_TOOL_CALLS",
        fallback=DEFAULT_MAX_TOOL_CALLS,
        minimum=0,
    )
    resolved_max_tokens_per_response = _resolve_int_option(
        explicit_value=max_tokens_per_response,
        env_var="ASRH_MAX_TOKENS_PER_RESPONSE",
        fallback=DEFAULT_MAX_TOKENS_PER_RESPONSE,
    )
    resolved_max_total_tokens = _resolve_int_option(
        explicit_value=max_total_tokens,
        env_var="ASRH_MAX_TOTAL_TOKENS",
        fallback=DEFAULT_MAX_TOTAL_TOKENS,
    )
    resolved_timeout_seconds = _resolve_int_option(
        explicit_value=timeout_seconds,
        env_var="ASRH_TIMEOUT_SECONDS",
        fallback=DEFAULT_TIMEOUT_SECONDS,
    )

    _validate_model(resolved_model)
    _validate_mitigation(resolved_mitigation)
    _validate_agent_mode(resolved_agent_mode)
    _validate_numeric_limits(
        temperature=resolved_temperature,
        max_steps=resolved_max_steps,
        max_tool_calls=resolved_max_tool_calls,
        max_tokens_per_response=resolved_max_tokens_per_response,
        max_total_tokens=resolved_max_total_tokens,
        timeout_seconds=resolved_timeout_seconds,
    )
    _validate_provider_configuration(provider=provider, model=resolved_model, dry_run=dry_run)

    return RunCliConfig(
        target=target,
        output_path=resolved_output_path,
        model=resolved_model,
        provider=provider,
        mitigation=resolved_mitigation,
        agent_mode=resolved_agent_mode,
        temperature=resolved_temperature,
        seed=seed if seed is not None else _optional_env_int("ASRH_SEED"),
        max_steps=resolved_max_steps,
        max_tool_calls=resolved_max_tool_calls,
        max_tokens_per_response=resolved_max_tokens_per_response,
        max_total_tokens=resolved_max_total_tokens,
        timeout_seconds=resolved_timeout_seconds,
        fail_fast=fail_fast or _env_bool("ASRH_FAIL_FAST", default=False),
        append=append,
        overwrite=overwrite,
        dry_run=dry_run,
        quiet=quiet,
        debug=debug,
        started_at=_utc_now_iso(),
    )


def _resolve_target(*, case_path: Path | None, suite_path: Path | None) -> RunTarget:
    """Validate and normalize the run target."""
    if case_path is None and suite_path is None:
        raise UsageError("Specify exactly one target: --case PATH or --suite PATH.")
    if case_path is not None and suite_path is not None:
        raise UsageError("--case and --suite are mutually exclusive.")

    if case_path is not None:
        path = case_path.expanduser()
        if not path.exists():
            raise UsageError(f"Case file does not exist: {path}")
        if not path.is_file():
            raise UsageError(f"--case must point to a YAML file, not a directory: {path}")
        if path.suffix.lower() not in CASE_SUFFIXES:
            suffixes = ", ".join(sorted(CASE_SUFFIXES))
            raise UsageError(f"Case file must use one of these suffixes: {suffixes}. Got: {path}")
        return RunTarget(kind=TargetKind.CASE, path=path, case_count=1, case_files=(path,))

    assert suite_path is not None
    path = suite_path.expanduser()
    if not path.exists():
        raise UsageError(f"Suite directory does not exist: {path}")
    if not path.is_dir():
        raise UsageError(f"--suite must point to a directory: {path}")

    case_files = _discover_case_files(path)
    if not case_files:
        raise UsageError(f"No YAML case files found under suite directory: {path}")

    _warn_if_suite_name_is_unexpected(path)
    return RunTarget(
        kind=TargetKind.SUITE,
        path=path,
        case_count=len(case_files),
        case_files=case_files,
    )


def _discover_case_files(path: Path) -> tuple[Path, ...]:
    """Return sorted non-hidden YAML case files under ``path``."""
    discovered: list[Path] = []
    for suffix in CASE_SUFFIXES:
        discovered.extend(path.rglob(f"*{suffix}"))

    return tuple(
        sorted(
            (
                candidate
                for candidate in discovered
                if candidate.is_file() and not any(part.startswith(".") for part in candidate.parts)
            ),
            key=lambda item: item.as_posix(),
        )
    )


def _warn_if_suite_name_is_unexpected(path: Path) -> None:
    """Warn for non-standard suite names without blocking custom suites."""
    if path.name == "suites" or path.name in SUPPORTED_SUITES:
        return

    parent_name = path.parent.name
    if parent_name == "suites" and path.name not in SUPPORTED_SUITES:
        supported = ", ".join(SUPPORTED_SUITES)
        console.print(
            f"[yellow]Warning:[/yellow] suite directory '{path.name}' is not one of the MVP suites: {supported}"
        )


def _resolve_output_path(
    *,
    output_path: Path | None,
    target: RunTarget,
    dry_run: bool,
    append: bool,
    overwrite: bool,
) -> Path:
    """Validate and prepare the JSONL output path."""
    if append and overwrite:
        raise UsageError("--append and --overwrite are mutually exclusive.")

    if output_path is None:
        if not dry_run:
            raise UsageError("--out is required for non-dry runs.")
        output_path = _default_dry_run_output_path(target)

    path = output_path.expanduser()
    if path.suffix.lower() != DEFAULT_JSONL_SUFFIX:
        raise UsageError(f"Run output must use the {DEFAULT_JSONL_SUFFIX} suffix: {path}")
    if path.exists() and path.is_dir():
        raise UsageError(f"Run output path points to a directory: {path}")
    if path.exists() and not append and not overwrite and not dry_run:
        raise UsageError(
            f"Run output already exists: {path}. Use --overwrite to replace it or --append to append."
        )

    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        if overwrite and path.exists():
            path.unlink()

    return path


def _default_dry_run_output_path(target: RunTarget) -> Path:
    """Return a deterministic placeholder output path for dry-run display."""
    target_name = target.path.stem if target.kind is TargetKind.CASE else target.path.name
    return DEFAULTS.run_dir / f"dry_run_{target_name}{DEFAULT_JSONL_SUFFIX}"


def _resolve_string_option(*, explicit_value: str | None, env_var: str, fallback: str) -> str:
    """Resolve a string option from CLI, environment, or fallback."""
    if explicit_value is not None and explicit_value.strip():
        return explicit_value.strip()

    env_value = os.getenv(env_var)
    if env_value is not None and env_value.strip():
        return env_value.strip()

    return fallback


def _resolve_float_option(*, explicit_value: float | None, env_var: str, fallback: float) -> float:
    """Resolve a float option from CLI, environment, or fallback."""
    if explicit_value is not None:
        return explicit_value

    env_value = os.getenv(env_var)
    if env_value is None or not env_value.strip():
        return fallback

    try:
        return float(env_value)
    except ValueError as exc:
        raise UsageError(f"Environment variable {env_var} must be a float. Got: {env_value!r}") from exc


def _resolve_int_option(
    *,
    explicit_value: int | None,
    env_var: str,
    fallback: int,
    minimum: int = 1,
) -> int:
    """Resolve an integer option from CLI, environment, or fallback."""
    if explicit_value is not None:
        value = explicit_value
    else:
        env_value = os.getenv(env_var)
        if env_value is None or not env_value.strip():
            value = fallback
        else:
            try:
                value = int(env_value)
            except ValueError as exc:
                raise UsageError(
                    f"Environment variable {env_var} must be an integer. Got: {env_value!r}"
                ) from exc

    if value < minimum:
        raise UsageError(f"{env_var} must be >= {minimum}. Got: {value}")
    return value


def _optional_env_int(env_var: str) -> int | None:
    """Return an optional integer from the environment."""
    env_value = os.getenv(env_var)
    if env_value is None or not env_value.strip():
        return None
    try:
        return int(env_value)
    except ValueError as exc:
        raise UsageError(f"Environment variable {env_var} must be an integer. Got: {env_value!r}") from exc


def _env_bool(env_var: str, *, default: bool) -> bool:
    """Parse a boolean environment variable with explicit truthy/falsy values."""
    env_value = os.getenv(env_var)
    if env_value is None:
        return default

    normalized = env_value.strip().lower()
    if normalized in TRUTHY_ENV_VALUES:
        return True
    if normalized in FALSY_ENV_VALUES:
        return False

    accepted = sorted(TRUTHY_ENV_VALUES | FALSY_ENV_VALUES)
    raise UsageError(
        f"Environment variable {env_var} must be a boolean value "
        f"({', '.join(accepted)}). Got: {env_value!r}"
    )


def _assert_side_effect_gates_closed() -> None:
    """Reject runs when non-MVP side-effect gates are enabled."""
    enabled = [name for name in SAFETY_GATE_ENV_VARS if _env_bool(name, default=False)]
    if not enabled:
        return

    joined = ", ".join(enabled)
    raise SafetyGateError(
        "ASRH MVP tools must remain simulated. These side-effect gates are enabled: "
        f"{joined}. Set them to false or rerun with --acknowledge-side-effects after implementing "
        "the corresponding sandbox-safe backend."
    )


def _infer_provider(model: str) -> ProviderKind:
    """Infer the provider family from a model identifier prefix."""
    prefix = model.split("/", 1)[0].lower()
    match prefix:
        case "mock":
            return ProviderKind.MOCK
        case "openai":
            return ProviderKind.OPENAI
        case "anthropic":
            return ProviderKind.ANTHROPIC
        case "local":
            return ProviderKind.LOCAL
        case _:
            return ProviderKind.UNKNOWN


def _validate_model(model: str) -> None:
    """Validate model identifier shape and supported mock modes."""
    if "/" not in model:
        raise UsageError(
            "Model identifiers must include a provider prefix, e.g. mock/safe or openai/gpt-4o-mini."
        )

    provider, name = model.split("/", 1)
    if not provider or not name:
        raise UsageError(f"Invalid model identifier: {model!r}")

    if provider == ProviderKind.MOCK.value and name not in SUPPORTED_MOCK_MODES:
        supported = ", ".join(f"mock/{mode}" for mode in SUPPORTED_MOCK_MODES)
        raise UsageError(f"Unsupported mock model mode '{model}'. Supported mock models: {supported}")


def _validate_mitigation(mitigation: str) -> None:
    """Validate mitigation mode."""
    if mitigation not in SUPPORTED_MITIGATIONS:
        supported = ", ".join(SUPPORTED_MITIGATIONS)
        raise UsageError(f"Unsupported mitigation '{mitigation}'. Supported mitigations: {supported}")


def _validate_agent_mode(agent_mode: str) -> None:
    """Validate agent mode."""
    if agent_mode not in SUPPORTED_AGENT_MODES:
        supported = ", ".join(SUPPORTED_AGENT_MODES)
        raise UsageError(f"Unsupported agent mode '{agent_mode}'. Supported modes: {supported}")


def _validate_numeric_limits(
    *,
    temperature: float,
    max_steps: int,
    max_tool_calls: int,
    max_tokens_per_response: int,
    max_total_tokens: int,
    timeout_seconds: int,
) -> None:
    """Validate cross-field numeric settings."""
    if not 0.0 <= temperature <= 2.0:
        raise UsageError(f"Temperature must be between 0.0 and 2.0. Got: {temperature}")
    if max_tool_calls > max_steps:
        raise UsageError(
            f"--max-tool-calls ({max_tool_calls}) cannot exceed --max-steps ({max_steps})."
        )
    if max_tokens_per_response > max_total_tokens:
        raise UsageError(
            "--max-tokens-per-response cannot exceed --max-total-tokens "
            f"({max_tokens_per_response} > {max_total_tokens})."
        )
    if timeout_seconds <= 0:
        raise UsageError(f"Timeout must be positive. Got: {timeout_seconds}")


def _validate_provider_configuration(*, provider: ProviderKind, model: str, dry_run: bool) -> None:
    """Validate provider-related configuration without performing network calls."""
    if provider is ProviderKind.UNKNOWN:
        console.print(
            f"[yellow]Warning:[/yellow] unknown provider prefix for model '{model}'. "
            "The backend runner must know how to handle it."
        )
        return

    if provider is ProviderKind.MOCK or dry_run:
        return

    provider_runs_enabled = _env_bool(PROVIDER_RUN_ENV_VAR, default=True)
    if not provider_runs_enabled:
        raise UsageError(
            f"Provider model '{model}' was requested, but {PROVIDER_RUN_ENV_VAR}=false. "
            f"Set {PROVIDER_RUN_ENV_VAR}=true or use a mock model."
        )

    if provider is ProviderKind.OPENAI and not os.getenv("OPENAI_API_KEY"):
        console.print(
            "[yellow]Warning:[/yellow] OPENAI_API_KEY is not set. The backend may fail when it "
            "constructs the OpenAI-compatible client."
        )
    elif provider is ProviderKind.ANTHROPIC and not os.getenv("ANTHROPIC_API_KEY"):
        console.print(
            "[yellow]Warning:[/yellow] ANTHROPIC_API_KEY is not set. The backend may fail when it "
            "constructs the Anthropic-compatible client."
        )


def _execute_backend(config: RunCliConfig) -> BackendCallResult:
    """Load the appropriate runner backend and execute the resolved run."""
    module_name = CASE_RUNNER_MODULE if config.target.kind is TargetKind.CASE else SUITE_RUNNER_MODULE
    function_name = CASE_RUNNER_FUNCTION if config.target.kind is TargetKind.CASE else SUITE_RUNNER_FUNCTION
    runner_function = _load_runner_function(module_name=module_name, function_name=function_name)

    backend_kwargs: dict[str, Any] = {
        "model": config.model,
        "mitigation": config.mitigation,
        "agent_mode": config.agent_mode,
        "output_path": config.output_path,
        "temperature": config.temperature,
        "seed": config.seed,
        "max_steps": config.max_steps,
        "max_tool_calls": config.max_tool_calls,
        "max_tokens_per_response": config.max_tokens_per_response,
        "max_total_tokens": config.max_total_tokens,
        "timeout_seconds": config.timeout_seconds,
        "fail_fast": config.fail_fast,
        "append": config.append,
        "run_started_at": config.started_at,
    }

    if config.target.kind is TargetKind.CASE:
        backend_kwargs["case_path"] = config.target.path
    else:
        backend_kwargs["suite_path"] = config.target.path

    raw_result = runner_function(**backend_kwargs)
    result_details = _normalize_backend_result(raw_result)
    case_count = _extract_case_count(result_details, fallback=config.target.case_count)

    return BackendCallResult(
        target_kind=config.target.kind.value,
        target_path=config.target.path.as_posix(),
        output_path=config.output_path.as_posix(),
        model=config.model,
        mitigation=config.mitigation,
        case_count=case_count,
        status=str(result_details.get("status", "completed")),
        details=result_details,
    )


def _load_runner_function(*, module_name: str, function_name: str) -> Callable[..., Any]:
    """Dynamically load a runner backend function."""
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name is not None and (exc.name == module_name or exc.name.startswith("asrh.runner")):
            raise UsageError(
                "Runner backend is not implemented yet. Implement "
                f"{CASE_RUNNER_MODULE}.{CASE_RUNNER_FUNCTION} and "
                f"{SUITE_RUNNER_MODULE}.{SUITE_RUNNER_FUNCTION} before executing real runs. "
                "Use --dry-run to validate CLI configuration only."
            ) from exc
        raise

    function = getattr(module, function_name, None)
    if function is None or not callable(function):
        raise UsageError(
            f"Runner backend '{module_name}' does not expose callable '{function_name}'."
        )

    return function


def _normalize_backend_result(raw_result: Any) -> dict[str, Any]:
    """Convert backend return values into a plain mapping for display."""
    if raw_result is None:
        return {"status": "completed"}
    if isinstance(raw_result, Mapping):
        return dict(raw_result)
    if is_dataclass(raw_result):
        return asdict(raw_result)
    if hasattr(raw_result, "model_dump"):
        dumped = raw_result.model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(raw_result, "dict"):
        dumped = raw_result.dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)

    return {"status": "completed", "repr": repr(raw_result)}


def _extract_case_count(details: Mapping[str, Any], *, fallback: int) -> int:
    """Extract a case count from backend details."""
    for key in ("case_count", "cases", "total_cases", "n_cases"):
        value = details.get(key)
        if isinstance(value, int) and value >= 0:
            return value
    return fallback


def _config_to_public_dict(config: RunCliConfig) -> dict[str, Any]:
    """Return a JSON-serializable view of the resolved configuration."""
    return {
        "target": {
            "kind": config.target.kind.value,
            "path": config.target.path.as_posix(),
            "case_count": config.target.case_count,
            "case_files": [path.as_posix() for path in config.target.case_files],
        },
        "output_path": config.output_path.as_posix(),
        "model": config.model,
        "provider": config.provider.value,
        "mitigation": config.mitigation,
        "agent_mode": config.agent_mode,
        "temperature": config.temperature,
        "seed": config.seed,
        "max_steps": config.max_steps,
        "max_tool_calls": config.max_tool_calls,
        "max_tokens_per_response": config.max_tokens_per_response,
        "max_total_tokens": config.max_total_tokens,
        "timeout_seconds": config.timeout_seconds,
        "fail_fast": config.fail_fast,
        "append": config.append,
        "overwrite": config.overwrite,
        "dry_run": config.dry_run,
        "started_at": config.started_at,
    }


def _backend_result_to_mapping(result: BackendCallResult) -> dict[str, Any]:
    """Return a JSON-serializable backend result summary."""
    return {
        "target_kind": result.target_kind,
        "target_path": result.target_path,
        "output_path": result.output_path,
        "model": result.model,
        "mitigation": result.mitigation,
        "case_count": result.case_count,
        "status": result.status,
        "details": dict(result.details),
    }


def _print_run_plan(config: RunCliConfig) -> None:
    """Render the resolved run plan using Rich."""
    table = Table(title="Resolved ASRH Run Plan", show_header=True, header_style="bold")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("target", f"{config.target.kind.value}: {config.target.path}")
    table.add_row("case_count", str(config.target.case_count))
    table.add_row("output", str(config.output_path))
    table.add_row("model", config.model)
    table.add_row("provider", config.provider.value)
    table.add_row("mitigation", config.mitigation)
    table.add_row("agent_mode", config.agent_mode)
    table.add_row("temperature", str(config.temperature))
    table.add_row("seed", "none" if config.seed is None else str(config.seed))
    table.add_row("max_steps", str(config.max_steps))
    table.add_row("max_tool_calls", str(config.max_tool_calls))
    table.add_row("timeout_seconds", str(config.timeout_seconds))
    table.add_row("dry_run", str(config.dry_run).lower())
    console.print(table)


def _print_result_summary(result: BackendCallResult) -> None:
    """Render backend execution summary."""
    details = dict(result.details)
    table = Table(title="ASRH Run Summary", show_header=True, header_style="bold")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("status", result.status)
    table.add_row("target", f"{result.target_kind}: {result.target_path}")
    table.add_row("output", result.output_path)
    table.add_row("model", result.model)
    table.add_row("mitigation", result.mitigation)
    table.add_row("case_count", str(result.case_count))

    for key in (
        "utility_pass_rate",
        "safety_pass_rate",
        "attack_success_rate",
        "unsafe_success_rate",
        "safe_but_useless_rate",
        "over_refusal_rate",
    ):
        value = details.get(key)
        if value is not None:
            table.add_row(key, _format_metric_value(value))

    console.print(table)


def _format_metric_value(value: Any) -> str:
    """Format a metric value for human-readable tables."""
    if isinstance(value, float):
        if 0.0 <= value <= 1.0:
            return f"{value:.1%}"
        return f"{value:.3f}"
    return str(value)


def _print_json(payload: Mapping[str, Any]) -> None:
    """Print a stable JSON payload to stdout."""
    stdout_console.print_json(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _exit_with_cli_error(exc: UsageError | SafetyGateError, *, json_output: bool, debug: bool) -> NoReturn:
    """Print a user-facing CLI error and exit with its stable code."""
    if debug:
        raise exc

    payload = {
        "error": exc.__class__.__name__,
        "message": str(exc),
        "exit_code": int(exc.exit_code),
    }
    if json_output:
        _print_json(payload)
    else:
        console.print(Panel(str(exc), title=f"{exc.__class__.__name__}", style="red"))
    raise typer.Exit(code=int(exc.exit_code))


def _exit_with_internal_error(exc: Exception, *, json_output: bool) -> NoReturn:
    """Print an internal error without a traceback and exit."""
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


def _utc_now_iso() -> str:
    """Return the current UTC time in trace-friendly ISO-8601 format."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main(argv: Sequence[str] | None = None) -> None:
    """Entrypoint for ``python -m asrh.cli.run`` and tests.

    Typer reads ``sys.argv`` by default. The optional ``argv`` argument exists
    for unit tests that want to patch process arguments before invoking the app.
    """
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
    "BackendCallResult",
    "ProviderKind",
    "RunCliConfig",
    "RunTarget",
    "TargetKind",
    "app",
    "main",
    "run_command",
)


if __name__ == "__main__":
    main()
