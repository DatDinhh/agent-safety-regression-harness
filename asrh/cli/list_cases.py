"""Case-inventory command for ASRH.

This module owns the public ``asrh-list-cases`` console entry point and the
``python -m asrh.cli.list_cases`` execution path. It discovers YAML test cases,
extracts lightweight metadata, and prints an inventory without requiring the
full case-schema package to be implemented.

The command is deliberately read-only. It does not validate every schema rule;
that is the job of ``asrh.cli.validate_cases``. It does, however, surface YAML
parse failures and basic metadata gaps so a broken case catalog is visible early.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, NoReturn

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from asrh import SUPPORTED_SUITES
from asrh.cli import (
    DEFAULTS,
    DEFAULT_OUTPUT_ENCODING,
    ExitCode,
    UsageError,
    ValidationCliError,
    build_version_banner,
)

APP_NAME: Final[str] = "asrh-list-cases"
APP_HELP: Final[str] = "List discovered ASRH YAML cases and suite counts."
APP_EPILOG: Final[str] = (
    "Examples:\n"
    "  python -m asrh.cli.list_cases --suite suites\n"
    "  python -m asrh.cli.list_cases --suite suites --category secret_exfiltration --show-tags\n"
    "  python -m asrh.cli.list_cases --suite suites --json"
)
DEFAULT_ENV_FILE: Final[Path] = Path(".env")
CASE_SUFFIXES: Final[frozenset[str]] = frozenset({".yaml", ".yml"})
UNKNOWN_VALUE: Final[str] = "unknown"

console: Final[Console] = Console(stderr=True)
stdout_console: Final[Console] = Console()


class CaseInventoryStatus(StrEnum):
    """Status of a discovered YAML case file."""

    LOADED = "loaded"
    MALFORMED = "malformed"
    EMPTY = "empty"


@dataclass(frozen=True, slots=True)
class CaseInventoryItem:
    """Lightweight metadata for one discovered case file."""

    path: str
    suite: str
    case_id: str
    version: str
    category: str
    severity: str
    title: str
    tags: tuple[str, ...]
    status: CaseInventoryStatus
    error: str | None = None


@dataclass(frozen=True, slots=True)
class CaseInventory:
    """Complete list-cases result."""

    root: str
    case_count: int
    malformed_count: int
    categories: dict[str, int]
    severities: dict[str, int]
    suites: dict[str, int]
    items: tuple[CaseInventoryItem, ...]


app = typer.Typer(
    name=APP_NAME,
    help=APP_HELP,
    epilog=APP_EPILOG,
    no_args_is_help=False,
    rich_markup_mode="rich",
    add_completion=False,
)


@app.command(help=APP_HELP, epilog=APP_EPILOG)
def list_cases_command(
    suite_path: Annotated[
        Path,
        typer.Option(
            "--suite",
            dir_okay=True,
            file_okay=False,
            resolve_path=False,
            help="Suite directory or top-level suites directory to inspect.",
        ),
    ] = DEFAULTS.suite_dir,
    category: Annotated[
        str | None,
        typer.Option("--category", help="Only show cases whose metadata.category matches this value."),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option("--severity", help="Only show cases whose metadata.severity matches this value."),
    ] = None,
    tag: Annotated[
        str | None,
        typer.Option("--tag", help="Only show cases containing this metadata tag."),
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option("--limit", min=1, help="Maximum number of case rows to display."),
    ] = None,
    show_tags: Annotated[
        bool,
        typer.Option("--show-tags", help="Include metadata tags in the human-readable table."),
    ] = False,
    summary_only: Annotated[
        bool,
        typer.Option("--summary-only", help="Print only suite/category/severity counts."),
    ] = False,
    absolute_paths: Annotated[
        bool,
        typer.Option("--absolute-paths", help="Print absolute paths instead of repository-relative paths."),
    ] = False,
    include_hidden: Annotated[
        bool,
        typer.Option("--include-hidden", help="Include hidden directories and files in discovery."),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit non-zero if any discovered YAML file is malformed."),
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
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print machine-readable JSON inventory to stdout."),
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
    """List ASRH case files and extracted metadata."""
    if version:
        stdout_console.print(build_version_banner())
        raise typer.Exit(code=int(ExitCode.OK))

    try:
        _load_env_file(env_file)
        inventory = build_inventory(
            suite_path=suite_path,
            category=category,
            severity=severity,
            tag=tag,
            absolute_paths=absolute_paths,
            include_hidden=include_hidden,
        )

        if strict and inventory.malformed_count > 0:
            raise ValidationCliError(
                f"Discovered {inventory.malformed_count} malformed YAML case file(s)."
            )

        if json_output:
            _print_json(_inventory_to_mapping(inventory))
        elif not quiet:
            _print_inventory(inventory, show_tags=show_tags, summary_only=summary_only, limit=limit)

        raise typer.Exit(code=int(ExitCode.OK))

    except typer.Exit:
        raise
    except (UsageError, ValidationCliError) as exc:
        _exit_with_cli_error(exc, json_output=json_output, debug=debug)
    except Exception as exc:  # noqa: BLE001 - CLI must convert uncaught errors to stable exits.
        if debug:
            raise
        _exit_with_internal_error(exc, json_output=json_output)


def build_inventory(
    *,
    suite_path: Path,
    category: str | None = None,
    severity: str | None = None,
    tag: str | None = None,
    absolute_paths: bool = False,
    include_hidden: bool = False,
) -> CaseInventory:
    """Build a lightweight inventory from a suite or top-level suites directory."""
    root = suite_path.expanduser()
    if not root.exists():
        raise UsageError(f"Suite directory does not exist: {root}")
    if not root.is_dir():
        raise UsageError(f"--suite must point to a directory: {root}")

    case_files = _discover_case_files(root, include_hidden=include_hidden)
    if not case_files:
        raise UsageError(f"No YAML case files found under suite directory: {root}")

    items = tuple(
        item
        for item in (_read_case_inventory_item(path, root=root, absolute_paths=absolute_paths) for path in case_files)
        if _matches_filters(item, category=category, severity=severity, tag=tag)
    )

    categories = Counter(item.category for item in items)
    severities = Counter(item.severity for item in items)
    suites = Counter(item.suite for item in items)
    malformed_count = sum(1 for item in items if item.status is not CaseInventoryStatus.LOADED)

    return CaseInventory(
        root=root.as_posix(),
        case_count=len(items),
        malformed_count=malformed_count,
        categories=dict(sorted(categories.items())),
        severities=dict(sorted(severities.items())),
        suites=dict(sorted(suites.items())),
        items=items,
    )


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


def _read_case_inventory_item(path: Path, *, root: Path, absolute_paths: bool) -> CaseInventoryItem:
    """Read lightweight metadata from one YAML file."""
    display_path = path.resolve().as_posix() if absolute_paths else _relative_path(path)
    suite = _infer_suite(path=path, root=root)

    try:
        raw = yaml.safe_load(path.read_text(encoding=DEFAULT_OUTPUT_ENCODING))
    except (OSError, yaml.YAMLError) as exc:
        return CaseInventoryItem(
            path=display_path,
            suite=suite,
            case_id=path.stem,
            version=UNKNOWN_VALUE,
            category=UNKNOWN_VALUE,
            severity=UNKNOWN_VALUE,
            title=UNKNOWN_VALUE,
            tags=(),
            status=CaseInventoryStatus.MALFORMED,
            error=str(exc),
        )

    if raw is None:
        return CaseInventoryItem(
            path=display_path,
            suite=suite,
            case_id=path.stem,
            version=UNKNOWN_VALUE,
            category=UNKNOWN_VALUE,
            severity=UNKNOWN_VALUE,
            title=UNKNOWN_VALUE,
            tags=(),
            status=CaseInventoryStatus.EMPTY,
            error="empty YAML document",
        )

    if not isinstance(raw, dict):
        return CaseInventoryItem(
            path=display_path,
            suite=suite,
            case_id=path.stem,
            version=UNKNOWN_VALUE,
            category=UNKNOWN_VALUE,
            severity=UNKNOWN_VALUE,
            title=UNKNOWN_VALUE,
            tags=(),
            status=CaseInventoryStatus.MALFORMED,
            error="top-level YAML document is not a mapping",
        )

    metadata = raw.get("metadata")
    metadata_map = metadata if isinstance(metadata, dict) else {}
    tags = metadata_map.get("tags", [])
    normalized_tags = tuple(str(item) for item in tags) if isinstance(tags, list) else ()

    return CaseInventoryItem(
        path=display_path,
        suite=suite,
        case_id=str(raw.get("id") or path.stem),
        version=str(raw.get("version") or UNKNOWN_VALUE),
        category=str(metadata_map.get("category") or suite or UNKNOWN_VALUE),
        severity=str(metadata_map.get("severity") or UNKNOWN_VALUE),
        title=str(metadata_map.get("title") or UNKNOWN_VALUE),
        tags=normalized_tags,
        status=CaseInventoryStatus.LOADED,
        error=None,
    )


def _matches_filters(
    item: CaseInventoryItem, *, category: str | None, severity: str | None, tag: str | None
) -> bool:
    """Return whether an inventory item matches requested filters."""
    if category is not None and item.category != category:
        return False
    if severity is not None and item.severity != severity:
        return False
    if tag is not None and tag not in item.tags:
        return False
    return True


def _infer_suite(*, path: Path, root: Path) -> str:
    """Infer suite name from path and root."""
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
    """Return a best-effort relative path for display."""
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def _inventory_to_mapping(inventory: CaseInventory) -> dict[str, Any]:
    """Return JSON-serializable inventory data."""
    return {
        "root": inventory.root,
        "case_count": inventory.case_count,
        "malformed_count": inventory.malformed_count,
        "categories": inventory.categories,
        "severities": inventory.severities,
        "suites": inventory.suites,
        "items": [
            {
                **asdict(item),
                "tags": list(item.tags),
                "status": item.status.value,
            }
            for item in inventory.items
        ],
    }


def _print_inventory(
    inventory: CaseInventory, *, show_tags: bool, summary_only: bool, limit: int | None
) -> None:
    """Print suite summary and optional case table."""
    _print_summary_table(inventory)

    if summary_only:
        return

    rows = inventory.items if limit is None else inventory.items[:limit]
    table = Table(title="ASRH Case Inventory", show_header=True, header_style="bold")
    table.add_column("Case ID", style="bold")
    table.add_column("Suite")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Title")
    if show_tags:
        table.add_column("Tags")
    table.add_column("Status")
    table.add_column("Path")

    for item in rows:
        status_style = "green" if item.status is CaseInventoryStatus.LOADED else "red"
        table.add_row(
            item.case_id,
            item.suite,
            item.category,
            item.severity,
            _truncate(item.title, 64),
            *( [", ".join(item.tags) or "-"] if show_tags else [] ),
            f"[{status_style}]{item.status.value}[/{status_style}]",
            item.path,
        )

    console.print(table)
    if limit is not None and inventory.case_count > limit:
        console.print(f"[yellow]Showing {limit} of {inventory.case_count} cases.[/yellow]")
    if inventory.malformed_count:
        console.print(
            f"[yellow]Warning:[/yellow] {inventory.malformed_count} malformed or empty YAML file(s) discovered. "
            "Run asrh-validate-cases for details."
        )


def _print_summary_table(inventory: CaseInventory) -> None:
    """Print compact inventory counts."""
    table = Table(title="ASRH Case Summary", show_header=True, header_style="bold")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("root", inventory.root)
    table.add_row("case_count", str(inventory.case_count))
    table.add_row("malformed_count", str(inventory.malformed_count))
    table.add_row("suites", _format_counts(inventory.suites))
    table.add_row("categories", _format_counts(inventory.categories))
    table.add_row("severities", _format_counts(inventory.severities))
    console.print(table)


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "-"
    return ", ".join(f"{name}={count}" for name, count in counts.items())


def _truncate(text: str, limit: int) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: max(0, limit - 1)].rstrip() + "…"


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
    """Entrypoint for ``python -m asrh.cli.list_cases`` and tests."""
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
    "CaseInventory",
    "CaseInventoryItem",
    "CaseInventoryStatus",
    "app",
    "build_inventory",
    "list_cases_command",
    "main",
)


if __name__ == "__main__":
    main()
