"""Report-command implementation for ASRH.

This module owns the public ``asrh-report`` console entry point and the
``python -m asrh.cli.report`` execution path. It turns JSONL traces produced by
``asrh.cli.run`` into Markdown reports.

The implementation is intentionally useful before the later ``asrh.report``
package exists. When backend report modules are added, this module can delegate
to them, but the CLI contract stays stable:

- ``--run RUN.jsonl --out REPORT.md`` generates a single-run regression report.
- ``--compare BASELINE.jsonl GUARDED.jsonl --out REPORT.md`` generates a
  baseline-versus-mitigation comparison report.

The report format follows the technical specification: run metadata, executive
summary, results by category and severity, tool-use summary, failure taxonomy,
notable failures, limitations, and next steps.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Final, NoReturn

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from asrh import TRACE_SCHEMA_VERSION, get_version
from asrh.cli import (
    DEFAULT_JSONL_SUFFIX,
    DEFAULT_MARKDOWN_SUFFIX,
    DEFAULT_OUTPUT_ENCODING,
    ExitCode,
    UsageError,
    ValidationCliError,
    build_version_banner,
)

APP_NAME: Final[str] = "asrh-report"
APP_HELP: Final[str] = "Generate Markdown reports from ASRH JSONL run traces."
APP_EPILOG: Final[str] = (
    "Examples:\n"
    "  python -m asrh.cli.report --run runs/all_baseline.jsonl --out reports/all_baseline.md\n"
    "  python -m asrh.cli.report --compare runs/baseline.jsonl runs/tool_policy_guard.jsonl "
    "--out reports/comparison.md"
)
DEFAULT_ENV_FILE: Final[Path] = Path(".env")
MAX_EVIDENCE_CHARS: Final[int] = 240
MAX_TOOL_OUTPUT_CHARS: Final[int] = 160
UNKNOWN_VALUE: Final[str] = "unknown"

console: Final[Console] = Console(stderr=True)
stdout_console: Final[Console] = Console()


@dataclass(frozen=True, slots=True)
class TraceLoadResult:
    """Loaded trace records and source metadata."""

    path: Path
    records: tuple[dict[str, Any], ...]
    line_count: int


@dataclass(frozen=True, slots=True)
class RunMetrics:
    """Computed metrics for one JSONL run."""

    path: Path
    total_cases: int
    run_ids: tuple[str, ...]
    model: str
    mitigation: str
    suite: str
    timestamp: str
    utility_pass_rate: float
    safety_pass_rate: float
    attack_success_rate: float
    unsafe_success_rate: float
    safe_but_useless_rate: float
    over_refusal_rate: float
    average_tool_calls: float
    average_policy_violations: float
    by_category: Mapping[str, Mapping[str, Any]]
    by_severity: Mapping[str, Mapping[str, Any]]
    by_tool: Mapping[str, Mapping[str, int]]
    failure_taxonomy: Mapping[str, Mapping[str, Any]]
    notable_failures: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class ReportWriteResult:
    """Summary returned after writing a Markdown report."""

    output_path: Path
    report_type: str
    total_cases: int
    compared_runs: int


app = typer.Typer(
    name=APP_NAME,
    help=APP_HELP,
    epilog=APP_EPILOG,
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)


@app.command(help=APP_HELP, epilog=APP_EPILOG, no_args_is_help=True)
def report_command(
    run_path: Annotated[
        Path | None,
        typer.Option(
            "--run",
            dir_okay=False,
            file_okay=True,
            resolve_path=False,
            help="Path to one JSONL run trace file. Mutually exclusive with --compare.",
        ),
    ] = None,
    compare_paths: Annotated[
        tuple[Path, Path] | None,
        typer.Option(
            "--compare",
            metavar="BASELINE_JSONL GUARDED_JSONL",
            help="Two JSONL run files to compare: baseline first, guarded/variant second.",
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
            help="Markdown output path. Required.",
        ),
    ] = None,
    max_failures: Annotated[
        int,
        typer.Option("--max-failures", min=0, help="Maximum notable failures to include."),
    ] = 8,
    include_traces: Annotated[
        bool,
        typer.Option("--include-traces", help="Include compact tool-call traces for notable failures."),
    ] = True,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Overwrite an existing Markdown report."),
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
        typer.Option("--json", help="Print a machine-readable report summary to stdout."),
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
    """Generate a Markdown regression or comparison report."""
    if version:
        stdout_console.print(build_version_banner())
        raise typer.Exit(code=int(ExitCode.OK))

    try:
        _load_env_file(env_file)
        output = _resolve_output_path(output_path=output_path, overwrite=overwrite)

        if run_path is not None and compare_paths is not None:
            raise UsageError("--run and --compare are mutually exclusive.")
        if run_path is None and compare_paths is None:
            raise UsageError("Specify exactly one report target: --run PATH or --compare BASELINE GUARDED.")

        if run_path is not None:
            result = _generate_single_run_report(
                run_path=run_path,
                output_path=output,
                max_failures=max_failures,
                include_traces=include_traces,
            )
        else:
            assert compare_paths is not None
            result = _generate_comparison_report(
                baseline_path=compare_paths[0],
                variant_path=compare_paths[1],
                output_path=output,
                max_failures=max_failures,
                include_traces=include_traces,
            )

        if json_output:
            _print_json(_result_to_mapping(result))
        elif not quiet:
            _print_result(result)

        raise typer.Exit(code=int(ExitCode.OK))

    except typer.Exit:
        raise
    except (UsageError, ValidationCliError) as exc:
        _exit_with_cli_error(exc, json_output=json_output, debug=debug)
    except Exception as exc:  # noqa: BLE001 - CLI must convert uncaught errors to stable exits.
        if debug:
            raise
        _exit_with_internal_error(exc, json_output=json_output)


def _load_env_file(env_file: Path | None) -> None:
    """Load a dotenv file if one exists."""
    if env_file is not None and env_file.exists():
        load_dotenv(dotenv_path=env_file, override=False)


def _resolve_output_path(*, output_path: Path | None, overwrite: bool) -> Path:
    """Validate and prepare the Markdown output path."""
    if output_path is None:
        raise UsageError("--out is required for report generation.")

    path = output_path.expanduser()
    if path.suffix.lower() != DEFAULT_MARKDOWN_SUFFIX:
        raise UsageError(f"Report output must use the {DEFAULT_MARKDOWN_SUFFIX} suffix: {path}")
    if path.exists() and path.is_dir():
        raise UsageError(f"Report output path points to a directory: {path}")
    if path.exists() and not overwrite:
        raise UsageError(f"Report output already exists: {path}. Use --overwrite to replace it.")

    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _generate_single_run_report(
    *,
    run_path: Path,
    output_path: Path,
    max_failures: int,
    include_traces: bool,
) -> ReportWriteResult:
    """Generate and write a single-run regression report."""
    trace = _load_jsonl_trace(run_path)
    metrics = _compute_run_metrics(trace, max_failures=max_failures)
    markdown = _render_single_run_markdown(metrics=metrics, include_traces=include_traces)
    output_path.write_text(markdown, encoding=DEFAULT_OUTPUT_ENCODING)
    return ReportWriteResult(
        output_path=output_path,
        report_type="single-run",
        total_cases=metrics.total_cases,
        compared_runs=1,
    )


def _generate_comparison_report(
    *,
    baseline_path: Path,
    variant_path: Path,
    output_path: Path,
    max_failures: int,
    include_traces: bool,
) -> ReportWriteResult:
    """Generate and write a two-run comparison report."""
    baseline_trace = _load_jsonl_trace(baseline_path)
    variant_trace = _load_jsonl_trace(variant_path)
    baseline_metrics = _compute_run_metrics(baseline_trace, max_failures=max_failures)
    variant_metrics = _compute_run_metrics(variant_trace, max_failures=max_failures)
    markdown = _render_comparison_markdown(
        baseline=baseline_metrics,
        variant=variant_metrics,
        include_traces=include_traces,
    )
    output_path.write_text(markdown, encoding=DEFAULT_OUTPUT_ENCODING)
    return ReportWriteResult(
        output_path=output_path,
        report_type="comparison",
        total_cases=max(baseline_metrics.total_cases, variant_metrics.total_cases),
        compared_runs=2,
    )


def _load_jsonl_trace(path: Path) -> TraceLoadResult:
    """Load a JSONL run trace into dictionaries with strict line-level errors."""
    resolved = path.expanduser()
    if not resolved.exists():
        raise UsageError(f"Run trace does not exist: {resolved}")
    if not resolved.is_file():
        raise UsageError(f"Run trace path is not a file: {resolved}")
    if resolved.suffix.lower() != DEFAULT_JSONL_SUFFIX:
        raise UsageError(f"Run trace must use the {DEFAULT_JSONL_SUFFIX} suffix: {resolved}")

    records: list[dict[str, Any]] = []
    line_count = 0
    with resolved.open("r", encoding=DEFAULT_OUTPUT_ENCODING) as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line_count = line_number
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                decoded = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValidationCliError(
                    f"Invalid JSON in {resolved} at line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(decoded, dict):
                raise ValidationCliError(
                    f"Invalid JSONL record in {resolved} at line {line_number}: expected object."
                )
            records.append(decoded)

    if not records:
        raise ValidationCliError(f"Run trace contains no JSON records: {resolved}")

    return TraceLoadResult(path=resolved, records=tuple(records), line_count=line_count)


def _compute_run_metrics(trace: TraceLoadResult, *, max_failures: int) -> RunMetrics:
    """Compute summary metrics required by the ASRH report specification."""
    records = trace.records
    total_cases = len(records)
    utility_passes = sum(1 for record in records if _record_bool(record, "utility_pass"))
    safety_passes = sum(1 for record in records if _record_bool(record, "safety_pass"))
    attack_successes = sum(1 for record in records if _record_bool(record, "attack_success"))
    unsafe_successes = sum(1 for record in records if _overall(record) == "UNSAFE_SUCCESS")
    safe_but_useless = sum(1 for record in records if _overall(record) == "SAFE_BUT_USELESS")
    over_refusals = sum(1 for record in records if _record_has_failure_class(record, "OVER_REFUSAL"))
    tool_call_counts = [_tool_call_count(record) for record in records]
    policy_violation_counts = [_policy_violation_count(record) for record in records]

    return RunMetrics(
        path=trace.path,
        total_cases=total_cases,
        run_ids=_unique_values(records, "run_id"),
        model=_common_value(records, "model"),
        mitigation=_common_value(records, "mitigation"),
        suite=_common_value(records, "suite"),
        timestamp=_common_timestamp(records),
        utility_pass_rate=_rate(utility_passes, total_cases),
        safety_pass_rate=_rate(safety_passes, total_cases),
        attack_success_rate=_rate(attack_successes, total_cases),
        unsafe_success_rate=_rate(unsafe_successes, total_cases),
        safe_but_useless_rate=_rate(safe_but_useless, total_cases),
        over_refusal_rate=_rate(over_refusals, total_cases),
        average_tool_calls=_average(tool_call_counts),
        average_policy_violations=_average(policy_violation_counts),
        by_category=_compute_group_metrics(records, key_fn=_category),
        by_severity=_compute_group_metrics(records, key_fn=_severity),
        by_tool=_compute_tool_metrics(records),
        failure_taxonomy=_compute_failure_taxonomy(records),
        notable_failures=_select_notable_failures(records, max_failures=max_failures),
    )


def _compute_group_metrics(
    records: Sequence[Mapping[str, Any]], *, key_fn: Any
) -> Mapping[str, Mapping[str, Any]]:
    """Compute per-category or per-severity metrics."""
    buckets: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for record in records:
        buckets[str(key_fn(record) or UNKNOWN_VALUE)].append(record)

    output: dict[str, dict[str, Any]] = {}
    for name, bucket in sorted(buckets.items(), key=lambda item: item[0]):
        n = len(bucket)
        failure_classes = Counter(_iter_failed_failure_classes(bucket))
        top_failure = failure_classes.most_common(1)[0][0] if failure_classes else "-"
        output[name] = {
            "n": n,
            "utility_pass_rate": _rate(sum(1 for record in bucket if _record_bool(record, "utility_pass")), n),
            "safety_pass_rate": _rate(sum(1 for record in bucket if _record_bool(record, "safety_pass")), n),
            "attack_success_rate": _rate(sum(1 for record in bucket if _record_bool(record, "attack_success")), n),
            "top_failure": top_failure,
        }
    return output


def _compute_tool_metrics(records: Sequence[Mapping[str, Any]]) -> Mapping[str, Mapping[str, int]]:
    """Compute per-tool call, blocked, and policy-violation counts."""
    tools: dict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        for call in _tool_calls(record):
            tool_name = str(call.get("tool") or call.get("tool_name") or UNKNOWN_VALUE)
            tools[tool_name]["calls"] += 1
            if call.get("allowed") is False:
                tools[tool_name]["blocked"] += 1
            if call.get("policy_violation") is True:
                tools[tool_name]["policy_violations"] += 1
            labels = call.get("accessed_labels", [])
            if isinstance(labels, list) and any("trust:sensitive" in str(label) for label in labels):
                tools[tool_name]["sensitive_accesses"] += 1

    return {
        tool: {
            "calls": counter.get("calls", 0),
            "blocked": counter.get("blocked", 0),
            "policy_violations": counter.get("policy_violations", 0),
            "sensitive_accesses": counter.get("sensitive_accesses", 0),
        }
        for tool, counter in sorted(tools.items(), key=lambda item: item[0])
    }


def _compute_failure_taxonomy(records: Sequence[Mapping[str, Any]]) -> Mapping[str, Mapping[str, Any]]:
    """Count failed checker classes and retain one example case for each."""
    counts: Counter[str] = Counter()
    examples: dict[str, str] = {}

    for record in records:
        case_id = _case_id(record)
        for failure_class in _failed_failure_classes(record):
            counts[failure_class] += 1
            examples.setdefault(failure_class, case_id)

    return {
        failure_class: {"count": counts[failure_class], "example_case": examples.get(failure_class, "-")}
        for failure_class in sorted(counts, key=lambda item: (-counts[item], item))
    }


def _select_notable_failures(
    records: Sequence[Mapping[str, Any]], *, max_failures: int
) -> tuple[dict[str, Any], ...]:
    """Select the most useful failed records for manual inspection."""
    if max_failures <= 0:
        return ()

    failed = [record for record in records if not _record_bool(record, "safety_pass") or not _record_bool(record, "utility_pass")]
    failed.sort(key=lambda record: (_severity_rank(_severity(record)), _case_id(record)), reverse=True)
    return tuple(dict(record) for record in failed[:max_failures])


def _render_single_run_markdown(*, metrics: RunMetrics, include_traces: bool) -> str:
    """Render the Markdown single-run report."""
    lines: list[str] = [
        "# ASRH Regression Report",
        "",
        "## Run Metadata",
        "",
        f"- Run ID: {_join_values(metrics.run_ids)}",
        f"- Model: {metrics.model}",
        f"- Mitigation: {metrics.mitigation}",
        f"- Suite: {metrics.suite}",
        f"- Total cases: {metrics.total_cases}",
        f"- Timestamp: {metrics.timestamp}",
        f"- Trace file: `{metrics.path.as_posix()}`",
        f"- Trace schema version: {TRACE_SCHEMA_VERSION}",
        f"- ASRH version: {get_version()}",
        "",
        "## Executive Summary",
        "",
        f"- Utility pass rate: {_pct(metrics.utility_pass_rate)}",
        f"- Safety pass rate: {_pct(metrics.safety_pass_rate)}",
        f"- Attack success rate: {_pct(metrics.attack_success_rate)}",
        f"- Unsafe-success rate: {_pct(metrics.unsafe_success_rate)}",
        f"- Safe-but-useless rate: {_pct(metrics.safe_but_useless_rate)}",
        f"- Over-refusal rate: {_pct(metrics.over_refusal_rate)}",
        f"- Average tool calls per case: {metrics.average_tool_calls:.2f}",
        f"- Average policy violations per case: {metrics.average_policy_violations:.2f}",
        "",
        "## Results by Category",
        "",
        _category_table(metrics.by_category),
        "",
        "## Results by Severity",
        "",
        _severity_table(metrics.by_severity),
        "",
        "## Tool Use Summary",
        "",
        _tool_table(metrics.by_tool),
        "",
        "## Failure Taxonomy",
        "",
        _failure_table(metrics.failure_taxonomy),
        "",
        "## Notable Failures",
        "",
        _notable_failures_markdown(metrics.notable_failures, include_traces=include_traces),
        "",
        "## Limitations",
        "",
        "- Metrics are derived from JSONL trace fields and deterministic checker outputs.",
        "- Missing fields are reported as `unknown` rather than inferred.",
        "- String-based checkers can miss paraphrased or indirect disclosures.",
        "- Utility checks based on required evidence are intentionally crude for MVP reproducibility.",
        "",
        "## Next Steps",
        "",
        "- Inspect notable failures and update checkers or cases only when the trace supports the change.",
        "- Compare this run against a guarded mitigation mode before claiming safety improvement.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _render_comparison_markdown(
    *, baseline: RunMetrics, variant: RunMetrics, include_traces: bool
) -> str:
    """Render a baseline-versus-variant Markdown report."""
    lines: list[str] = [
        "# ASRH Mitigation Comparison Report",
        "",
        "## Compared Runs",
        "",
        "| Mode | Model | Cases | Trace |",
        "|---|---|---:|---|",
        f"| {baseline.mitigation} | {baseline.model} | {baseline.total_cases} | `{baseline.path.as_posix()}` |",
        f"| {variant.mitigation} | {variant.model} | {variant.total_cases} | `{variant.path.as_posix()}` |",
        "",
        "## Summary",
        "",
        "| Mode | Utility Pass | Safety Pass | Attack Success | Over-refusal | Avg Tool Calls |",
        "|---|---:|---:|---:|---:|---:|",
        _comparison_summary_row(baseline),
        _comparison_summary_row(variant),
        "",
        "## Delta vs Baseline",
        "",
        "| Mode | Delta Utility | Delta Safety | Delta Attack Success | Delta Over-refusal | Delta Avg Tool Calls |",
        "|---|---:|---:|---:|---:|---:|",
        _delta_row(baseline=baseline, variant=variant),
        "",
        "## Failure Taxonomy Delta",
        "",
        _failure_delta_table(baseline=baseline, variant=variant),
        "",
        "## Interpretation",
        "",
        _comparison_interpretation(baseline=baseline, variant=variant),
        "",
        "## Variant Notable Failures",
        "",
        _notable_failures_markdown(variant.notable_failures, include_traces=include_traces),
        "",
        "## Limitations",
        "",
        "- This comparison is descriptive. It does not prove statistical significance.",
        "- Case sets should match before interpreting mitigation deltas.",
        "- Tool-policy guards can improve safety by blocking actions too aggressively, so utility deltas matter.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _category_table(by_category: Mapping[str, Mapping[str, Any]]) -> str:
    rows = ["| Category | N | Utility Pass | Safety Pass | Attack Success | Top Failure |", "|---|---:|---:|---:|---:|---|"]
    for category, metrics in by_category.items():
        rows.append(
            "| {category} | {n} | {utility} | {safety} | {attack} | {failure} |".format(
                category=_md_escape(category),
                n=metrics["n"],
                utility=_pct(metrics["utility_pass_rate"]),
                safety=_pct(metrics["safety_pass_rate"]),
                attack=_pct(metrics["attack_success_rate"]),
                failure=_md_escape(str(metrics["top_failure"])),
            )
        )
    return "\n".join(rows)


def _severity_table(by_severity: Mapping[str, Mapping[str, Any]]) -> str:
    rows = ["| Severity | N | Safety Pass | Attack Success | Top Failure |", "|---|---:|---:|---:|---|"]
    for severity, metrics in sorted(by_severity.items(), key=lambda item: _severity_sort_key(item[0])):
        rows.append(
            "| {severity} | {n} | {safety} | {attack} | {failure} |".format(
                severity=_md_escape(severity),
                n=metrics["n"],
                safety=_pct(metrics["safety_pass_rate"]),
                attack=_pct(metrics["attack_success_rate"]),
                failure=_md_escape(str(metrics["top_failure"])),
            )
        )
    return "\n".join(rows)


def _tool_table(by_tool: Mapping[str, Mapping[str, int]]) -> str:
    if not by_tool:
        return "No tool calls recorded."

    rows = [
        "| Tool | Calls | Blocked | Policy Violations | Sensitive Accesses |",
        "|---|---:|---:|---:|---:|",
    ]
    for tool_name, metrics in by_tool.items():
        rows.append(
            f"| {_md_escape(tool_name)} | {metrics['calls']} | {metrics['blocked']} | "
            f"{metrics['policy_violations']} | {metrics['sensitive_accesses']} |"
        )
    return "\n".join(rows)


def _failure_table(failure_taxonomy: Mapping[str, Mapping[str, Any]]) -> str:
    if not failure_taxonomy:
        return "No failed checker classes recorded."

    rows = ["| Failure Class | Count | Example Case |", "|---|---:|---|"]
    for failure_class, metrics in failure_taxonomy.items():
        rows.append(
            f"| {_md_escape(failure_class)} | {metrics['count']} | {_md_escape(str(metrics['example_case']))} |"
        )
    return "\n".join(rows)


def _failure_delta_table(*, baseline: RunMetrics, variant: RunMetrics) -> str:
    all_classes = sorted(set(baseline.failure_taxonomy) | set(variant.failure_taxonomy))
    if not all_classes:
        return "No failed checker classes recorded in either run."

    rows = ["| Failure Class | Baseline | Variant | Delta |", "|---|---:|---:|---:|"]
    for failure_class in all_classes:
        base_count = int(baseline.failure_taxonomy.get(failure_class, {}).get("count", 0))
        variant_count = int(variant.failure_taxonomy.get(failure_class, {}).get("count", 0))
        rows.append(
            f"| {_md_escape(failure_class)} | {base_count} | {variant_count} | {variant_count - base_count:+d} |"
        )
    return "\n".join(rows)


def _notable_failures_markdown(records: Sequence[Mapping[str, Any]], *, include_traces: bool) -> str:
    if not records:
        return "No notable failures selected."

    sections: list[str] = []
    for record in records:
        failed_checks = [check for check in _checker_results(record) if check.get("passed") is False]
        first_failure = failed_checks[0] if failed_checks else {}
        sections.extend(
            [
                f"### {_md_escape(_case_id(record))}",
                "",
                f"- Category: {_md_escape(_category(record))}",
                f"- Severity: {_md_escape(_severity(record))}",
                f"- Overall verdict: {_md_escape(_overall(record))}",
                f"- User goal: {_md_escape(_user_goal(record))}",
                f"- Attack: {_md_escape(_attack_summary(record))}",
                f"- Checker failure: {_md_escape(str(first_failure.get('checker') or first_failure.get('checker_name') or '-'))}",
                f"- Failure class: {_md_escape(str(first_failure.get('failure_class') or '-'))}",
                f"- Evidence: {_md_escape(_compact_evidence(first_failure))}",
            ]
        )
        if include_traces:
            sections.extend(["", "Tool trace:", "", _compact_tool_trace(record)])
        sections.append("")
    return "\n".join(sections).rstrip()


def _comparison_summary_row(metrics: RunMetrics) -> str:
    return (
        f"| {_md_escape(metrics.mitigation)} | {_pct(metrics.utility_pass_rate)} | "
        f"{_pct(metrics.safety_pass_rate)} | {_pct(metrics.attack_success_rate)} | "
        f"{_pct(metrics.over_refusal_rate)} | {metrics.average_tool_calls:.2f} |"
    )


def _delta_row(*, baseline: RunMetrics, variant: RunMetrics) -> str:
    return (
        f"| {_md_escape(variant.mitigation)} | {_signed_pct(variant.utility_pass_rate - baseline.utility_pass_rate)} | "
        f"{_signed_pct(variant.safety_pass_rate - baseline.safety_pass_rate)} | "
        f"{_signed_pct(variant.attack_success_rate - baseline.attack_success_rate)} | "
        f"{_signed_pct(variant.over_refusal_rate - baseline.over_refusal_rate)} | "
        f"{variant.average_tool_calls - baseline.average_tool_calls:+.2f} |"
    )


def _comparison_interpretation(*, baseline: RunMetrics, variant: RunMetrics) -> str:
    lines: list[str] = []
    safety_delta = variant.safety_pass_rate - baseline.safety_pass_rate
    utility_delta = variant.utility_pass_rate - baseline.utility_pass_rate
    attack_delta = variant.attack_success_rate - baseline.attack_success_rate

    if safety_delta > 0:
        lines.append(f"- Safety pass rate increased by {_pct(abs(safety_delta))}.")
    elif safety_delta < 0:
        lines.append(f"- Safety pass rate decreased by {_pct(abs(safety_delta))}.")
    else:
        lines.append("- Safety pass rate did not change.")

    if utility_delta > 0:
        lines.append(f"- Utility pass rate increased by {_pct(abs(utility_delta))}.")
    elif utility_delta < 0:
        lines.append(f"- Utility pass rate decreased by {_pct(abs(utility_delta))}.")
    else:
        lines.append("- Utility pass rate did not change.")

    if attack_delta < 0:
        lines.append(f"- Attack success rate decreased by {_pct(abs(attack_delta))}.")
    elif attack_delta > 0:
        lines.append(f"- Attack success rate increased by {_pct(abs(attack_delta))}.")
    else:
        lines.append("- Attack success rate did not change.")

    if variant.total_cases != baseline.total_cases:
        lines.append(
            f"- Case counts differ: baseline has {baseline.total_cases}, variant has {variant.total_cases}. "
            "Interpret deltas cautiously."
        )

    return "\n".join(lines)


def _record_bool(record: Mapping[str, Any], field: str) -> bool:
    verdict = record.get("verdict")
    if isinstance(verdict, Mapping) and isinstance(verdict.get(field), bool):
        return bool(verdict[field])
    if isinstance(record.get(field), bool):
        return bool(record[field])
    if field == "attack_success":
        safety = _record_bool(record, "safety_pass")
        return not safety
    return False


def _overall(record: Mapping[str, Any]) -> str:
    verdict = record.get("verdict")
    if isinstance(verdict, Mapping) and verdict.get("overall") is not None:
        return str(verdict["overall"])
    value = record.get("overall")
    return str(value) if value is not None else UNKNOWN_VALUE


def _category(record: Mapping[str, Any]) -> str:
    metadata = record.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("category") is not None:
        return str(metadata["category"])
    if record.get("suite") is not None:
        return str(record["suite"])
    return UNKNOWN_VALUE


def _severity(record: Mapping[str, Any]) -> str:
    metadata = record.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("severity") is not None:
        return str(metadata["severity"])
    for check in _checker_results(record):
        severity = check.get("severity")
        if severity:
            return str(severity)
    return UNKNOWN_VALUE


def _case_id(record: Mapping[str, Any]) -> str:
    return str(record.get("case_id") or record.get("id") or UNKNOWN_VALUE)


def _user_goal(record: Mapping[str, Any]) -> str:
    task = record.get("task")
    if isinstance(task, Mapping) and task.get("user_goal") is not None:
        return _truncate(str(task["user_goal"]), MAX_EVIDENCE_CHARS)
    return _truncate(str(record.get("user_goal") or UNKNOWN_VALUE), MAX_EVIDENCE_CHARS)


def _attack_summary(record: Mapping[str, Any]) -> str:
    attack = record.get("attack")
    if isinstance(attack, Mapping):
        if attack.get("payload") is not None:
            return _truncate(str(attack["payload"]), MAX_EVIDENCE_CHARS)
        if attack.get("type") is not None:
            return str(attack["type"])
    return UNKNOWN_VALUE


def _checker_results(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = record.get("checker_results")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, Mapping)]


def _tool_calls(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = record.get("tool_calls")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, Mapping)]


def _tool_call_count(record: Mapping[str, Any]) -> int:
    return len(_tool_calls(record))


def _policy_violation_count(record: Mapping[str, Any]) -> int:
    return sum(1 for call in _tool_calls(record) if call.get("policy_violation") is True)


def _failed_failure_classes(record: Mapping[str, Any]) -> tuple[str, ...]:
    classes: list[str] = []
    for check in _checker_results(record):
        if check.get("passed") is False:
            failure_class = check.get("failure_class")
            if failure_class:
                classes.append(str(failure_class))
    if not classes and _overall(record) not in {"PASS", UNKNOWN_VALUE}:
        classes.append(_overall(record))
    return tuple(classes)


def _iter_failed_failure_classes(records: Iterable[Mapping[str, Any]]) -> Iterable[str]:
    for record in records:
        yield from _failed_failure_classes(record)


def _record_has_failure_class(record: Mapping[str, Any], failure_class: str) -> bool:
    return failure_class in _failed_failure_classes(record)


def _unique_values(records: Sequence[Mapping[str, Any]], key: str) -> tuple[str, ...]:
    values = sorted({str(record[key]) for record in records if record.get(key) is not None})
    return tuple(values)


def _common_value(records: Sequence[Mapping[str, Any]], key: str) -> str:
    values = _unique_values(records, key)
    if not values:
        return UNKNOWN_VALUE
    if len(values) == 1:
        return values[0]
    return "mixed"


def _common_timestamp(records: Sequence[Mapping[str, Any]]) -> str:
    for key in ("started_at", "ended_at", "timestamp"):
        values = _unique_values(records, key)
        if values:
            return values[0] if len(values) == 1 else f"{values[0]} ... {values[-1]}"
    return _utc_now_iso()


def _rate(count: int, total: int) -> float:
    return 0.0 if total <= 0 else count / total


def _average(values: Sequence[int]) -> float:
    return 0.0 if not values else sum(values) / len(values)


def _pct(value: float) -> str:
    return f"{value:.1%}"


def _signed_pct(value: float) -> str:
    return f"{value:+.1%}"


def _join_values(values: Sequence[str]) -> str:
    if not values:
        return UNKNOWN_VALUE
    if len(values) <= 3:
        return ", ".join(values)
    return ", ".join(values[:3]) + f", ... (+{len(values) - 3} more)"


def _compact_evidence(check: Mapping[str, Any]) -> str:
    evidence = check.get("evidence")
    if isinstance(evidence, list) and evidence:
        return _truncate("; ".join(str(item) for item in evidence), MAX_EVIDENCE_CHARS)
    explanation = check.get("explanation")
    if explanation:
        return _truncate(str(explanation), MAX_EVIDENCE_CHARS)
    return "-"


def _compact_tool_trace(record: Mapping[str, Any]) -> str:
    calls = _tool_calls(record)
    if not calls:
        return "No tool calls recorded."

    lines = ["```text"]
    for call in calls[:8]:
        step = call.get("step", "?")
        tool = call.get("tool") or call.get("tool_name") or UNKNOWN_VALUE
        allowed = call.get("allowed", UNKNOWN_VALUE)
        violation = call.get("policy_violation", UNKNOWN_VALUE)
        args = _truncate(json.dumps(call.get("args", {}), sort_keys=True, default=str), MAX_TOOL_OUTPUT_CHARS)
        lines.append(f"step={step} tool={tool} allowed={allowed} policy_violation={violation} args={args}")
    if len(calls) > 8:
        lines.append(f"... {len(calls) - 8} more tool calls omitted")
    lines.append("```")
    return "\n".join(lines)


def _severity_rank(severity: str) -> int:
    ranks = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return ranks.get(severity.lower(), 0)


def _severity_sort_key(severity: str) -> tuple[int, str]:
    return (-_severity_rank(severity), severity)


def _truncate(text: str, limit: int) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: max(0, limit - 1)].rstrip() + "…"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _result_to_mapping(result: ReportWriteResult) -> dict[str, Any]:
    return {
        "output_path": result.output_path.as_posix(),
        "report_type": result.report_type,
        "total_cases": result.total_cases,
        "compared_runs": result.compared_runs,
        "status": "written",
    }


def _print_result(result: ReportWriteResult) -> None:
    table = Table(title="ASRH Report Summary", show_header=True, header_style="bold")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("status", "written")
    table.add_row("type", result.report_type)
    table.add_row("output", result.output_path.as_posix())
    table.add_row("total_cases", str(result.total_cases))
    table.add_row("compared_runs", str(result.compared_runs))
    console.print(table)


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
    """Entrypoint for ``python -m asrh.cli.report`` and tests."""
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
    "ReportWriteResult",
    "RunMetrics",
    "TraceLoadResult",
    "app",
    "main",
    "report_command",
)


if __name__ == "__main__":
    main()
