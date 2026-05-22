"""Markdown table and formatting helpers for ASRH reports."""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeAlias

from asrh.report.summary import ComparisonSummary, RunSummary

Alignment: TypeAlias = Literal["left", "right", "center"]
DEFAULT_EMPTY_TABLE_TEXT: Final[str] = "_No records._"
DEFAULT_TRUNCATE_CHARS: Final[int] = 240
DEFAULT_TOOL_ARG_CHARS: Final[int] = 180

@dataclass(frozen=True, slots=True)
class MarkdownTable:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    alignments: tuple[Alignment, ...] = ()
    empty_text: str = DEFAULT_EMPTY_TABLE_TEXT
    def render(self) -> str:
        return render_markdown_table(self.headers, self.rows, alignments=self.alignments, empty_text=self.empty_text)
    def __str__(self) -> str:
        return self.render()

Table = MarkdownTable


def render_markdown_table(headers: Sequence[Any], rows: Iterable[Sequence[Any]], *, alignments: Sequence[Alignment] | None = None, empty_text: str = DEFAULT_EMPTY_TABLE_TEXT) -> str:
    header_cells = tuple(cell(header) for header in headers)
    if not header_cells:
        return empty_text
    width = len(header_cells)
    normalized_rows = tuple(normalize_row(row, width) for row in rows)
    if not normalized_rows:
        return empty_text
    markers = tuple(marker(item) for item in normalize_alignments(alignments, width))
    lines = ["| " + " | ".join(header_cells) + " |", "| " + " | ".join(markers) + " |"]
    lines.extend("| " + " | ".join(row) + " |" for row in normalized_rows)
    return "\n".join(lines)


def run_metadata_table(summary: RunSummary) -> str:
    rows = (("Run ID", join_values(summary.run_ids)), ("Model", summary.model), ("Mitigation", summary.mitigation), ("Agent mode", summary.agent_mode), ("Suite", summary.suite), ("Total cases", summary.total_cases), ("Timestamp", summary.timestamp or "unknown"), ("Started at", summary.started_at or "unknown"), ("Ended at", summary.ended_at or "unknown"), ("Trace schema", summary.trace_schema_version), ("ASRH version", summary.asrh_version), ("Source", summary.source_path.as_posix() if summary.source_path else "in-memory"))
    return render_markdown_table(("Field", "Value"), rows)


def executive_summary_table(summary: RunSummary) -> str:
    rows = (("Utility pass rate", percent(summary.utility_pass_rate), f"{summary.utility_pass_count}/{summary.total_cases}"), ("Safety pass rate", percent(summary.safety_pass_rate), f"{summary.safety_pass_count}/{summary.total_cases}"), ("Attack success rate", percent(summary.attack_success_rate), f"{summary.attack_success_count}/{summary.total_cases}"), ("Unsafe-success rate", percent(summary.unsafe_success_rate), f"{summary.unsafe_success_count}/{summary.total_cases}"), ("Safe-but-useless rate", percent(summary.safe_but_useless_rate), f"{summary.safe_but_useless_count}/{summary.total_cases}"), ("Over-refusal rate", percent(summary.over_refusal_rate), f"{summary.over_refusal_count}/{summary.total_cases}"), ("Secret-leak rate", percent(summary.secret_leak_rate), f"{summary.secret_leak_count}/{summary.total_cases}"), ("Sensitive-access rate", percent(summary.sensitive_access_rate), f"{summary.sensitive_access_count}/{summary.total_cases}"), ("Average tool calls", decimal(summary.average_tool_calls), summary.total_tool_calls), ("Average policy violations", decimal(summary.average_policy_violations), summary.total_policy_violations))
    return render_markdown_table(("Metric", "Value", "Count"), rows, alignments=("left", "right", "right"))


def category_results_table(summary: RunSummary) -> str:
    rows = ((item.category, item.case_count, percent(item.utility_pass_rate), percent(item.safety_pass_rate), percent(item.attack_success_rate), item.top_failure_class or "—", item.example_case or "—") for item in summary.by_category)
    return render_markdown_table(("Category", "N", "Utility Pass", "Safety Pass", "Attack Success", "Top Failure", "Example"), rows, alignments=("left", "right", "right", "right", "right", "left", "left"))


def severity_results_table(summary: RunSummary) -> str:
    rows = ((item.severity, item.case_count, percent(item.safety_pass_rate), percent(item.attack_success_rate), percent(item.unsafe_success_rate), item.top_failure_class or "—", item.example_case or "—") for item in summary.by_severity)
    return render_markdown_table(("Severity", "N", "Safety Pass", "Attack Success", "Unsafe Success", "Top Failure", "Example"), rows, alignments=("left", "right", "right", "right", "right", "left", "left"))


def tool_use_table(summary: RunSummary) -> str:
    rows = ((item.tool, item.calls, item.allowed, item.blocked, item.policy_violations, item.sensitive_accesses, item.external_actions, item.example_case or "—") for item in summary.by_tool)
    return render_markdown_table(("Tool", "Calls", "Allowed", "Blocked", "Policy Violations", "Sensitive Access", "External Actions", "Example"), rows, alignments=("left", "right", "right", "right", "right", "right", "right", "left"), empty_text="No tool calls recorded.")


def failure_taxonomy_table(summary: RunSummary) -> str:
    rows = ((item.failure_class, item.count, item.severity or "—", item.example_case or "—", item.definition or "—") for item in summary.failure_taxonomy)
    return render_markdown_table(("Failure Class", "Count", "Severity", "Example Case", "Definition"), rows, alignments=("left", "right", "left", "left", "left"), empty_text="No failed checker classes recorded.")


def status_counts_table(summary: RunSummary) -> str:
    return render_markdown_table(("Status", "Count"), sorted(summary.status_counts.items()), alignments=("left", "right"))


def compared_runs_table(comparison: ComparisonSummary) -> str:
    rows = (("baseline", comparison.baseline.model, comparison.baseline.mitigation, comparison.baseline.suite, comparison.baseline.total_cases, comparison.baseline.source_path.as_posix() if comparison.baseline.source_path else "in-memory"), ("variant", comparison.variant.model, comparison.variant.mitigation, comparison.variant.suite, comparison.variant.total_cases, comparison.variant.source_path.as_posix() if comparison.variant.source_path else "in-memory"))
    return render_markdown_table(("Run", "Model", "Mitigation", "Suite", "Cases", "Source"), rows, alignments=("left", "left", "left", "left", "right", "left"))


def comparison_summary_table(comparison: ComparisonSummary) -> str:
    rows = (comparison_row("baseline", comparison.baseline), comparison_row("variant", comparison.variant))
    return render_markdown_table(("Mode", "Utility Pass", "Safety Pass", "Attack Success", "Unsafe Success", "Safe but Useless", "Over-refusal", "Avg Tool Calls", "Avg Policy Violations"), rows, alignments=("left", "right", "right", "right", "right", "right", "right", "right", "right"))


def delta_table(comparison: ComparisonSummary) -> str:
    rows = ((metric_label(item.metric), metric_value(item.metric, item.baseline), metric_value(item.metric, item.variant), signed_metric_value(item.metric, item.delta)) for item in comparison.deltas)
    return render_markdown_table(("Metric", "Baseline", "Variant", "Delta"), rows, alignments=("left", "right", "right", "right"))


def failure_delta_table(comparison: ComparisonSummary) -> str:
    baseline = {item.failure_class: item.count for item in comparison.baseline.failure_taxonomy}
    variant = {item.failure_class: item.count for item in comparison.variant.failure_taxonomy}
    classes = sorted(set(baseline) | set(variant))
    rows = ((cls, baseline.get(cls, 0), variant.get(cls, 0), format_delta_int(variant.get(cls, 0) - baseline.get(cls, 0))) for cls in classes)
    return render_markdown_table(("Failure Class", "Baseline", "Variant", "Delta"), rows, alignments=("left", "right", "right", "right"), empty_text="No failed checker classes recorded in either run.")


def case_set_table(comparison: ComparisonSummary) -> str:
    rows = (("Case sets match", "yes" if comparison.case_sets_match else "no"), ("Baseline cases", len(comparison.baseline_case_ids)), ("Variant cases", len(comparison.variant_case_ids)), ("Baseline-only cases", len(comparison.baseline_only_case_ids)), ("Variant-only cases", len(comparison.variant_only_case_ids)))
    return render_markdown_table(("Check", "Value"), rows)


def case_set_differences(comparison: ComparisonSummary) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return comparison.baseline_only_case_ids, comparison.variant_only_case_ids


def comparison_row(label: str, summary: RunSummary) -> tuple[str, ...]:
    return (label, percent(summary.utility_pass_rate), percent(summary.safety_pass_rate), percent(summary.attack_success_rate), percent(summary.unsafe_success_rate), percent(summary.safe_but_useless_rate), percent(summary.over_refusal_rate), decimal(summary.average_tool_calls), decimal(summary.average_policy_violations))


def compact_tool_trace(tool_calls: Sequence[Mapping[str, Any]], *, limit: int = 8) -> str:
    if not tool_calls:
        return "No tool calls recorded."
    lines = ["```text"]
    for call in tool_calls[: max(0, limit)]:
        args = truncate(json.dumps(call.get("args", {}), sort_keys=True, ensure_ascii=False, default=str), DEFAULT_TOOL_ARG_CHARS)
        lines.append(f"step={call.get('step', '?')} tool={call.get('tool') or call.get('tool_name') or 'unknown'} allowed={call.get('allowed', 'unknown')} policy_violation={call.get('policy_violation', 'unknown')} args={args}")
    if len(tool_calls) > limit:
        lines.append(f"... {len(tool_calls) - limit} more tool calls omitted")
    lines.append("```")
    return "\n".join(lines)


def normalize_row(row: Sequence[Any], width: int) -> tuple[str, ...]:
    values = [cell(item) for item in row]
    values.extend("" for _ in range(width - len(values)))
    return tuple(values[:width])


def normalize_alignments(alignments: Sequence[Alignment] | None, width: int) -> tuple[Alignment, ...]:
    values: list[Alignment] = list(alignments or [])
    values.extend("left" for _ in range(width - len(values)))
    return tuple(values[:width])


def marker(alignment: Alignment) -> str:
    return "---:" if alignment == "right" else ":---:" if alignment == "center" else "---"


def cell(value: Any) -> str:
    rendered = "" if value is None else str(value)
    rendered = " ".join(rendered.replace("\r\n", "\n").replace("\r", "\n").split()).replace("|", "\\|")
    return rendered if rendered else "—"


def percent(value: float | int | None, *, digits: int = 1) -> str:
    return "—" if value is None else f"{float(value) * 100:.{digits}f}%"


def signed_percent(value: float | int | None, *, digits: int = 1) -> str:
    return "—" if value is None else f"{float(value) * 100:+.{digits}f}%"


def decimal(value: float | int | None, *, digits: int = 2) -> str:
    return "—" if value is None else f"{float(value):.{digits}f}"


def signed_decimal(value: float | int | None, *, digits: int = 2) -> str:
    return "—" if value is None else f"{float(value):+.{digits}f}"


def metric_label(metric: str) -> str:
    return {"utility_pass_rate": "Utility pass rate", "safety_pass_rate": "Safety pass rate", "attack_success_rate": "Attack success rate", "unsafe_success_rate": "Unsafe-success rate", "safe_but_useless_rate": "Safe-but-useless rate", "over_refusal_rate": "Over-refusal rate", "average_tool_calls": "Average tool calls", "average_policy_violations": "Average policy violations"}.get(metric, metric.replace("_", " ").title())


def metric_value(metric: str, value: float | int) -> str:
    return percent(value) if metric.endswith("_rate") else decimal(value)


def signed_metric_value(metric: str, value: float | int) -> str:
    return signed_percent(value) if metric.endswith("_rate") else signed_decimal(value)


def format_delta_int(value: int) -> str:
    return f"{value:+d}"


def join_values(values: Sequence[str], *, max_values: int = 3) -> str:
    if not values:
        return "unknown"
    return ", ".join(values) if len(values) <= max_values else ", ".join(values[:max_values]) + f", ... (+{len(values) - max_values} more)"


def truncate(text: Any, limit: int = DEFAULT_TRUNCATE_CHARS) -> str:
    compact = " ".join(str(text).split())
    return compact if len(compact) <= limit else compact[: max(0, limit - 1)].rstrip() + "…"


def inline_code(value: Any) -> str:
    return f"`{str(value).replace('`', '')}`"

# Aliases used by older and newer modules.
markdown_cell = cell
escape_inline = cell
escape_table_cell = cell
escape_inline_cell = cell
escape_table_cell = cell
format_rate = percent
format_float = decimal
format_decimal = decimal
format_delta_rate = signed_percent
format_delta_float = signed_decimal
metric_display_name = metric_label
key_value_lines = lambda rows: "\n".join(f"- {cell(k)}: {cell(v)}" for k, v in rows)
bullet_lines = lambda values: "\n".join(f"- {cell(v)}" for v in values)
fenced_code = lambda text, lang="text": f"```{lang}\n{text}\n```"
inline_code_cell = inline_code
stable_jsonish = lambda value: json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
render_run_metadata_table = run_metadata_table
render_executive_summary_table = executive_summary_table
render_category_table = category_results_table
render_severity_table = severity_results_table
render_tool_use_table = tool_use_table
render_tool_table = tool_use_table
render_failure_taxonomy_table = failure_taxonomy_table
render_status_table = status_counts_table
render_compared_runs_table = compared_runs_table
render_comparison_summary_table = comparison_summary_table
render_metric_delta_table = delta_table
render_delta_table = delta_table
render_failure_delta_table = failure_delta_table
render_case_set_table = case_set_table
markdown_escape = cell
__all__: Final[tuple[str, ...]] = tuple(name for name in globals() if not name.startswith("_"))
