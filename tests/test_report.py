"""Unit tests for ASRH Markdown report generation and trace summarization."""

from __future__ import annotations

from pathlib import Path

import pytest

from asrh.report import (
    compare_trace_files,
    render_comparison_report,
    render_single_run_report,
    summarize_trace_file,
    write_comparison_report,
    write_single_run_report,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASELINE_TRACE = PROJECT_ROOT / "runs" / "sample_baseline.jsonl"
GUARDED_TRACE = PROJECT_ROOT / "runs" / "sample_guarded.jsonl"


@pytest.mark.unit
def test_summarize_sample_baseline_trace() -> None:
    summary = summarize_trace_file(BASELINE_TRACE)

    assert summary.total_cases == 50
    assert summary.model == "mock/unsafe_leaker"
    assert summary.mitigation == "none"
    assert summary.utility_pass_rate == 1.0
    assert 0.0 <= summary.safety_pass_rate <= 1.0
    assert summary.notable_failures


@pytest.mark.unit
def test_single_run_markdown_report_contains_required_sections() -> None:
    summary = summarize_trace_file(BASELINE_TRACE, max_failures=3)

    markdown = render_single_run_report(summary)

    assert markdown.startswith("# ASRH Regression Report")
    assert "## Run Metadata" in markdown
    assert "## Executive Summary" in markdown
    assert "## Results by Category" in markdown
    assert "## Tool Use Summary" in markdown
    assert "## Failure Taxonomy" in markdown
    assert "## Notable Failures" in markdown
    assert "SECRET_LEAK" in markdown or "SENSITIVE_ACCESS" in markdown


@pytest.mark.unit
def test_write_single_run_report_creates_markdown_file(tmp_path: Path) -> None:
    output_path = tmp_path / "baseline_report.md"

    result = write_single_run_report(BASELINE_TRACE, output_path, max_failures=2, overwrite=True)

    assert result.output_path == output_path
    assert result.report_type == "single-run"
    assert result.total_cases == 50
    assert output_path.exists()
    assert "# ASRH Regression Report" in output_path.read_text(encoding="utf-8")


@pytest.mark.unit
def test_comparison_summary_computes_case_set_and_deltas() -> None:
    comparison = compare_trace_files(BASELINE_TRACE, GUARDED_TRACE)

    assert comparison.case_sets_match is True
    assert comparison.baseline.total_cases == 50
    assert comparison.variant.total_cases == 50
    assert "safety_pass_rate" in comparison.deltas
    assert "attack_success_rate" in comparison.deltas


@pytest.mark.unit
def test_comparison_markdown_report_contains_required_sections() -> None:
    comparison = compare_trace_files(BASELINE_TRACE, GUARDED_TRACE, max_failures=3)

    markdown = render_comparison_report(comparison)

    assert markdown.startswith("# ASRH Mitigation Comparison Report")
    assert "## Compared Runs" in markdown
    assert "## Summary" in markdown
    assert "## Delta vs Baseline" in markdown
    assert "## Failure Taxonomy Delta" in markdown
    assert "tool_policy_guard" in markdown


@pytest.mark.unit
def test_write_comparison_report_creates_markdown_file(tmp_path: Path) -> None:
    output_path = tmp_path / "comparison.md"

    result = write_comparison_report(
        BASELINE_TRACE,
        GUARDED_TRACE,
        output_path,
        max_failures=2,
        overwrite=True,
    )

    assert result.output_path == output_path
    assert result.report_type == "comparison"
    assert result.compared_runs == 2
    assert "# ASRH Mitigation Comparison Report" in output_path.read_text(encoding="utf-8")
