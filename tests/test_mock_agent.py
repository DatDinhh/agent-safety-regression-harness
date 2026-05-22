"""End-to-end tests for deterministic mock-agent execution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asrh.runner.run_case import run_case
from asrh.runner.run_suite import run_suite
from asrh.runner.trace import read_trace_jsonl

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_SECRET_CASE = PROJECT_ROOT / "suites" / "secret_exfiltration" / "secret_exfiltration_001.yaml"
SECRET_SUITE = PROJECT_ROOT / "suites" / "secret_exfiltration"


@pytest.mark.unit
def test_safe_mock_agent_passes_canonical_case(tmp_path: Path) -> None:
    output_path = tmp_path / "safe.jsonl"

    result = run_case(
        case_path=CANONICAL_SECRET_CASE,
        model="mock/safe",
        mitigation="none",
        output_path=output_path,
    )
    records = read_trace_jsonl(output_path)

    assert result["status"] == "completed"
    assert result["overall"] == "PASS"
    assert result["utility_pass"] is True
    assert result["safety_pass"] is True
    assert output_path.exists()
    assert len(records) == 1
    assert records[0]["case_id"] == "secret_exfiltration_001"
    assert records[0]["verdict"]["overall"] == "PASS"


@pytest.mark.unit
def test_unsafe_mock_agent_triggers_checker_failure_without_guard() -> None:
    result = run_case(
        case_path=CANONICAL_SECRET_CASE,
        model="mock/unsafe_leaker",
        mitigation="none",
    )

    assert result["status"] == "completed"
    assert result["overall"] == "UNSAFE_SUCCESS"
    assert result["utility_pass"] is True
    assert result["safety_pass"] is False
    assert result["attack_success"] is True


@pytest.mark.unit
def test_tool_policy_guard_prevents_unsafe_mock_secret_leak() -> None:
    result = run_case(
        case_path=CANONICAL_SECRET_CASE,
        model="mock/unsafe_leaker",
        mitigation="tool_policy_guard",
    )

    assert result["status"] == "completed"
    assert result["overall"] == "PASS"
    assert result["utility_pass"] is True
    assert result["safety_pass"] is True
    assert result["attack_success"] is False


@pytest.mark.unit
def test_refuser_mock_agent_is_safe_but_useless() -> None:
    result = run_case(
        case_path=CANONICAL_SECRET_CASE,
        model="mock/refuser",
        mitigation="none",
    )

    assert result["status"] == "completed"
    assert result["overall"] == "SAFE_BUT_USELESS"
    assert result["utility_pass"] is False
    assert result["safety_pass"] is True


@pytest.mark.unit
def test_invalid_json_mock_is_handled_as_traceable_failure() -> None:
    result = run_case(
        case_path=CANONICAL_SECRET_CASE,
        model="mock/json_invalid",
        mitigation="none",
        max_steps=2,
    )

    assert result["status"] == "completed"
    assert result["overall"] == "SAFE_BUT_USELESS"
    assert result["utility_pass"] is False
    assert result["errors"]
    assert any("valid JSON" in error for error in result["errors"])


@pytest.mark.unit
def test_looping_mock_hits_tool_call_limit_without_crashing() -> None:
    result = run_case(
        case_path=CANONICAL_SECRET_CASE,
        model="mock/looping",
        mitigation="none",
        max_steps=4,
        max_tool_calls=1,
    )

    assert result["status"] == "completed"
    assert result["overall"] in {"SAFE_BUT_USELESS", "FAIL"}
    assert result["errors"]
    assert any("max_tool_calls" in error for error in result["errors"])


@pytest.mark.unit
def test_suite_runner_writes_one_jsonl_record_per_case(tmp_path: Path) -> None:
    output_path = tmp_path / "secret_suite.jsonl"

    result = run_suite(
        suite_path=SECRET_SUITE,
        model="mock/safe",
        mitigation="none",
        output_path=output_path,
    )

    assert result["status"] == "completed"
    assert result["case_count"] == 10
    assert result["completed_case_count"] == 10
    assert result["utility_pass_rate"] == 1.0
    assert result["safety_pass_rate"] == 1.0

    lines = [line for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 10
    assert {json.loads(line)["suite"] for line in lines} == {"secret_exfiltration"}
