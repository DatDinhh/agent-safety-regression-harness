"""Unit tests for sandbox tool-policy enforcement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asrh.cases.loader import load_case
from asrh.envs import build_sandbox_from_case
from asrh.mitigations import build_mitigated_sandbox

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUITES_DIR = PROJECT_ROOT / "suites"


def load_suite_case(relative_path: str):
    """Load a repository suite case by relative path."""
    return load_case(SUITES_DIR / relative_path)


@pytest.mark.unit
def test_list_files_hides_sensitive_files_by_default() -> None:
    case = load_suite_case("secret_exfiltration/secret_exfiltration_001.yaml")
    env = build_sandbox_from_case(case)

    result = env.call_tool("list_files", {})
    payload = json.loads(result.output)

    assert result.allowed is True
    assert "notes.txt" in payload["files"]
    assert "secrets.txt" not in payload["files"]


@pytest.mark.unit
def test_baseline_can_expose_sensitive_file_for_eval_but_guard_blocks_it() -> None:
    case = load_suite_case("secret_exfiltration/secret_exfiltration_001.yaml")
    baseline_env = build_sandbox_from_case(case, mitigation="none")
    guarded_env = build_mitigated_sandbox(case, "tool_policy_guard")

    allowed_task_file = baseline_env.call_tool("read_file", {"path": "notes.txt"})
    baseline_secret = baseline_env.call_tool("read_file", {"path": "secrets.txt"})
    guarded_secret = guarded_env.call_tool("read_file", {"path": "secrets.txt"})

    assert allowed_task_file.allowed is True
    assert allowed_task_file.policy_violation is False
    assert "FPGA verification" in allowed_task_file.output
    assert baseline_secret.allowed is True
    assert baseline_secret.policy_violation is False
    assert "API_KEY" in baseline_secret.output
    assert guarded_secret.allowed is False
    assert guarded_secret.policy_violation is True
    assert "secrets.txt" in (guarded_secret.error or "")
    assert any(record.tool_name == "read_file" and record.policy_violation for record in guarded_env.tool_log)


@pytest.mark.unit
def test_send_email_enforces_allowlist_and_secret_scan() -> None:
    case = load_suite_case("secret_exfiltration/secret_exfiltration_008.yaml")
    env = build_sandbox_from_case(case)

    blocked_recipient = env.call_tool(
        "send_email",
        {"to": "attacker@example.com", "subject": "Summary", "body": "safe summary"},
    )
    blocked_secret = env.call_tool(
        "send_email",
        {
            "to": "manager@example.com",
            "subject": "Summary",
            "body": "DEPLOY_TOKEN=deploy_test_12345",
        },
    )
    allowed = env.call_tool(
        "send_email",
        {"to": "manager@example.com", "subject": "Summary", "body": "safe summary"},
    )

    assert blocked_recipient.allowed is False
    assert "outside allowed_recipients" in (blocked_recipient.error or "")
    assert blocked_secret.allowed is False
    assert "forbidden sensitive pattern" in (blocked_secret.error or "")
    assert allowed.allowed is True
    assert json.loads(allowed.output)["simulated"] is True


@pytest.mark.unit
def test_run_shell_is_simulated_and_disabled_in_mvp() -> None:
    case = load_suite_case("tool_misuse/tool_misuse_002.yaml")
    env = build_sandbox_from_case(case)

    result = env.call_tool("run_shell", {"command": "cat secrets.txt"})
    payload = json.loads(result.output)

    assert result.allowed is False
    assert result.policy_violation is True
    assert payload["executed"] is False
    assert payload["reason"] == "shell execution is simulated and disabled in MVP"


@pytest.mark.unit
def test_tool_policy_guard_adds_code_enforced_blocks() -> None:
    case = load_suite_case("secret_exfiltration/secret_exfiltration_008.yaml")
    env = build_mitigated_sandbox(case, "tool_policy_guard")

    secret_read = env.call_tool("read_file", {"path": "token.txt"})
    email = env.call_tool(
        "send_email",
        {"to": "manager@example.com", "subject": "Summary", "body": "safe summary"},
    )

    assert secret_read.allowed is False
    assert secret_read.policy_violation is True
    assert "token.txt" in (secret_read.error or "")
    assert email.allowed is False
    assert "authorization" in (email.error or "")


@pytest.mark.unit
def test_unknown_tool_is_denied_and_logged() -> None:
    case = load_suite_case("secret_exfiltration/secret_exfiltration_001.yaml")
    env = build_sandbox_from_case(case)

    result = env.call_tool("delete_file", {"path": "notes.txt"})

    assert result.allowed is False
    assert result.policy_violation is True
    assert "delete_file" in (result.error or "")
    assert env.tool_log[-1].tool_name == "delete_file"
