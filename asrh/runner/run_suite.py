"""Suite execution backend for ASRH.

Discovers YAML cases, executes them in deterministic order, writes one JSONL
record per case, and returns aggregate utility/safety metrics for the CLI and
future reports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from asrh import (
    DEFAULT_MAX_STEPS,
    DEFAULT_MAX_TOKENS_PER_RESPONSE,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TOTAL_TOKENS,
    DEFAULT_MITIGATION,
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
)
from asrh.cases.loader import LoadedCase, load_suite
from asrh.runner.result import (
    DEFAULT_AGENT_MODE,
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    CaseExecutionConfig,
    RunCaseResult,
    RunSuiteResult,
)
from asrh.runner.run_case import (
    build_error_case_result,
    execute_loaded_case,
    make_case_config,
    normalize_agent_mode_for_runner,
)
from asrh.runner.trace import make_run_id, utc_now_iso


def run_suite(
    *,
    suite_path: str | Path,
    model: str = DEFAULT_MODEL,
    mitigation: str = DEFAULT_MITIGATION,
    agent_mode: str = DEFAULT_AGENT_MODE,
    output_path: str | Path | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    seed: int | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    max_tokens_per_response: int = DEFAULT_MAX_TOKENS_PER_RESPONSE,
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    fail_fast: bool = False,
    append: bool = False,
    run_started_at: str | None = None,
    strict_json: bool = True,
    model_client: Any | None = None,
) -> dict[str, Any]:
    """Run a suite directory or top-level ``suites/`` tree.

    The public backend returns a JSON-compatible mapping so the CLI can render
    ``--json`` output without custom encoders.
    """
    root = Path(suite_path).expanduser()
    loaded_cases = tuple(load_suite(root))
    result = run_loaded_cases(
        loaded_cases,
        suite_path=root,
        model=model,
        mitigation=mitigation,
        agent_mode=agent_mode,
        output_path=output_path,
        temperature=temperature,
        seed=seed,
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        max_tokens_per_response=max_tokens_per_response,
        max_total_tokens=max_total_tokens,
        timeout_seconds=timeout_seconds,
        fail_fast=fail_fast,
        append=append,
        run_started_at=run_started_at,
        strict_json=strict_json,
        model_client=model_client,
    )
    return result.to_dict(include_case_results=True)


def run_loaded_cases(
    loaded_cases: tuple[LoadedCase, ...] | list[LoadedCase],
    *,
    suite_path: str | Path,
    model: str = DEFAULT_MODEL,
    mitigation: str = DEFAULT_MITIGATION,
    agent_mode: str = DEFAULT_AGENT_MODE,
    output_path: str | Path | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    seed: int | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    max_tokens_per_response: int = DEFAULT_MAX_TOKENS_PER_RESPONSE,
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    fail_fast: bool = False,
    append: bool = False,
    run_started_at: str | None = None,
    strict_json: bool = True,
    model_client: Any | None = None,
) -> RunSuiteResult:
    """Run an already-loaded case collection; useful for tests."""
    root = Path(suite_path).expanduser()
    target = None if output_path is None else Path(output_path).expanduser()
    started_at = run_started_at or utc_now_iso()
    normalized_agent_mode = normalize_agent_mode_for_runner(agent_mode)
    config: CaseExecutionConfig = make_case_config(
        model=model,
        mitigation=mitigation,
        agent_mode=normalized_agent_mode,
        temperature=temperature,
        seed=seed,
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        max_tokens_per_response=max_tokens_per_response,
        max_total_tokens=max_total_tokens,
        timeout_seconds=timeout_seconds,
        fail_fast=fail_fast,
        append=append,
        run_started_at=started_at,
        strict_json=strict_json,
        metadata={"suite_path": root.as_posix()},
    )
    run_id = make_run_id(
        model=config.model,
        mitigation=config.mitigation,
        started_at=started_at,
        suite=root.name or "suites",
    )
    results: list[RunCaseResult] = []
    errors: list[str] = []

    for index, loaded in enumerate(loaded_cases):
        should_append = append or index > 0
        try:
            result = execute_loaded_case(
                loaded_case=loaded,
                config=config,
                output_path=target,
                append=should_append,
                run_id=run_id,
                run_started_at=started_at,
                model_client=model_client,
            )
        except Exception as exc:  # noqa: BLE001 - suite can keep running unless fail-fast is set.
            if fail_fast:
                raise
            result = build_error_case_result(
                case_path=loaded.path,
                output_path=target,
                config=config,
                error=exc,
                append=should_append,
                run_id=run_id,
            )
        if result.errors:
            errors.extend(f"{result.case_id}: {error}" for error in result.errors)
        results.append(result)

    status = STATUS_PARTIAL if errors else STATUS_COMPLETED
    return RunSuiteResult(
        run_id=run_id,
        suite_path=root,
        output_path=target,
        model=config.model,
        mitigation=config.mitigation,
        agent_mode=normalized_agent_mode,
        results=tuple(results),
        status=status,
        started_at=started_at,
        ended_at=utc_now_iso(),
        errors=tuple(errors),
        metadata={"runner": "asrh.runner.run_suite"},
    )


__all__: Final[tuple[str, ...]] = ("run_suite", "run_loaded_cases")
