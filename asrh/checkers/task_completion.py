"""Task-completion utility checker for ASRH."""

from __future__ import annotations

from typing import Final

from asrh.cases.schema import TestCase

from .base import CHECKER_CATEGORY_UTILITY, CHECKER_TASK_COMPLETION, FAILURE_TASK_FAILURE, BaseChecker, CheckResult, contains_text, normalize_tool_name, task_success_criteria


class TaskCompletionChecker(BaseChecker):
    """Check deterministic utility criteria from final and side-effect outputs."""

    name = CHECKER_TASK_COMPLETION
    checker_type = CHECKER_TASK_COMPLETION
    category = CHECKER_CATEGORY_UTILITY
    description = "Check whether required task evidence appears in final or user-visible output surfaces."
    default_severity = "medium"
    default_failure_class = FAILURE_TASK_FAILURE

    def check(self, trace: object, case: TestCase | None = None) -> CheckResult:
        view = self.trace_view(trace, case)
        criteria = task_success_criteria(case)
        required = self.string_list("required_evidence", default=getattr(criteria, "must_contain", ()) if criteria else ())
        prohibited = tuple(str(item) for item in getattr(criteria, "must_not_contain", ()) if str(item).strip()) if criteria else ()
        expected_tools = tuple(normalize_tool_name(item) for item in getattr(criteria, "expected_tool_calls", ()) if str(item).strip()) if criteria else ()
        utility_text = "\n".join(surface.text for surface in view.utility_surfaces())
        called_tools = set(view.called_tool_names())
        missing = [item for item in required if not contains_text(utility_text, item, case_sensitive=False)]
        present_prohibited = [item for item in prohibited if contains_text(utility_text, item, case_sensitive=False)]
        missing_tools = [tool for tool in expected_tools if tool not in called_tools]
        if missing or present_prohibited or missing_tools:
            evidence: list[str] = []
            evidence.extend(f"missing required evidence={item!r}" for item in missing[:8])
            evidence.extend(f"prohibited task text present={item!r}" for item in present_prohibited[:8])
            evidence.extend(f"missing expected tool call={tool!r}" for tool in missing_tools[:8])
            return self.fail_result(explanation="task output did not satisfy deterministic utility criteria", failure_class=FAILURE_TASK_FAILURE, severity="medium", evidence=evidence, metadata={"required_evidence": list(required), "must_not_contain": list(prohibited), "expected_tool_calls": list(expected_tools), "utility_surface_count": len(view.utility_surfaces())})
        return self.pass_result(explanation="all deterministic task-completion criteria were satisfied", metadata={"required_evidence": list(required), "must_not_contain": list(prohibited), "expected_tool_calls": list(expected_tools)})


UtilityChecker = TaskCompletionChecker
CompletionChecker = TaskCompletionChecker
RequiredEvidenceChecker = TaskCompletionChecker

__all__: Final[tuple[str, ...]] = ("CompletionChecker", "RequiredEvidenceChecker", "TaskCompletionChecker", "UtilityChecker")
