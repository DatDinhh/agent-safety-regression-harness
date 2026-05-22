"""Structured validation for ASRH YAML cases and suites.

``schema.py`` handles hard structural validation through Pydantic. This module
adds catalog-level and research-quality checks: duplicate ids, suite coverage,
checker coverage, risky tool policies, sensitive-asset coverage, and
path/category consistency. It returns structured findings instead of printing,
so CLI commands and tests can decide how to present failures.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from asrh import SUPPORTED_CHECKER_TYPES, SUPPORTED_SUITES, SUPPORTED_TOOLS
from asrh.cases.loader import CaseDiscoveryError, CaseLoadError, discover_case_files, read_case_document
from asrh.cases.schema import (
    HIGH_RISK_TOOLS,
    REQUIRED_CASES_PER_MVP_SUITE,
    REQUIRED_MVP_CASE_COUNT,
    SAFETY_CHECKER_TYPES,
    SENSITIVE_CHECKER_TYPES,
    SUPPORTED_CATEGORY_SET,
    SUPPORTED_CHECKER_TYPE_SET,
    SUPPORTED_TOOL_SET,
    UTILITY_CHECKER_TYPES,
    CaseSchemaError,
    RawCaseDocument,
    TestCase,
    category_from_case_id,
    parse_case_document,
)

SUPPORTED_SUITE_SET: Final[frozenset[str]] = frozenset(SUPPORTED_SUITES)
SUPPORTED_TOOL_NAME_SET: Final[frozenset[str]] = frozenset(SUPPORTED_TOOLS)
SUPPORTED_CHECKER_NAME_SET: Final[frozenset[str]] = frozenset(SUPPORTED_CHECKER_TYPES)


class FindingSeverity(StrEnum):
    """Severity level for validation findings."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    """One schema or quality finding emitted by the case validator."""

    severity: FindingSeverity
    code: str
    message: str
    path: Path | None = None
    case_id: str | None = None
    location: str | None = None

    @property
    def is_error(self) -> bool:
        """Return whether the finding is an error."""
        return self.severity == FindingSeverity.ERROR

    @property
    def is_warning(self) -> bool:
        """Return whether the finding is a warning."""
        return self.severity == FindingSeverity.WARNING

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "path": self.path.as_posix() if self.path is not None else None,
            "case_id": self.case_id,
            "location": self.location,
        }


@dataclass(frozen=True, slots=True)
class ValidationOptions:
    """Options for case and suite validation."""

    strict: bool = False
    fail_on_warnings: bool = False
    require_mvp_suites: bool = False
    include_hidden: bool = False


@dataclass(frozen=True, slots=True)
class CaseValidationResult:
    """Validation result for one YAML case file or in-memory case."""

    path: Path | None
    case: TestCase | None
    raw: RawCaseDocument | None
    findings: tuple[ValidationFinding, ...] = field(default_factory=tuple)

    @property
    def case_id(self) -> str | None:
        """Return the case id when the document parsed successfully."""
        return self.case.id if self.case is not None else None

    @property
    def error_count(self) -> int:
        """Return the number of error findings."""
        return sum(finding.is_error for finding in self.findings)

    @property
    def warning_count(self) -> int:
        """Return the number of warning findings."""
        return sum(finding.is_warning for finding in self.findings)

    @property
    def valid(self) -> bool:
        """Return whether this case has no error findings."""
        return self.error_count == 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable result."""
        return {
            "path": self.path.as_posix() if self.path is not None else None,
            "case_id": self.case_id,
            "valid": self.valid,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class SuiteValidationResult:
    """Validation result for a suite directory or top-level suites tree."""

    root: Path
    cases: tuple[CaseValidationResult, ...]
    suite_findings: tuple[ValidationFinding, ...] = field(default_factory=tuple)
    options: ValidationOptions = field(default_factory=ValidationOptions)

    @property
    def findings(self) -> tuple[ValidationFinding, ...]:
        """Return suite-level and case-level findings."""
        case_findings = tuple(finding for result in self.cases for finding in result.findings)
        return (*self.suite_findings, *case_findings)

    @property
    def parsed_cases(self) -> tuple[TestCase, ...]:
        """Return successfully parsed cases."""
        return tuple(result.case for result in self.cases if result.case is not None)

    @property
    def case_count(self) -> int:
        """Return the number of successfully parsed cases."""
        return len(self.parsed_cases)

    @property
    def file_count(self) -> int:
        """Return the number of YAML files considered."""
        return len(self.cases)

    @property
    def error_count(self) -> int:
        """Return the number of error findings."""
        return sum(finding.is_error for finding in self.findings)

    @property
    def warning_count(self) -> int:
        """Return the number of warning findings."""
        return sum(finding.is_warning for finding in self.findings)

    @property
    def valid(self) -> bool:
        """Return whether the suite has no errors and, optionally, no warnings."""
        if self.error_count > 0:
            return False
        return not (self.options.fail_on_warnings and self.warning_count > 0)

    @property
    def categories(self) -> dict[str, int]:
        """Return parsed case counts by category."""
        return dict(Counter(case.category for case in self.parsed_cases))

    @property
    def severities(self) -> dict[str, int]:
        """Return parsed case counts by severity."""
        return dict(Counter(case.severity for case in self.parsed_cases))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable suite validation result."""
        return {
            "root": self.root.as_posix(),
            "valid": self.valid,
            "file_count": self.file_count,
            "case_count": self.case_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "categories": self.categories,
            "severities": self.severities,
            "findings": [finding.to_dict() for finding in self.findings],
            "cases": [case_result.to_dict() for case_result in self.cases],
            "options": {
                "strict": self.options.strict,
                "fail_on_warnings": self.options.fail_on_warnings,
                "require_mvp_suites": self.options.require_mvp_suites,
                "include_hidden": self.options.include_hidden,
            },
        }


def validate_case_file(
    path: Path,
    *,
    strict: bool = False,
    suite_root: Path | None = None,
) -> CaseValidationResult:
    """Validate one YAML case file and return structured findings."""
    findings: list[ValidationFinding] = []
    raw: RawCaseDocument | None = None
    case: TestCase | None = None

    try:
        raw = read_case_document(path)
    except CaseLoadError as exc:
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="case.load_error",
                message=str(exc),
                path=path,
            )
        )
        return CaseValidationResult(path=path, case=None, raw=None, findings=tuple(findings))

    try:
        case = parse_case_document(raw)
    except CaseSchemaError as exc:
        case_id = _safe_raw_case_id(raw)
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="case.schema_error",
                message=str(exc),
                path=path,
                case_id=case_id,
            )
        )
        return CaseValidationResult(path=path, case=None, raw=raw, findings=tuple(findings))

    findings.extend(validate_case_model(case, path=path, strict=strict, suite_root=suite_root))
    return CaseValidationResult(path=path, case=case, raw=raw, findings=tuple(findings))


def validate_case_document(
    document: RawCaseDocument,
    *,
    path: Path | None = None,
    strict: bool = False,
    suite_root: Path | None = None,
) -> CaseValidationResult:
    """Validate an in-memory raw case document."""
    try:
        case = parse_case_document(document)
    except CaseSchemaError as exc:
        return CaseValidationResult(
            path=path,
            case=None,
            raw=document,
            findings=(
                _finding(
                    FindingSeverity.ERROR,
                    code="case.schema_error",
                    message=str(exc),
                    path=path,
                    case_id=_safe_raw_case_id(document),
                ),
            ),
        )

    return CaseValidationResult(
        path=path,
        case=case,
        raw=document,
        findings=tuple(validate_case_model(case, path=path, strict=strict, suite_root=suite_root)),
    )


def validate_case_model(
    case: TestCase,
    *,
    path: Path | None = None,
    strict: bool = False,
    suite_root: Path | None = None,
) -> tuple[ValidationFinding, ...]:
    """Run non-Pydantic quality checks on a parsed ``TestCase`` model."""
    findings: list[ValidationFinding] = []
    findings.extend(_validate_case_identity(case, path=path, strict=strict, suite_root=suite_root))
    findings.extend(_validate_checker_coverage(case, path=path, strict=strict))
    findings.extend(_validate_sensitive_asset_coverage(case, path=path, strict=strict))
    findings.extend(_validate_tools(case, path=path, strict=strict))
    findings.extend(_validate_tool_policies(case, path=path, strict=strict))
    findings.extend(_validate_attack_consistency(case, path=path, strict=strict))
    findings.extend(_validate_task_criteria(case, path=path, strict=strict))
    return tuple(findings)


def validate_suite(
    root: Path,
    *,
    strict: bool = False,
    fail_on_warnings: bool = False,
    require_mvp_suites: bool = False,
    include_hidden: bool = False,
) -> SuiteValidationResult:
    """Validate every YAML case under a suite or top-level suites directory."""
    options = ValidationOptions(
        strict=strict,
        fail_on_warnings=fail_on_warnings,
        require_mvp_suites=require_mvp_suites,
        include_hidden=include_hidden,
    )
    expanded = root.expanduser()
    suite_findings: list[ValidationFinding] = []

    try:
        case_files = discover_case_files(
            expanded,
            include_hidden=include_hidden,
            require_non_empty=False,
        )
    except CaseDiscoveryError as exc:
        suite_findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="suite.discovery_error",
                message=str(exc),
                path=expanded,
            )
        )
        return SuiteValidationResult(
            root=expanded,
            cases=(),
            suite_findings=tuple(suite_findings),
            options=options,
        )

    if not case_files:
        suite_findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="suite.empty",
                message="no YAML case files found",
                path=expanded,
            )
        )

    case_results = tuple(
        validate_case_file(path, strict=strict, suite_root=expanded) for path in case_files
    )
    suite_findings.extend(_validate_duplicate_case_ids(case_results))

    if require_mvp_suites:
        suite_findings.extend(_validate_mvp_suite_coverage(expanded, case_results))

    return SuiteValidationResult(
        root=expanded,
        cases=case_results,
        suite_findings=tuple(suite_findings),
        options=options,
    )


def collect_findings(results: Iterable[CaseValidationResult]) -> tuple[ValidationFinding, ...]:
    """Flatten findings from many case results."""
    return tuple(finding for result in results for finding in result.findings)


def has_blocking_findings(
    findings: Iterable[ValidationFinding],
    *,
    fail_on_warnings: bool = False,
) -> bool:
    """Return whether findings should cause a command/test failure."""
    findings_tuple = tuple(findings)
    if any(finding.is_error for finding in findings_tuple):
        return True
    return fail_on_warnings and any(finding.is_warning for finding in findings_tuple)


def summarize_findings(findings: Iterable[ValidationFinding]) -> dict[str, int]:
    """Return finding counts by severity."""
    counts = Counter(finding.severity.value for finding in findings)
    return {severity.value: counts.get(severity.value, 0) for severity in FindingSeverity}


def _validate_case_identity(
    case: TestCase,
    *,
    path: Path | None,
    strict: bool,
    suite_root: Path | None,
) -> tuple[ValidationFinding, ...]:
    findings: list[ValidationFinding] = []
    id_category = category_from_case_id(case.id)
    if id_category != case.category:
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="case.id_category_mismatch",
                message=f"case id prefix {id_category!r} does not match category {case.category!r}",
                path=path,
                case_id=case.id,
                location="id",
            )
        )

    if case.category not in SUPPORTED_CATEGORY_SET:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="case.unknown_category",
                message=f"category {case.category!r} is outside MVP categories {sorted(SUPPORTED_SUITES)}",
                path=path,
                case_id=case.id,
                location="metadata.category",
            )
        )

    inferred_suite = _infer_expected_suite(path, suite_root=suite_root)
    if inferred_suite is not None and inferred_suite in SUPPORTED_SUITE_SET and inferred_suite != case.category:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="case.path_category_mismatch",
                message=(
                    f"case is under suite directory {inferred_suite!r} but metadata.category is "
                    f"{case.category!r}"
                ),
                path=path,
                case_id=case.id,
                location="metadata.category",
            )
        )
    return tuple(findings)


def _validate_checker_coverage(
    case: TestCase,
    *,
    path: Path | None,
    strict: bool,
) -> tuple[ValidationFinding, ...]:
    findings: list[ValidationFinding] = []
    checker_types = set(case.checker_types)

    unknown_checker_types = sorted(checker_types - SUPPORTED_CHECKER_TYPE_SET)
    for checker_type in unknown_checker_types:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="checker.unknown_type",
                message=f"checker type {checker_type!r} is not in supported types {sorted(SUPPORTED_CHECKER_TYPES)}",
                path=path,
                case_id=case.id,
                location="checkers[].type",
            )
        )

    if not checker_types.intersection(UTILITY_CHECKER_TYPES):
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="checker.missing_utility_checker",
                message="case must include at least one utility checker",
                path=path,
                case_id=case.id,
                location="checkers",
            )
        )
    if not checker_types.intersection(SAFETY_CHECKER_TYPES):
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="checker.missing_safety_checker",
                message="case must include at least one safety checker",
                path=path,
                case_id=case.id,
                location="checkers",
            )
        )

    if case.expected.utility == "pass" and "task_completion" not in checker_types:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="checker.expected_pass_without_task_completion",
                message="expected.utility is pass, but no task_completion checker is configured",
                path=path,
                case_id=case.id,
                location="checkers",
            )
        )
    return tuple(findings)


def _validate_sensitive_asset_coverage(
    case: TestCase,
    *,
    path: Path | None,
    strict: bool,
) -> tuple[ValidationFinding, ...]:
    findings: list[ValidationFinding] = []
    sensitive_paths = set(case.sensitive_file_paths)
    if not sensitive_paths:
        return tuple(findings)

    checker_types = set(case.checker_types)
    if not checker_types.intersection(SENSITIVE_CHECKER_TYPES):
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="sensitive.missing_sensitive_checker",
                message="case contains sensitive files but no sensitive-data checker",
                path=path,
                case_id=case.id,
                location="checkers",
            )
        )

    if "no_secret_leak" not in checker_types:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="sensitive.missing_secret_leak_checker",
                message="case contains sensitive files but no no_secret_leak checker",
                path=path,
                case_id=case.id,
                location="checkers",
            )
        )

    sensitive_access_checkers = [
        checker for checker in case.checkers if checker.type.value == "no_sensitive_file_access"
    ]
    if not sensitive_access_checkers:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="sensitive.missing_access_checker",
                message="case contains sensitive files but no no_sensitive_file_access checker",
                path=path,
                case_id=case.id,
                location="checkers",
            )
        )
        return tuple(findings)

    checked_paths = {
        checked_path
        for checker in sensitive_access_checkers
        for checked_path in (checker.paths or [])
    }
    missing_paths = sorted(sensitive_paths - checked_paths)
    if missing_paths:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="sensitive.unchecked_sensitive_path",
                message=f"sensitive path(s) not covered by no_sensitive_file_access: {missing_paths}",
                path=path,
                case_id=case.id,
                location="checkers[].paths",
            )
        )
    return tuple(findings)


def _validate_tools(case: TestCase, *, path: Path | None, strict: bool) -> tuple[ValidationFinding, ...]:
    findings: list[ValidationFinding] = []
    unknown_tools = sorted(set(case.allowed_tools) - SUPPORTED_TOOL_SET)
    for tool_name in unknown_tools:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="tools.unknown_allowed_tool",
                message=f"tool {tool_name!r} is outside required MVP tools {sorted(SUPPORTED_TOOLS)}",
                path=path,
                case_id=case.id,
                location="tools.allowed",
            )
        )

    high_risk_allowed = sorted(set(case.allowed_tools).intersection(HIGH_RISK_TOOLS))
    for tool_name in high_risk_allowed:
        if tool_name not in case.tools.tool_policies:
            findings.append(
                _finding(
                    _strict_or_warning(strict),
                    code="tools.high_risk_without_policy",
                    message=f"high-risk tool {tool_name!r} is allowed without an explicit tool policy",
                    path=path,
                    case_id=case.id,
                    location="tools.tool_policies",
                )
            )
    return tuple(findings)


def _validate_tool_policies(
    case: TestCase,
    *,
    path: Path | None,
    strict: bool,
) -> tuple[ValidationFinding, ...]:
    findings: list[ValidationFinding] = []
    allowed_tools = set(case.allowed_tools)
    policy_names = set(case.tools.tool_policies)

    unused_policies = sorted(policy_names - allowed_tools)
    for policy_name in unused_policies:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="tools.policy_for_disallowed_tool",
                message=f"tool policy {policy_name!r} is configured but the tool is not in tools.allowed",
                path=path,
                case_id=case.id,
                location=f"tools.tool_policies.{policy_name}",
            )
        )

    # Sensitive files are intentionally not required to be denied in baseline
    # cases. ASRH evaluates whether an agent attempts unsafe access, and
    # code-enforced mitigations such as tool_policy_guard may add denied_paths
    # at runtime. Structural validation therefore checks checker coverage for
    # sensitive assets, not whether the baseline case is already hardened.

    run_shell_policy = case.tools.tool_policies.get("run_shell", {})
    if bool(run_shell_policy.get("enabled")):
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="tools.real_shell_not_mvp_safe",
                message="run_shell.enabled=true violates the MVP rule that shell execution must be fake/disabled",
                path=path,
                case_id=case.id,
                location="tools.tool_policies.run_shell.enabled",
            )
        )

    send_email_policy = case.tools.tool_policies.get("send_email", {})
    if "send_email" in allowed_tools:
        requires_authorization = send_email_policy.get("requires_authorization")
        allowed_recipients = _string_sequence(send_email_policy.get("allowed_recipients"))
        if requires_authorization is False and not allowed_recipients:
            findings.append(
                _finding(
                    _strict_or_warning(strict),
                    code="tools.email_without_authorization_or_allowlist",
                    message=(
                        "send_email requires_authorization=false but no allowed_recipients allowlist "
                        "is configured"
                    ),
                    path=path,
                    case_id=case.id,
                    location="tools.tool_policies.send_email",
                )
            )
    return tuple(findings)


def _validate_attack_consistency(
    case: TestCase,
    *,
    path: Path | None,
    strict: bool,
) -> tuple[ValidationFinding, ...]:
    if case.attack is None:
        return ()

    findings: list[ValidationFinding] = []
    location = case.attack.payload_location.value
    if location == "file" and not case.environment.files:
        findings.append(_attack_location_finding(case, path, strict, "file payload location but no files exist"))
    if location == "email" and not case.environment.inbox:
        findings.append(_attack_location_finding(case, path, strict, "email payload location but inbox is empty"))
    if location == "memory" and not case.environment.memory:
        findings.append(_attack_location_finding(case, path, strict, "memory payload location but memory is empty"))

    if case.attack.type.value in {"indirect_prompt_injection", "instruction_conflict"}:
        has_hierarchy_checker = "instruction_hierarchy" in case.checker_types
        if not has_hierarchy_checker:
            findings.append(
                _finding(
                    _strict_or_warning(strict),
                    code="attack.missing_instruction_hierarchy_checker",
                    message=(
                        "indirect prompt-injection/instruction-conflict case lacks an "
                        "instruction_hierarchy checker"
                    ),
                    path=path,
                    case_id=case.id,
                    location="checkers",
                )
            )
    return tuple(findings)


def _validate_task_criteria(
    case: TestCase,
    *,
    path: Path | None,
    strict: bool,
) -> tuple[ValidationFinding, ...]:
    findings: list[ValidationFinding] = []
    criteria = case.task.success_criteria
    if not criteria.must_contain and "task_completion" not in case.checker_types:
        findings.append(
            _finding(
                _strict_or_warning(strict),
                code="task.no_deterministic_utility_evidence",
                message="case has neither task.success_criteria.must_contain nor a task_completion checker",
                path=path,
                case_id=case.id,
                location="task.success_criteria",
            )
        )
    return tuple(findings)


def _validate_duplicate_case_ids(
    case_results: Sequence[CaseValidationResult],
) -> tuple[ValidationFinding, ...]:
    by_id: defaultdict[str, list[CaseValidationResult]] = defaultdict(list)
    for result in case_results:
        if result.case is not None:
            by_id[result.case.id].append(result)

    findings: list[ValidationFinding] = []
    for case_id, duplicates in sorted(by_id.items()):
        if len(duplicates) <= 1:
            continue
        duplicate_paths = [str(result.path) for result in duplicates if result.path is not None]
        message = f"duplicate case id {case_id!r} appears in: {', '.join(duplicate_paths)}"
        for result in duplicates:
            findings.append(
                _finding(
                    FindingSeverity.ERROR,
                    code="case.duplicate_id",
                    message=message,
                    path=result.path,
                    case_id=case_id,
                    location="id",
                )
            )
    return tuple(findings)


def _validate_mvp_suite_coverage(
    root: Path,
    case_results: Sequence[CaseValidationResult],
) -> tuple[ValidationFinding, ...]:
    findings: list[ValidationFinding] = []
    parsed_cases = [result.case for result in case_results if result.case is not None]
    category_counts = Counter(case.category for case in parsed_cases)

    missing_dirs = [suite for suite in SUPPORTED_SUITES if not (root / suite).exists()]
    if root.name in SUPPORTED_SUITE_SET:
        missing_dirs = []

    for suite in missing_dirs:
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="suite.missing_required_directory",
                message=f"required MVP suite directory is missing: {suite}",
                path=root / suite,
            )
        )

    if len(parsed_cases) < REQUIRED_MVP_CASE_COUNT:
        findings.append(
            _finding(
                FindingSeverity.ERROR,
                code="suite.insufficient_case_count",
                message=(
                    f"MVP requires at least {REQUIRED_MVP_CASE_COUNT} parsed cases; "
                    f"found {len(parsed_cases)}"
                ),
                path=root,
            )
        )

    for suite in SUPPORTED_SUITES:
        count = category_counts.get(suite, 0)
        if count < REQUIRED_CASES_PER_MVP_SUITE:
            findings.append(
                _finding(
                    FindingSeverity.ERROR,
                    code="suite.insufficient_category_count",
                    message=(
                        f"MVP suite {suite!r} requires at least {REQUIRED_CASES_PER_MVP_SUITE} "
                        f"cases; found {count}"
                    ),
                    path=root / suite,
                    location="metadata.category",
                )
            )
    return tuple(findings)


def _attack_location_finding(
    case: TestCase,
    path: Path | None,
    strict: bool,
    message: str,
) -> ValidationFinding:
    return _finding(
        _strict_or_warning(strict),
        code="attack.payload_location_mismatch",
        message=message,
        path=path,
        case_id=case.id,
        location="attack.payload_location",
    )


def _strict_or_warning(strict: bool) -> FindingSeverity:
    return FindingSeverity.ERROR if strict else FindingSeverity.WARNING


def _finding(
    severity: FindingSeverity,
    *,
    code: str,
    message: str,
    path: Path | None = None,
    case_id: str | None = None,
    location: str | None = None,
) -> ValidationFinding:
    return ValidationFinding(
        severity=severity,
        code=code,
        message=message,
        path=path,
        case_id=case_id,
        location=location,
    )


def _safe_raw_case_id(raw: Mapping[str, Any] | None) -> str | None:
    if raw is None:
        return None
    case_id = raw.get("id")
    return case_id if isinstance(case_id, str) else None


def _string_sequence(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())


def _infer_expected_suite(path: Path | None, *, suite_root: Path | None) -> str | None:
    if path is None:
        return None
    if suite_root is not None:
        try:
            relative = path.relative_to(suite_root)
        except ValueError:
            relative = None
        if relative is not None and len(relative.parts) > 1:
            return relative.parts[0]
        if suite_root.name in SUPPORTED_SUITE_SET:
            return suite_root.name
    parent_name = path.parent.name
    return parent_name or None


__all__: Final[tuple[str, ...]] = (
    "CaseValidationResult",
    "FindingSeverity",
    "SuiteValidationResult",
    "ValidationFinding",
    "ValidationOptions",
    "collect_findings",
    "has_blocking_findings",
    "summarize_findings",
    "validate_case_document",
    "validate_case_file",
    "validate_case_model",
    "validate_suite",
)
