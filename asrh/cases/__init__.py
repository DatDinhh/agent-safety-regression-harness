"""Case-schema, loading, and validation package for ASRH.

The ``asrh.cases`` package owns the YAML test-case contract described by the
technical specification. It exposes three layers:

- ``schema``: Pydantic models for a single case document.
- ``loader``: deterministic YAML discovery/loading helpers.
- ``validator``: structured schema and catalog-quality findings.

Runner and CLI modules should use this package instead of parsing case YAML
ad hoc. That keeps the benchmark catalog, test suite, and report pipeline on a
single source of truth.
"""

from __future__ import annotations

from typing import Final

from asrh.cases.loader import (
    DEFAULT_YAML_ENCODING,
    DEFAULT_YAML_INDENT,
    CaseCatalog,
    CaseDiscoveryError,
    CaseDiscoveryOptions,
    CaseLoadError,
    DuplicateCaseIdError,
    LoadedCase,
    discover_case_files,
    dump_case,
    infer_suite_name,
    is_case_file,
    load_catalog,
    load_case,
    load_case_with_metadata,
    load_cases,
    load_suite,
    read_case_document,
    reject_duplicate_case_ids,
    write_case,
)
from asrh.cases.schema import (
    CASE_FILE_SUFFIXES,
    CASE_ID_PATTERN,
    HIGH_RISK_TOOLS,
    PYDANTIC_V2,
    REQUIRED_CASES_PER_MVP_SUITE,
    REQUIRED_MVP_CASE_COUNT,
    SAFETY_CHECKER_TYPES,
    SENSITIVE_CHECKER_TYPES,
    SUPPORTED_CATEGORY_SET,
    SUPPORTED_CHECKER_TYPE_SET,
    SUPPORTED_TOOL_SET,
    UTILITY_CHECKER_TYPES,
    AttackSpec,
    AttackType,
    CaseBaseModel,
    CaseCategory,
    CaseSchemaError,
    CaseSeverity,
    CheckerSpec,
    CheckerType,
    Difficulty,
    EmailSpec,
    EmailTrustLevel,
    EnvironmentSpec,
    ExpectedSafety,
    ExpectedSpec,
    ExpectedUtility,
    FileSpec,
    FileTrustLevel,
    Metadata,
    PayloadLocation,
    RawCaseDocument,
    SeverityLevel,
    TaskSpec,
    TaskSuccessCriteria,
    TestCase,
    ThreatModelSpec,
    ToolSpec,
    ToolSpecModel,
    TrustLevel,
    category_from_case_id,
    is_safety_checker_type,
    is_utility_checker_type,
    parse_case_document,
    validate_case_relative_path,
)
from asrh.cases.validator import (
    CaseValidationResult,
    FindingSeverity,
    SuiteValidationResult,
    ValidationFinding,
    ValidationOptions,
    collect_findings,
    has_blocking_findings,
    summarize_findings,
    validate_case_document,
    validate_case_file,
    validate_case_model,
    validate_suite,
)

CASE_PACKAGE_NAME: Final[str] = "asrh.cases"
"""Import path for the ASRH case package."""

CASE_SCHEMA_MODULE: Final[str] = "asrh.cases.schema"
"""Import path for Pydantic case models."""

CASE_LOADER_MODULE: Final[str] = "asrh.cases.loader"
"""Import path for YAML loading and discovery utilities."""

CASE_VALIDATOR_MODULE: Final[str] = "asrh.cases.validator"
"""Import path for structured validation utilities."""

__all__: Final[tuple[str, ...]] = (
    "CASE_FILE_SUFFIXES",
    "CASE_ID_PATTERN",
    "CASE_LOADER_MODULE",
    "CASE_PACKAGE_NAME",
    "CASE_SCHEMA_MODULE",
    "CASE_VALIDATOR_MODULE",
    "DEFAULT_YAML_ENCODING",
    "DEFAULT_YAML_INDENT",
    "HIGH_RISK_TOOLS",
    "PYDANTIC_V2",
    "REQUIRED_CASES_PER_MVP_SUITE",
    "REQUIRED_MVP_CASE_COUNT",
    "SAFETY_CHECKER_TYPES",
    "SENSITIVE_CHECKER_TYPES",
    "SUPPORTED_CATEGORY_SET",
    "SUPPORTED_CHECKER_TYPE_SET",
    "SUPPORTED_TOOL_SET",
    "UTILITY_CHECKER_TYPES",
    "AttackSpec",
    "AttackType",
    "CaseBaseModel",
    "CaseCatalog",
    "CaseCategory",
    "CaseDiscoveryError",
    "CaseDiscoveryOptions",
    "CaseLoadError",
    "CaseSchemaError",
    "CaseSeverity",
    "CaseValidationResult",
    "CheckerSpec",
    "CheckerType",
    "Difficulty",
    "DuplicateCaseIdError",
    "EmailSpec",
    "EmailTrustLevel",
    "EnvironmentSpec",
    "ExpectedSafety",
    "ExpectedSpec",
    "ExpectedUtility",
    "FileSpec",
    "FileTrustLevel",
    "FindingSeverity",
    "LoadedCase",
    "Metadata",
    "PayloadLocation",
    "RawCaseDocument",
    "SeverityLevel",
    "SuiteValidationResult",
    "TaskSpec",
    "TaskSuccessCriteria",
    "TestCase",
    "ThreatModelSpec",
    "ToolSpec",
    "ToolSpecModel",
    "TrustLevel",
    "ValidationFinding",
    "ValidationOptions",
    "category_from_case_id",
    "collect_findings",
    "discover_case_files",
    "dump_case",
    "has_blocking_findings",
    "infer_suite_name",
    "is_case_file",
    "is_safety_checker_type",
    "is_utility_checker_type",
    "load_catalog",
    "load_case",
    "load_case_with_metadata",
    "load_cases",
    "load_suite",
    "parse_case_document",
    "read_case_document",
    "reject_duplicate_case_ids",
    "summarize_findings",
    "validate_case_document",
    "validate_case_file",
    "validate_case_model",
    "validate_case_relative_path",
    "validate_suite",
    "write_case",
)
