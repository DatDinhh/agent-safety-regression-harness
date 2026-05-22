"""YAML case loading and discovery utilities for ASRH.

The loader layer is deliberately free of CLI concerns. It reads case files,
normalizes discovery order, delegates structural validation to
``asrh.cases.schema``, and returns typed ``TestCase`` objects that runner,
reporting, and validation modules can share.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Final, TextIO, cast

import yaml

from asrh import SUPPORTED_SUITES
from asrh.cases.schema import CASE_FILE_SUFFIXES, RawCaseDocument, TestCase, parse_case_document

DEFAULT_YAML_ENCODING: Final[str] = "utf-8"
"""Encoding used when reading and writing YAML case files."""

DEFAULT_YAML_INDENT: Final[int] = 2
"""YAML indentation used by ``dump_case`` and ``write_case``."""

SUPPORTED_SUITE_SET: Final[frozenset[str]] = frozenset(SUPPORTED_SUITES)


class CaseLoadError(RuntimeError):
    """Base exception for case loading failures."""

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        self.path = path
        if path is not None:
            message = f"{path}: {message}"
        super().__init__(message)


class CaseDiscoveryError(CaseLoadError):
    """Raised when suite/case discovery fails before YAML parsing."""


class DuplicateCaseIdError(CaseLoadError):
    """Raised when multiple files define the same case id."""

    def __init__(self, duplicate_ids: Mapping[str, Sequence[Path]]) -> None:
        self.duplicate_ids = {case_id: tuple(paths) for case_id, paths in duplicate_ids.items()}
        details = "; ".join(
            f"{case_id}: {', '.join(str(path) for path in paths)}"
            for case_id, paths in sorted(self.duplicate_ids.items())
        )
        super().__init__(f"duplicate case id(s) found: {details}")


@dataclass(frozen=True, slots=True)
class LoadedCase:
    """A parsed ASRH case plus loader metadata."""

    path: Path
    case: TestCase
    raw: RawCaseDocument
    suite: str

    @property
    def case_id(self) -> str:
        """Return the loaded case id."""
        return self.case.id

    @property
    def category(self) -> str:
        """Return the loaded case category."""
        return self.case.category

    @property
    def severity(self) -> str:
        """Return the loaded case severity."""
        return self.case.severity

    def to_summary(self) -> dict[str, Any]:
        """Return a compact summary suitable for logs or JSON output."""
        return {
            "path": self.path.as_posix(),
            "suite": self.suite,
            "id": self.case.id,
            "category": self.case.category,
            "severity": self.case.severity,
            "title": self.case.metadata.title,
            "tools": list(self.case.allowed_tools),
            "checkers": list(self.case.checker_types),
        }


@dataclass(frozen=True, slots=True)
class CaseCatalog:
    """Loaded case collection with useful aggregate indexes."""

    root: Path
    cases: tuple[LoadedCase, ...]

    @property
    def case_count(self) -> int:
        """Return the number of loaded cases."""
        return len(self.cases)

    @property
    def case_ids(self) -> tuple[str, ...]:
        """Return case ids in deterministic discovery order."""
        return tuple(loaded.case.id for loaded in self.cases)

    @property
    def suites(self) -> dict[str, int]:
        """Return case counts by inferred suite name."""
        return dict(Counter(loaded.suite for loaded in self.cases))

    @property
    def categories(self) -> dict[str, int]:
        """Return case counts by metadata category."""
        return dict(Counter(loaded.case.category for loaded in self.cases))

    @property
    def severities(self) -> dict[str, int]:
        """Return case counts by metadata severity."""
        return dict(Counter(loaded.case.severity for loaded in self.cases))

    def by_id(self) -> dict[str, LoadedCase]:
        """Return a mapping from case id to loaded case."""
        return {loaded.case.id: loaded for loaded in self.cases}

    def by_suite(self) -> dict[str, tuple[LoadedCase, ...]]:
        """Return loaded cases grouped by inferred suite."""
        grouped: defaultdict[str, list[LoadedCase]] = defaultdict(list)
        for loaded in self.cases:
            grouped[loaded.suite].append(loaded)
        return {suite: tuple(items) for suite, items in sorted(grouped.items())}


@dataclass(frozen=True, slots=True)
class CaseDiscoveryOptions:
    """Options controlling deterministic YAML case discovery."""

    include_hidden: bool = False
    require_non_empty: bool = True
    suffixes: tuple[str, ...] = CASE_FILE_SUFFIXES


def is_case_file(path: Path, *, suffixes: Sequence[str] = CASE_FILE_SUFFIXES) -> bool:
    """Return whether ``path`` looks like an ASRH YAML case file."""
    return path.is_file() and path.suffix.lower() in {suffix.lower() for suffix in suffixes}


def discover_case_files(
    root: Path,
    *,
    include_hidden: bool = False,
    require_non_empty: bool = True,
    suffixes: Sequence[str] = CASE_FILE_SUFFIXES,
) -> tuple[Path, ...]:
    """Discover YAML case files under ``root`` in stable order.

    ``root`` may point to a single case file, one suite directory, or the
    top-level ``suites/`` directory.
    """
    expanded = root.expanduser()
    if expanded.is_file():
        if not is_case_file(expanded, suffixes=suffixes):
            raise CaseDiscoveryError("file is not a supported YAML case file", path=expanded)
        if not include_hidden and _is_hidden_relative_path(expanded, expanded.parent):
            raise CaseDiscoveryError("hidden case file excluded by default", path=expanded)
        return (expanded,)

    if not expanded.exists():
        raise CaseDiscoveryError("path does not exist", path=expanded)
    if not expanded.is_dir():
        raise CaseDiscoveryError("path must be a YAML case file or directory", path=expanded)

    suffix_set = {suffix.lower() for suffix in suffixes}
    discovered = tuple(
        sorted(
            (
                candidate
                for candidate in expanded.rglob("*")
                if candidate.is_file()
                and candidate.suffix.lower() in suffix_set
                and (include_hidden or not _is_hidden_relative_path(candidate, expanded))
            ),
            key=lambda path: path.as_posix(),
        )
    )

    if require_non_empty and not discovered:
        raise CaseDiscoveryError("no YAML case files found", path=expanded)
    return discovered


def read_case_document(path: Path, *, encoding: str = DEFAULT_YAML_ENCODING) -> RawCaseDocument:
    """Read one YAML file and return the raw mapping."""
    expanded = path.expanduser()
    if not expanded.exists():
        raise CaseLoadError("case file does not exist", path=expanded)
    if not expanded.is_file():
        raise CaseLoadError("case path must point to a file", path=expanded)
    if expanded.suffix.lower() not in CASE_FILE_SUFFIXES:
        raise CaseLoadError(
            f"unsupported case file suffix {expanded.suffix!r}; expected one of {CASE_FILE_SUFFIXES}",
            path=expanded,
        )

    try:
        with expanded.open("r", encoding=encoding) as handle:
            loaded = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise CaseLoadError(f"invalid YAML: {exc}", path=expanded) from exc
    except OSError as exc:
        raise CaseLoadError(f"failed to read case file: {exc}", path=expanded) from exc

    if loaded is None:
        raise CaseLoadError("case file is empty", path=expanded)
    if not isinstance(loaded, dict):
        raise CaseLoadError("case YAML root must be a mapping/object", path=expanded)

    return cast(RawCaseDocument, loaded)


def load_case(path: Path, *, encoding: str = DEFAULT_YAML_ENCODING) -> TestCase:
    """Load and validate one YAML case file."""
    return load_case_with_metadata(path, encoding=encoding).case


def load_case_with_metadata(
    path: Path,
    *,
    suite_root: Path | None = None,
    encoding: str = DEFAULT_YAML_ENCODING,
) -> LoadedCase:
    """Load one YAML case file and return typed case plus loader metadata."""
    raw = read_case_document(path, encoding=encoding)
    try:
        case = parse_case_document(raw)
    except Exception as exc:  # noqa: BLE001 - preserve schema exception as loader context.
        raise CaseLoadError(str(exc), path=path) from exc

    suite = infer_suite_name(path, suite_root=suite_root)
    return LoadedCase(path=path, case=case, raw=raw, suite=suite)


def load_cases(
    paths: Iterable[Path],
    *,
    suite_root: Path | None = None,
    encoding: str = DEFAULT_YAML_ENCODING,
    reject_duplicate_ids: bool = True,
) -> tuple[LoadedCase, ...]:
    """Load multiple case files in deterministic order."""
    loaded = tuple(
        load_case_with_metadata(path, suite_root=suite_root, encoding=encoding)
        for path in sorted(paths, key=lambda item: item.as_posix())
    )
    if reject_duplicate_ids:
        reject_duplicate_case_ids(loaded)
    return loaded


def load_suite(
    root: Path,
    *,
    include_hidden: bool = False,
    encoding: str = DEFAULT_YAML_ENCODING,
    reject_duplicate_ids: bool = True,
) -> tuple[LoadedCase, ...]:
    """Discover, load, and validate all YAML cases under ``root``."""
    case_files = discover_case_files(root, include_hidden=include_hidden)
    return load_cases(
        case_files,
        suite_root=root.expanduser(),
        encoding=encoding,
        reject_duplicate_ids=reject_duplicate_ids,
    )


def load_catalog(
    root: Path,
    *,
    include_hidden: bool = False,
    encoding: str = DEFAULT_YAML_ENCODING,
    reject_duplicate_ids: bool = True,
) -> CaseCatalog:
    """Load a suite or suite tree into a ``CaseCatalog``."""
    expanded = root.expanduser()
    return CaseCatalog(
        root=expanded,
        cases=load_suite(
            expanded,
            include_hidden=include_hidden,
            encoding=encoding,
            reject_duplicate_ids=reject_duplicate_ids,
        ),
    )


def reject_duplicate_case_ids(cases: Sequence[LoadedCase]) -> None:
    """Raise ``DuplicateCaseIdError`` if two loaded cases share an id."""
    by_id: defaultdict[str, list[Path]] = defaultdict(list)
    for loaded in cases:
        by_id[loaded.case.id].append(loaded.path)

    duplicates = {case_id: paths for case_id, paths in by_id.items() if len(paths) > 1}
    if duplicates:
        raise DuplicateCaseIdError(duplicates)


def infer_suite_name(path: Path, *, suite_root: Path | None = None) -> str:
    """Infer suite name for a case path.

    For ``suites/secret_exfiltration/case_001.yaml`` with ``suite_root`` set to
    ``suites/``, this returns ``secret_exfiltration``. For direct suite runs it
    returns the parent directory name.
    """
    expanded = path.expanduser()
    if suite_root is not None:
        root = suite_root.expanduser()
        try:
            relative = expanded.relative_to(root)
        except ValueError:
            relative = None
        if relative is not None and len(relative.parts) > 1:
            return relative.parts[0]
        if root.name in SUPPORTED_SUITE_SET:
            return root.name

    parent_name = expanded.parent.name
    if parent_name:
        return parent_name
    return "unknown"


def dump_case(case: TestCase, *, stream: TextIO | None = None) -> str:
    """Serialize a case model to YAML.

    If ``stream`` is provided, YAML is written to it and the same text is also
    returned. Unknown Python objects are not emitted; enum and date objects are
    converted to plain strings first.
    """
    payload = _to_yaml_safe(case.to_mapping(by_alias=True, exclude_none=True))
    text = yaml.safe_dump(
        payload,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        indent=DEFAULT_YAML_INDENT,
    )
    if stream is not None:
        stream.write(text)
    return text


def write_case(
    case: TestCase,
    path: Path,
    *,
    overwrite: bool = False,
    encoding: str = DEFAULT_YAML_ENCODING,
) -> Path:
    """Write a validated case model to a YAML file."""
    expanded = path.expanduser()
    if expanded.exists() and not overwrite:
        raise CaseLoadError("refusing to overwrite existing case file", path=expanded)
    if expanded.suffix.lower() not in CASE_FILE_SUFFIXES:
        raise CaseLoadError(
            f"unsupported output suffix {expanded.suffix!r}; expected one of {CASE_FILE_SUFFIXES}",
            path=expanded,
        )

    expanded.parent.mkdir(parents=True, exist_ok=True)
    try:
        with expanded.open("w", encoding=encoding) as handle:
            dump_case(case, stream=handle)
    except OSError as exc:
        raise CaseLoadError(f"failed to write case file: {exc}", path=expanded) from exc
    return expanded


def _is_hidden_relative_path(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    return any(part.startswith(".") for part in relative.parts)


def _to_yaml_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, date | datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _to_yaml_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_to_yaml_safe(item) for item in value]
    return value


__all__: Final[tuple[str, ...]] = (
    "CaseCatalog",
    "CaseDiscoveryError",
    "CaseDiscoveryOptions",
    "CaseLoadError",
    "DEFAULT_YAML_ENCODING",
    "DEFAULT_YAML_INDENT",
    "DuplicateCaseIdError",
    "LoadedCase",
    "discover_case_files",
    "dump_case",
    "infer_suite_name",
    "is_case_file",
    "load_catalog",
    "load_case",
    "load_case_with_metadata",
    "load_cases",
    "load_suite",
    "read_case_document",
    "reject_duplicate_case_ids",
    "write_case",
)
