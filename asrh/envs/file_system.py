"""In-memory file system for ASRH synthetic sandboxes.

The MVP harness must not touch the host filesystem when an agent calls file
operations. This module models case-defined files as in-memory objects with
trust labels and coarse taint metadata. Tool wrappers and checkers can inspect
all accesses through the sandbox trace instead of relying on operating-system
side effects.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Final

from asrh.cases.schema import FileSpec, TrustLevel, validate_case_relative_path

DEFAULT_WRITTEN_FILE_TRUST_LEVEL: Final[str] = "trusted"
SOURCE_LABEL_PREFIX: Final[str] = "source:file:"
TRUST_LABEL_PREFIX: Final[str] = "trust:"


class FileSystemError(Exception):
    """Base exception for the synthetic file system."""


class FileNotFound(FileSystemError):
    """Raised when a synthetic file path does not exist."""


class FileAlreadyExists(FileSystemError):
    """Raised when a write would create a duplicate file without overwrite."""


class UnsafeFilePath(FileSystemError):
    """Raised when a path is invalid for the synthetic file system."""


@dataclass(frozen=True, slots=True)
class FileObject:
    """Synthetic file with content, trust level, and labels."""

    path: str
    content: str
    trust_level: str
    labels: tuple[str, ...] = field(default_factory=tuple)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    modified_at: str = field(default_factory=lambda: _utc_now_iso())

    def __post_init__(self) -> None:
        """Validate and normalize fields."""
        object.__setattr__(self, "path", _safe_path(self.path))
        object.__setattr__(self, "trust_level", _normalize_trust_level(self.trust_level))
        object.__setattr__(self, "labels", _dedupe(self.labels))

    @classmethod
    def from_spec(cls, spec: FileSpec) -> FileObject:
        """Build a file object from a parsed YAML file spec."""
        return cls(
            path=spec.path,
            content=spec.content,
            trust_level=_enum_value(spec.trust_level),
            labels=tuple(spec.labels),
        )

    @property
    def access_labels(self) -> tuple[str, ...]:
        """Return labels that should be attached to reads of this file."""
        return _dedupe(
            (
                f"{SOURCE_LABEL_PREFIX}{self.path}",
                f"{TRUST_LABEL_PREFIX}{self.trust_level}",
                *self.labels,
            )
        )

    @property
    def is_sensitive(self) -> bool:
        """Return whether this file is marked sensitive."""
        return self.trust_level == "sensitive"

    @property
    def is_untrusted(self) -> bool:
        """Return whether this file is marked untrusted."""
        return self.trust_level == "untrusted"

    def with_content(
        self,
        content: str,
        *,
        trust_level: str | None = None,
        labels: Iterable[str] = (),
    ) -> FileObject:
        """Return a copy with new content and updated metadata."""
        return replace(
            self,
            content=content,
            trust_level=_normalize_trust_level(trust_level or self.trust_level),
            labels=_dedupe((*self.labels, *labels)),
            modified_at=_utc_now_iso(),
        )

    def to_dict(self, *, include_content: bool = True) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        data: dict[str, Any] = {
            "path": self.path,
            "trust_level": self.trust_level,
            "labels": list(self.labels),
            "access_labels": list(self.access_labels),
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "size": len(self.content),
        }
        if include_content:
            data["content"] = self.content
        return data


@dataclass(frozen=True, slots=True)
class FileWriteResult:
    """Result metadata for a synthetic write operation."""

    path: str
    created: bool
    overwritten: bool
    previous_trust_level: str | None
    trust_level: str
    labels: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "path": self.path,
            "created": self.created,
            "overwritten": self.overwritten,
            "previous_trust_level": self.previous_trust_level,
            "trust_level": self.trust_level,
            "labels": list(self.labels),
        }


class FileSystem:
    """In-memory synthetic file system for one sandbox run."""

    def __init__(self, files: Iterable[FileObject] = ()) -> None:
        self._files: dict[str, FileObject] = {}
        for file_object in files:
            self.add(file_object, overwrite=False)

    @classmethod
    def from_specs(cls, specs: Sequence[FileSpec]) -> FileSystem:
        """Build a file system from parsed YAML file specs."""
        return cls(FileObject.from_spec(spec) for spec in specs)

    def __contains__(self, path: object) -> bool:
        """Return whether a path exists."""
        if not isinstance(path, str):
            return False
        try:
            return _safe_path(path) in self._files
        except UnsafeFilePath:
            return False

    def __len__(self) -> int:
        """Return number of files."""
        return len(self._files)

    def __iter__(self) -> Iterable[FileObject]:
        """Iterate over files in path order."""
        for path in self.paths(include_sensitive=True):
            yield self._files[path]

    def add(self, file_object: FileObject, *, overwrite: bool = False) -> None:
        """Add a file object to the synthetic filesystem."""
        path = _safe_path(file_object.path)
        if path in self._files and not overwrite:
            raise FileAlreadyExists(f"file already exists: {path}")
        self._files[path] = file_object

    def exists(self, path: str) -> bool:
        """Return whether a safe path exists."""
        return _safe_path(path) in self._files

    def get(self, path: str) -> FileObject:
        """Return a file object, raising ``FileNotFound`` if absent."""
        normalized = _safe_path(path)
        try:
            return self._files[normalized]
        except KeyError as exc:
            raise FileNotFound(f"file not found: {normalized}") from exc

    def get_optional(self, path: str) -> FileObject | None:
        """Return a file object if it exists; otherwise return ``None``."""
        normalized = _safe_path(path)
        return self._files.get(normalized)

    def read(self, path: str) -> str:
        """Return file content."""
        return self.get(path).content

    def write(
        self,
        path: str,
        content: str,
        *,
        trust_level: str = DEFAULT_WRITTEN_FILE_TRUST_LEVEL,
        labels: Iterable[str] = (),
        overwrite: bool = True,
    ) -> FileWriteResult:
        """Write a synthetic file and return write metadata."""
        normalized = _safe_path(path)
        previous = self._files.get(normalized)
        if previous is not None and not overwrite:
            raise FileAlreadyExists(f"file already exists: {normalized}")

        normalized_trust = _normalize_trust_level(trust_level)
        normalized_labels = _dedupe(labels)
        now = _utc_now_iso()
        if previous is None:
            file_object = FileObject(
                path=normalized,
                content=content,
                trust_level=normalized_trust,
                labels=normalized_labels,
                created_at=now,
                modified_at=now,
            )
        else:
            file_object = previous.with_content(
                content,
                trust_level=normalized_trust,
                labels=normalized_labels,
            )
        self._files[normalized] = file_object
        return FileWriteResult(
            path=normalized,
            created=previous is None,
            overwritten=previous is not None,
            previous_trust_level=previous.trust_level if previous is not None else None,
            trust_level=file_object.trust_level,
            labels=file_object.access_labels,
        )

    def delete(self, path: str) -> FileObject:
        """Delete and return a file object from the synthetic filesystem."""
        normalized = _safe_path(path)
        try:
            return self._files.pop(normalized)
        except KeyError as exc:
            raise FileNotFound(f"file not found: {normalized}") from exc

    def paths(self, *, include_sensitive: bool = False) -> tuple[str, ...]:
        """Return file paths in deterministic order."""
        return tuple(
            sorted(
                path
                for path, file_object in self._files.items()
                if include_sensitive or not file_object.is_sensitive
            )
        )

    def visible_paths(
        self,
        *,
        include_sensitive: bool = False,
        denied_paths: Iterable[str] = (),
    ) -> tuple[str, ...]:
        """Return paths visible to a list-files style operation."""
        denied = {_safe_path(path) for path in denied_paths}
        return tuple(path for path in self.paths(include_sensitive=include_sensitive) if path not in denied)

    def snapshot(self, *, include_content: bool = False) -> dict[str, Any]:
        """Return a JSON-serializable snapshot."""
        return {
            "files": [
                self._files[path].to_dict(include_content=include_content)
                for path in self.paths(include_sensitive=True)
            ],
            "count": len(self._files),
        }

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        """Alias for ``snapshot``."""
        return self.snapshot(include_content=include_content)


FileSystemSnapshot = Mapping[str, Any]
"""JSON-like file-system snapshot type alias."""


def _safe_path(path: str) -> str:
    """Validate and normalize a synthetic file path."""
    try:
        return validate_case_relative_path(path, field_name="file path")
    except ValueError as exc:
        raise UnsafeFilePath(str(exc)) from exc


def _enum_value(value: Any) -> str:
    """Return enum value or string representation."""
    return str(getattr(value, "value", value))


def _normalize_trust_level(value: str) -> str:
    """Normalize and validate a file trust level."""
    normalized = _enum_value(value).strip().lower()
    allowed = {item.value for item in TrustLevel}
    if normalized not in allowed:
        raise ValueError(f"unsupported file trust level {value!r}; expected one of {sorted(allowed)}")
    return normalized


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate non-blank labels while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return tuple(result)


def _utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(UTC).isoformat(timespec="seconds")


__all__: Final[tuple[str, ...]] = (
    "DEFAULT_WRITTEN_FILE_TRUST_LEVEL",
    "FileAlreadyExists",
    "FileNotFound",
    "FileObject",
    "FileSystem",
    "FileSystemError",
    "FileSystemSnapshot",
    "FileWriteResult",
    "SOURCE_LABEL_PREFIX",
    "TRUST_LABEL_PREFIX",
    "UnsafeFilePath",
)
