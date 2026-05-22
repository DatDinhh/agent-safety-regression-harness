"""Synthetic memory store for ASRH sandboxes.

The YAML schema allows a case to provide arbitrary memory values. This module
normalizes them into labeled ``MemoryItem`` objects so future memory tools and
checkers can reason about sensitive or untrusted memory without special-casing
raw dictionaries.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Final

SOURCE_LABEL_PREFIX: Final[str] = "source:memory:"
TRUST_LABEL_PREFIX: Final[str] = "trust:"
DEFAULT_MEMORY_TRUST_LEVEL: Final[str] = "trusted"
SENSITIVE_MEMORY_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "password",
        "private",
        "secret",
        "token",
    }
)
TRUST_LEVELS: Final[frozenset[str]] = frozenset({"trusted", "untrusted", "sensitive"})
MEMORY_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:/-]+$")


class MemoryStoreError(Exception):
    """Base exception for synthetic memory state."""


class MemoryKeyNotFound(MemoryStoreError):
    """Raised when a memory key does not exist."""


class UnsafeMemoryKey(MemoryStoreError):
    """Raised when a memory key is invalid."""


@dataclass(frozen=True, slots=True)
class MemoryItem:
    """One labeled item in the synthetic memory store."""

    key: str
    value: Any
    trust_level: str = DEFAULT_MEMORY_TRUST_LEVEL
    labels: tuple[str, ...] = field(default_factory=tuple)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    modified_at: str = field(default_factory=lambda: _utc_now_iso())

    def __post_init__(self) -> None:
        """Validate and normalize fields."""
        object.__setattr__(self, "key", validate_memory_key(self.key))
        object.__setattr__(self, "trust_level", _normalize_trust_level(self.trust_level))
        object.__setattr__(self, "labels", _dedupe(self.labels))

    @classmethod
    def from_raw(cls, key: str, raw_value: Any) -> MemoryItem:
        """Build a memory item from YAML-provided raw memory data."""
        normalized_key = validate_memory_key(key)
        if isinstance(raw_value, Mapping) and _looks_like_memory_item(raw_value):
            value = raw_value.get("value", raw_value.get("content"))
            trust_level = str(raw_value.get("trust_level") or infer_trust_level(normalized_key, value))
            labels = raw_value.get("labels") or ()
            if isinstance(labels, str):
                labels = (labels,)
            return cls(
                key=normalized_key,
                value=value,
                trust_level=trust_level,
                labels=tuple(str(label) for label in labels),
            )

        return cls(
            key=normalized_key,
            value=raw_value,
            trust_level=infer_trust_level(normalized_key, raw_value),
        )

    @property
    def access_labels(self) -> tuple[str, ...]:
        """Return labels attached to reads of this memory item."""
        return _dedupe(
            (
                f"{SOURCE_LABEL_PREFIX}{self.key}",
                f"{TRUST_LABEL_PREFIX}{self.trust_level}",
                *self.labels,
            )
        )

    @property
    def is_sensitive(self) -> bool:
        """Return whether this memory item is marked sensitive."""
        return self.trust_level == "sensitive"

    def value_text(self) -> str:
        """Return a stable string representation of the value for tool output."""
        try:
            return json.dumps(self.value, ensure_ascii=False, sort_keys=True)
        except TypeError:
            return str(self.value)

    def with_value(
        self,
        value: Any,
        *,
        trust_level: str | None = None,
        labels: Iterable[str] = (),
    ) -> MemoryItem:
        """Return a copy with updated value and labels."""
        return replace(
            self,
            value=value,
            trust_level=_normalize_trust_level(trust_level or self.trust_level),
            labels=_dedupe((*self.labels, *labels)),
            modified_at=_utc_now_iso(),
        )

    def to_dict(self, *, include_value: bool = True) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        data: dict[str, Any] = {
            "key": self.key,
            "trust_level": self.trust_level,
            "labels": list(self.labels),
            "access_labels": list(self.access_labels),
            "created_at": self.created_at,
            "modified_at": self.modified_at,
        }
        if include_value:
            data["value"] = self.value
        return data


class MemoryStore:
    """In-memory labeled key/value store."""

    def __init__(self, items: Iterable[MemoryItem] = ()) -> None:
        self._items: dict[str, MemoryItem] = {}
        for item in items:
            self.set_item(item)

    @classmethod
    def from_mapping(cls, raw_memory: Mapping[str, Any]) -> MemoryStore:
        """Build a memory store from a YAML memory mapping."""
        return cls(MemoryItem.from_raw(key, value) for key, value in raw_memory.items())

    def __len__(self) -> int:
        """Return number of memory items."""
        return len(self._items)

    def __contains__(self, key: object) -> bool:
        """Return whether a memory key exists."""
        if not isinstance(key, str):
            return False
        try:
            return validate_memory_key(key) in self._items
        except UnsafeMemoryKey:
            return False

    def keys(self) -> tuple[str, ...]:
        """Return memory keys in deterministic order."""
        return tuple(sorted(self._items))

    def set_item(self, item: MemoryItem) -> None:
        """Set a memory item."""
        self._items[item.key] = item

    def set(
        self,
        key: str,
        value: Any,
        *,
        trust_level: str | None = None,
        labels: Iterable[str] = (),
    ) -> MemoryItem:
        """Set a raw value and return the stored memory item."""
        normalized = validate_memory_key(key)
        existing = self._items.get(normalized)
        if existing is None:
            item = MemoryItem(
                key=normalized,
                value=value,
                trust_level=trust_level or infer_trust_level(normalized, value),
                labels=_dedupe(labels),
            )
        else:
            item = existing.with_value(
                value,
                trust_level=trust_level or existing.trust_level,
                labels=labels,
            )
        self._items[normalized] = item
        return item

    def get(self, key: str) -> MemoryItem:
        """Return a memory item."""
        normalized = validate_memory_key(key)
        try:
            return self._items[normalized]
        except KeyError as exc:
            raise MemoryKeyNotFound(f"memory key not found: {normalized}") from exc

    def get_optional(self, key: str) -> MemoryItem | None:
        """Return a memory item if present; otherwise return ``None``."""
        normalized = validate_memory_key(key)
        return self._items.get(normalized)

    def read_value(self, key: str) -> Any:
        """Return raw value for a key."""
        return self.get(key).value

    def snapshot(self, *, include_values: bool = False) -> dict[str, Any]:
        """Return a JSON-serializable snapshot."""
        return {
            "items": [self._items[key].to_dict(include_value=include_values) for key in self.keys()],
            "count": len(self._items),
        }

    def to_dict(self, *, include_values: bool = False) -> dict[str, Any]:
        """Alias for ``snapshot``."""
        return self.snapshot(include_values=include_values)


def validate_memory_key(key: str) -> str:
    """Validate and normalize a synthetic memory key."""
    normalized = str(key).strip()
    if not normalized:
        raise UnsafeMemoryKey("memory key must not be blank")
    if ".." in normalized:
        raise UnsafeMemoryKey("memory key must not contain '..'")
    if "\\" in normalized:
        raise UnsafeMemoryKey("memory key must use forward slashes, not backslashes")
    if not MEMORY_KEY_PATTERN.match(normalized):
        raise UnsafeMemoryKey(
            "memory key may contain only letters, numbers, underscore, dash, dot, colon, and slash"
        )
    return normalized


def infer_trust_level(key: str, value: Any) -> str:
    """Infer a conservative trust level for raw YAML memory entries."""
    lowered_key = key.lower()
    if any(keyword in lowered_key for keyword in SENSITIVE_MEMORY_KEYWORDS):
        return "sensitive"
    if isinstance(value, str) and any(keyword in value.lower() for keyword in ("api_key", "secret", "token=")):
        return "sensitive"
    return DEFAULT_MEMORY_TRUST_LEVEL


def _looks_like_memory_item(value: Mapping[str, Any]) -> bool:
    """Return whether a mapping carries memory-item metadata."""
    return any(key in value for key in ("value", "content", "trust_level", "labels"))


def _normalize_trust_level(value: str) -> str:
    """Normalize and validate a memory trust level."""
    normalized = str(value).strip().lower()
    if normalized not in TRUST_LEVELS:
        raise ValueError(f"unsupported memory trust level {value!r}; expected one of {sorted(TRUST_LEVELS)}")
    return normalized


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate non-blank strings while preserving order."""
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
    "DEFAULT_MEMORY_TRUST_LEVEL",
    "MEMORY_KEY_PATTERN",
    "MemoryItem",
    "MemoryKeyNotFound",
    "MemoryStore",
    "MemoryStoreError",
    "SENSITIVE_MEMORY_KEYWORDS",
    "SOURCE_LABEL_PREFIX",
    "TRUST_LABEL_PREFIX",
    "UnsafeMemoryKey",
    "infer_trust_level",
    "validate_memory_key",
)
