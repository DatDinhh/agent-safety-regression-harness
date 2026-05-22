"""Synthetic email inbox and outbox for ASRH sandboxes.

The MVP harness must never send real email. ``EmailBox`` records inbox reads,
simulated sends, and blocked send attempts as deterministic in-memory state that
can be inspected by traces and checkers.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Final

from asrh.cases.schema import EmailSpec, EmailTrustLevel

SOURCE_LABEL_PREFIX: Final[str] = "source:email:"
TRUST_LABEL_PREFIX: Final[str] = "trust:"
DEFAULT_INBOX_ID_PREFIX: Final[str] = "email"


class EmailBoxError(Exception):
    """Base exception for synthetic email state."""


class EmailNotFound(EmailBoxError):
    """Raised when an email message id does not exist."""


@dataclass(frozen=True, slots=True)
class EmailObject:
    """Synthetic inbound email message."""

    message_id: str
    sender: str
    subject: str
    body: str
    trust_level: str
    labels: tuple[str, ...] = field(default_factory=tuple)
    read: bool = False
    created_at: str = field(default_factory=lambda: _utc_now_iso())

    def __post_init__(self) -> None:
        """Normalize fields."""
        object.__setattr__(self, "message_id", _require_non_blank(self.message_id, "message_id"))
        object.__setattr__(self, "sender", _require_non_blank(self.sender, "sender"))
        object.__setattr__(self, "subject", _require_non_blank(self.subject, "subject"))
        object.__setattr__(self, "trust_level", _normalize_email_trust_level(self.trust_level))
        object.__setattr__(self, "labels", _dedupe(self.labels))

    @classmethod
    def from_spec(cls, spec: EmailSpec, *, index: int) -> EmailObject:
        """Build an inbound email from a parsed YAML email spec."""
        return cls(
            message_id=f"{DEFAULT_INBOX_ID_PREFIX}_{index:03d}",
            sender=spec.sender,
            subject=spec.subject,
            body=spec.body,
            trust_level=_enum_value(spec.trust_level),
            labels=tuple(spec.labels),
        )

    @property
    def access_labels(self) -> tuple[str, ...]:
        """Return taint labels for reads of this message."""
        return _dedupe(
            (
                f"{SOURCE_LABEL_PREFIX}{self.message_id}",
                f"sender:{self.sender}",
                f"{TRUST_LABEL_PREFIX}{self.trust_level}",
                *self.labels,
            )
        )

    @property
    def is_untrusted(self) -> bool:
        """Return whether this message is marked untrusted."""
        return self.trust_level == "untrusted"

    def mark_read(self) -> EmailObject:
        """Return a copy marked as read."""
        return replace(self, read=True)

    def to_dict(self, *, include_body: bool = True) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        data: dict[str, Any] = {
            "message_id": self.message_id,
            "from": self.sender,
            "subject": self.subject,
            "trust_level": self.trust_level,
            "labels": list(self.labels),
            "access_labels": list(self.access_labels),
            "read": self.read,
            "created_at": self.created_at,
        }
        if include_body:
            data["body"] = self.body
        return data


@dataclass(frozen=True, slots=True)
class SentEmailRecord:
    """Synthetic outbox record for a send attempt."""

    to: str
    subject: str
    body: str
    allowed: bool
    sent: bool
    reason: str | None = None
    labels: tuple[str, ...] = field(default_factory=tuple)
    timestamp: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self, *, include_body: bool = True) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        data: dict[str, Any] = {
            "to": self.to,
            "subject": self.subject,
            "allowed": self.allowed,
            "sent": self.sent,
            "reason": self.reason,
            "labels": list(self.labels),
            "timestamp": self.timestamp,
            "simulated": True,
        }
        if include_body:
            data["body"] = self.body
        return data


class EmailBox:
    """In-memory synthetic inbox and outbox."""

    def __init__(self, messages: Iterable[EmailObject] = ()) -> None:
        self._messages: dict[str, EmailObject] = {}
        self._outbox: list[SentEmailRecord] = []
        for message in messages:
            self.add(message)

    @classmethod
    def from_specs(cls, specs: Sequence[EmailSpec]) -> EmailBox:
        """Build an email box from parsed YAML email specs."""
        return cls(EmailObject.from_spec(spec, index=index) for index, spec in enumerate(specs, start=1))

    def __len__(self) -> int:
        """Return inbox message count."""
        return len(self._messages)

    def add(self, message: EmailObject) -> None:
        """Add an inbound message."""
        if message.message_id in self._messages:
            raise EmailBoxError(f"duplicate email message id: {message.message_id}")
        self._messages[message.message_id] = message

    def list_messages(self, *, unread_only: bool = False) -> tuple[EmailObject, ...]:
        """Return messages in deterministic order."""
        messages = tuple(self._messages[key] for key in sorted(self._messages))
        if unread_only:
            return tuple(message for message in messages if not message.read)
        return messages

    def get(self, message_id: str) -> EmailObject:
        """Return an inbound message by id."""
        normalized = _require_non_blank(message_id, "message_id")
        try:
            return self._messages[normalized]
        except KeyError as exc:
            raise EmailNotFound(f"email not found: {normalized}") from exc

    def read(self, message_id: str) -> EmailObject:
        """Return an inbound message and mark it as read."""
        message = self.get(message_id)
        updated = message.mark_read()
        self._messages[message.message_id] = updated
        return updated

    def first_unread(self) -> EmailObject | None:
        """Return the first unread message, or ``None`` if all are read."""
        for message in self.list_messages(unread_only=True):
            return message
        return None

    def record_send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        allowed: bool,
        reason: str | None = None,
        labels: Iterable[str] = (),
    ) -> SentEmailRecord:
        """Record a simulated send or blocked send attempt."""
        record = SentEmailRecord(
            to=_require_non_blank(to, "to"),
            subject=subject,
            body=body,
            allowed=bool(allowed),
            sent=bool(allowed),
            reason=reason,
            labels=_dedupe(labels),
        )
        self._outbox.append(record)
        return record

    @property
    def outbox(self) -> tuple[SentEmailRecord, ...]:
        """Return synthetic outbox records."""
        return tuple(self._outbox)

    def snapshot(self, *, include_body: bool = False) -> dict[str, Any]:
        """Return a JSON-serializable inbox/outbox snapshot."""
        return {
            "inbox": [message.to_dict(include_body=include_body) for message in self.list_messages()],
            "outbox": [record.to_dict(include_body=include_body) for record in self._outbox],
            "inbox_count": len(self._messages),
            "outbox_count": len(self._outbox),
        }

    def to_dict(self, *, include_body: bool = False) -> dict[str, Any]:
        """Alias for ``snapshot``."""
        return self.snapshot(include_body=include_body)


def _normalize_email_trust_level(value: str) -> str:
    """Normalize and validate an email trust level."""
    normalized = _enum_value(value).strip().lower()
    allowed = {item.value for item in EmailTrustLevel}
    if normalized not in allowed:
        raise ValueError(f"unsupported email trust level {value!r}; expected one of {sorted(allowed)}")
    return normalized


def _enum_value(value: Any) -> str:
    """Return enum value or string representation."""
    return str(getattr(value, "value", value))


def _require_non_blank(value: str, field_name: str) -> str:
    """Normalize a required string."""
    text = str(value).strip()
    if not text:
        raise ValueError(f"{field_name} must not be blank")
    return text


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
    "DEFAULT_INBOX_ID_PREFIX",
    "EmailBox",
    "EmailBoxError",
    "EmailNotFound",
    "EmailObject",
    "SOURCE_LABEL_PREFIX",
    "SentEmailRecord",
    "TRUST_LABEL_PREFIX",
)
