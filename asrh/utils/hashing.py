"""Deterministic hashing and canonicalization helpers for ASRH artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Final, Literal, TypeAlias
from uuid import UUID

JsonDict: TypeAlias = dict[str, Any]
JsonMapping: TypeAlias = Mapping[str, Any]
HashAlgorithm: TypeAlias = Literal["sha256", "sha1", "blake2b"]
PathLike: TypeAlias = str | Path

DEFAULT_ENCODING: Final[str] = "utf-8"
DEFAULT_HASH_ALGORITHM: Final[HashAlgorithm] = "sha256"
DEFAULT_SHORT_HASH_LENGTH: Final[int] = 12
DEFAULT_FILE_CHUNK_SIZE: Final[int] = 1024 * 1024
RUN_ID_UNSAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9_.-]+")
NONDETERMINISTIC_RECORD_FIELDS: Final[frozenset[str]] = frozenset(
    {"started_at", "ended_at", "timestamp", "loaded_at", "duration_seconds", "cost_estimate_usd"}
)


class HashingError(ValueError):
    """Base exception for hashing/canonicalization errors."""


class UnsupportedHashAlgorithmError(HashingError):
    """Raised when a requested hash algorithm is unsupported."""


class CanonicalizationError(HashingError):
    """Raised when a value cannot be converted to canonical JSON."""


class FileHashError(HashingError):
    """Raised when a file cannot be read for hashing."""


@dataclass(frozen=True, slots=True)
class ContentDigest:
    """Structured digest metadata for files, traces, cases, and reports."""

    algorithm: str
    hexdigest: str
    byte_length: int | None = None
    label: str | None = None

    @property
    def short(self) -> str:
        return short_digest(self.hexdigest)

    def to_dict(self) -> JsonDict:
        return {
            "algorithm": self.algorithm,
            "hexdigest": self.hexdigest,
            "short": self.short,
            "byte_length": self.byte_length,
            "label": self.label,
        }


def normalize_hash_algorithm(algorithm: str | None = None) -> HashAlgorithm:
    """Normalize and validate a supported hash algorithm name."""

    normalized = (algorithm or DEFAULT_HASH_ALGORITHM).strip().lower().replace("-", "")
    if normalized == "sha256":
        return "sha256"
    if normalized == "sha1":
        return "sha1"
    if normalized == "blake2b":
        return "blake2b"
    raise UnsupportedHashAlgorithmError(f"unsupported hash algorithm: {algorithm!r}")


ensure_supported_algorithm = normalize_hash_algorithm
validate_algorithm = normalize_hash_algorithm


def new_hasher(algorithm: str | None = None) -> Any:
    """Create a hashlib object for a supported algorithm."""

    normalized = normalize_hash_algorithm(algorithm)
    if normalized == "sha256":
        return hashlib.sha256()
    if normalized == "sha1":  # nosec B324 - non-security fingerprint support only.
        return hashlib.sha1()
    return hashlib.blake2b(digest_size=32)


def jsonable(value: Any) -> Any:
    """Convert common Python objects into deterministic JSON-compatible values."""

    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, float):
        if value != value:
            return "NaN"
        if value == float("inf"):
            return "Infinity"
        if value == float("-inf"):
            return "-Infinity"
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        normalized = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return normalized.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return jsonable(value.value)
    if is_dataclass(value) and not isinstance(value, type):
        return jsonable(asdict(value))
    for method_name in ("to_dict", "model_dump", "dict"):
        method = getattr(value, method_name, None)
        if callable(method):
            try:
                return jsonable(method())
            except TypeError:
                continue
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, set | frozenset):
        return [jsonable(item) for item in sorted(value, key=repr)]
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [jsonable(item) for item in value]
    return str(value)


canonicalize = jsonable

def canonical_json(value: Any, *, pretty: bool = False) -> str:
    """Serialize a value as stable canonical JSON."""

    try:
        if pretty:
            return json.dumps(jsonable(value), ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        return json.dumps(jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(f"value cannot be serialized as canonical JSON: {exc}") from exc


stable_json = canonical_json
stable_json_dumps = canonical_json
canonical_json_dumps = canonical_json


def canonical_json_bytes(value: Any, *, encoding: str = DEFAULT_ENCODING) -> bytes:
    return canonical_json(value).encode(encoding)


stable_json_bytes = canonical_json_bytes


def digest_bytes(data: bytes | bytearray | memoryview, *, algorithm: str | None = None, label: str | None = None) -> ContentDigest:
    payload = data.tobytes() if isinstance(data, memoryview) else bytes(data)
    hasher = new_hasher(algorithm)
    hasher.update(payload)
    return ContentDigest(normalize_hash_algorithm(algorithm), hasher.hexdigest(), len(payload), label)


def hash_bytes(data: bytes | bytearray | memoryview, *, algorithm: str | None = None) -> str:
    return digest_bytes(data, algorithm=algorithm).hexdigest


def digest_text(text: str, *, encoding: str = DEFAULT_ENCODING, algorithm: str | None = None, label: str | None = None) -> ContentDigest:
    return digest_bytes(text.encode(encoding), algorithm=algorithm, label=label)


def hash_text(text: str, *, encoding: str = DEFAULT_ENCODING, algorithm: str | None = None) -> str:
    return digest_text(text, encoding=encoding, algorithm=algorithm).hexdigest


def digest_json(value: Any, *, algorithm: str | None = None, label: str | None = None) -> ContentDigest:
    return digest_bytes(canonical_json_bytes(value), algorithm=algorithm, label=label)


def hash_json(value: Any, *, algorithm: str | None = None) -> str:
    return digest_json(value, algorithm=algorithm).hexdigest


stable_hash = hash_json
content_hash = hash_json
fingerprint = hash_json
artifact_fingerprint = hash_json
json_digest = hash_json
sha256_json = hash_json
sha256_text = hash_text
sha256_bytes = hash_bytes


def digest_file(path: PathLike, *, algorithm: str | None = None, chunk_size: int = DEFAULT_FILE_CHUNK_SIZE, label: str | None = None) -> ContentDigest:
    """Hash a real local file. Synthetic case files stay inside the sandbox."""

    if chunk_size <= 0:
        raise HashingError("chunk_size must be positive")
    source = Path(path).expanduser()
    hasher = new_hasher(algorithm)
    byte_length = 0
    try:
        with source.open("rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                byte_length += len(chunk)
                hasher.update(chunk)
    except OSError as exc:
        raise FileHashError(f"failed to hash file {source}: {exc}") from exc
    return ContentDigest(normalize_hash_algorithm(algorithm), hasher.hexdigest(), byte_length, label or source.as_posix())


def hash_file(path: PathLike, *, algorithm: str | None = None, chunk_size: int = DEFAULT_FILE_CHUNK_SIZE) -> str:
    return digest_file(path, algorithm=algorithm, chunk_size=chunk_size).hexdigest


file_digest = hash_file
fingerprint_file = hash_file


def directory_digest(path: PathLike, *, algorithm: str | None = None) -> ContentDigest:
    root = Path(path).expanduser()
    records: list[JsonDict] = []
    for file_path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
        digest = digest_file(file_path, algorithm=algorithm)
        records.append({"path": file_path.relative_to(root).as_posix(), "digest": digest.hexdigest})
    return digest_json({"root": root.as_posix(), "files": records}, algorithm=algorithm, label=root.as_posix())


def fingerprint_directory(path: PathLike, *, algorithm: str | None = None) -> str:
    return directory_digest(path, algorithm=algorithm).hexdigest


def combine_digests(digests: Iterable[str], *, algorithm: str | None = None, label: str | None = None) -> ContentDigest:
    return digest_json(sorted(str(item) for item in digests), algorithm=algorithm, label=label)


def short_digest(digest: str, *, length: int = DEFAULT_SHORT_HASH_LENGTH) -> str:
    if length <= 0:
        raise HashingError("length must be positive")
    return str(digest)[:length]


def short_hash(value: Any, *, length: int = DEFAULT_SHORT_HASH_LENGTH, algorithm: str | None = None) -> str:
    return short_digest(hash_json(value, algorithm=algorithm), length=length)


short_sha256 = short_hash

def content_address(value: Any, *, prefix: str = "asrh", length: int = DEFAULT_SHORT_HASH_LENGTH) -> str:
    return f"{safe_id_part(prefix)}-{short_hash(value, length=length)}"


def safe_id_part(value: Any, *, default: str = "unknown") -> str:
    text = RUN_ID_UNSAFE_RE.sub("-", str(value or "").strip()).strip("-_.")
    return text or default


def make_run_id(*parts: Any) -> str:
    cleaned = [safe_id_part(part) for part in parts if str(part).strip()]
    return "_".join(cleaned) if cleaned else content_address("run")


build_run_id = make_run_id


def compare_digest(left: str, right: str) -> bool:
    return hashlib.compare_digest(str(left), str(right))


def drop_fields(value: Any, fields: Iterable[str]) -> Any:
    field_set = {str(field) for field in fields}
    payload = jsonable(value)
    if isinstance(payload, Mapping):
        return {key: drop_fields(item, field_set) for key, item in payload.items() if key not in field_set}
    if isinstance(payload, list):
        return [drop_fields(item, field_set) for item in payload]
    return payload


def record_fingerprint(record: Mapping[str, Any], *, ignore_fields: Iterable[str] = NONDETERMINISTIC_RECORD_FIELDS, algorithm: str | None = None) -> str:
    return hash_json(drop_fields(record, ignore_fields), algorithm=algorithm)


__all__: Final[tuple[str, ...]] = tuple(
    sorted(
        name
        for name in globals()
        if not name.startswith("_") and name not in {"annotations", "Any", "Final", "Literal", "TypeAlias"}
    )
)
