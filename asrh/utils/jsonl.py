"""JSON and JSONL utilities for ASRH traces and reports."""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final, TextIO, TypeAlias

from asrh.utils.hashing import canonicalize, hash_file

JsonDict: TypeAlias = dict[str, Any]
JsonMapping: TypeAlias = Mapping[str, Any]
DEFAULT_JSONL_ENCODING: Final[str] = "utf-8"
DEFAULT_JSONL_SUFFIX: Final[str] = ".jsonl"

class JsonlError(RuntimeError): pass
class JsonlReadError(JsonlError): pass
class JsonlIOError(JsonlReadError): pass
class JsonlWriteError(JsonlError): pass
class JsonlDecodeError(JsonlReadError): pass
class JsonlTypeError(JsonlError): pass
class JsonlValidationError(JsonlError): pass
class JsonlRecordError(JsonlTypeError): pass
class JsonlSerializationError(JsonlWriteError): pass

@dataclass(frozen=True, slots=True)
class JsonlLine:
    path: Path
    line_number: int
    record: JsonDict
    raw: str = ""
    @property
    def line_no(self) -> int: return self.line_number
    def to_dict(self) -> JsonDict: return {"path": self.path.as_posix(), "line_number": self.line_number, "record": self.record, "raw": self.raw}

@dataclass(frozen=True, slots=True)
class JsonlReadResult:
    path: Path
    records: tuple[JsonDict, ...]
    line_count: int
    skipped_blank_lines: int = 0
    @property
    def record_count(self) -> int: return len(self.records)
    @property
    def records_read(self) -> int: return len(self.records)
    def to_dict(self) -> JsonDict: return {"path": self.path.as_posix(), "records_read": self.records_read, "line_count": self.line_count, "skipped_blank_lines": self.skipped_blank_lines}

@dataclass(frozen=True, slots=True)
class JsonlWriteResult:
    path: Path
    records_written: int
    bytes_written: int
    append: bool = False
    atomic: bool = False
    encoding: str = DEFAULT_JSONL_ENCODING
    digest: str | None = None
    def to_dict(self) -> JsonDict: return {**asdict(self), "path": self.path.as_posix()}

ReadResult = JsonlReadResult
WriteResult = JsonlWriteResult

def ensure_json_object(value: Any) -> JsonDict:
    payload = canonicalize(value)
    if not isinstance(payload, Mapping): raise JsonlTypeError("JSONL records must be objects")
    return {str(k): v for k, v in payload.items()}
def dumps_json(value: Any, *, sort_keys: bool = False, pretty: bool = False) -> str:
    try:
        if pretty: return json.dumps(canonicalize(value), ensure_ascii=False, sort_keys=sort_keys, indent=2, allow_nan=False)
        return json.dumps(canonicalize(value), ensure_ascii=False, sort_keys=sort_keys, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc: raise JsonlWriteError(str(exc)) from exc
def dumps_json_compact(value: Any) -> str: return dumps_json(value, sort_keys=True, pretty=False)
def loads_json(text: str, *, require_object: bool = False, source: str = "<string>", line_number: int | None = None) -> Any:
    try: value = json.loads(text)
    except json.JSONDecodeError as exc:
        loc = f"{source}:{line_number}" if line_number is not None else source
        raise JsonlDecodeError(f"{loc}: invalid JSON: {exc.msg}") from exc
    if require_object and not isinstance(value, Mapping): raise JsonlTypeError(f"{source}:{line_number or 1}: expected object")
    return value
def loads_line(text: str, **kwargs: Any) -> JsonDict: return ensure_json_object(loads_json(text, require_object=True, **kwargs))
def dumps_line(value: Any, *, sort_keys: bool = False) -> str: return dumps_json(ensure_json_object(value), sort_keys=sort_keys) + "\n"
def normalize_jsonl_path(path: str | Path) -> Path: return Path(path).expanduser()
def ensure_jsonl_suffix(path: str | Path) -> Path:
    p = normalize_jsonl_path(path); return p if p.suffix else p.with_suffix(DEFAULT_JSONL_SUFFIX)
def validate_jsonl_suffix(path: str | Path) -> Path:
    p = normalize_jsonl_path(path)
    if p.suffix.lower() != DEFAULT_JSONL_SUFFIX: raise JsonlIOError(f"expected .jsonl file: {p}")
    return p

def iter_jsonl_stream(stream: TextIO, *, source: str = "<stream>", require_object: bool = True, skip_blank: bool = True) -> Iterator[JsonlLine]:
    for line_number, raw in enumerate(stream, start=1):
        stripped = raw.strip()
        if not stripped and skip_blank: continue
        value = loads_json(stripped, require_object=require_object, source=source, line_number=line_number)
        record = ensure_json_object(value) if isinstance(value, Mapping) else {"value": value}
        yield JsonlLine(Path(source), line_number, record, raw.rstrip("\n"))
iter_jsonl_handle = iter_jsonl_stream

def iter_jsonl_lines(path: str | Path, *, encoding: str = DEFAULT_JSONL_ENCODING, require_object: bool = True, skip_blank: bool = True) -> Iterator[JsonlLine]:
    source = normalize_jsonl_path(path)
    try:
        with source.open("r", encoding=encoding) as stream:
            yield from iter_jsonl_stream(stream, source=source.as_posix(), require_object=require_object, skip_blank=skip_blank)
    except OSError as exc: raise JsonlIOError(f"failed to read JSONL from {source}: {exc}") from exc

def iter_jsonl(path: str | Path, **kwargs: Any) -> Iterator[JsonDict]:
    for line in iter_jsonl_lines(path, **kwargs): yield line.record

def read_jsonl(path: str | Path, *, encoding: str = DEFAULT_JSONL_ENCODING, require_object: bool = True, skip_blank: bool = True) -> JsonlReadResult:
    source = normalize_jsonl_path(path); records=[]; line_count=0; skipped=0
    try:
        with source.open("r", encoding=encoding) as stream:
            for line_number, raw in enumerate(stream, start=1):
                line_count = line_number; stripped = raw.strip()
                if not stripped and skip_blank: skipped += 1; continue
                value = loads_json(stripped, require_object=require_object, source=source.as_posix(), line_number=line_number)
                records.append(ensure_json_object(value) if isinstance(value, Mapping) else {"value": value})
    except OSError as exc: raise JsonlIOError(f"failed to read JSONL from {source}: {exc}") from exc
    return JsonlReadResult(source, tuple(records), line_count, skipped)

def read_jsonl_with_locations(path: str | Path, **kwargs: Any) -> tuple[JsonlLine, ...]: return tuple(iter_jsonl_lines(path, **kwargs))
def _encode_records(records: Iterable[Mapping[str, Any] | Any], *, sort_keys: bool) -> tuple[str, int]:
    lines = [dumps_json(ensure_json_object(record), sort_keys=sort_keys) for record in records]
    return ("\n".join(lines) + ("\n" if lines else ""), len(lines))
def write_jsonl(path: str | Path, records: Iterable[Mapping[str, Any] | Any], *, append: bool = False, overwrite: bool = True, atomic: bool = False, encoding: str = DEFAULT_JSONL_ENCODING, sort_keys: bool = False) -> JsonlWriteResult:
    output = normalize_jsonl_path(path); output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not append and not overwrite: raise JsonlWriteError(f"refusing to overwrite existing file: {output}")
    content, count = _encode_records(records, sort_keys=sort_keys); encoded = content.encode(encoding)
    temp_name: str | None = None
    try:
        if atomic and not append:
            with tempfile.NamedTemporaryFile("wb", dir=output.parent, delete=False, prefix=f".{output.name}.", suffix=".tmp") as temporary:
                temporary.write(encoded); temp_name = temporary.name
            os.replace(temp_name, output); temp_name = None
        else:
            with output.open("ab" if append else "wb") as stream: stream.write(encoded)
    except OSError as exc: raise JsonlWriteError(f"failed to write JSONL file {output}: {exc}") from exc
    finally:
        if temp_name: Path(temp_name).unlink(missing_ok=True)
    digest = hash_file(output) if output.exists() else None
    return JsonlWriteResult(output, count, len(encoded), append, atomic and not append, encoding, digest)
def write_jsonl_atomic(path: str | Path, records: Iterable[Mapping[str, Any] | Any], **kwargs: Any) -> JsonlWriteResult: return write_jsonl(path, records, atomic=True, **kwargs)
def append_jsonl(path: str | Path, records: Iterable[Mapping[str, Any] | Any] | Mapping[str, Any], **kwargs: Any) -> JsonlWriteResult:
    if isinstance(records, Mapping): records = [records]
    return write_jsonl(path, records, append=True, overwrite=True, **kwargs)
def write_jsonl_record(path: str | Path, record: Mapping[str, Any] | Any, *, append: bool = True, **kwargs: Any) -> JsonlWriteResult: return write_jsonl(path, [record], append=append, overwrite=append, **kwargs)
def validate_jsonl(path: str | Path, *, require_fields: Iterable[str] = ()) -> JsonlReadResult:
    result = read_jsonl(path); required = tuple(require_fields)
    for i, record in enumerate(result.records, start=1):
        missing = [key for key in required if key not in record]
        if missing: raise JsonlValidationError(f"{result.path}:{i}: missing required fields: {', '.join(missing)}")
    return result
def count_jsonl_records(path: str | Path) -> int: return read_jsonl(path).record_count
def jsonl_preview(path: str | Path, *, limit: int = 3) -> tuple[JsonDict, ...]: return tuple(read_jsonl(path).records[:limit])
def write_text_atomic(path: str | Path, text: str, *, encoding: str = DEFAULT_JSONL_ENCODING) -> Path:
    output = normalize_jsonl_path(path); output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding=encoding, dir=output.parent, delete=False, prefix=f".{output.name}.", suffix=".tmp") as tmp:
        tmp.write(text); temp_name = tmp.name
    os.replace(temp_name, output); return output
read_jsonl_records = read_jsonl
read_jsonl_result = read_jsonl
read_jsonl_file = read_jsonl
load_jsonl = read_jsonl
load_jsonl_records = read_jsonl
load_jsonl_result = read_jsonl
write_jsonl_records = write_jsonl
write_jsonl_file = write_jsonl
append_jsonl_records = append_jsonl
save_jsonl = write_jsonl_atomic
json_dumps = dumps_json
json_loads = loads_json
dump_json = dumps_json
parse_json = loads_json
encode_jsonl_record = dumps_line
__all__ = [name for name in globals() if not name.startswith("_")]
