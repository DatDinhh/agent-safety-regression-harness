"""Text normalization, redaction, and Markdown-safe formatting helpers for ASRH."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Pattern, TypeAlias

TextPattern: TypeAlias = str | Pattern[str]
DEFAULT_REDACTION: Final[str] = "[REDACTED]"
DEFAULT_TRUNCATE_LENGTH: Final[int] = 240
DEFAULT_CONTEXT_CHARS: Final[int] = 80
DEFAULT_SECRET_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|credential|private[_-]?key)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
)
WHITESPACE_RE: Final[Pattern[str]] = re.compile(r"\s+")
CONTROL_CHAR_RE: Final[Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SLUG_UNSAFE_RE: Final[Pattern[str]] = re.compile(r"[^A-Za-z0-9_.-]+")
FENCED_CODE_RE: Final[Pattern[str]] = re.compile(r"^```(?:\w+)?\s*(.*?)\s*```$", re.DOTALL)
REFUSAL_RE: Final[Pattern[str]] = re.compile(r"\b(i\s+can(?:not|'t)\s+(?:help|assist|comply)|i(?:'m| am)\s+unable\s+to)\b", re.IGNORECASE)
SECRET_LIKE_RE: Final[Pattern[str]] = re.compile("|".join(p.pattern for p in DEFAULT_SECRET_PATTERNS), re.IGNORECASE)


class TextError(ValueError):
    """Base exception for text helpers."""


class PatternError(TextError):
    """Raised when a pattern is invalid."""


@dataclass(frozen=True, slots=True)
class PatternMatch:
    """Pattern match evidence for checker/report output."""

    pattern: str
    start: int
    end: int
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {"pattern": self.pattern, "start": self.start, "end": self.end, "snippet": self.snippet}


@dataclass(frozen=True, slots=True)
class TextSurface:
    """Named text surface used by checkers and reports."""

    name: str
    text: str
    labels: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "text": self.text, "labels": list(self.labels)}


def ensure_text(value: Any, *, none: str = "") -> str:
    if value is None:
        return none
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


safe_str = ensure_text


def normalize_unicode(text: Any, *, form: str = "NFC") -> str:
    return unicodedata.normalize(form, ensure_text(text))


def normalize_newlines(text: Any) -> str:
    return ensure_text(text).replace("\r\n", "\n").replace("\r", "\n")


def remove_control_chars(text: Any, *, replacement: str = "") -> str:
    return CONTROL_CHAR_RE.sub(replacement, ensure_text(text))


strip_control_chars = remove_control_chars


def normalize_whitespace(text: Any, *, preserve_newlines: bool = False) -> str:
    raw = remove_control_chars(normalize_unicode(normalize_newlines(text))).strip()
    if not preserve_newlines:
        return WHITESPACE_RE.sub(" ", raw)
    return "\n".join(WHITESPACE_RE.sub(" ", line).strip() for line in raw.splitlines() if line.strip())


collapse_whitespace = normalize_whitespace


def normalize_for_match(text: Any, *, case_sensitive: bool = False) -> str:
    value = normalize_whitespace(text)
    return value if case_sensitive else value.casefold()


normalize_for_matching = normalize_for_match


def truncate(text: Any, *, max_length: int = DEFAULT_TRUNCATE_LENGTH, marker: str = "…", middle: bool = False) -> str:
    raw = ensure_text(text)
    if len(raw) <= max_length:
        return raw
    if max_length <= len(marker):
        return marker[:max_length]
    if not middle:
        return raw[: max_length - len(marker)] + marker
    keep = max_length - len(marker)
    left = keep // 2
    right = keep - left
    return raw[:left] + marker + raw[-right:]


ellipsize = truncate
preview = truncate
safe_snippet = truncate


def truncate_middle(text: Any, *, max_length: int = DEFAULT_TRUNCATE_LENGTH, marker: str = "…") -> str:
    return truncate(text, max_length=max_length, marker=marker, middle=True)


def context_window(text: Any, *, start: int, end: int, radius: int = DEFAULT_CONTEXT_CHARS) -> str:
    raw = ensure_text(text)
    left = max(0, start - radius)
    right = min(len(raw), end + radius)
    prefix = "…" if left > 0 else ""
    suffix = "…" if right < len(raw) else ""
    return normalize_whitespace(f"{prefix}{raw[left:right]}{suffix}")


def compile_pattern(pattern: TextPattern, *, flags: int = 0) -> Pattern[str]:
    if isinstance(pattern, re.Pattern):
        return pattern
    try:
        return re.compile(str(pattern), flags)
    except re.error as exc:
        raise PatternError(f"invalid regex pattern {pattern!r}: {exc}") from exc


def pattern_label(pattern: TextPattern) -> str:
    return pattern.pattern if isinstance(pattern, re.Pattern) else str(pattern)


def find_patterns(text: Any, patterns: Iterable[str], *, case_sensitive: bool = True, max_matches: int | None = None) -> tuple[PatternMatch, ...]:
    raw = ensure_text(text)
    haystack = raw if case_sensitive else raw.casefold()
    matches: list[PatternMatch] = []
    for pattern in patterns:
        needle = ensure_text(pattern)
        if not needle:
            continue
        comparable = needle if case_sensitive else needle.casefold()
        pos = haystack.find(comparable)
        if pos < 0:
            continue
        end = pos + len(comparable)
        matches.append(PatternMatch(needle, pos, end, context_window(raw, start=pos, end=end)))
        if max_matches is not None and len(matches) >= max_matches:
            break
    return tuple(matches)


find_pattern_matches = find_patterns
find_forbidden_patterns = find_patterns

def find_first_match(text: Any, patterns: Iterable[str], *, case_sensitive: bool = True) -> PatternMatch | None:
    matches = find_patterns(text, patterns, case_sensitive=case_sensitive, max_matches=1)
    return matches[0] if matches else None


def contains_any(text: Any, patterns: Iterable[str], *, case_sensitive: bool = True) -> bool:
    return find_first_match(text, patterns, case_sensitive=case_sensitive) is not None


def contains_all(text: Any, patterns: Iterable[str], *, case_sensitive: bool = True) -> bool:
    return all(contains_any(text, (pattern,), case_sensitive=case_sensitive) for pattern in patterns if ensure_text(pattern))


def missing_patterns(text: Any, patterns: Iterable[str], *, case_sensitive: bool = True) -> tuple[str, ...]:
    return tuple(pattern for pattern in patterns if ensure_text(pattern) and not contains_any(text, (pattern,), case_sensitive=case_sensitive))


def find_regex_patterns(text: Any, patterns: Iterable[TextPattern]) -> tuple[PatternMatch, ...]:
    raw = ensure_text(text)
    results: list[PatternMatch] = []
    for pattern in patterns:
        regex = compile_pattern(pattern)
        match = regex.search(raw)
        if match:
            results.append(PatternMatch(pattern_label(pattern), match.start(), match.end(), context_window(raw, start=match.start(), end=match.end())))
    return tuple(results)


def redact_patterns(text: Any, patterns: Iterable[str], *, replacement: str = DEFAULT_REDACTION, case_sensitive: bool = True) -> str:
    out = ensure_text(text)
    flags = 0 if case_sensitive else re.IGNORECASE
    for pattern in patterns:
        needle = ensure_text(pattern)
        if needle:
            out = re.sub(re.escape(needle), replacement, out, flags=flags)
    return out


def redact_regex_patterns(text: Any, patterns: Iterable[TextPattern], *, replacement: str = DEFAULT_REDACTION) -> str:
    out = ensure_text(text)
    for pattern in patterns:
        out = compile_pattern(pattern).sub(replacement, out)
    return out


def redact_common_secrets(text: Any, *, replacement: str = DEFAULT_REDACTION) -> str:
    return redact_regex_patterns(text, DEFAULT_SECRET_PATTERNS, replacement=replacement)


redact_secrets = redact_common_secrets


def redact_mapping(value: Mapping[str, Any], *, replacement: str = DEFAULT_REDACTION) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key)
        if any(marker in key_text.casefold() for marker in ("api_key", "secret", "token", "password", "credential")):
            out[key_text] = replacement
        elif isinstance(item, Mapping):
            out[key_text] = redact_mapping(item, replacement=replacement)
        elif isinstance(item, str):
            out[key_text] = redact_common_secrets(item, replacement=replacement)
        else:
            out[key_text] = item
    return out


def slugify(text: Any, *, separator: str = "-", max_length: int = 80, lowercase: bool = True) -> str:
    raw = normalize_unicode(text, form="NFKC").strip()
    if lowercase:
        raw = raw.lower()
    slug = SLUG_UNSAFE_RE.sub(separator, raw).strip(f"{separator}._")
    slug = re.sub(rf"{re.escape(separator)}+", separator, slug)
    return truncate(slug or "untitled", max_length=max_length, marker="").strip(f"{separator}._") or "untitled"


def to_snake_case(text: Any, *, max_length: int = 80) -> str:
    return slugify(text, separator="_", max_length=max_length)


def split_nonempty_lines(text: Any) -> tuple[str, ...]:
    return tuple(line.strip() for line in normalize_newlines(text).splitlines() if line.strip())


def first_nonempty_line(text: Any, *, default: str = "") -> str:
    lines = split_nonempty_lines(text)
    return lines[0] if lines else default


def join_human(items: Iterable[Any], *, sep: str = ", ") -> str:
    return sep.join(ensure_text(item).strip() for item in items if ensure_text(item).strip())


def render_bullets(items: Iterable[Any], *, bullet: str = "-") -> str:
    values = [ensure_text(item).strip() for item in items if ensure_text(item).strip()]
    return "\n".join(f"{bullet} {item}" for item in values)


bullet_list = render_bullets


def indent_lines(text: Any, *, prefix: str = "  ", skip_empty: bool = False) -> str:
    return "\n".join((prefix + line if line or not skip_empty else line) for line in ensure_text(text).splitlines())


indent_text = indent_lines


def markdown_escape(text: Any) -> str:
    return normalize_whitespace(text).replace("\\", "\\\\").replace("|", "\\|")


def strip_fenced_code(text: Any) -> str:
    raw = ensure_text(text).strip()
    match = FENCED_CODE_RE.match(raw)
    return match.group(1).strip() if match else raw


def extract_json_candidate(text: Any) -> str | None:
    raw = strip_fenced_code(text)
    for left, right in (("{", "}"), ("[", "]")):
        start = raw.find(left)
        end = raw.rfind(right)
        if start >= 0 and end > start:
            return raw[start : end + 1]
    return None


def is_refusal(text: Any) -> bool:
    return REFUSAL_RE.search(normalize_whitespace(text)) is not None


def format_key_values(values: Mapping[str, Any]) -> str:
    return ", ".join(f"{key}={truncate(value, max_length=80)}" for key, value in sorted(values.items()))


def text_surfaces_from_mapping(mapping: Mapping[str, Any]) -> tuple[TextSurface, ...]:
    return tuple(TextSurface(str(key), ensure_text(value)) for key, value in mapping.items())


__all__: Final[tuple[str, ...]] = tuple(name for name in globals() if not name.startswith("_") and name not in {"annotations", "Any", "Final", "Iterable", "Mapping", "Sequence"})

# Compatibility aliases for previous ASRH utility contracts.
looks_like_refusal = is_refusal
REFUSAL_PHRASES = ("i can't help", "i cannot help", "i cannot assist", "i'm unable to", "i am unable to", "i can't comply", "i cannot comply")
REFUSAL_PATTERNS = REFUSAL_PHRASES
DEFAULT_EXCERPT_CHARS = DEFAULT_CONTEXT_CHARS
DEFAULT_EXCERPT_RADIUS = DEFAULT_CONTEXT_CHARS
DEFAULT_TRUNCATION_SUFFIX = "..."
DEFAULT_TRUNCATION_MARKER = DEFAULT_TRUNCATION_SUFFIX
DEFAULT_TRUNCATION_LIMIT = DEFAULT_TRUNCATE_LENGTH
SECRET_LIKE_PATTERNS = DEFAULT_SECRET_PATTERNS
CONTROL_CHARS_RE = CONTROL_CHAR_RE
TextMatch = PatternMatch
contains_any_pattern = contains_any
contains_all_patterns = contains_all
find_literal_matches = find_patterns
find_regex_matches = find_regex_patterns
redact_secret_like_text = redact_secrets
redact_common_secrets = redact_secrets
collapse_whitespace = normalize_whitespace
normalize_space = normalize_whitespace
strip_control_chars = remove_control_chars
excerpt = truncate
safe_excerpt = excerpt
slugify = safe_identifier if "safe_identifier" in globals() else lambda value, **_: normalize_whitespace(value).lower().replace(" ", "-")
markdown_escape_table_cell = markdown_escape
escape_markdown_table_cell = markdown_escape
strip_code_fence = strip_fenced_code
bullet_list = lambda items, bullet="-", empty="- none": "\n".join(f"{bullet} {ensure_text(item)}" for item in items) or empty
indent_text = indent_lines
join_nonempty = lambda items, separator=", ": separator.join(value for item in items if (value := ensure_text(item).strip()))
split_nonempty_lines = lambda text: tuple(line.strip() for line in normalize_newlines(text).split("\n") if line.strip())
format_percent = lambda value, digits=1: f"{value * 100:.{digits}f}%"
format_rate = lambda numerator, denominator, digits=1: "n/a" if denominator == 0 else format_percent(numerator / denominator, digits=digits)
__all__ = tuple(dict.fromkeys((*__all__, "looks_like_refusal", "REFUSAL_PHRASES", "REFUSAL_PATTERNS", "DEFAULT_EXCERPT_CHARS", "DEFAULT_EXCERPT_RADIUS", "DEFAULT_TRUNCATION_SUFFIX", "DEFAULT_TRUNCATION_MARKER", "DEFAULT_TRUNCATION_LIMIT", "SECRET_LIKE_PATTERNS", "CONTROL_CHARS_RE", "TextMatch", "contains_any_pattern", "contains_all_patterns", "find_literal_matches", "find_regex_patterns", "find_regex_matches", "redact_secret_like_text", "redact_common_secrets", "collapse_whitespace", "normalize_space", "strip_control_chars", "excerpt", "safe_excerpt", "slugify", "markdown_escape_table_cell", "escape_markdown_table_cell", "strip_code_fence", "bullet_list", "indent_text", "join_nonempty", "split_nonempty_lines", "format_percent", "format_rate")))
