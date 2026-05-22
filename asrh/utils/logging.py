"""Explicit logging configuration helpers for ASRH."""

from __future__ import annotations

import contextlib
import json
import logging as _logging
import os
import sys
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Final, TextIO, TypeAlias

from asrh import PROJECT_NAME
from asrh.utils.text import DEFAULT_REDACTION, TextPattern, format_key_values, redact_patterns, redact_secrets

LogLevel: TypeAlias = int | str
ASRH_LOG_LEVEL_ENV: Final[str] = "ASRH_LOG_LEVEL"
ASRH_LOG_FORMAT_ENV: Final[str] = "ASRH_LOG_FORMAT"
ASRH_LOG_REDACT_ENV: Final[str] = "ASRH_LOG_REDACT"
ASRH_LOGGER_NAME: Final[str] = "asrh"
ROOT_LOGGER_NAME: Final[str] = ASRH_LOGGER_NAME
DEFAULT_LOG_LEVEL: Final[int] = _logging.INFO
DEFAULT_LOG_FORMAT: Final[str] = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
PLAIN_FORMAT_NAME: Final[str] = "plain"
STRUCTURED_FORMAT_NAME: Final[str] = "structured"
JSON_FORMAT_NAME: Final[str] = "json"
RICH_FORMAT_NAME: Final[str] = "rich"
PROVIDER_LOGGERS: Final[tuple[str, ...]] = ("anthropic", "httpcore", "httpx", "openai", "urllib3")
NOISY_PROVIDER_LOGGERS = PROVIDER_LOGGERS


class LoggingError(RuntimeError):
    """Base exception for logging utilities."""


class LogLevelError(LoggingError):
    """Raised when a log level cannot be parsed."""


class LoggingConfigurationError(LoggingError):
    """Raised when logging configuration is invalid."""


LoggingConfigError = LoggingConfigurationError


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: int
    level_name: str
    format_name: str = STRUCTURED_FORMAT_NAME
    json_format: bool = False
    configured: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


LogConfiguration = LoggingConfig


class PlainLogFormatter(_logging.Formatter):
    """Plain text formatter."""


class JsonLogFormatter(_logging.Formatter):
    """JSON formatter for machine-readable logs."""

    def format(self, record: _logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "project": PROJECT_NAME,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "asrh_fields", None)
        if isinstance(fields, Mapping):
            payload["fields"] = dict(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)


class RedactingFilter(_logging.Filter):
    def __init__(self, patterns: Iterable[TextPattern] = (), *, replacement: str = DEFAULT_REDACTION) -> None:
        super().__init__()
        self.patterns = tuple(patterns)
        self.replacement = replacement

    def filter(self, record: _logging.LogRecord) -> bool:
        record.msg = self._redact(record.msg)
        if record.args:
            if isinstance(record.args, Mapping):
                record.args = {key: self._redact(value) for key, value in record.args.items()}
            else:
                record.args = tuple(self._redact(value) for value in record.args)
        return True

    def _redact(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        redacted = redact_patterns(value, self.patterns) if self.patterns else value
        return redact_secrets(redacted)


def parse_bool_env(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "t", "yes", "y", "on"}


def parse_log_level(level: LogLevel | None = None, *, default: int = DEFAULT_LOG_LEVEL) -> int:
    if level is None:
        return default
    if isinstance(level, int):
        return level
    value = str(level).strip()
    if value.isdigit():
        return int(value)
    parsed = getattr(_logging, value.upper(), None)
    if not isinstance(parsed, int):
        raise LogLevelError(f"unknown log level: {level!r}")
    return parsed


def log_level_name(level: int) -> str:
    name = _logging.getLevelName(level)
    return name if isinstance(name, str) else str(level)


def get_logger(name: str | None = None) -> _logging.Logger:
    if not name or name == ROOT_LOGGER_NAME:
        return _logging.getLogger(ROOT_LOGGER_NAME)
    if name.startswith(f"{ROOT_LOGGER_NAME}."):
        return _logging.getLogger(name)
    return _logging.getLogger(f"{ROOT_LOGGER_NAME}.{name}")


def build_formatter(*, json_format: bool = False, format_name: str = STRUCTURED_FORMAT_NAME) -> _logging.Formatter:
    if json_format or format_name == JSON_FORMAT_NAME:
        return JsonLogFormatter()
    if format_name == PLAIN_FORMAT_NAME:
        return PlainLogFormatter("%(levelname)s %(message)s")
    return PlainLogFormatter(DEFAULT_LOG_FORMAT)


def build_console_handler(*, level: int, json_format: bool = False, stream: TextIO | None = None) -> _logging.Handler:
    handler = _logging.StreamHandler(stream or sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(build_formatter(json_format=json_format))
    return handler


def configure_logging(level: LogLevel | None = None, *, format_name: str | None = None, json_format: bool | None = None, stream: TextIO | None = None, force: bool = False, redact_patterns_: Iterable[TextPattern] = ()) -> LoggingConfig:
    resolved = parse_log_level(level or os.getenv(ASRH_LOG_LEVEL_ENV))
    fmt = (format_name or os.getenv(ASRH_LOG_FORMAT_ENV) or STRUCTURED_FORMAT_NAME).strip().lower()
    json_logs = bool(json_format) or fmt == JSON_FORMAT_NAME
    logger = get_logger()
    if force:
        for handler in tuple(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
    if not logger.handlers:
        logger.addHandler(build_console_handler(level=resolved, json_format=json_logs, stream=stream))
    for handler in logger.handlers:
        handler.setLevel(resolved)
        if not any(isinstance(item, RedactingFilter) for item in handler.filters):
            handler.addFilter(RedactingFilter(redact_patterns_))
    logger.setLevel(resolved)
    logger.propagate = False
    silence_provider_loggers()
    return LoggingConfig(resolved, log_level_name(resolved), fmt, json_logs, True)


def env_log_configuration() -> LoggingConfig:
    return configure_logging(force=False)


ensure_configured = env_log_configuration
configure_logging_from_env = env_log_configuration


def silence_provider_loggers(level: LogLevel = _logging.WARNING) -> None:
    resolved = parse_log_level(level)
    for name in PROVIDER_LOGGERS:
        _logging.getLogger(name).setLevel(resolved)


silence_noisy_loggers = silence_provider_loggers
set_provider_log_level = silence_provider_loggers


def install_redaction_filter(logger: _logging.Logger | None = None, *, patterns: Iterable[TextPattern] = ()) -> RedactingFilter:
    target = logger or get_logger()
    filter_ = RedactingFilter(patterns)
    for handler in target.handlers:
        handler.addFilter(filter_)
    return filter_


def log_event(logger: _logging.Logger, level: LogLevel, event: str, **fields: Any) -> None:
    message = event if not fields else f"{event} | {format_key_values(fields)}"
    logger.log(parse_log_level(level), message, extra={"asrh_fields": dict(fields)})


def debug_event(logger: _logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, _logging.DEBUG, event, **fields)


def info_event(logger: _logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, _logging.INFO, event, **fields)


def warning_event(logger: _logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, _logging.WARNING, event, **fields)


def error_event(logger: _logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, _logging.ERROR, event, **fields)


@contextlib.contextmanager
def temporary_log_level(logger: _logging.Logger | LogLevel, level: LogLevel | None = None) -> Iterator[None]:
    if isinstance(logger, _logging.Logger):
        target = logger
        new_level = parse_log_level(level)
    else:
        target = get_logger()
        new_level = parse_log_level(logger)
    old = target.level
    target.setLevel(new_level)
    try:
        yield
    finally:
        target.setLevel(old)


@contextlib.contextmanager
def timed_log(logger: _logging.Logger, event: str, **fields: Any) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        debug_event(logger, event, elapsed_seconds=round(time.perf_counter() - start, 6), **fields)


def format_error(error: BaseException) -> str:
    return f"{error.__class__.__name__}: {error}"


def logger_summary(logger: _logging.Logger | None = None) -> dict[str, Any]:
    target = logger or get_logger()
    return {"logger": target.name, "level": log_level_name(target.level), "handlers": [type(h).__name__ for h in target.handlers]}


logger = get_logger()
project_logger = logger

__all__: Final[tuple[str, ...]] = tuple(name for name in globals() if not name.startswith("_") and name not in {"annotations", "Any", "Final", "Iterable", "Iterator", "Mapping", "TextIO", "TypeAlias"})
