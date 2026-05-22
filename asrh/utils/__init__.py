"""Shared utility package for ASRH.

This package exposes side-effect-free helpers for deterministic hashing, JSONL
trace IO, text normalization/redaction, and explicit logging configuration.
"""

from __future__ import annotations

from importlib import import_module
from typing import Final

UTILS_PACKAGE_NAME: Final[str] = "asrh.utils"
UTILITY_MODULES: Final[tuple[str, ...]] = ("hashing", "jsonl", "text", "logging")
_exported: list[str] = ["UTILS_PACKAGE_NAME", "UTILITY_MODULES"]

for _module_name in UTILITY_MODULES:
    _module = import_module(f"{UTILS_PACKAGE_NAME}.{_module_name}")
    for _name in getattr(_module, "__all__", (name for name in vars(_module) if not name.startswith("_"))):
        if hasattr(_module, _name):
            globals()[_name] = getattr(_module, _name)
            _exported.append(_name)

# Common compatibility aliases used by runner/report code.
if "canonical_json" in globals():
    canonical_json_dumps = globals()["canonical_json"]
    _exported.append("canonical_json_dumps")
if "iter_jsonl_lines" in globals():
    read_jsonl_with_line_numbers = globals()["iter_jsonl_lines"]
    _exported.append("read_jsonl_with_line_numbers")
if "DEFAULT_DIGEST_LENGTH" not in globals() and "DEFAULT_SHORT_HASH_LENGTH" in globals():
    DEFAULT_DIGEST_LENGTH = globals()["DEFAULT_SHORT_HASH_LENGTH"]
    _exported.append("DEFAULT_DIGEST_LENGTH")
if "redact_common_secrets" not in globals() and "redact_secrets" in globals():
    redact_common_secrets = globals()["redact_secrets"]
    _exported.append("redact_common_secrets")
if "ensure_text" not in globals() and "safe_str" in globals():
    ensure_text = globals()["safe_str"]
    _exported.append("ensure_text")
if "json_dumps" not in globals() and "dumps_json" in globals():
    json_dumps = globals()["dumps_json"]
    _exported.append("json_dumps")
if "json_loads" not in globals() and "loads_json" in globals():
    json_loads = globals()["loads_json"]
    _exported.append("json_loads")

__all__: Final[tuple[str, ...]] = tuple(dict.fromkeys(_exported))

del import_module, _exported, _module, _module_name, _name
