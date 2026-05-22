"""Sandbox-backed file tools for ASRH.

These tools operate only on the synthetic in-memory filesystem owned by
``SandboxEnv``. They never read from or write to the host filesystem.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from asrh.envs import LIST_FILES_TOOL_NAME, READ_FILE_TOOL_NAME, WRITE_FILE_TOOL_NAME
from asrh.tools.base import (
    JsonSchema,
    SandboxDispatchTool,
    ToolArgumentError,
    ToolRiskLevel,
    object_schema,
    require_string_arg,
    string_property,
)

LIST_FILES_DESCRIPTION: Final[str] = (
    "List file paths visible in the current synthetic sandbox. Sensitive files "
    "are hidden unless policy exposes them."
)
READ_FILE_DESCRIPTION: Final[str] = "Read the content of a case-local synthetic file through sandbox policy."
WRITE_FILE_DESCRIPTION: Final[str] = "Write content to a case-local synthetic file. No host filesystem write occurs."

LIST_FILES_SCHEMA: Final[JsonSchema] = object_schema(
    title="ListFilesInput",
    description="No fields required.",
)
READ_FILE_SCHEMA: Final[JsonSchema] = object_schema(
    {
        "path": string_property(
            "Case-local POSIX-style relative path to read.",
            min_length=1,
        )
    },
    required=("path",),
    title="ReadFileInput",
)
WRITE_FILE_SCHEMA: Final[JsonSchema] = object_schema(
    {
        "path": string_property(
            "Case-local POSIX-style relative destination path.",
            min_length=1,
        ),
        "content": string_property("Text content to write into the synthetic file."),
    },
    required=("path", "content"),
    title="WriteFileInput",
)

FILE_TOOL_SAFETY_NOTES: Final[tuple[str, ...]] = (
    "All file operations target the synthetic sandbox, not the host filesystem.",
    "Sensitive file access is controlled by sandbox policy.",
)


class ListFilesTool(SandboxDispatchTool):
    """List files visible under the active policy."""

    name = LIST_FILES_TOOL_NAME
    description = LIST_FILES_DESCRIPTION
    schema = LIST_FILES_SCHEMA
    risk_level = ToolRiskLevel.LOW.value
    side_effect_free = True
    safety_notes = FILE_TOOL_SAFETY_NOTES


class ReadFileTool(SandboxDispatchTool):
    """Read a synthetic file through sandbox policy."""

    name = READ_FILE_TOOL_NAME
    description = READ_FILE_DESCRIPTION
    schema = READ_FILE_SCHEMA
    risk_level = ToolRiskLevel.MEDIUM.value
    side_effect_free = True
    safety_notes = FILE_TOOL_SAFETY_NOTES

    def normalize_args(self, args: Mapping[str, Any] | None) -> dict[str, Any]:
        raw = super().normalize_args(args)
        return {"path": require_string_arg(raw, "path", max_chars=512)}


class WriteFileTool(SandboxDispatchTool):
    """Write a synthetic file through sandbox policy."""

    name = WRITE_FILE_TOOL_NAME
    description = WRITE_FILE_DESCRIPTION
    schema = WRITE_FILE_SCHEMA
    risk_level = ToolRiskLevel.HIGH.value
    side_effect_free = False
    safety_notes = FILE_TOOL_SAFETY_NOTES

    def normalize_args(self, args: Mapping[str, Any] | None) -> dict[str, Any]:
        raw = super().normalize_args(args)
        path = require_string_arg(raw, "path", max_chars=512)
        if "content" not in raw:
            raise ToolArgumentError("missing required argument: content")
        return {"path": path, "content": str(raw["content"])}


FILE_TOOL_CLASSES: Final[tuple[type[SandboxDispatchTool], ...]] = (
    ListFilesTool,
    ReadFileTool,
    WriteFileTool,
)
FILE_TOOL_NAMES: Final[tuple[str, ...]] = tuple(cls.name for cls in FILE_TOOL_CLASSES)
FILE_TOOLS: Final[tuple[SandboxDispatchTool, ...]] = tuple(cls() for cls in FILE_TOOL_CLASSES)


def build_file_tools() -> tuple[SandboxDispatchTool, ...]:
    """Return fresh file tool instances in deterministic prompt order."""
    return tuple(cls() for cls in FILE_TOOL_CLASSES)


__all__: Final[tuple[str, ...]] = (
    "FILE_TOOL_CLASSES",
    "FILE_TOOL_NAMES",
    "FILE_TOOL_SAFETY_NOTES",
    "FILE_TOOLS",
    "LIST_FILES_DESCRIPTION",
    "LIST_FILES_SCHEMA",
    "ListFilesTool",
    "READ_FILE_DESCRIPTION",
    "READ_FILE_SCHEMA",
    "ReadFileTool",
    "WRITE_FILE_DESCRIPTION",
    "WRITE_FILE_SCHEMA",
    "WriteFileTool",
    "build_file_tools",
)
