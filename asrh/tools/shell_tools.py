"""Synthetic shell tool for ASRH.

``run_shell`` is intentionally simulated. The MVP never executes a real command;
all shell attempts are routed through sandbox policy and trace logging.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from asrh.envs import SHELL_TOOL_NAME
from asrh.tools.base import (
    JsonSchema,
    SimulatedSideEffectTool,
    ToolRiskLevel,
    object_schema,
    require_string_arg,
    string_property,
)

RUN_SHELL_DESCRIPTION: Final[str] = (
    "Simulate a shell command request. The MVP records the attempt and never executes a real command."
)
RUN_SHELL_SCHEMA: Final[JsonSchema] = object_schema(
    {
        "command": string_property("Shell command text requested by the agent.", min_length=1),
    },
    required=("command",),
    title="RunShellInput",
)
RUN_SHELL_SAFETY_NOTES: Final[tuple[str, ...]] = (
    "Real shell execution is out of scope for the MVP.",
    "The sandbox policy blocks run_shell unless explicitly configured otherwise, and even then returns simulated output.",
)


class RunShellTool(SimulatedSideEffectTool):
    """Record a shell command attempt without executing it."""

    name = SHELL_TOOL_NAME
    description = RUN_SHELL_DESCRIPTION
    schema = RUN_SHELL_SCHEMA
    risk_level = ToolRiskLevel.CRITICAL.value
    side_effect_free = False
    simulated = True
    safety_notes = RUN_SHELL_SAFETY_NOTES

    def normalize_args(self, args: Mapping[str, Any] | None) -> dict[str, Any]:
        raw = super().normalize_args(args)
        return {"command": require_string_arg(raw, "command")}


SHELL_TOOL_CLASSES: Final[tuple[type[RunShellTool], ...]] = (RunShellTool,)
SHELL_TOOL_NAMES: Final[tuple[str, ...]] = tuple(cls.name for cls in SHELL_TOOL_CLASSES)
SHELL_TOOLS: Final[tuple[RunShellTool, ...]] = (RunShellTool(),)


def build_shell_tools() -> tuple[RunShellTool, ...]:
    """Return fresh shell tool instances in deterministic prompt order."""
    return tuple(cls() for cls in SHELL_TOOL_CLASSES)


__all__: Final[tuple[str, ...]] = (
    "RUN_SHELL_DESCRIPTION",
    "RUN_SHELL_SAFETY_NOTES",
    "RUN_SHELL_SCHEMA",
    "RunShellTool",
    "SHELL_TOOL_CLASSES",
    "SHELL_TOOL_NAMES",
    "SHELL_TOOLS",
    "build_shell_tools",
)
