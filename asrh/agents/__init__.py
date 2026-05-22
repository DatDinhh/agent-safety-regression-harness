"""Provider-neutral agent package for ASRH.

Exports message/config dataclasses, prompt builders, the strict JSON-action
``ToolAgent`` loop, a no-tool ``SingleTurnAgent`` baseline, and a ReAct-named
wrapper. Importing this package does not import provider SDKs and creates no
external side effects.
"""

from __future__ import annotations

from typing import Final

from asrh.agents.base import *
from asrh.agents.prompts import *
from asrh.agents.react_agent import *
from asrh.agents.tool_agent import *

AGENTS_PACKAGE_NAME: Final[str] = "asrh.agents"
AGENTS_BASE_MODULE: Final[str] = "asrh.agents.base"
AGENTS_PROMPTS_MODULE: Final[str] = "asrh.agents.prompts"
AGENTS_TOOL_AGENT_MODULE: Final[str] = "asrh.agents.tool_agent"
AGENTS_REACT_AGENT_MODULE: Final[str] = "asrh.agents.react_agent"
SUPPORTED_CONCRETE_AGENTS: Final[tuple[str, ...]] = (
    DEFAULT_TOOL_AGENT_NAME,
    DEFAULT_SINGLE_TURN_AGENT_NAME,
    REACT_AGENT_NAME,
)
DEFAULT_AGENT_CLASS: Final[type[ToolAgent]] = ToolAgent


def create_agent(mode: str = "tool_agent") -> Agent:
    """Create an ASRH agent by mode name."""
    normalized = str(mode).strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in {"tool_agent", "tool", "tools"}:
        return ToolAgent()
    if normalized == "mock":
        return ToolAgent(name="mock_tool_agent")
    if normalized in {"react", "react_agent", "json_react", "json_react_agent"}:
        return ReActAgent()
    if normalized in {"single_turn", "single", "no_tool", "no_tools"}:
        return SingleTurnAgent()
    raise AgentConfigurationError(f"unsupported agent mode: {mode!r}")


build_agent_by_mode = create_agent
get_agent = create_agent
build_agent = create_agent

__all__: Final[tuple[str, ...]] = tuple(
    name for name in globals() if not name.startswith("_") and name not in {"annotations", "Final"}
)
