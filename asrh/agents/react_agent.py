"""ReAct-named wrapper for the ASRH JSON-action tool loop.

The MVP does not expose free-form chain-of-thought or provider-native function
calling. The ReAct-style behavior is implemented as a repeatable observe-act
loop using strict JSON actions and sandboxed tool observations.
"""

from __future__ import annotations

from typing import Any, Final

from asrh.agents.base import AgentResult, ModelClient
from asrh.agents.tool_agent import ToolAgent
from asrh.cases.schema import TestCase
from asrh.envs.sandbox import SandboxEnv
from asrh.tools.registry import ToolRegistry

DEFAULT_REACT_AGENT_NAME: Final[str] = "react_agent"
REACT_AGENT_NAME: Final[str] = DEFAULT_REACT_AGENT_NAME
REACT_AGENT_MODE: Final[str] = "tool_agent"
REACT_STYLE_DESCRIPTION: Final[str] = "ReAct-style observe-act loop implemented with ASRH strict JSON actions."


class ReactAgent(ToolAgent):
    """Named compatibility wrapper around ``ToolAgent``."""

    description = REACT_STYLE_DESCRIPTION

    def __init__(
        self,
        *,
        name: str = DEFAULT_REACT_AGENT_NAME,
        extra_system_instructions: tuple[str, ...] | list[str] = (),
    ) -> None:
        super().__init__(name=name, extra_system_instructions=extra_system_instructions)

    def run(
        self,
        *,
        case: TestCase,
        model: ModelClient | Any | None = None,
        model_client: ModelClient | Any | None = None,
        env: SandboxEnv | None = None,
        tool_registry: ToolRegistry | None = None,
        registry: ToolRegistry | None = None,
        config: Any = None,
        model_name: str | None = None,
        mitigation: str | None = None,
    ) -> AgentResult:
        return super().run(
            case=case,
            model=model,
            model_client=model_client,
            env=env,
            tool_registry=tool_registry,
            registry=registry,
            config=config,
            model_name=model_name,
            mitigation=mitigation,
        )


def build_react_agent(**kwargs: Any) -> ReactAgent:
    return ReactAgent(**kwargs)


def build_json_react_agent(**kwargs: Any) -> ReactAgent:
    return build_react_agent(**kwargs)


def run_react_agent(
    *,
    case: TestCase,
    model: ModelClient | Any | None = None,
    model_client: ModelClient | Any | None = None,
    env: SandboxEnv | None = None,
    tool_registry: ToolRegistry | None = None,
    registry: ToolRegistry | None = None,
    config: Any = None,
) -> AgentResult:
    return ReactAgent().run(
        case=case,
        model=model,
        model_client=model_client,
        env=env,
        tool_registry=tool_registry,
        registry=registry,
        config=config,
    )


JsonReActAgent = ReactAgent
JsonReactAgent = ReactAgent
JsonActionReActAgent = ReactAgent
ReActAgent = ReactAgent
ReactToolAgent = ReactAgent

__all__: Final[tuple[str, ...]] = (
    "DEFAULT_REACT_AGENT_NAME",
    "REACT_AGENT_NAME",
    "REACT_AGENT_MODE",
    "REACT_STYLE_DESCRIPTION",
    "ReactAgent",
    "ReActAgent",
    "ReactToolAgent",
    "JsonReActAgent",
    "JsonReactAgent",
    "JsonActionReActAgent",
    "build_react_agent",
    "build_json_react_agent",
    "run_react_agent",
)
