"""Tool registry for ASRH sandbox-backed tools."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Final

from asrh import SUPPORTED_TOOLS
from asrh.cases.schema import TestCase
from asrh.tools.base import (
    Tool,
    ToolCall,
    ToolDefinition,
    ToolError,
    ToolResult,
    definitions_to_prompt_text,
    normalize_tool_name,
    thaw_json,
)
from asrh.tools.email_tools import build_email_tools
from asrh.tools.file_tools import build_file_tools
from asrh.tools.network_tools import build_network_tools
from asrh.tools.shell_tools import build_shell_tools

STRICT_MVP_PROFILE: Final[str] = "mvp"
EXTENDED_SANDBOX_PROFILE: Final[str] = "extended"
DEFAULT_REGISTRY_PROFILE: Final[str] = STRICT_MVP_PROFILE
MVP_TOOL_NAMES: Final[tuple[str, ...]] = tuple(SUPPORTED_TOOLS)
OPTIONAL_TOOL_NAMES: Final[tuple[str, ...]] = ("list_emails", "read_email", "network_request")


class ToolRegistryError(ToolError):
    """Base exception for registry operations."""


class DuplicateToolError(ToolRegistryError):
    """Raised when a registry receives duplicate tool names."""


class UnknownToolError(ToolRegistryError):
    """Raised when a requested tool is not registered."""


ToolNotRegisteredError = UnknownToolError


@dataclass(frozen=True, slots=True)
class RegistrySummary:
    """Compact registry metadata for reports and debugging."""

    profile: str
    tool_names: tuple[str, ...]
    high_risk_tools: tuple[str, ...]
    simulated_tools: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary."""
        return {
            "profile": self.profile,
            "tool_names": list(self.tool_names),
            "high_risk_tools": list(self.high_risk_tools),
            "simulated_tools": list(self.simulated_tools),
        }


@dataclass(frozen=True, slots=True)
class ToolRegistry:
    """Immutable ordered registry of model-facing ASRH tools."""

    tools: tuple[Tool, ...] = field(default_factory=tuple)
    profile: str = DEFAULT_REGISTRY_PROFILE
    _by_name: Mapping[str, Tool] = field(init=False, repr=False)
    _aliases: Mapping[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        by_name: dict[str, Tool] = {}
        aliases: dict[str, str] = {}
        for tool in self.tools:
            definition = tool.definition()
            name = normalize_tool_name(definition.name)
            if name in by_name:
                raise DuplicateToolError(f"duplicate tool registered: {name}")
            by_name[name] = tool
            for alias in definition.aliases:
                alias_name = normalize_tool_name(alias)
                if alias_name in by_name or alias_name in aliases:
                    raise DuplicateToolError(f"duplicate tool alias registered: {alias_name}")
                aliases[alias_name] = name
        object.__setattr__(self, "_by_name", by_name)
        object.__setattr__(self, "_aliases", aliases)

    def __len__(self) -> int:
        return len(self.tools)

    def __iter__(self) -> Iterator[Tool]:
        return iter(self.tools)

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        try:
            return self.resolve_name(name) in self._by_name
        except ToolRegistryError:
            return False

    @property
    def names(self) -> tuple[str, ...]:
        """Return tool names in deterministic prompt order."""
        return tuple(tool.definition().name for tool in self.tools)

    @property
    def mvp_names(self) -> tuple[str, ...]:
        """Return names of tools marked as required by the MVP."""
        return tuple(tool.definition().name for tool in self.tools if tool.definition().mvp_required)

    def resolve_name(self, name: str) -> str:
        """Resolve a tool name or alias to its canonical registered name."""
        normalized = normalize_tool_name(name)
        return self._aliases.get(normalized, normalized)

    def get(self, name: str) -> Tool:
        """Return a registered tool by name or alias."""
        resolved = self.resolve_name(name)
        try:
            return self._by_name[resolved]
        except KeyError as exc:
            raise UnknownToolError(f"unknown tool: {resolved}") from exc

    def maybe_get(self, name: str) -> Tool | None:
        """Return a tool if registered, otherwise ``None``."""
        try:
            return self._by_name.get(self.resolve_name(name))
        except ToolRegistryError:
            return None

    def subset(self, names: Iterable[str], *, strict: bool = True) -> ToolRegistry:
        """Return an ordered registry subset for a case-defined tool allowlist."""
        wanted: list[str] = []
        missing: list[str] = []
        for raw_name in names:
            try:
                resolved = self.resolve_name(raw_name)
            except ToolRegistryError:
                missing.append(str(raw_name))
                continue
            if resolved in self._by_name:
                wanted.append(resolved)
            else:
                missing.append(resolved)

        if strict and missing:
            raise UnknownToolError(f"unknown tools requested for subset: {sorted(set(missing))}")

        selected_names = set(wanted)
        selected = tuple(tool for tool in self.tools if tool.definition().name in selected_names)
        return ToolRegistry(selected, profile=self.profile)

    def filter(self, names: Iterable[str], *, strict: bool = False) -> ToolRegistry:
        """Compatibility alias for ``subset``."""
        return self.subset(names, strict=strict)

    def available_for_case(self, allowed_tool_names: Iterable[str], *, strict: bool = False) -> ToolRegistry:
        """Return the tools exposed by a YAML case's ``tools.allowed`` field."""
        return self.subset(allowed_tool_names, strict=strict)

    def for_case(self, case: TestCase, *, strict: bool = True) -> ToolRegistry:
        """Return the registry subset allowed for a parsed test case."""
        return self.available_for_case(case.tools.allowed, strict=strict)

    def definitions(self) -> tuple[ToolDefinition, ...]:
        """Return tool definitions in prompt order."""
        return tuple(tool.definition() for tool in self.tools)

    def descriptors(self) -> list[dict[str, Any]]:
        """Return JSON-serializable descriptors in prompt order."""
        return [tool.to_descriptor() for tool in self.tools]

    def schemas(self) -> dict[str, Any]:
        """Return a mapping of tool names to JSON schemas."""
        return {tool.definition().name: thaw_json(tool.definition().schema) for tool in self.tools}

    def prompt_blocks(self) -> str:
        """Return a deterministic text block describing available tools."""
        return definitions_to_prompt_text(self.definitions())

    def to_prompt_text(self) -> str:
        """Compatibility alias for ``prompt_blocks``."""
        return self.prompt_blocks()

    def call(self, tool_name: str, args: Mapping[str, Any] | None, env: Any) -> ToolResult:
        """Dispatch one tool call through the registered sandbox-backed wrapper."""
        return self.get(tool_name).call(args, env)

    def call_tool_call(self, call: ToolCall, env: Any) -> ToolResult:
        """Dispatch a parsed ``ToolCall`` object."""
        return self.call(call.tool_name, call.args, env)

    def summary(self) -> RegistrySummary:
        """Return compact registry metadata."""
        return RegistrySummary(
            profile=self.profile,
            tool_names=self.names,
            high_risk_tools=tuple(
                tool.definition().name for tool in self.tools if tool.definition().risk_level in {"high", "critical"}
            ),
            simulated_tools=tuple(tool.definition().name for tool in self.tools if tool.definition().simulated),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable registry description."""
        return {
            "profile": self.profile,
            "tools": self.descriptors(),
            "tool_count": len(self.tools),
            "mvp_tools": list(self.mvp_names),
            "aliases": dict(self._aliases),
        }


SUPPORTED_MVP_TOOL_SET: Final[frozenset[str]] = frozenset(SUPPORTED_TOOLS)


def build_mvp_tools() -> tuple[Tool, ...]:
    """Return required MVP tool instances only."""
    return (*build_file_tools(), *build_email_tools(), *build_shell_tools())


def build_extended_tools() -> tuple[Tool, ...]:
    """Return MVP tools plus optional inbox/network tools."""
    return (*build_file_tools(), *build_email_tools(include_optional=True), *build_shell_tools(), *build_network_tools())


def build_mvp_tool_registry() -> ToolRegistry:
    """Return the strict MVP registry."""
    return ToolRegistry(build_mvp_tools(), profile=STRICT_MVP_PROFILE)


def build_default_tool_registry(
    *,
    include_email_inbox_tools: bool = False,
    include_network_tools: bool = False,
) -> ToolRegistry:
    """Return a default registry with optional synthetic tools when requested."""
    tools: list[Tool] = [
        *build_file_tools(),
        *build_email_tools(include_inbox_tools=include_email_inbox_tools),
        *build_shell_tools(),
    ]
    if include_network_tools:
        tools.extend(build_network_tools())
    profile = EXTENDED_SANDBOX_PROFILE if include_email_inbox_tools or include_network_tools else STRICT_MVP_PROFILE
    return ToolRegistry(tuple(tools), profile=profile)


def build_extended_tool_registry() -> ToolRegistry:
    """Return a registry with MVP and optional synthetic tools."""
    return ToolRegistry(build_extended_tools(), profile=EXTENDED_SANDBOX_PROFILE)


def build_tool_registry(*, include_optional: bool = False) -> ToolRegistry:
    """Compatibility builder used by runner and agent modules."""
    return build_default_tool_registry(
        include_email_inbox_tools=include_optional,
        include_network_tools=include_optional,
    )


def registry_for_allowed_tools(
    allowed_tool_names: Iterable[str],
    *,
    include_email_inbox_tools: bool = True,
    include_network_tools: bool = True,
    strict: bool = True,
) -> ToolRegistry:
    """Build a registry subset from a case-defined allowlist."""
    return build_default_tool_registry(
        include_email_inbox_tools=include_email_inbox_tools,
        include_network_tools=include_network_tools,
    ).available_for_case(allowed_tool_names, strict=strict)


def build_case_tool_registry(
    case: TestCase,
    *,
    include_optional_tools: bool = True,
    strict: bool = True,
) -> ToolRegistry:
    """Build the tool registry exposed to one parsed test case."""
    return registry_for_allowed_tools(
        case.tools.allowed,
        include_email_inbox_tools=include_optional_tools,
        include_network_tools=include_optional_tools,
        strict=strict,
    )


def dispatch_tool_call(
    tool_name: str,
    args: Mapping[str, Any] | None,
    env: Any,
    *,
    registry: ToolRegistry | None = None,
) -> ToolResult:
    """Dispatch one tool call through a registry."""
    return (registry or DEFAULT_TOOL_REGISTRY).call(tool_name, args, env)


@lru_cache(maxsize=2)
def _cached_registry(include_optional: bool) -> ToolRegistry:
    return build_tool_registry(include_optional=include_optional)


def default_registry() -> ToolRegistry:
    """Return a fresh strict MVP registry."""
    return build_default_tool_registry()


def build_required_mvp_registry() -> ToolRegistry:
    """Compatibility alias for strict MVP registry construction."""
    return build_mvp_tool_registry()


def get_required_mvp_registry() -> ToolRegistry:
    """Compatibility alias for strict MVP registry construction."""
    return build_mvp_tool_registry()


def get_default_registry(*, include_optional: bool = False) -> ToolRegistry:
    """Return a cached default registry for descriptor-only use."""
    return _cached_registry(include_optional)


def tool_definitions_for_allowed(
    allowed_tools: Iterable[str],
    *,
    include_optional: bool = True,
    strict: bool = True,
) -> tuple[ToolDefinition, ...]:
    """Return definitions for a case-defined allowlist."""
    registry = get_default_registry(include_optional=include_optional).available_for_case(allowed_tools, strict=strict)
    return registry.definitions()


build_registry_for_allowed_tools = registry_for_allowed_tools

DEFAULT_TOOL_REGISTRY: Final[ToolRegistry] = build_mvp_tool_registry()
DEFAULT_EXTENDED_TOOL_REGISTRY: Final[ToolRegistry] = build_extended_tool_registry()

__all__: Final[tuple[str, ...]] = tuple(
    name
    for name in globals()
    if not name.startswith("_")
    and name not in {"annotations", "Any", "Final", "Iterable", "Iterator", "Mapping", "dataclass", "field", "lru_cache"}
)
