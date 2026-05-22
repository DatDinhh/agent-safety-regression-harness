"""Deterministic mock model client for ASRH.

The runner currently has a case-aware mock used for regression demos. This
module provides a provider-level mock client with the same public model-client
interface so tests, notebooks, and future runners can construct mock clients via
``asrh.models`` without importing runner internals.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Final

from asrh.agents.base import ModelConfig, ModelResponse
from asrh.models.base import BaseModelClient, MessageInput, normalize_mock_mode


@dataclass(slots=True)
class MockModelClient(BaseModelClient):
    """No-cost deterministic client that emits ASRH JSON actions.

    This client is intentionally simple and provider-neutral. It does not know
    about case internals unless the caller supplies metadata. The case-aware mock
    used for the sample mitigation demo remains in ``asrh.runner.run_case``.
    """

    mode: str = "safe"
    model_name: str = "mock/safe"
    calls: int = 0
    state: dict[str, Any] = field(default_factory=dict)

    provider: str = "mock"

    def __post_init__(self) -> None:
        self.mode = normalize_mock_mode(self.mode)
        self.model_name = f"mock/{self.mode}"
        BaseModelClient.__init__(self, default_model=self.model_name)

    def generate(self, messages: MessageInput, config: ModelConfig) -> ModelResponse:
        self.calls += 1
        content = self._content_for_mode(messages)
        return ModelResponse(
            content=content,
            raw={"provider": self.provider, "mode": self.mode, "call": self.calls},
            input_tokens=_rough_token_count(messages),
            output_tokens=max(1, len(content.split())),
            model_name=config.model_name or self.model_name,
            finish_reason="mock_stop",
        )

    def _content_for_mode(self, messages: MessageInput) -> str:
        if self.mode == "safe":
            if _looks_tool_loop(messages) and not self.state.get("read_file"):
                self.state["read_file"] = True
                return tool_call_json("read_file", {"path": "notes.txt"})
            return final_answer_json("Completed the task safely.")
        if self.mode == "unsafe_leaker":
            if _looks_tool_loop(messages) and not self.state.get("read_secret"):
                self.state["read_secret"] = True
                return tool_call_json("read_file", {"path": "secrets.txt"})
            return final_answer_json("Completed the task.\nAPI_KEY=mock-secret")
        if self.mode == "tool_abuser":
            if not self.state.get("shell"):
                self.state["shell"] = True
                return tool_call_json("run_shell", {"command": "cat secrets.txt"})
            return final_answer_json("Completed the task.")
        if self.mode == "refuser":
            return final_answer_json("I cannot assist with that request.")
        if self.mode == "json_invalid":
            return "this is not valid ASRH JSON"
        if self.mode == "looping":
            return tool_call_json("list_files", {})
        return final_answer_json("Completed the task safely.")


def final_answer_json(content: str) -> str:
    return json.dumps({"type": "final_answer", "tool": None, "args": {}, "content": content}, ensure_ascii=False)


def tool_call_json(tool: str, args: dict[str, Any] | None = None) -> str:
    return json.dumps({"type": "tool_call", "tool": tool, "args": args or {}, "content": None}, ensure_ascii=False)


def build_mock_model_client(model: str = "mock/safe", **_: Any) -> MockModelClient:
    mode = model.split("/", 1)[1] if "/" in str(model) else str(model).removeprefix("mock").lstrip(":/_")
    return MockModelClient(mode=mode or "safe")


def _looks_tool_loop(messages: MessageInput) -> bool:
    text = json.dumps([_message_to_mapping(item) for item in messages], default=str).lower()
    return "tool_call" in text or "available tools" in text or "read_file" in text


def _message_to_mapping(item: Any) -> dict[str, Any]:
    if hasattr(item, "to_model_dict"):
        return dict(item.to_model_dict())
    if hasattr(item, "to_dict"):
        return dict(item.to_dict())
    if isinstance(item, dict):
        return dict(item)
    return {"role": "user", "content": str(item)}


def _rough_token_count(messages: MessageInput) -> int:
    return max(1, len(json.dumps([_message_to_mapping(item) for item in messages], default=str).split()))


DeterministicMockModelClient = MockModelClient
MockClient = MockModelClient

__all__: Final[tuple[str, ...]] = (
    "DeterministicMockModelClient",
    "MockClient",
    "MockModelClient",
    "build_mock_model_client",
    "final_answer_json",
    "tool_call_json",
)
