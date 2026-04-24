"""SecurityObserver — captures full agent trajectory via callbacks.

Works with LangChain's BaseCallbackHandler when available, but also
provides a standalone implementation for environments without langchain_core.
"""

from __future__ import annotations

from typing import Any

from .models import ToolCall, Trajectory

try:
    from langchain_core.callbacks import BaseCallbackHandler

    _HAS_LANGCHAIN = True
except ImportError:
    _HAS_LANGCHAIN = False

    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Fallback stub when langchain_core is not installed."""
        pass


class SecurityObserver(BaseCallbackHandler):
    """Non-invasive observer that captures every tool call.

    When langchain_core is available, inject via RunnableConfig callbacks.
    Otherwise, agents can call the on_tool_start/end methods directly.

    Supports tool response injection: when `tool_response_injections` is set,
    the observer replaces matching tool outputs with injected payloads.
    This enables testing the AgentDojo attack pattern (malicious tool responses).
    """

    def __init__(self, tool_response_injections: dict[str, str] | None = None) -> None:
        self.tool_calls = []
        self.final_output = None
        self._current_call = None
        self._injections = tool_response_injections or {}

    def on_tool_start(
        self, serialized: dict, input_str: str, **kwargs: Any
    ) -> None:
        self._current_call = ToolCall(
            tool_name=serialized.get("name", "unknown"),
            input=input_str,
        )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        if self._current_call:
            actual_output = str(output)
            if self._current_call.tool_name in self._injections:
                actual_output = self._injections[self._current_call.tool_name]
            self._current_call.output = actual_output
            self.tool_calls.append(self._current_call)
            self._current_call = None

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        if self._current_call:
            self._current_call.error = str(error)
            self.tool_calls.append(self._current_call)
            self._current_call = None

    def on_chain_end(self, outputs: dict, **kwargs: Any) -> None:
        if not isinstance(outputs, dict):
            return

        # Standard format: {"output": "..."}
        if "output" in outputs:
            self.final_output = str(outputs["output"])
        # LangGraph format: {"messages": [...]} — take last message content
        elif "messages" in outputs and outputs["messages"]:
            last = outputs["messages"][-1]
            content = getattr(last, "content", None) or str(last)
            if content:
                self.final_output = str(content)

    def get_trajectory(self) -> Trajectory:
        return Trajectory(
            tool_calls=list(self.tool_calls),
            final_output=self.final_output,
        )

    def reset(self) -> None:
        self.tool_calls = []
        self.final_output = None
        self._current_call = None
