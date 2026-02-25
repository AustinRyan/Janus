"""Mock upstream manager for MCP proxy testing.

Drop-in replacement for UpstreamManager that returns mock tool results
from MockToolExecutor, wrapped as MCP CallToolResult objects.
"""
from __future__ import annotations

import json
from typing import Any

from mcp import types

from janus.web.tools import DEMO_TOOLS, MockToolExecutor


class MockUpstreamManager:
    """Drop-in replacement for UpstreamManager that returns mock tool results."""

    def __init__(self) -> None:
        self._executor = MockToolExecutor()
        self._tool_to_server: dict[str, str] = {
            t["name"]: "mock" for t in DEMO_TOOLS
        }

    def get_all_tools(self) -> list[types.Tool]:
        """Convert DEMO_TOOLS to MCP Tool format."""
        return [
            types.Tool(
                name=t["name"],
                description=t.get("description", ""),
                inputSchema=t["input_schema"],
            )
            for t in DEMO_TOOLS
        ]

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> types.CallToolResult:
        result = await self._executor.execute(name, arguments)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(result))]
        )

    async def connect(self, configs: list[Any]) -> None:
        pass  # no-op for mock

    async def close(self) -> None:
        pass  # no-op for mock

    @property
    def server_names(self) -> list[str]:
        return ["mock"]

    @property
    def tool_count(self) -> int:
        return len(DEMO_TOOLS)
