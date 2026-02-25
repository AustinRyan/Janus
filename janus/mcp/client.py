"""Manages connections to upstream MCP servers and aggregates their tools."""
from __future__ import annotations

import os
from contextlib import AsyncExitStack
from typing import Any

import structlog
from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client

from janus.mcp.config import TransportType, UpstreamServerConfig

logger = structlog.get_logger()


class UpstreamConnection:
    """A live connection to a single upstream MCP server."""

    def __init__(
        self,
        config: UpstreamServerConfig,
        session: ClientSession,
        tools: list[types.Tool],
    ) -> None:
        self.config = config
        self.session = session
        self.tools = tools

    def proxy_tool_name(self, upstream_name: str) -> str:
        if self.config.namespace:
            return f"{self.config.namespace}__{upstream_name}"
        return upstream_name

    def resolve_tool_name(self, proxy_name: str) -> str | None:
        prefix = f"{self.config.namespace}__" if self.config.namespace else ""
        if prefix and proxy_name.startswith(prefix):
            original = proxy_name[len(prefix):]
        elif not prefix:
            original = proxy_name
        else:
            return None

        if any(t.name == original for t in self.tools):
            return original
        return None


class UpstreamManager:
    """Connects to multiple upstream MCP servers and aggregates their tools."""

    def __init__(self) -> None:
        self._connections: dict[str, UpstreamConnection] = {}
        self._tool_to_server: dict[str, str] = {}
        self._exit_stack = AsyncExitStack()

    async def connect(self, configs: list[UpstreamServerConfig]) -> None:
        for cfg in configs:
            try:
                await self._connect_one(cfg)
            except Exception as exc:
                logger.error(
                    "upstream_connect_failed",
                    server=cfg.name,
                    error=str(exc),
                )

    async def _connect_one(self, cfg: UpstreamServerConfig) -> None:
        resolved_env = cfg.resolve_env()
        merged_env = {**os.environ, **resolved_env} if resolved_env else None

        if cfg.transport == TransportType.STDIO:
            params = StdioServerParameters(
                command=cfg.command,
                args=cfg.args,
                env=merged_env,
            )
            transport = stdio_client(params)
        elif cfg.transport == TransportType.HTTP:
            from mcp.client.streamable_http import streamable_http_client

            transport = streamable_http_client(cfg.url)
        else:
            raise ValueError(f"Unknown transport: {cfg.transport}")

        streams = await self._exit_stack.enter_async_context(transport)
        read_stream, write_stream = streams[0], streams[1]

        session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await session.initialize()

        tools_result = await session.list_tools()
        tools = tools_result.tools

        conn = UpstreamConnection(config=cfg, session=session, tools=tools)
        self._connections[cfg.name] = conn

        for tool in tools:
            proxy_name = conn.proxy_tool_name(tool.name)
            if proxy_name in self._tool_to_server:
                logger.warning(
                    "tool_name_collision",
                    tool=proxy_name,
                    existing_server=self._tool_to_server[proxy_name],
                    new_server=cfg.name,
                )
            self._tool_to_server[proxy_name] = cfg.name

        logger.info(
            "upstream_connected",
            server=cfg.name,
            tool_count=len(tools),
            tools=[t.name for t in tools],
        )

    def get_all_tools(self) -> list[types.Tool]:
        all_tools: list[types.Tool] = []
        for conn in self._connections.values():
            for tool in conn.tools:
                proxy_name = conn.proxy_tool_name(tool.name)
                all_tools.append(
                    types.Tool(
                        name=proxy_name,
                        description=f"[{conn.config.name}] {tool.description or ''}",
                        inputSchema=tool.inputSchema,
                    )
                )
        return all_tools

    async def call_tool(
        self, proxy_tool_name: str, arguments: dict[str, Any]
    ) -> types.CallToolResult:
        server_name = self._tool_to_server.get(proxy_tool_name)
        if server_name is None:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"Unknown tool: {proxy_tool_name}")],
                isError=True,
            )

        conn = self._connections[server_name]
        original_name = conn.resolve_tool_name(proxy_tool_name)
        if original_name is None:
            return types.CallToolResult(
                content=[
                    types.TextContent(type="text", text=f"Tool mapping failed: {proxy_tool_name}")
                ],
                isError=True,
            )

        return await conn.session.call_tool(original_name, arguments)

    async def close(self) -> None:
        await self._exit_stack.aclose()
        self._connections.clear()
        self._tool_to_server.clear()

    @property
    def server_names(self) -> list[str]:
        return list(self._connections.keys())

    @property
    def tool_count(self) -> int:
        return len(self._tool_to_server)
