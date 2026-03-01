"""Tool execution — routes approved tool calls to real backends."""
from __future__ import annotations

import json
import os
import uuid
from typing import Any, Protocol

import httpx
import structlog

from janus.tools.models import RegisteredTool
from janus.tools.registry import ToolRegistry

logger = structlog.get_logger()

# Max response body size (1 MB)
_MAX_RESPONSE_BYTES = 1_048_576


class ToolExecutorProtocol(Protocol):
    """Protocol for tool executors (real or mock)."""

    async def execute(self, tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]: ...

    def get_tool_definitions(self) -> list[dict[str, Any]]: ...

    @property
    def tool_names(self) -> list[str]: ...


def _resolve_credential(credential: str) -> str:
    """Resolve a credential value.

    If it starts with '$', treat it as an env var name.
    Otherwise use it as a literal value.
    """
    if credential.startswith("$"):
        env_name = credential[1:]
        return os.environ.get(env_name, "")
    return credential


class WebhookExecutor:
    """Executes tools by calling customer-provided HTTP endpoints."""

    async def call(
        self, tool: RegisteredTool, tool_input: dict[str, Any]
    ) -> dict[str, Any]:
        """Make an HTTP request to the tool's webhook endpoint."""
        request_id = f"janus-{uuid.uuid4().hex[:12]}"

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Janus-Request-Id": request_id,
            "User-Agent": "Janus-Security/1.0",
        }

        # Apply auth
        if tool.auth_type == "bearer":
            token = _resolve_credential(tool.auth_credential)
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif tool.auth_type == "api_key":
            token = _resolve_credential(tool.auth_credential)
            if token:
                headers["X-API-Key"] = token
        elif tool.auth_type == "hmac":
            # HMAC signing — customer provides a secret, we sign the body
            import hashlib
            import hmac as hmac_mod

            secret = _resolve_credential(tool.auth_credential)
            if secret:
                body_bytes = json.dumps(tool_input).encode()
                sig = hmac_mod.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
                headers["X-Janus-Signature"] = sig

        try:
            async with httpx.AsyncClient(timeout=tool.timeout_seconds) as client:
                response = await client.request(
                    method=tool.method,
                    url=tool.endpoint,
                    json=tool_input,
                    headers=headers,
                )

                # Enforce response size limit
                body = response.content[:_MAX_RESPONSE_BYTES]

                try:
                    result = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    result = {"raw_response": body.decode("utf-8", errors="replace")}

                logger.info(
                    "webhook_tool_executed",
                    tool=tool.name,
                    endpoint=tool.endpoint,
                    status=response.status_code,
                    request_id=request_id,
                )

                if response.status_code >= 400:
                    return {
                        "error": f"Tool returned HTTP {response.status_code}",
                        "status_code": response.status_code,
                        "body": result,
                    }

                return result

        except httpx.TimeoutException:
            logger.warning("webhook_timeout", tool=tool.name, timeout=tool.timeout_seconds)
            return {"error": f"Tool '{tool.name}' timed out after {tool.timeout_seconds}s"}
        except httpx.ConnectError as e:
            logger.warning("webhook_connect_error", tool=tool.name, error=str(e))
            return {"error": f"Could not connect to tool '{tool.name}': {e}"}
        except Exception as e:
            logger.error("webhook_execution_error", tool=tool.name, error=str(e))
            return {"error": f"Tool execution failed: {e}"}


class ToolExecutor:
    """Routes tool calls to the appropriate backend (webhook or MCP).

    Falls back to MockToolExecutor when JANUS_MOCK_TOOLS=true or when
    the requested tool is not registered.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        mcp_upstream: Any | None = None,
    ) -> None:
        self._registry = registry
        self._webhook = WebhookExecutor()
        self._mcp_upstream = mcp_upstream
        self._tools_cache: list[RegisteredTool] | None = None

        # Mock fallback
        self._mock: ToolExecutorProtocol | None = None
        if os.environ.get("JANUS_MOCK_TOOLS", "").lower() == "true":
            from janus.web.tools import MockToolExecutor
            self._mock = MockToolExecutor()
            logger.info("tool_executor_mock_mode", reason="JANUS_MOCK_TOOLS=true")

    @property
    def is_mock_mode(self) -> bool:
        return self._mock is not None

    async def _refresh_cache(self) -> list[RegisteredTool]:
        self._tools_cache = await self._registry.list_tools(active_only=True)
        return self._tools_cache

    async def execute(
        self, tool_name: str, tool_input: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a tool call, routing to the appropriate backend."""
        # Mock mode — use mock executor for everything
        if self._mock is not None:
            return await self._mock.execute(tool_name, tool_input)

        # Look up the registered tool
        tool = await self._registry.get_by_name(tool_name)
        if tool is None or not tool.is_active:
            return {"error": f"Tool '{tool_name}' is not registered or inactive"}

        if tool.type == "webhook":
            return await self._webhook.call(tool, tool_input)
        elif tool.type == "mcp":
            return await self._execute_mcp(tool, tool_name, tool_input)
        else:
            return {"error": f"Unknown tool type: {tool.type}"}

    async def _execute_mcp(
        self, tool: RegisteredTool, tool_name: str, tool_input: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute via MCP upstream manager."""
        if self._mcp_upstream is None:
            return {"error": "No MCP upstream configured for this tool"}

        try:
            result = await self._mcp_upstream.call_tool(tool_name, tool_input)
            # MCP CallToolResult → dict
            if hasattr(result, "content"):
                texts = [
                    c.text for c in result.content
                    if hasattr(c, "text")
                ]
                combined = "\n".join(texts)
                try:
                    return json.loads(combined)
                except json.JSONDecodeError:
                    return {"result": combined}
            return {"result": str(result)}
        except Exception as e:
            logger.error("mcp_tool_error", tool=tool_name, error=str(e))
            return {"error": f"MCP tool execution failed: {e}"}

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return tool definitions in Claude's tool_use format.

        Uses the cached tool list. Call refresh_definitions() to update.
        """
        if self._mock is not None:
            return self._mock.get_tool_definitions()

        if self._tools_cache is None:
            return []

        return [t.to_claude_tool() for t in self._tools_cache if t.is_active]

    async def refresh_definitions(self) -> list[dict[str, Any]]:
        """Refresh the tool definitions from the database."""
        tools = await self._refresh_cache()
        return [t.to_claude_tool() for t in tools if t.is_active]

    @property
    def tool_names(self) -> list[str]:
        if self._mock is not None:
            return self._mock.tool_names
        if self._tools_cache is None:
            return []
        return [t.name for t in self._tools_cache if t.is_active]
