"""Tool registry — CRUD operations for registered tools."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from janus.storage.database import DatabaseManager
from janus.tools.models import RegisteredTool

logger = structlog.get_logger()


class ToolRegistry:
    """Manages registered tools in the database."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def register(
        self,
        name: str,
        description: str = "",
        type: str = "webhook",
        endpoint: str = "",
        method: str = "POST",
        auth_type: str = "none",
        auth_credential: str = "",
        input_schema: dict[str, Any] | None = None,
        timeout_seconds: float = 30.0,
        mcp_server_name: str = "",
    ) -> RegisteredTool:
        """Register a new tool. Raises ValueError if name already exists."""
        existing = await self.get_by_name(name)
        if existing is not None:
            raise ValueError(f"Tool '{name}' already registered")

        tool = RegisteredTool(
            id=RegisteredTool.new_id(),
            name=name,
            description=description,
            type=type,
            endpoint=endpoint,
            method=method,
            auth_type=auth_type,
            auth_credential=auth_credential,
            input_schema=input_schema or {"type": "object", "properties": {}},
            timeout_seconds=timeout_seconds,
            mcp_server_name=mcp_server_name,
        )

        await self._db.execute(
            """
            INSERT INTO registered_tools
                (id, name, description, type, endpoint, method,
                 auth_type, auth_credential, input_schema, timeout_seconds,
                 mcp_server_name, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                tool.id, tool.name, tool.description, tool.type,
                tool.endpoint, tool.method, tool.auth_type, tool.auth_credential,
                json.dumps(tool.input_schema), tool.timeout_seconds,
                tool.mcp_server_name, tool.created_at, tool.updated_at,
            ),
        )
        await self._db.commit()
        logger.info("tool_registered", name=name, type=type, tool_id=tool.id)
        return tool

    async def get_by_id(self, tool_id: str) -> RegisteredTool | None:
        row = await self._db.fetchone(
            "SELECT * FROM registered_tools WHERE id = ?", (tool_id,)
        )
        return RegisteredTool.from_row(row) if row else None

    async def get_by_name(self, name: str) -> RegisteredTool | None:
        row = await self._db.fetchone(
            "SELECT * FROM registered_tools WHERE name = ?", (name,)
        )
        return RegisteredTool.from_row(row) if row else None

    async def list_tools(self, active_only: bool = True) -> list[RegisteredTool]:
        if active_only:
            rows = await self._db.fetchall(
                "SELECT * FROM registered_tools WHERE is_active = 1 ORDER BY name"
            )
        else:
            rows = await self._db.fetchall(
                "SELECT * FROM registered_tools ORDER BY name"
            )
        return [RegisteredTool.from_row(r) for r in rows]

    async def update(self, tool_id: str, **fields: Any) -> RegisteredTool | None:
        """Update tool fields. Returns updated tool or None if not found."""
        tool = await self.get_by_id(tool_id)
        if tool is None:
            return None

        allowed = {
            "name", "description", "type", "endpoint", "method",
            "auth_type", "auth_credential", "input_schema",
            "timeout_seconds", "mcp_server_name", "is_active",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return tool

        if "input_schema" in updates and isinstance(updates["input_schema"], dict):
            updates["input_schema"] = json.dumps(updates["input_schema"])

        updates["updated_at"] = datetime.now(UTC).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [tool_id]

        await self._db.execute(
            f"UPDATE registered_tools SET {set_clause} WHERE id = ?",
            tuple(values),
        )
        await self._db.commit()
        logger.info("tool_updated", tool_id=tool_id, fields=list(updates.keys()))
        return await self.get_by_id(tool_id)

    async def delete(self, tool_id: str) -> bool:
        """Delete a tool. Returns True if deleted, False if not found."""
        tool = await self.get_by_id(tool_id)
        if tool is None:
            return False
        await self._db.execute("DELETE FROM registered_tools WHERE id = ?", (tool_id,))
        await self._db.commit()
        logger.info("tool_deleted", tool_id=tool_id, name=tool.name)
        return True

    async def tool_count(self) -> int:
        row = await self._db.fetchone("SELECT COUNT(*) FROM registered_tools WHERE is_active = 1")
        return int(row[0]) if row else 0
