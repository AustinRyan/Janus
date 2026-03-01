"""Data models for registered tools."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class RegisteredTool:
    """A tool registered by a customer for real execution."""

    id: str
    name: str
    description: str = ""
    type: str = "webhook"  # "webhook" or "mcp"
    endpoint: str = ""  # URL for webhook tools
    method: str = "POST"  # HTTP method for webhook
    auth_type: str = "none"  # "none", "bearer", "api_key", "hmac"
    auth_credential: str = ""  # env var name like $MY_TOKEN, or raw value
    input_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    timeout_seconds: float = 30.0
    mcp_server_name: str = ""  # for MCP-type tools
    is_active: bool = True
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now = datetime.now(UTC).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    @staticmethod
    def new_id() -> str:
        return f"tool-{uuid.uuid4().hex[:12]}"

    def to_claude_tool(self) -> dict[str, Any]:
        """Convert to Claude's tool_use format."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "type": self.type,
            "endpoint": self.endpoint,
            "method": self.method,
            "auth_type": self.auth_type,
            "auth_credential": self.auth_credential,
            "input_schema": self.input_schema,
            "timeout_seconds": self.timeout_seconds,
            "mcp_server_name": self.mcp_server_name,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_row(cls, row: Any) -> RegisteredTool:
        """Construct from a database row (sqlite3.Row or tuple)."""
        schema = row["input_schema"] if isinstance(row["input_schema"], str) else "{}"
        try:
            parsed_schema = json.loads(schema)
        except (json.JSONDecodeError, TypeError):
            parsed_schema = {"type": "object", "properties": {}}

        return cls(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            type=row["type"],
            endpoint=row["endpoint"] or "",
            method=row["method"] or "POST",
            auth_type=row["auth_type"] or "none",
            auth_credential=row["auth_credential"] or "",
            input_schema=parsed_schema,
            timeout_seconds=float(row["timeout_seconds"] or 30.0),
            mcp_server_name=row["mcp_server_name"] or "",
            is_active=bool(row["is_active"]),
            created_at=row["created_at"] or "",
            updated_at=row["updated_at"] or "",
        )
