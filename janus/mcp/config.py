"""Configuration models for the Janus MCP Proxy."""
from __future__ import annotations

import os
import tomllib
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class TransportType(StrEnum):
    STDIO = "stdio"
    HTTP = "http"


class UpstreamServerConfig(BaseModel):
    """Configuration for a single upstream MCP server."""

    name: str
    transport: TransportType = TransportType.STDIO

    # stdio transport
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)

    # HTTP transport
    url: str = ""

    # Optional namespace prefix — tools exposed as "{namespace}__{tool_name}"
    namespace: str = ""

    timeout: float = 30.0

    def resolve_env(self) -> dict[str, str]:
        """Resolve ${VAR} patterns in env values from os.environ."""
        resolved: dict[str, str] = {}
        for k, v in self.env.items():
            if v.startswith("${") and v.endswith("}"):
                var_name = v[2:-1]
                resolved[k] = os.environ.get(var_name, "")
            else:
                resolved[k] = v
        return resolved


class AgentConfig(BaseModel):
    """Identity of the MCP client connecting through the proxy."""

    agent_id: str = "mcp-proxy-agent"
    name: str = "MCP Proxy Agent"
    role: str = "code"
    permissions: list[str] = Field(default_factory=lambda: ["*"])
    original_goal: str = ""


class SessionConfig(BaseModel):
    """Session management settings."""

    session_id_prefix: str = "mcp-proxy"
    persistent_session_id: str = ""


class ProxyTransportConfig(BaseModel):
    """How the proxy itself is served to MCP clients."""

    type: TransportType = TransportType.STDIO
    host: str = "127.0.0.1"
    port: int = 8100


class ProxyConfig(BaseModel):
    """Root configuration for the Janus MCP Proxy."""

    server_name: str = "janus-proxy"
    server_version: str = "0.1.0"
    upstream_servers: list[UpstreamServerConfig] = Field(default_factory=list)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    transport: ProxyTransportConfig = Field(default_factory=ProxyTransportConfig)
    janus: dict[str, Any] = Field(default_factory=dict)
    database_path: str = ":memory:"
    log_level: str = "INFO"

    @classmethod
    def from_toml(cls, path: str | Path) -> ProxyConfig:
        """Load configuration from a TOML file."""
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return cls(**data)
