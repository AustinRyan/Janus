from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class AgentRole(Enum):
    """Roles that define the general category of an AI agent."""

    RESEARCH = "research"
    FINANCIAL = "financial"
    CODE = "code"
    ADMIN = "admin"
    DATA_ANALYSIS = "data_analysis"
    COMMUNICATION = "communication"
    CUSTOM = "custom"


@dataclass
class ToolPermission:
    """A single permission entry that controls tool access via glob patterns.

    Attributes:
        tool_pattern: Glob-style pattern (e.g. "read_*", "write_file", "*").
        allowed: Whether matching tools are permitted.
        requires_sandbox: Whether matching tools must run in a sandbox.
    """

    tool_pattern: str
    allowed: bool = True
    requires_sandbox: bool = False


@dataclass
class AgentIdentity:
    """Full identity record for a registered AI agent.

    Attributes:
        agent_id: Unique identifier for the agent.
        name: Human-readable display name.
        role: The agent's assigned role category.
        permissions: List of glob-based tool permission rules.
        created_at: When the agent was first registered.
        credential_hash: SHA-256 hash of the agent's current credential.
        credential_expires_at: Optional expiry time for the credential.
        credential_last_rotated: When the credential was last rotated.
        is_locked: Whether the agent is currently locked out.
        lock_reason: Explanation for why the agent was locked.
        metadata: Arbitrary key-value metadata.
    """

    agent_id: str
    name: str
    role: AgentRole
    permissions: list[ToolPermission] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    credential_hash: str = ""
    credential_expires_at: datetime | None = None
    credential_last_rotated: datetime | None = None
    is_locked: bool = False
    lock_reason: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
