from __future__ import annotations

import fnmatch
import json
from datetime import UTC, datetime

from sentinel.core.exceptions import AgentAlreadyExistsError, AgentNotFoundError
from sentinel.identity.agent import AgentIdentity, AgentRole, ToolPermission
from sentinel.storage.database import DatabaseManager
from sentinel.storage.models import ToolUsageRow


class AgentRegistry:
    """Manages agent lifecycle — registration, lookup, locking, and tool-usage tracking."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Registration & retrieval
    # ------------------------------------------------------------------

    async def register_agent(self, identity: AgentIdentity) -> None:
        """Persist a new agent identity. Raises AgentAlreadyExistsError on duplicate."""
        existing = await self._db.fetchone(
            "SELECT agent_id FROM agents WHERE agent_id = ?",
            (identity.agent_id,),
        )
        if existing is not None:
            raise AgentAlreadyExistsError(identity.agent_id)

        permissions_json = json.dumps(
            [
                {
                    "tool_pattern": p.tool_pattern,
                    "allowed": p.allowed,
                    "requires_sandbox": p.requires_sandbox,
                }
                for p in identity.permissions
            ]
        )
        metadata_json = json.dumps(identity.metadata)

        await self._db.execute(
            """
            INSERT INTO agents
                (agent_id, name, role, permissions_json, created_at,
                 credential_hash, credential_expires_at, credential_last_rotated,
                 is_locked, lock_reason, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                identity.agent_id,
                identity.name,
                identity.role.value,
                permissions_json,
                identity.created_at.isoformat(),
                identity.credential_hash,
                identity.credential_expires_at.isoformat()
                if identity.credential_expires_at
                else None,
                identity.credential_last_rotated.isoformat()
                if identity.credential_last_rotated
                else None,
                int(identity.is_locked),
                identity.lock_reason,
                metadata_json,
            ),
        )
        await self._db.commit()

    async def get_agent(self, agent_id: str) -> AgentIdentity | None:
        """Retrieve an agent by ID, or return None if not found."""
        row = await self._db.fetchone(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        )
        if row is None:
            return None
        return self._row_to_identity(row)

    # ------------------------------------------------------------------
    # Locking
    # ------------------------------------------------------------------

    async def lock_agent(self, agent_id: str, reason: str) -> None:
        """Lock an agent, preventing it from performing actions."""
        await self._ensure_agent_exists(agent_id)
        await self._db.execute(
            "UPDATE agents SET is_locked = 1, lock_reason = ? WHERE agent_id = ?",
            (reason, agent_id),
        )
        await self._db.commit()

    async def unlock_agent(self, agent_id: str) -> None:
        """Remove the lock from an agent."""
        await self._ensure_agent_exists(agent_id)
        await self._db.execute(
            "UPDATE agents SET is_locked = 0, lock_reason = '' WHERE agent_id = ?",
            (agent_id,),
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Credential management
    # ------------------------------------------------------------------

    async def update_credential(
        self, agent_id: str, new_hash: str, expires_at: datetime
    ) -> None:
        """Update an agent's credential hash, expiry, and rotation timestamp."""
        await self._ensure_agent_exists(agent_id)
        now = datetime.now(UTC)
        await self._db.execute(
            """
            UPDATE agents
            SET credential_hash = ?,
                credential_expires_at = ?,
                credential_last_rotated = ?
            WHERE agent_id = ?
            """,
            (new_hash, expires_at.isoformat(), now.isoformat(), agent_id),
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    async def list_agents(self, role: AgentRole | None = None) -> list[AgentIdentity]:
        """Return all agents, optionally filtered by role."""
        if role is not None:
            rows = await self._db.fetchall(
                "SELECT * FROM agents WHERE role = ?", (role.value,)
            )
        else:
            rows = await self._db.fetchall("SELECT * FROM agents")
        return [self._row_to_identity(r) for r in rows]

    # ------------------------------------------------------------------
    # Permission checking
    # ------------------------------------------------------------------

    def check_permission(self, agent: AgentIdentity, tool_name: str) -> bool:
        """Return True if any of the agent's permission patterns match *tool_name*.

        Uses ``fnmatch.fnmatch`` for glob-style matching.  Only patterns
        with ``allowed=True`` are considered a positive match.
        """
        for perm in agent.permissions:
            if fnmatch.fnmatch(tool_name, perm.tool_pattern) and perm.allowed:
                return True
        return False

    # ------------------------------------------------------------------
    # Tool-usage tracking
    # ------------------------------------------------------------------

    async def record_tool_usage(
        self,
        agent_id: str,
        tool_name: str,
        session_id: str,
        risk_score: float,
    ) -> None:
        """Insert a row into ``tool_usage_log``."""
        now = datetime.now(UTC)
        await self._db.execute(
            """
            INSERT INTO tool_usage_log
                (agent_id, tool_name, session_id, timestamp, risk_score_at_time)
            VALUES (?, ?, ?, ?, ?)
            """,
            (agent_id, tool_name, session_id, now.isoformat(), risk_score),
        )
        await self._db.commit()

    async def get_tool_usage(
        self, agent_id: str, since: datetime | None = None
    ) -> list[ToolUsageRow]:
        """Retrieve tool-usage rows for an agent, optionally filtered by time."""
        if since is not None:
            rows = await self._db.fetchall(
                """
                SELECT * FROM tool_usage_log
                WHERE agent_id = ? AND timestamp >= ?
                ORDER BY timestamp
                """,
                (agent_id, since.isoformat()),
            )
        else:
            rows = await self._db.fetchall(
                """
                SELECT * FROM tool_usage_log
                WHERE agent_id = ?
                ORDER BY timestamp
                """,
                (agent_id,),
            )
        return [
            ToolUsageRow(
                agent_id=r["agent_id"],
                tool_name=r["tool_name"],
                session_id=r["session_id"],
                timestamp=r["timestamp"],
                risk_score_at_time=r["risk_score_at_time"],
                id=r["id"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _ensure_agent_exists(self, agent_id: str) -> None:
        row = await self._db.fetchone(
            "SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,)
        )
        if row is None:
            raise AgentNotFoundError(agent_id)

    @staticmethod
    def _row_to_identity(row: object) -> AgentIdentity:
        """Convert a SQLite Row into an ``AgentIdentity`` dataclass."""
        permissions_data: list[dict[str, object]] = json.loads(row["permissions_json"])  # type: ignore[index]
        permissions = [
            ToolPermission(
                tool_pattern=str(p["tool_pattern"]),
                allowed=bool(p.get("allowed", True)),
                requires_sandbox=bool(p.get("requires_sandbox", False)),
            )
            for p in permissions_data
        ]
        metadata: dict[str, str] = json.loads(row["metadata_json"])  # type: ignore[index]

        expires_raw = row["credential_expires_at"]  # type: ignore[index]
        rotated_raw = row["credential_last_rotated"]  # type: ignore[index]

        return AgentIdentity(
            agent_id=row["agent_id"],  # type: ignore[index]
            name=row["name"],  # type: ignore[index]
            role=AgentRole(row["role"]),  # type: ignore[index]
            permissions=permissions,
            created_at=datetime.fromisoformat(row["created_at"]),  # type: ignore[index]
            credential_hash=row["credential_hash"],  # type: ignore[index]
            credential_expires_at=datetime.fromisoformat(expires_raw) if expires_raw else None,
            credential_last_rotated=datetime.fromisoformat(rotated_raw) if rotated_raw else None,
            is_locked=bool(row["is_locked"]),  # type: ignore[index]
            lock_reason=row["lock_reason"],  # type: ignore[index]
            metadata=metadata,
        )
