from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from janus.identity.agent import AgentIdentity
from janus.identity.registry import AgentRegistry


class CredentialManager:
    """Handles credential hashing, rotation, and expiry checks for agents."""

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    async def rotate_credential(self, agent_id: str, new_credential: str) -> str:
        """Hash *new_credential* with SHA-256, persist via the registry, and return the hash."""
        new_hash = hashlib.sha256(new_credential.encode("utf-8")).hexdigest()
        expires_at = datetime.now(UTC) + timedelta(days=90)
        await self._registry.update_credential(agent_id, new_hash, expires_at)
        return new_hash

    def is_expired(self, agent: AgentIdentity) -> bool:
        """Return True if the agent's credential has passed its expiry time."""
        if agent.credential_expires_at is None:
            return False
        now = datetime.now(UTC)
        # Ensure we compare timezone-aware datetimes
        expires = agent.credential_expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return now >= expires

    def was_recently_rotated(
        self, agent: AgentIdentity, within_hours: float = 24.0
    ) -> bool:
        """Return True if the credential was rotated within *within_hours* hours."""
        if agent.credential_last_rotated is None:
            return False
        now = datetime.now(UTC)
        rotated = agent.credential_last_rotated
        if rotated.tzinfo is None:
            rotated = rotated.replace(tzinfo=UTC)
        return (now - rotated) < timedelta(hours=within_hours)
