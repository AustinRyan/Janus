from __future__ import annotations

from sentinel.identity.agent import AgentIdentity, AgentRole, ToolPermission
from sentinel.identity.challenge import ChallengeResult, IdentityChallenger
from sentinel.identity.credential import CredentialManager
from sentinel.identity.registry import AgentRegistry

__all__ = [
    "AgentIdentity",
    "AgentRegistry",
    "AgentRole",
    "ChallengeResult",
    "CredentialManager",
    "IdentityChallenger",
    "ToolPermission",
]
