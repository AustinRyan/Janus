from __future__ import annotations


class SentinelError(Exception):
    """Base exception for all Sentinel errors."""


class AgentNotFoundError(SentinelError):
    """Raised when an agent ID is not found in the registry."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent not found: {agent_id}")


class AgentLockedError(SentinelError):
    """Raised when an operation is attempted on a locked agent."""

    def __init__(self, agent_id: str, reason: str = "") -> None:
        self.agent_id = agent_id
        self.reason = reason
        super().__init__(f"Agent locked: {agent_id}" + (f" ({reason})" if reason else ""))


class AgentAlreadyExistsError(SentinelError):
    """Raised when trying to register an agent with a duplicate ID."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent already exists: {agent_id}")


class SessionNotFoundError(SentinelError):
    """Raised when a session ID is not found."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        super().__init__(f"Session not found: {session_id}")


class GuardianError(SentinelError):
    """Raised when the Guardian encounters an internal error."""


class CircuitBreakerOpenError(SentinelError):
    """Raised when the circuit breaker is open and blocking all requests."""


class ClassificationError(SentinelError):
    """Raised when the LLM classifier fails to produce a valid result."""


class DatabaseError(SentinelError):
    """Raised on database operation failures."""
