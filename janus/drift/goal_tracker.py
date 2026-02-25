from __future__ import annotations

from janus.storage.session_store import InMemorySessionStore


class GoalTracker:
    """Stores and retrieves the original user goal per session.

    The goal is set ONCE per session and is immutable — agent actions
    cannot modify it.
    """

    def __init__(self, session_store: InMemorySessionStore) -> None:
        self._store = session_store

    def set_goal(self, session_id: str, goal: str) -> None:
        """Set the goal for a session. Only takes effect if not already set."""
        self._store.set_goal(session_id, goal)

    def get_goal(self, session_id: str) -> str:
        """Get the original goal for a session. Returns empty string if unset."""
        return self._store.get_goal(session_id)
