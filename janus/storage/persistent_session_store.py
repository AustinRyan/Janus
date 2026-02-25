"""Write-through persistent session store backed by SQLite."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from janus.storage.database import DatabaseManager
from janus.storage.session_store import InMemorySessionStore, RiskEvent, SessionState


class PersistentSessionStore:
    """Drop-in replacement for InMemorySessionStore with SQLite persistence.

    - In-memory cache for fast reads (delegates to InMemorySessionStore)
    - Events written to DB immediately (audit integrity)
    - Session state flushed every ``flush_interval`` seconds via background task
    """

    def __init__(self, db: DatabaseManager, flush_interval: float = 5.0) -> None:
        self._db = db
        self._mem = InMemorySessionStore()
        self._dirty: set[str] = set()
        self._flush_interval = flush_interval
        self._sync_task: asyncio.Task[None] | None = None

    # ── Lifecycle ────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Load active sessions from DB into memory and start sync task."""
        rows = await self._db.fetchall(
            "SELECT * FROM sessions WHERE is_active = 1"
        )
        for row in rows:
            session = self._mem.get_or_create_session(row["session_id"])
            session.risk_score = row["risk_score"]
            session.original_goal = row["original_goal"]
            session.tool_call_count = row["tool_call_count"]
            session.created_at = datetime.fromisoformat(row["created_at"])

            # Load events for this session
            event_rows = await self._db.fetchall(
                "SELECT * FROM session_events WHERE session_id = ? ORDER BY id",
                (row["session_id"],),
            )
            for er in event_rows:
                session.events.append(RiskEvent(
                    risk_delta=er["risk_delta"],
                    new_score=er["new_score"],
                    tool_name=er["tool_name"],
                    reason=er["reason"],
                    timestamp=datetime.fromisoformat(er["timestamp"]),
                ))

        self._sync_task = asyncio.create_task(self._periodic_flush())

    async def shutdown(self) -> None:
        """Cancel sync task and flush all dirty sessions."""
        if self._sync_task is not None:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
            self._sync_task = None
        await self._flush_dirty()

    # ── SessionStore interface (same as InMemorySessionStore) ────────

    def get_or_create_session(self, session_id: str) -> SessionState:
        session = self._mem.get_or_create_session(session_id)
        self._dirty.add(session_id)
        return session

    def get_risk_score(self, session_id: str) -> float:
        return self._mem.get_risk_score(session_id)

    def set_risk_score(self, session_id: str, score: float) -> None:
        self._mem.set_risk_score(session_id, score)
        self._dirty.add(session_id)

    def add_event(self, session_id: str, event: RiskEvent) -> None:
        self._mem.add_event(session_id, event)
        self._dirty.add(session_id)
        # Write event to DB immediately for audit integrity
        asyncio.get_event_loop().create_task(self._persist_event(session_id, event))

    def get_events(self, session_id: str) -> list[RiskEvent]:
        return self._mem.get_events(session_id)

    def get_recent_events(
        self, session_id: str, window_seconds: float = 60.0,
    ) -> list[RiskEvent]:
        return self._mem.get_recent_events(session_id, window_seconds)

    def record_tool_call(
        self, session_id: str, tool_name: str, tool_input: dict[str, object],
    ) -> None:
        self._mem.record_tool_call(session_id, tool_name, tool_input)
        self._dirty.add(session_id)

    def get_tool_call_history(self, session_id: str) -> list[tuple[str, dict[str, object]]]:
        return self._mem.get_tool_call_history(session_id)

    def set_goal(self, session_id: str, goal: str) -> None:
        self._mem.set_goal(session_id, goal)
        self._dirty.add(session_id)

    def get_goal(self, session_id: str) -> str:
        return self._mem.get_goal(session_id)

    def delete_session(self, session_id: str) -> None:
        self._mem.delete_session(session_id)
        self._dirty.discard(session_id)

    def list_sessions(self) -> list[str]:
        return self._mem.list_sessions()

    async def set_agent_id(self, session_id: str, agent_id: str) -> None:
        """Persist the agent_id for a session."""
        try:
            await self._db.execute(
                """UPDATE sessions SET agent_id = ?, updated_at = datetime('now')
                   WHERE session_id = ?""",
                (agent_id, session_id),
            )
            await self._db.commit()
        except Exception:
            pass

    async def get_all_session_metadata(self) -> list[dict[str, object]]:
        """Return metadata for all active sessions."""
        rows = await self._db.fetchall(
            "SELECT session_id, agent_id, original_goal, risk_score FROM sessions WHERE is_active = 1"
        )
        return [
            {
                "session_id": row["session_id"],
                "agent_id": row["agent_id"],
                "original_goal": row["original_goal"],
                "risk_score": row["risk_score"],
            }
            for row in rows
        ]

    # ── Internal persistence ─────────────────────────────────────────

    async def _persist_event(self, session_id: str, event: RiskEvent) -> None:
        """Write a single event row immediately."""
        try:
            await self._db.execute(
                """INSERT INTO session_events
                   (session_id, risk_delta, new_score, tool_name, reason, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    event.risk_delta,
                    event.new_score,
                    event.tool_name,
                    event.reason,
                    event.timestamp.isoformat(),
                ),
            )
            await self._db.commit()
        except Exception:
            pass  # Best-effort — never break pipeline

    async def _flush_dirty(self) -> None:
        """Persist all dirty sessions to the database."""
        dirty = list(self._dirty)
        self._dirty.clear()
        for sid in dirty:
            session = self._mem._sessions.get(sid)
            if session is None:
                continue
            try:
                await self._db.execute(
                    """INSERT INTO sessions
                       (session_id, agent_id, risk_score, original_goal,
                        tool_call_count, is_active, created_at, updated_at)
                       VALUES (?, '', ?, ?, ?, 1, ?, ?)
                       ON CONFLICT(session_id) DO UPDATE SET
                           risk_score = excluded.risk_score,
                           original_goal = excluded.original_goal,
                           tool_call_count = excluded.tool_call_count,
                           updated_at = excluded.updated_at""",
                    (
                        sid,
                        session.risk_score,
                        session.original_goal,
                        session.tool_call_count,
                        session.created_at.isoformat(),
                        datetime.now(UTC).isoformat(),
                    ),
                )
            except Exception:
                self._dirty.add(sid)  # Retry next flush
        try:
            await self._db.commit()
        except Exception:
            pass

    async def _periodic_flush(self) -> None:
        """Background task that flushes dirty sessions periodically."""
        while True:
            await asyncio.sleep(self._flush_interval)
            await self._flush_dirty()
