from __future__ import annotations

import aiosqlite

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id          TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    role              TEXT NOT NULL,
    permissions_json  TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL,
    credential_hash   TEXT NOT NULL DEFAULT '',
    credential_expires_at TEXT,
    credential_last_rotated TEXT,
    is_locked         INTEGER NOT NULL DEFAULT 0,
    lock_reason       TEXT NOT NULL DEFAULT '',
    metadata_json     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tool_usage_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id          TEXT NOT NULL REFERENCES agents(agent_id),
    tool_name         TEXT NOT NULL,
    session_id        TEXT NOT NULL,
    timestamp         TEXT NOT NULL,
    risk_score_at_time REAL NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_tool_usage_agent ON tool_usage_log(agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_tool_usage_session ON tool_usage_log(session_id);

CREATE TABLE IF NOT EXISTS security_traces (
    trace_id          TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    request_id        TEXT NOT NULL,
    tool_name         TEXT NOT NULL,
    tool_input_json   TEXT NOT NULL,
    verdict           TEXT NOT NULL,
    risk_score        REAL NOT NULL,
    risk_delta        REAL NOT NULL,
    drift_score       REAL,
    reasons_json      TEXT NOT NULL DEFAULT '[]',
    itdr_signals_json TEXT NOT NULL DEFAULT '[]',
    explanation       TEXT NOT NULL DEFAULT '',
    original_goal     TEXT NOT NULL DEFAULT '',
    conversation_context_json TEXT NOT NULL DEFAULT '[]',
    timestamp         TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_traces_session ON security_traces(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_agent ON security_traces(agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_verdict ON security_traces(verdict);

CREATE TABLE IF NOT EXISTS pattern_matches (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id        TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    pattern_name      TEXT NOT NULL,
    matched_steps     INTEGER NOT NULL,
    total_steps       INTEGER NOT NULL,
    trace_ids_json    TEXT NOT NULL,
    risk_contribution REAL NOT NULL,
    timestamp         TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_patterns_session ON pattern_matches(session_id);

CREATE TABLE IF NOT EXISTS itdr_signals (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id          TEXT NOT NULL,
    signal_type       TEXT NOT NULL,
    severity          TEXT NOT NULL,
    description       TEXT NOT NULL,
    metadata_json     TEXT NOT NULL DEFAULT '{}',
    session_id        TEXT,
    related_agent_id  TEXT,
    timestamp         TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_itdr_agent ON itdr_signals(agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_itdr_type ON itdr_signals(signal_type, severity);

CREATE TABLE IF NOT EXISTS schema_version (
    version           INTEGER PRIMARY KEY,
    applied_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class DatabaseManager:
    """SQLite connection manager with schema migrations."""

    def __init__(self, db_path: str = "sentinel.db") -> None:
        self._db_path = db_path
        self._connection: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._connection = await aiosqlite.connect(self._db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._connection.execute("PRAGMA journal_mode=WAL")
        await self._connection.execute("PRAGMA foreign_keys=ON")

    async def close(self) -> None:
        if self._connection:
            await self._connection.close()
            self._connection = None

    @property
    def connection(self) -> aiosqlite.Connection:
        if self._connection is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._connection

    async def apply_migrations(self) -> None:
        await self.connection.executescript(SCHEMA_SQL)
        await self.connection.execute(
            "INSERT OR IGNORE INTO schema_version (version) VALUES (1)"
        )
        await self.connection.commit()

    async def execute(
        self, sql: str, params: tuple[object, ...] | None = None
    ) -> aiosqlite.Cursor:
        if params:
            return await self.connection.execute(sql, params)
        return await self.connection.execute(sql)

    async def fetchone(
        self, sql: str, params: tuple[object, ...] | None = None
    ) -> aiosqlite.Row | None:
        cursor = await self.execute(sql, params)
        return await cursor.fetchone()

    async def fetchall(
        self, sql: str, params: tuple[object, ...] | None = None
    ) -> list[aiosqlite.Row]:
        cursor = await self.execute(sql, params)
        rows = await cursor.fetchall()
        return list(rows)

    async def commit(self) -> None:
        await self.connection.commit()
