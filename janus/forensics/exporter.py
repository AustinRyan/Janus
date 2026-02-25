"""Audit log export — CSV/JSON/JSONL from security_traces table."""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from janus.storage.database import DatabaseManager


class TraceExporter:
    """Queries and formats security traces for export."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def query_traces(
        self,
        date_from: str | None = None,
        date_to: str | None = None,
        verdict: str | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        min_risk: float | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        """Query security_traces with optional filters."""
        conditions: list[str] = []
        params: list[object] = []

        if date_from:
            conditions.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            conditions.append("timestamp <= ?")
            params.append(date_to)
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict)
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if min_risk is not None:
            conditions.append("risk_score >= ?")
            params.append(min_risk)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM security_traces {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = await self._db.fetchall(sql, tuple(params))
        return [self._row_to_dict(row) for row in rows]

    @staticmethod
    def _row_to_dict(row: Any) -> dict[str, Any]:
        return {
            "trace_id": row["trace_id"],
            "session_id": row["session_id"],
            "agent_id": row["agent_id"],
            "request_id": row["request_id"],
            "tool_name": row["tool_name"],
            "tool_input": row["tool_input_json"],
            "verdict": row["verdict"],
            "risk_score": row["risk_score"],
            "risk_delta": row["risk_delta"],
            "drift_score": row["drift_score"],
            "reasons": row["reasons_json"],
            "itdr_signals": row["itdr_signals_json"],
            "explanation": row["explanation"],
            "original_goal": row["original_goal"],
            "timestamp": row["timestamp"],
        }

    @staticmethod
    def to_json(traces: list[dict[str, Any]]) -> str:
        """Format traces as a pretty-printed JSON array."""
        return json.dumps(traces, indent=2, default=str)

    @staticmethod
    def to_jsonl(traces: list[dict[str, Any]]) -> str:
        """Format traces as newline-delimited JSON (one object per line)."""
        return "\n".join(json.dumps(t, default=str) for t in traces)

    @staticmethod
    def to_csv(traces: list[dict[str, Any]]) -> str:
        """Format traces as CSV with headers."""
        if not traces:
            return ""
        fieldnames = list(traces[0].keys())
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(traces)
        return buf.getvalue()
