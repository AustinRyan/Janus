from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from janus.core.decision import SecurityVerdict, ToolCallRequest
from janus.forensics.explainer import TraceExplainer
from janus.forensics.trace import SecurityTrace
from janus.storage.database import DatabaseManager


class BlackBoxRecorder:
    """Records and retrieves security traces from the database."""

    def __init__(self, db: DatabaseManager, explainer: TraceExplainer) -> None:
        self._db = db
        self._explainer = explainer

    async def record(
        self,
        request: ToolCallRequest,
        verdict: SecurityVerdict,
        agent_name: str = "",
        agent_role: str = "",
    ) -> SecurityTrace:
        """Record a security event and return the resulting trace."""
        explanation = await self._explainer.explain(request, verdict, agent_name, agent_role)

        trace = SecurityTrace(
            trace_id=verdict.trace_id,
            session_id=request.session_id,
            agent_id=request.agent_id,
            request_id=request.request_id,
            tool_name=request.tool_name,
            tool_input=request.tool_input,
            verdict=verdict.verdict.value,
            risk_score=verdict.risk_score,
            risk_delta=verdict.risk_delta,
            timestamp=verdict.timestamp,
            drift_score=verdict.drift_score,
            reasons=list(verdict.reasons),
            itdr_signals=list(verdict.itdr_signals),
            explanation=explanation,
            original_goal=request.original_goal,
            conversation_context=list(request.conversation_history),
        )

        await self._db.execute(
            """
            INSERT INTO security_traces (
                trace_id, session_id, agent_id, request_id, tool_name,
                tool_input_json, verdict, risk_score, risk_delta, drift_score,
                reasons_json, itdr_signals_json, explanation, original_goal,
                conversation_context_json, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trace.trace_id,
                trace.session_id,
                trace.agent_id,
                trace.request_id,
                trace.tool_name,
                json.dumps(trace.tool_input, default=str),
                trace.verdict,
                trace.risk_score,
                trace.risk_delta,
                trace.drift_score,
                json.dumps(trace.reasons),
                json.dumps(trace.itdr_signals),
                trace.explanation,
                trace.original_goal,
                json.dumps(trace.conversation_context, default=str),
                trace.timestamp.isoformat(),
            ),
        )
        await self._db.commit()

        return trace

    async def get_trace(self, trace_id: str) -> SecurityTrace | None:
        """Retrieve a single trace by its ID."""
        row = await self._db.fetchone(
            "SELECT * FROM security_traces WHERE trace_id = ?",
            (trace_id,),
        )
        if row is None:
            return None
        return self._row_to_trace(row)

    async def get_traces_by_session(self, session_id: str) -> list[SecurityTrace]:
        """Retrieve all traces for a given session."""
        rows = await self._db.fetchall(
            "SELECT * FROM security_traces WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        )
        return [self._row_to_trace(row) for row in rows]

    async def get_traces_by_verdict(
        self, verdict: str, limit: int = 100
    ) -> list[SecurityTrace]:
        """Retrieve traces filtered by verdict."""
        rows = await self._db.fetchall(
            "SELECT * FROM security_traces WHERE verdict = ? ORDER BY timestamp DESC LIMIT ?",
            (verdict, limit),
        )
        return [self._row_to_trace(row) for row in rows]

    async def get_recent_traces(self, limit: int = 50) -> list[SecurityTrace]:
        """Retrieve the most recent traces."""
        rows = await self._db.fetchall(
            "SELECT * FROM security_traces ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        return [self._row_to_trace(row) for row in rows]

    @staticmethod
    def _row_to_trace(row: Any) -> SecurityTrace:
        """Convert a database row to a SecurityTrace."""
        return SecurityTrace(
            trace_id=row["trace_id"],
            session_id=row["session_id"],
            agent_id=row["agent_id"],
            request_id=row["request_id"],
            tool_name=row["tool_name"],
            tool_input=json.loads(row["tool_input_json"]),
            verdict=row["verdict"],
            risk_score=row["risk_score"],
            risk_delta=row["risk_delta"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            drift_score=row["drift_score"],
            reasons=json.loads(row["reasons_json"]),
            itdr_signals=json.loads(row["itdr_signals_json"]),
            explanation=row["explanation"],
            original_goal=row["original_goal"],
            conversation_context=json.loads(row["conversation_context_json"]),
        )
