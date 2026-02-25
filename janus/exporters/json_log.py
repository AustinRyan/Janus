"""JSON log exporter — writes SecurityVerdict as JSON lines to a file or stdout."""
from __future__ import annotations

import json
import sys
from typing import Any, TextIO

import structlog

from janus.core.decision import SecurityVerdict

logger = structlog.get_logger()


class JsonLogExporter:
    """Appends security verdicts as JSON lines to a file or stdout."""

    def __init__(self, path: str = "-") -> None:
        self._path = path
        self._file: TextIO | None = None

    def _get_file(self) -> TextIO:
        if self._path == "-":
            return sys.stdout
        if self._file is None:
            self._file = open(self._path, "a")  # noqa: SIM115
        return self._file

    def build_payload(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any]:
        return {
            "verdict": verdict.verdict.value,
            "risk_score": verdict.risk_score,
            "risk_delta": verdict.risk_delta,
            "reasons": verdict.reasons,
            "drift_score": verdict.drift_score,
            "trace_id": verdict.trace_id,
            "timestamp": verdict.timestamp.isoformat(),
            "tool_name": tool_name,
            "agent_id": agent_id,
            "session_id": session_id,
        }

    def log(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> None:
        """Write a verdict as a JSON line."""
        payload = self.build_payload(verdict, tool_name, agent_id, session_id)
        try:
            f = self._get_file()
            f.write(json.dumps(payload, default=str) + "\n")
            f.flush()
        except OSError as e:
            logger.warning("json_log_write_error", error=str(e))

    def close(self) -> None:
        if self._file is not None and self._path != "-":
            self._file.close()
            self._file = None
