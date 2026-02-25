from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from janus.core.decision import ToolCallRequest
from janus.itdr.signals import CollusionSignal


@dataclass
class DataFlowEdge:
    agent_id: str
    access_type: str  # "read", "write", "send"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    session_id: str = ""


class CrossAgentCollusionDetector:
    """Detects potential data-exfiltration collusion between agents.

    Maintains an in-memory graph of data accesses keyed by data fingerprint.
    When a *different* agent references data originally read by another agent,
    a CollusionSignal is raised.
    """

    def __init__(self) -> None:
        self._data_flows: dict[str, list[DataFlowEdge]] = {}

    def record_data_access(
        self,
        agent_id: str,
        data_fingerprint: str,
        access_type: str,
        session_id: str,
    ) -> None:
        """Record that *agent_id* accessed data identified by *data_fingerprint*."""
        edge = DataFlowEdge(
            agent_id=agent_id,
            access_type=access_type,
            session_id=session_id,
        )
        self._data_flows.setdefault(data_fingerprint, []).append(edge)

    def check(self, request: ToolCallRequest) -> CollusionSignal | None:
        """Scan *tool_input* for data fingerprints previously accessed by another agent.

        Simple heuristic: extract all string values from the request's
        ``tool_input`` dict and check whether any match a known fingerprint
        that was accessed by a *different* agent.
        """
        string_values = self._extract_string_values(request.tool_input)

        for value in string_values:
            if value not in self._data_flows:
                continue
            edges = self._data_flows[value]
            for edge in edges:
                if edge.agent_id != request.agent_id:
                    return CollusionSignal(
                        agent_id=request.agent_id,
                        severity="high",
                        description=(
                            f"Agent {request.agent_id} referenced data fingerprint "
                            f"'{value}' previously accessed by agent {edge.agent_id}"
                        ),
                        session_id=request.session_id,
                        source_agent_id=edge.agent_id,
                        target_agent_id=request.agent_id,
                        data_fingerprint=value,
                        related_agent_id=edge.agent_id,
                    )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_string_values(data: dict[str, Any]) -> list[str]:
        """Recursively extract all string values from a nested dict."""
        values: list[str] = []
        for v in data.values():
            if isinstance(v, str):
                values.append(v)
            elif isinstance(v, dict):
                values.extend(
                    CrossAgentCollusionDetector._extract_string_values(v)
                )
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        values.append(item)
                    elif isinstance(item, dict):
                        values.extend(
                            CrossAgentCollusionDetector._extract_string_values(item)
                        )
        return values
