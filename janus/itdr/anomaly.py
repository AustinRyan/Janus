from __future__ import annotations

from janus.core.decision import ToolCallRequest
from janus.identity.agent import AgentIdentity
from janus.identity.registry import AgentRegistry
from janus.itdr.signals import AnomalySignal
from janus.storage.models import ToolUsageRow


class ServiceAccountAnomalyDetector:
    """Detects anomalous tool-call behaviour for service accounts (AI agents)."""

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    async def check(
        self,
        request: ToolCallRequest,
        agent: AgentIdentity,
        usage_history: list[ToolUsageRow],
    ) -> AnomalySignal | None:
        """Run all anomaly heuristics and return a signal if any trigger."""
        anomaly_types: list[str] = []

        if self._is_unusual_hour(request.timestamp):
            anomaly_types.append("unusual_hour")

        if self._is_new_endpoint(request.tool_name, usage_history):
            anomaly_types.append("new_endpoint")

        if self._is_volume_spike(request.session_id, usage_history):
            anomaly_types.append("volume_spike")

        if not anomaly_types:
            return None

        severity = self._severity_for(len(anomaly_types))

        return AnomalySignal(
            agent_id=agent.agent_id,
            severity=severity,
            description=f"Anomalies detected: {', '.join(anomaly_types)}",
            session_id=request.session_id,
            anomaly_types=anomaly_types,
            timestamp=request.timestamp,
        )

    # ------------------------------------------------------------------
    # Heuristics
    # ------------------------------------------------------------------

    @staticmethod
    def _is_unusual_hour(timestamp: object) -> bool:
        """Hours 0-5 UTC are considered unusual for service accounts."""
        from datetime import datetime

        if not isinstance(timestamp, datetime):
            return False
        return timestamp.hour < 6

    @staticmethod
    def _is_new_endpoint(tool_name: str, usage_history: list[ToolUsageRow]) -> bool:
        """Return True if *tool_name* has never appeared in the agent's history."""
        known_tools = {row.tool_name for row in usage_history}
        return tool_name not in known_tools

    @staticmethod
    def _is_volume_spike(
        session_id: str,
        usage_history: list[ToolUsageRow],
        threshold: int = 10,
    ) -> bool:
        """Return True if the session already has more than *threshold* calls."""
        count = sum(1 for row in usage_history if row.session_id == session_id)
        return count > threshold

    @staticmethod
    def _severity_for(anomaly_count: int) -> str:
        if anomaly_count >= 3:
            return "high"
        if anomaly_count >= 2:
            return "medium"
        return "low"
