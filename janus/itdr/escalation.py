from __future__ import annotations

from datetime import UTC, datetime, timedelta

from janus.itdr.signals import EscalationAttempt, EscalationSignal


class PrivilegeEscalationTracker:
    """Tracks repeated boundary-probing attempts by agents.

    If an agent keeps trying to call tools it does not have permission for,
    this tracker accumulates those attempts and raises an EscalationSignal
    once the pattern becomes significant.
    """

    def __init__(self) -> None:
        self._boundary_attempts: dict[str, list[EscalationAttempt]] = {}

    def record_attempt(self, agent_id: str, tool_name: str) -> None:
        """Record a single privilege-boundary probe."""
        attempt = EscalationAttempt(agent_id=agent_id, tool_attempted=tool_name)
        self._boundary_attempts.setdefault(agent_id, []).append(attempt)

    def check(
        self, agent_id: str, window_minutes: float = 30.0
    ) -> EscalationSignal | None:
        """Return an EscalationSignal if the agent has recent boundary attempts.

        Only attempts within the last *window_minutes* are considered.

        * >= 3 attempts  -> severity "high"
        * >= 1 attempt   -> severity "low"
        * 0 attempts     -> None
        """
        all_attempts = self._boundary_attempts.get(agent_id, [])
        if not all_attempts:
            return None

        cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
        recent = [a for a in all_attempts if a.timestamp >= cutoff]

        if not recent:
            return None

        if len(recent) >= 3:
            severity = "high"
        else:
            severity = "low"

        return EscalationSignal(
            agent_id=agent_id,
            severity=severity,
            description=(
                f"Agent {agent_id} made {len(recent)} privilege escalation "
                f"attempt(s) in the last {window_minutes} minutes"
            ),
            attempts=recent,
        )
