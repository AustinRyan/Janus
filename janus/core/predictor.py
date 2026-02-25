"""Predictive risk with lookahead.

Analyzes session trajectory to predict dangerous next actions
and pre-emptively elevate risk scores.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from janus.core.decision import (
    CheckResult,
    PipelineContext,
    ToolCallRequest,
)
from janus.risk import thresholds


@dataclass
class ThreatTrajectory:
    name: str
    tool_sequence: list[str]  # pipe-separated glob patterns
    risk_at_completion: float
    description: str


@dataclass
class Prediction:
    trajectory_name: str
    confidence: float
    current_step: int
    total_steps: int
    predicted_next: list[str]
    advisory: str


KNOWN_TRAJECTORIES: list[ThreatTrajectory] = [
    ThreatTrajectory(
        "data_exfiltration",
        ["read_*|search_*", "database_*|read_*", "send_*|api_call"],
        35.0,
        "Agent gathering data then attempting to export it",
    ),
    ThreatTrajectory(
        "financial_fraud",
        ["database_*|read_*", "database_*|read_*", "financial_*"],
        40.0,
        "Agent querying financial data then attempting transfer",
    ),
    ThreatTrajectory(
        "code_injection",
        ["read_*", "execute_code", "write_*|api_call"],
        30.0,
        "Agent reading code, executing, then writing/sending results",
    ),
    ThreatTrajectory(
        "credential_theft",
        ["read_*|search_*", "read_*|database_*", "api_call|send_*"],
        35.0,
        "Agent searching for credentials then sending externally",
    ),
    ThreatTrajectory(
        "recon_and_exploit",
        [
            "search_*",
            "read_*|database_*",
            "execute_code",
            "api_call|send_*",
        ],
        35.0,
        "Full attack chain: recon, read, exploit, exfil",
    ),
]


def _tool_matches_pattern(tool_name: str, pattern: str) -> bool:
    """Check if tool matches a pipe-separated glob pattern."""
    return any(
        fnmatch.fnmatch(tool_name, p.strip())
        for p in pattern.split("|")
    )


class PredictiveRiskCheck:
    """Predicts dangerous trajectories based on session history.

    Priority 38: runs after taint analysis, before drift detection.
    Advisory only -- never force-blocks.
    """

    name: str = "predictive_risk"
    priority: int = 38

    def __init__(self) -> None:
        self._session_tools: dict[str, list[str]] = {}

    def record_tool(self, session_id: str, tool_name: str) -> None:
        """Record a tool call in session history for prediction."""
        if session_id not in self._session_tools:
            self._session_tools[session_id] = []
        self._session_tools[session_id].append(tool_name)

    def get_session_tools(self, session_id: str) -> list[str]:
        return list(self._session_tools.get(session_id, []))

    async def evaluate(
        self,
        request: ToolCallRequest,
        context: PipelineContext,
    ) -> CheckResult:
        history = self.get_session_tools(request.session_id)
        current_sequence = [*history, request.tool_name]

        best_match: Prediction | None = None
        best_confidence = 0.0

        for trajectory in KNOWN_TRAJECTORIES:
            prediction = self._match_trajectory(
                current_sequence, trajectory
            )
            if prediction and prediction.confidence > best_confidence:
                best_match = prediction
                best_confidence = prediction.confidence

        if best_match is None or best_confidence < 0.3:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason="No threatening trajectory detected.",
            )

        trajectory = next(
            t
            for t in KNOWN_TRAJECTORIES
            if t.name == best_match.trajectory_name
        )

        # Only materialise predictive risk when:
        # 1. The current tool is an action tool (not read-only), AND
        # 2. The trajectory is fully completed (all steps matched).
        #
        # Incomplete trajectories are advisory warnings — a search→read
        # →execute sequence is normal work.  Risk only kicks in when
        # the full attack chain completes (e.g. recon→read→exploit→exfil).
        trajectory_complete = best_match.current_step >= best_match.total_steps
        if request.tool_name not in thresholds.KEYWORD_SENSITIVE_TOOLS or not trajectory_complete:
            risk = 0.0
        else:
            risk = (
                best_match.confidence
                * trajectory.risk_at_completion
                * 0.4
            )

        return CheckResult(
            check_name=self.name,
            passed=True,  # Advisory only
            risk_contribution=risk,
            reason=(
                f"Threat trajectory"
                f" '{best_match.trajectory_name}'"
                f" detected"
                f" ({best_match.confidence:.0%} confidence)."
                f" {best_match.advisory}"
            ),
            force_verdict=None,
            metadata={
                "prediction": {
                    "trajectory_name": (
                        best_match.trajectory_name
                    ),
                    "confidence": best_match.confidence,
                    "current_step": best_match.current_step,
                    "total_steps": best_match.total_steps,
                    "predicted_next": (
                        best_match.predicted_next
                    ),
                    "advisory": best_match.advisory,
                },
            },
        )

    def _match_trajectory(
        self,
        tool_sequence: list[str],
        trajectory: ThreatTrajectory,
    ) -> Prediction | None:
        """Match tool sequence against a trajectory pattern."""
        pattern = trajectory.tool_sequence
        seq_len = len(tool_sequence)
        pat_len = len(pattern)

        if seq_len == 0:
            return None

        # Find how many consecutive pattern steps match
        # from the end of the sequence
        matched = 0
        for pi in range(min(seq_len, pat_len)):
            si = seq_len - 1 - pi
            pat_step = pattern[
                min(seq_len, pat_len) - 1 - pi
            ]
            if _tool_matches_pattern(
                tool_sequence[si], pat_step
            ):
                matched += 1
            else:
                break

        if matched < 2:
            return None

        confidence = matched / pat_len
        current_step = matched
        predicted_next: list[str] = []

        if matched < pat_len:
            next_pattern = pattern[matched]
            predicted_next = [
                p.strip() for p in next_pattern.split("|")
            ]

        return Prediction(
            trajectory_name=trajectory.name,
            confidence=confidence,
            current_step=current_step,
            total_steps=pat_len,
            predicted_next=predicted_next,
            advisory=(
                f"Agent may attempt "
                f"{', '.join(predicted_next) if predicted_next else 'completion'}"
                f" next. {trajectory.description}."
            ),
        )
