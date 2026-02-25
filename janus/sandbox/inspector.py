from __future__ import annotations

import json
import re
from dataclasses import dataclass

from janus.core.decision import ToolCallRequest
from janus.sandbox.mock_env import SimulationResult


@dataclass
class InspectionVerdict:
    """Result of inspecting a simulation for red flags."""

    safe: bool
    finding: str
    confidence: float


# Patterns that indicate sensitive data leakage
_EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_API_KEY_PATTERN = re.compile(
    r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|bearer)\s*[:=]\s*\S+"
)
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Maximum allowed output size in characters
_MAX_OUTPUT_SIZE = 50_000


class ResultInspector:
    """Inspects sandbox simulation results for red flags."""

    async def inspect(
        self,
        simulation: SimulationResult,
        request: ToolCallRequest,
    ) -> InspectionVerdict:
        """Check simulated output for sensitive data, errors, and unexpected volume."""
        output_str = json.dumps(simulation.simulated_output, default=str)

        # 1. Check for sensitive data patterns
        sensitive_finding = self._check_sensitive_data(output_str)
        if sensitive_finding:
            return InspectionVerdict(
                safe=False,
                finding=sensitive_finding,
                confidence=0.85,
            )

        # 2. Check for error indicators suggesting exploitation
        error_finding = self._check_error_indicators(simulation)
        if error_finding:
            return InspectionVerdict(
                safe=False,
                finding=error_finding,
                confidence=0.7,
            )

        # 3. Check for unexpected data volume
        volume_finding = self._check_data_volume(output_str)
        if volume_finding:
            return InspectionVerdict(
                safe=False,
                finding=volume_finding,
                confidence=0.6,
            )

        return InspectionVerdict(
            safe=True,
            finding="No red flags detected in simulation output.",
            confidence=0.9,
        )

    @staticmethod
    def _check_sensitive_data(output: str) -> str | None:
        """Scan output for patterns that look like sensitive data."""
        if _API_KEY_PATTERN.search(output):
            return "Sensitive data detected: possible API key or secret in output."
        if _SSN_PATTERN.search(output):
            return "Sensitive data detected: possible SSN pattern in output."
        if _EMAIL_PATTERN.search(output):
            return "Sensitive data detected: email address found in output."
        return None

    @staticmethod
    def _check_error_indicators(simulation: SimulationResult) -> str | None:
        """Check for errors that could indicate exploitation attempts."""
        if simulation.errors:
            return f"Simulation produced errors: {'; '.join(simulation.errors)}"

        output = simulation.simulated_output
        stderr = output.get("stderr", "")
        if stderr and isinstance(stderr, str) and len(stderr) > 0:
            # Non-empty stderr could indicate issues
            exit_code = output.get("exit_code")
            if exit_code is not None and exit_code != 0:
                return (
                    f"Simulation exited with non-zero code ({exit_code}) "
                    f"and stderr output."
                )
        return None

    @staticmethod
    def _check_data_volume(output: str) -> str | None:
        """Flag unexpectedly large output."""
        if len(output) > _MAX_OUTPUT_SIZE:
            return (
                f"Unexpected data volume: output is {len(output)} characters "
                f"(limit: {_MAX_OUTPUT_SIZE})."
            )
        return None
