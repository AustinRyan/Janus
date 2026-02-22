from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.decision import ToolCallRequest
from sentinel.sandbox.policy import SandboxPolicy


@dataclass
class SimulationResult:
    """Result of a sandbox simulation run."""

    tool_name: str
    simulated_output: dict[str, Any]
    execution_time_ms: float
    errors: list[str] = field(default_factory=list)


class MockEnvironment:
    """Simulates tool execution in a sandboxed environment."""

    def __init__(self, policy: SandboxPolicy) -> None:
        self._policy = policy

    async def simulate(self, request: ToolCallRequest) -> SimulationResult:
        """Run a simulated execution of the requested tool call."""
        start = time.monotonic()

        simulated_output: dict[str, Any]
        errors: list[str] = []

        tool = request.tool_name

        if tool == "execute_code":
            simulated_output = self._simulate_execute_code(request)
        elif tool == "database_write":
            simulated_output = self._simulate_database_write(request)
        elif tool == "send_email":
            simulated_output = self._simulate_send_email(request)
        elif tool == "delete_file":
            simulated_output = self._simulate_delete_file(request)
        elif tool == "modify_permissions":
            simulated_output = self._simulate_modify_permissions(request)
        elif tool == "financial_transfer":
            simulated_output = self._simulate_financial_transfer(request)
        else:
            simulated_output = {
                "status": "simulated",
                "tool": tool,
                "message": f"Generic simulation for '{tool}'",
            }

        elapsed_ms = (time.monotonic() - start) * 1000

        return SimulationResult(
            tool_name=tool,
            simulated_output=simulated_output,
            execution_time_ms=elapsed_ms,
            errors=errors,
        )

    @staticmethod
    def _simulate_execute_code(request: ToolCallRequest) -> dict[str, Any]:
        code = request.tool_input.get("code", "")
        return {
            "stdout": f"[SIMULATED] Execution of {len(code)} chars of code completed.",
            "stderr": "",
            "exit_code": 0,
            "runtime_ms": 42.0,
        }

    @staticmethod
    def _simulate_database_write(request: ToolCallRequest) -> dict[str, Any]:
        query = request.tool_input.get("query", "")
        return {
            "affected_rows": 1,
            "query_echo": query[:100] if query else "",
            "status": "simulated_success",
        }

    @staticmethod
    def _simulate_send_email(request: ToolCallRequest) -> dict[str, Any]:
        to = request.tool_input.get("to", "unknown@example.com")
        return {
            "delivered": True,
            "recipient": to,
            "message_id": "sim-msg-001",
            "status": "simulated_delivered",
        }

    @staticmethod
    def _simulate_delete_file(request: ToolCallRequest) -> dict[str, Any]:
        path = request.tool_input.get("path", "")
        return {
            "deleted": True,
            "path": path,
            "status": "simulated_deleted",
        }

    @staticmethod
    def _simulate_modify_permissions(request: ToolCallRequest) -> dict[str, Any]:
        target = request.tool_input.get("target", "")
        permissions = request.tool_input.get("permissions", "")
        return {
            "target": target,
            "new_permissions": permissions,
            "status": "simulated_modified",
        }

    @staticmethod
    def _simulate_financial_transfer(request: ToolCallRequest) -> dict[str, Any]:
        amount = request.tool_input.get("amount", 0)
        return {
            "amount": amount,
            "transaction_id": "sim-txn-001",
            "status": "simulated_pending",
        }
