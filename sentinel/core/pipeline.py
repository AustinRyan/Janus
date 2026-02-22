from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import structlog

from sentinel.core.decision import (
    CheckResult,
    PipelineContext,
    SecurityVerdict,
    ToolCallRequest,
    Verdict,
)
from sentinel.risk.thresholds import LOCK_THRESHOLD, SANDBOX_THRESHOLD

logger = structlog.get_logger()


@runtime_checkable
class SecurityCheck(Protocol):
    """Protocol that all security check components must implement."""

    @property
    def name(self) -> str: ...

    @property
    def priority(self) -> int: ...

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> CheckResult: ...


class IdentityCheck:
    """Check that the agent is registered and not locked."""

    name: str = "identity_check"
    priority: int = 10

    def __init__(self, registry: Any) -> None:
        self._registry = registry

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> CheckResult:
        if context.agent_identity is None:
            return CheckResult(
                check_name=self.name,
                passed=False,
                risk_contribution=0.0,
                reason=f"Agent '{request.agent_id}' is not registered.",
                force_verdict=Verdict.BLOCK,
            )

        if context.agent_identity.is_locked:
            return CheckResult(
                check_name=self.name,
                passed=False,
                risk_contribution=0.0,
                reason=(
                    f"Agent '{request.agent_id}' is locked: "
                    f"{context.agent_identity.lock_reason}"
                ),
                force_verdict=Verdict.BLOCK,
            )

        return CheckResult(
            check_name=self.name,
            passed=True,
            risk_contribution=0.0,
            reason="Agent is registered and active.",
        )


class PermissionScopeCheck:
    """Check that the agent has permission to use the requested tool."""

    name: str = "permission_scope"
    priority: int = 20

    def __init__(self, registry: Any) -> None:
        self._registry = registry

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> CheckResult:
        if context.agent_identity is None:
            return CheckResult(
                check_name=self.name,
                passed=False,
                risk_contribution=0.0,
                reason="No agent identity available for permission check.",
                force_verdict=Verdict.BLOCK,
            )

        has_permission = self._registry.check_permission(
            context.agent_identity, request.tool_name
        )

        if has_permission:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason=f"Agent has permission for tool '{request.tool_name}'.",
            )

        return CheckResult(
            check_name=self.name,
            passed=False,
            risk_contribution=5.0,
            reason=(
                f"Agent '{request.agent_id}' ({context.agent_identity.role.value}) "
                f"does not have permission for tool '{request.tool_name}'."
            ),
            force_verdict=Verdict.CHALLENGE,
        )


class SecurityPipeline:
    """Chains SecurityCheck implementations in priority order."""

    def __init__(self, checks: list[SecurityCheck]) -> None:
        self._checks = sorted(checks, key=lambda c: c.priority)

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> SecurityVerdict:
        for check in self._checks:
            try:
                result = await check.evaluate(request, context)
            except Exception as e:
                logger.error("security_check_failed", check=check.name, error=str(e))
                result = CheckResult(
                    check_name=check.name,
                    passed=False,
                    risk_contribution=10.0,
                    reason=f"Check '{check.name}' failed with error: {e}",
                )

            context.check_results.append(result)
            context.accumulated_risk_delta += result.risk_contribution

            # Short-circuit on hard block or challenge
            if result.force_verdict in (Verdict.BLOCK, Verdict.CHALLENGE):
                return self._build_verdict(result.force_verdict, context, request)

        # No hard block — compute final verdict from accumulated score
        new_score = context.session_risk_score + context.accumulated_risk_delta

        if new_score >= LOCK_THRESHOLD:
            verdict = Verdict.BLOCK
        elif new_score >= SANDBOX_THRESHOLD:
            verdict = Verdict.SANDBOX
        elif any(
            r.check_name == "semantic_drift" and r.force_verdict == Verdict.PAUSE
            for r in context.check_results
        ):
            verdict = Verdict.PAUSE
        else:
            verdict = Verdict.ALLOW

        return self._build_verdict(verdict, context, request)

    def _build_verdict(
        self,
        verdict: Verdict,
        context: PipelineContext,
        request: ToolCallRequest,
    ) -> SecurityVerdict:
        reasons = [r.reason for r in context.check_results if r.reason and not r.passed]
        drift_score = 0.0
        itdr_signals: list[str] = []

        for r in context.check_results:
            if r.check_name == "semantic_drift" and "drift_score" in r.metadata:
                drift_score = r.metadata["drift_score"]
            if r.check_name == "itdr" and r.metadata.get("signals"):
                itdr_signals.extend(r.metadata["signals"])

        new_score = context.session_risk_score + context.accumulated_risk_delta
        recommended = self._recommend_action(verdict, reasons)

        return SecurityVerdict(
            verdict=verdict,
            risk_score=new_score,
            risk_delta=context.accumulated_risk_delta,
            reasons=reasons,
            drift_score=drift_score,
            itdr_signals=itdr_signals,
            recommended_action=recommended,
        )

    def _recommend_action(self, verdict: Verdict, reasons: list[str]) -> str:
        if verdict == Verdict.BLOCK:
            return "Tool call blocked. Review agent behavior and session trace for details."
        if verdict == Verdict.CHALLENGE:
            return "Agent attempted an out-of-scope tool. Identity verification required."
        if verdict == Verdict.SANDBOX:
            return "Tool call requires sandbox simulation before real execution."
        if verdict == Verdict.PAUSE:
            return "Semantic drift detected. Human review recommended before continuing."
        return "Tool call approved."
