from __future__ import annotations

from typing import Any

import structlog

from sentinel.circuit.breaker import CircuitBreaker
from sentinel.circuit.health import HealthMonitor
from sentinel.config import SentinelConfig
from sentinel.core.decision import (
    CheckResult,
    PipelineContext,
    SecurityVerdict,
    ToolCallRequest,
    Verdict,
)
from sentinel.core.pipeline import (
    IdentityCheck,
    PermissionScopeCheck,
    SecurityCheck,
    SecurityPipeline,
)
from sentinel.drift.detector import SemanticDriftDetector
from sentinel.identity.agent import AgentIdentity
from sentinel.identity.registry import AgentRegistry
from sentinel.llm.classifier import SecurityClassifier
from sentinel.risk.engine import RiskEngine
from sentinel.storage.session_store import InMemorySessionStore, RiskEvent

logger = structlog.get_logger()


class _DeterministicRiskCheck:
    """Pipeline check that runs the rule-based risk scorer and pattern detector."""

    name: str = "deterministic_risk"
    priority: int = 25

    def __init__(self, risk_engine: RiskEngine) -> None:
        self._risk_engine = risk_engine

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> CheckResult:
        session_events = self._risk_engine.session_store.get_recent_events(
            request.session_id
        )
        # Score using deterministic rules (no LLM)
        base_risk = self._risk_engine.scorer.score(
            tool_name=request.tool_name,
            tool_input=request.tool_input,
            llm_risk=0.0,
            session_events=session_events,
            escalation_attempts=0,
        )

        # Pattern matching — use full tool call history (with inputs) for keyword matching
        session_history = self._risk_engine.session_store.get_tool_call_history(
            request.session_id
        )
        pattern_result = self._risk_engine.pattern_detector.match(
            request.tool_name, request.tool_input, session_history
        )
        pattern_risk = pattern_result.risk_contribution if pattern_result.matched else 0.0

        total = base_risk + pattern_risk
        reason = f"Base risk: {base_risk:.1f}"
        if pattern_result.matched:
            reason += (
                f" | Pattern '{pattern_result.pattern_name}' matched"
                f" ({pattern_result.matched_steps}/{pattern_result.total_steps}"
                f" steps, +{pattern_risk:.1f})"
            )

        return CheckResult(
            check_name=self.name,
            passed=True,
            risk_contribution=total,
            reason=reason,
            metadata={
                "base_risk": base_risk,
                "pattern_risk": pattern_risk,
                "pattern_name": pattern_result.pattern_name if pattern_result.matched else None,
            },
        )


class _LLMRiskCheck:
    """Pipeline check that uses Haiku for contextual risk classification."""

    name: str = "llm_risk_classifier"
    priority: int = 30

    def __init__(self, classifier: SecurityClassifier) -> None:
        self._classifier = classifier

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> CheckResult:
        agent = context.agent_identity
        agent_role = agent.role.value if agent else "unknown"
        agent_name = agent.name if agent else "unknown"

        result = await self._classifier.classify_risk(
            agent_role=agent_role,
            agent_name=agent_name,
            original_goal=request.original_goal,
            tool_name=request.tool_name,
            tool_input=request.tool_input,
            session_history=request.conversation_history,
            current_risk_score=context.session_risk_score,
        )

        return CheckResult(
            check_name=self.name,
            passed=True,
            risk_contribution=result.risk * 0.3,
            reason=result.reasoning,
            metadata={"llm_risk": result.risk},
        )


class _ITDRCheck:
    """Pipeline check that runs all ITDR detectors."""

    name: str = "itdr"
    priority: int = 60

    def __init__(
        self,
        anomaly_detector: Any | None = None,
        collusion_detector: Any | None = None,
        escalation_tracker: Any | None = None,
        registry: AgentRegistry | None = None,
    ) -> None:
        self._anomaly = anomaly_detector
        self._collusion = collusion_detector
        self._escalation = escalation_tracker
        self._registry = registry

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> CheckResult:
        signals: list[str] = []
        risk_contribution = 0.0

        # Anomaly detection
        if self._anomaly and context.agent_identity and self._registry:
            usage_history = await self._registry.get_tool_usage(request.agent_id)
            anomaly = await self._anomaly.check(
                request, context.agent_identity, usage_history
            )
            if anomaly:
                signals.append(f"anomaly: {anomaly.description}")
                risk_contribution += {"low": 5, "medium": 10, "high": 15, "critical": 25}.get(
                    anomaly.severity, 5
                )

        # Collusion detection
        if self._collusion:
            collusion = self._collusion.check(request)
            if collusion:
                signals.append(f"collusion: {collusion.description}")
                risk_contribution += 20

        # Escalation tracking
        if self._escalation:
            # Check if this tool is out of scope
            if context.agent_identity and self._registry:
                has_perm = self._registry.check_permission(
                    context.agent_identity, request.tool_name
                )
                if not has_perm:
                    self._escalation.record_attempt(request.agent_id, request.tool_name)

            escalation = self._escalation.check(request.agent_id)
            if escalation:
                signals.append(f"escalation: {escalation.description}")
                risk_contribution += {"low": 5, "medium": 10, "high": 20, "critical": 30}.get(
                    escalation.severity, 5
                )

        return CheckResult(
            check_name=self.name,
            passed=len(signals) == 0,
            risk_contribution=risk_contribution,
            reason="; ".join(signals) if signals else "No ITDR signals detected.",
            metadata={"signals": signals},
        )


class Guardian:
    """The Guardian sits between the Worker Agent and all tool execution.

    Every tool call passes through Guardian.intercept() before reaching
    the real tool.
    """

    def __init__(
        self,
        config: SentinelConfig,
        registry: AgentRegistry,
        risk_engine: RiskEngine,
        drift_detector: SemanticDriftDetector | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        classifier: SecurityClassifier | None = None,
        sandbox: Any | None = None,
        recorder: Any | None = None,
        anomaly_detector: Any | None = None,
        collusion_detector: Any | None = None,
        escalation_tracker: Any | None = None,
    ) -> None:
        self._config = config
        self._registry = registry
        self._risk_engine = risk_engine
        self._drift_detector = drift_detector
        self._circuit_breaker = circuit_breaker or CircuitBreaker(config.circuit_breaker)
        self._sandbox = sandbox
        self._recorder = recorder
        self._health = HealthMonitor()

        # Build pipeline checks
        checks: list[SecurityCheck] = [
            IdentityCheck(registry),
            PermissionScopeCheck(registry),
            _DeterministicRiskCheck(risk_engine),
        ]

        if classifier:
            checks.append(_LLMRiskCheck(classifier))

        if drift_detector:
            checks.append(drift_detector)

        checks.append(
            _ITDRCheck(
                anomaly_detector=anomaly_detector,
                collusion_detector=collusion_detector,
                escalation_tracker=escalation_tracker,
                registry=registry,
            )
        )

        self._pipeline = SecurityPipeline(checks)

    @classmethod
    async def from_config(
        cls,
        config: SentinelConfig,
        registry: AgentRegistry,
        session_store: InMemorySessionStore,
        classifier: SecurityClassifier | None = None,
        sandbox: Any | None = None,
        recorder: Any | None = None,
        anomaly_detector: Any | None = None,
        collusion_detector: Any | None = None,
        escalation_tracker: Any | None = None,
    ) -> Guardian:
        """Factory that wires all components together from config."""
        from sentinel.risk.engine import RiskEngine

        risk_engine = RiskEngine(session_store)

        drift_detector = None
        if classifier:
            drift_detector = SemanticDriftDetector(
                classifier=classifier,
                threshold=config.drift.threshold,
                max_risk_contribution=config.drift.max_risk_contribution,
            )

        return cls(
            config=config,
            registry=registry,
            risk_engine=risk_engine,
            drift_detector=drift_detector,
            classifier=classifier,
            sandbox=sandbox,
            recorder=recorder,
            anomaly_detector=anomaly_detector,
            collusion_detector=collusion_detector,
            escalation_tracker=escalation_tracker,
        )

    async def intercept(self, request: ToolCallRequest) -> SecurityVerdict:
        """Main entry point. Called for EVERY tool call the Worker Agent makes."""
        timer = self._health.start_timer()

        # 1. Circuit breaker gate
        if not self._circuit_breaker.allow_request():
            return SecurityVerdict(
                verdict=Verdict.BLOCK,
                risk_score=100.0,
                risk_delta=0.0,
                reasons=["Circuit breaker OPEN — Guardian unavailable, fail-safe engaged."],
                recommended_action=(
                    "Guardian service degraded. All tool calls blocked until recovery."
                ),
            )

        try:
            # 2. Set goal if first request in session
            if request.original_goal:
                self._risk_engine.session_store.set_goal(
                    request.session_id, request.original_goal
                )

            # 3. Build pipeline context
            context = PipelineContext(
                session_risk_score=self._risk_engine.get_score(request.session_id),
                agent_identity=await self._registry.get_agent(request.agent_id),
            )

            # 4. Run security pipeline
            verdict = await self._pipeline.evaluate(request, context)

            # 5. Record tool call for pattern matching history
            self._risk_engine.session_store.record_tool_call(
                request.session_id, request.tool_name, dict(request.tool_input)
            )

            # 6. Update session risk score
            new_score = self._risk_engine.update_score(
                request.session_id, verdict.risk_delta
            )
            verdict.risk_score = new_score

            # 6. Add risk event
            self._risk_engine.add_event(
                request.session_id,
                RiskEvent(
                    risk_delta=verdict.risk_delta,
                    new_score=new_score,
                    tool_name=request.tool_name,
                    reason=verdict.recommended_action,
                ),
            )

            # 7. Record tool usage (only if agent exists)
            if context.agent_identity is not None:
                await self._registry.record_tool_usage(
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    session_id=request.session_id,
                    risk_score=new_score,
                )

            # 8. Handle sandbox verdict
            if verdict.verdict == Verdict.SANDBOX and self._sandbox:
                sandbox_result = await self._sandbox.simulate(request)
                inspection = await self._sandbox.inspector.inspect(sandbox_result, request)
                if not inspection.safe:
                    verdict.verdict = Verdict.BLOCK
                    verdict.reasons.append(
                        f"Sandbox simulation revealed: {inspection.finding}"
                    )

            # 9. Record forensic trace
            if self._recorder:
                agent = context.agent_identity
                await self._recorder.record(
                    request,
                    verdict,
                    agent_name=agent.name if agent else "unknown",
                    agent_role=agent.role.value if agent else "unknown",
                )

            # 10. Report success to circuit breaker
            self._circuit_breaker.record_success()
            self._health.record_latency(timer.elapsed_ms, success=True)

            logger.info(
                "guardian_intercept",
                agent_id=request.agent_id,
                tool=request.tool_name,
                verdict=verdict.verdict.value,
                risk_score=verdict.risk_score,
                risk_delta=verdict.risk_delta,
            )

            return verdict

        except Exception as exc:
            self._circuit_breaker.record_failure()
            self._health.record_latency(timer.elapsed_ms, success=False)
            logger.error("guardian_error", error=str(exc), agent_id=request.agent_id)

            # Fail-safe: block on Guardian errors
            return SecurityVerdict(
                verdict=Verdict.BLOCK,
                risk_score=100.0,
                risk_delta=0.0,
                reasons=[f"Guardian internal error (fail-safe): {exc}"],
                recommended_action=(
                    "Guardian encountered an error. Blocking as precaution."
                ),
            )

    async def wrap_tool_call(
        self,
        agent_id: str,
        session_id: str,
        original_goal: str,
        tool_name: str,
        tool_input: dict[str, Any],
        conversation_history: list[dict[str, Any]] | None = None,
    ) -> SecurityVerdict:
        """High-level SDK method. Returns SecurityVerdict."""
        request = ToolCallRequest(
            agent_id=agent_id,
            session_id=session_id,
            tool_name=tool_name,
            tool_input=tool_input,
            original_goal=original_goal,
            conversation_history=conversation_history or [],
        )
        return await self.intercept(request)

    async def register_agent(self, identity: AgentIdentity) -> None:
        """Convenience method to register an agent through the Guardian."""
        await self._registry.register_agent(identity)

    @property
    def health(self) -> HealthMonitor:
        return self._health

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        return self._circuit_breaker
