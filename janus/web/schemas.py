"""Pydantic schemas for the REST API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    session_id: str
    message: str


class ToolCallOut(BaseModel):
    tool_name: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    verdict: str
    risk_score: float
    risk_delta: float
    result: dict[str, Any] | None = None
    reasons: list[str] = Field(default_factory=list)


class ChatResponseOut(BaseModel):
    message: str
    tool_calls: list[ToolCallOut] = Field(default_factory=list)
    session_id: str


class SessionCreateRequest(BaseModel):
    agent_id: str = "demo-agent"
    original_goal: str = ""


class SessionOut(BaseModel):
    session_id: str
    agent_id: str
    original_goal: str
    risk_score: float


class AgentOut(BaseModel):
    agent_id: str
    name: str
    role: str
    permissions: list[str]
    is_locked: bool


class HealthOut(BaseModel):
    status: str
    total_requests: int = 0
    error_rate: float = 0.0
    circuit_breaker: str = "closed"


class MessageOut(BaseModel):
    role: str
    content: str
    tool_calls: list[ToolCallOut] = Field(default_factory=list)


class TraceOut(BaseModel):
    trace_id: str
    session_id: str
    agent_id: str
    tool_name: str
    verdict: str
    risk_score: float
    risk_delta: float
    explanation: str
    timestamp: str
    reasons: list[str] = Field(default_factory=list)


class CheckResultOut(BaseModel):
    check_name: str
    passed: bool
    risk_contribution: float = 0.0
    reason: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    force_verdict: str | None = None


class RiskEventOut(BaseModel):
    risk_delta: float
    new_score: float
    tool_name: str
    reason: str
    timestamp: str


class TaintEntryOut(BaseModel):
    label: str
    source_tool: str
    source_step: int
    patterns_matched: list[str] = Field(default_factory=list)
    timestamp: str


class HealthFullOut(BaseModel):
    status: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    error_rate: float = 0.0
    circuit_breaker: str = "closed"
    active_sessions: int = 0


class ToolEvalRequest(BaseModel):
    agent_id: str
    session_id: str
    tool_name: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    original_goal: str = ""


class ToolEvalResponse(BaseModel):
    verdict: str
    risk_score: float
    risk_delta: float
    reasons: list[str] = Field(default_factory=list)
    session_id: str
    tool_name: str
    approval_id: str | None = None


class ApprovalRequestOut(BaseModel):
    id: str
    session_id: str
    agent_id: str
    tool_name: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    original_goal: str = ""
    verdict: str
    risk_score: float = 0.0
    risk_delta: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    check_results: list[dict[str, Any]] = Field(default_factory=list)
    trace_id: str = ""
    status: str = "pending"
    decided_by: str | None = None
    decided_at: str | None = None
    decision_reason: str = ""
    tool_result: dict[str, Any] | None = None
    created_at: str = ""
    expires_at: str | None = None


class ApprovalDecisionRequest(BaseModel):
    decided_by: str = "human"
    reason: str = ""


class ApprovalDecisionOut(BaseModel):
    id: str
    status: str
    decided_by: str | None = None
    decided_at: str | None = None
    decision_reason: str = ""
    tool_result: dict[str, Any] | None = None
