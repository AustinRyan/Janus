from __future__ import annotations

from pydantic import BaseModel, Field


class GuardianModelConfig(BaseModel):
    model: str = "claude-haiku-4-5-20251001"
    max_tokens: int = 512
    temperature: float = 0.0
    timeout_seconds: float = 5.0


class WorkerModelConfig(BaseModel):
    model: str = "claude-sonnet-4-6-20250220"
    max_tokens: int = 4096


class CircuitBreakerConfig(BaseModel):
    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    success_threshold: int = 3


class RiskConfig(BaseModel):
    lock_threshold: float = 80.0
    sandbox_threshold: float = 60.0
    elevated_logging_threshold: float = 40.0
    decay_rate_per_minute: float = 2.0
    decay_idle_threshold_minutes: float = 5.0


class DriftConfig(BaseModel):
    threshold: float = 0.6
    max_risk_contribution: float = 40.0


class SentinelConfig(BaseModel):
    guardian_model: GuardianModelConfig = Field(default_factory=GuardianModelConfig)
    worker_model: WorkerModelConfig = Field(default_factory=WorkerModelConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    drift: DriftConfig = Field(default_factory=DriftConfig)
    database_path: str = "sentinel.db"
    log_level: str = "INFO"
