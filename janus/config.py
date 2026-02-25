from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


def _default_db_path() -> str:
    return str(Path.home() / ".janus" / "janus.db")


class GuardianModelConfig(BaseModel):
    model: str = "claude-haiku-4-5-20251001"
    max_tokens: int = 512
    temperature: float = 0.0
    timeout_seconds: float = 5.0
    provider: str = "anthropic"  # "anthropic" | "openai" | "ollama"
    api_key: str = ""
    base_url: str = ""


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


class SlackNotificationConfig(BaseModel):
    webhook_url: str
    channel: str = ""
    min_verdict: str = "block"


class EmailNotificationConfig(BaseModel):
    smtp_host: str
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_addr: str
    to_addrs: list[str]
    min_verdict: str = "block"


class TelegramNotificationConfig(BaseModel):
    bot_token: str
    chat_id: str
    min_verdict: str = "block"


class NotificationConfig(BaseModel):
    slack: SlackNotificationConfig | None = None
    email: EmailNotificationConfig | None = None
    telegram: TelegramNotificationConfig | None = None


class ExporterConfig(BaseModel):
    webhook_url: str = ""
    webhook_signing_secret: str = ""
    json_log_path: str = ""  # empty = disabled; "-" = stdout
    prometheus_enabled: bool = False
    otel_enabled: bool = False
    otel_service_name: str = "janus"
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)


class PolicyConfig(BaseModel):
    keyword_amplifiers: dict[str, float] = Field(default_factory=dict)
    keyword_sensitive_tools: list[str] = Field(default_factory=list)
    velocity_threshold_calls: int | None = None
    velocity_window_seconds: float | None = None
    velocity_penalty_per_call: float | None = None
    velocity_penalty_cap: float | None = None
    escalation_penalty_per_attempt: float | None = None
    escalation_penalty_cap: float | None = None
    keyword_amplifier_cap: float | None = None
    llm_risk_weight: float | None = None


class JanusConfig(BaseModel):
    guardian_model: GuardianModelConfig = Field(default_factory=GuardianModelConfig)
    worker_model: WorkerModelConfig = Field(default_factory=WorkerModelConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    drift: DriftConfig = Field(default_factory=DriftConfig)
    exporters: ExporterConfig = Field(default_factory=ExporterConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    database_path: str = Field(default_factory=_default_db_path)
    log_level: str = "INFO"
    license_key: str = ""

    @classmethod
    def from_toml(cls, path: str | Path) -> JanusConfig:
        """Load configuration from a TOML file."""
        import tomllib

        with open(path, "rb") as f:
            data = tomllib.load(f)
        janus_data = data.get("janus", data.get("sentinel", {}))
        for section in (
            "risk", "circuit_breaker", "drift", "guardian_model", "exporters", "policy",
        ):
            if section in data:
                janus_data[section] = data[section]
        return cls(**janus_data)
