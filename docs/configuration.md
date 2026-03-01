# Janus Configuration Reference

Complete reference for all configuration options in the Janus security pipeline, including the TOML config file, environment variables, CLI flags, and security pipeline tuning parameters.

---

## Table of Contents

- [Configuration File](#configuration-file)
  - [Loading Order](#loading-order)
  - [Full Example](#full-example)
  - [Section Reference](#section-reference)
- [Environment Variables](#environment-variables)
- [CLI Reference](#cli-reference)
- [Security Pipeline Tuning](#security-pipeline-tuning)
  - [Risk Thresholds](#risk-thresholds)
  - [Risk Decay](#risk-decay)
  - [Keyword Amplifiers](#keyword-amplifiers)
  - [Velocity Controls](#velocity-controls)
  - [LLM Classification (Pro)](#llm-classification-pro)
- [Tiers](#tiers)

---

## Configuration File

Janus is configured via a TOML file that maps directly to the `JanusConfig` Pydantic model. All fields have sensible defaults; a minimal config file can be empty.

### Loading Order

1. **Default location:** `janus.toml` in the current working directory.
2. **Environment override:** Set `JANUS_CONFIG_PATH` to point to an alternate file.
3. **CLI override:** Pass `--config /path/to/janus.toml` to any command that accepts it.

Generate a starter config interactively:

```bash
janus init
```

Or non-interactively with defaults:

```bash
janus init -y
```

### Full Example

```toml
# janus.toml
log_level = "INFO"
license_key = "sk-janus-..."           # Pro license key
database_path = "~/.janus/janus.db"

[guardian_model]
model = "claude-haiku-4-5-20251001"    # LLM model for security checks
max_tokens = 512
temperature = 0.0
timeout_seconds = 5.0
provider = "anthropic"                  # "anthropic" | "openai" | "ollama"
api_key = ""                            # Override ANTHROPIC_API_KEY
base_url = ""                           # Custom API endpoint (e.g. for Ollama)

[worker_model]
model = "claude-sonnet-4-6-20250220"
max_tokens = 4096

[circuit_breaker]
failure_threshold = 5                   # Failures before circuit opens
recovery_timeout_seconds = 30.0         # Time before half-open
success_threshold = 3                   # Successes needed to close

[risk]
lock_threshold = 80.0                   # Risk score that locks the session
sandbox_threshold = 60.0                # Risk score that triggers sandboxing
elevated_logging_threshold = 40.0       # Risk score that triggers verbose logging
decay_rate_per_minute = 2.0             # How fast risk decays when idle
decay_idle_threshold_minutes = 5.0      # Idle time before decay starts

[drift]
threshold = 0.6                         # Semantic similarity threshold (0-1, lower = more strict)
max_risk_contribution = 40.0            # Maximum risk points from drift

[policy]
llm_risk_weight = 0.4                   # Weight of LLM classifier risk (0-1, Pro only)
keyword_amplifier_cap = 50.0            # Max risk from keyword detection
velocity_threshold_calls = 10           # Calls per window before velocity penalty
velocity_window_seconds = 60.0          # Time window for velocity checks
velocity_penalty_per_call = 3.0         # Risk per excess call
velocity_penalty_cap = 30.0             # Max velocity penalty
escalation_penalty_per_attempt = 10.0   # Risk per permission escalation
escalation_penalty_cap = 40.0           # Max escalation penalty

[policy.keyword_amplifiers]
# Custom tool keywords -> risk score amplifiers
"rm" = 25.0
"DROP TABLE" = 40.0
"sudo" = 30.0
"curl" = 15.0

[policy.keyword_sensitive_tools]
# Override default sensitive tools list
# Default: execute_code, write_file, database_query, api_call, send_email, etc.

[exporters]
webhook_url = "https://your-siem.example.com/webhook"
webhook_signing_secret = "whsec_..."    # HMAC-SHA256 signing key
json_log_path = "/var/log/janus/events.json"  # "" = disabled, "-" = stdout
prometheus_enabled = false
otel_enabled = false
otel_service_name = "janus"

[exporters.notifications.slack]
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
channel = "#security-alerts"            # Optional channel override
min_verdict = "block"                   # Minimum verdict to notify

[exporters.notifications.email]
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_user = "alerts@yourcompany.com"
smtp_password = "app-password-here"
from_addr = "alerts@yourcompany.com"
to_addrs = ["security@yourcompany.com", "oncall@yourcompany.com"]
min_verdict = "block"

[exporters.notifications.telegram]
bot_token = "123456:ABC-DEF..."
chat_id = "-1001234567890"
min_verdict = "block"
```

### Section Reference

#### Top-Level

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `log_level` | string | `"INFO"` | Logging level. One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `license_key` | string | `""` | Pro license key. Must start with `sk-janus-` (or legacy `sk-sentinel-`). Leave empty for Free tier. |
| `database_path` | string | `"~/.janus/janus.db"` | Path to the SQLite database for sessions, traces, and agent registry. |

#### `[guardian_model]`

Configuration for the LLM used by the security classifier (Pro tier).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `model` | string | `"claude-haiku-4-5-20251001"` | Model identifier for security analysis. |
| `max_tokens` | int | `512` | Maximum tokens in the LLM response. |
| `temperature` | float | `0.0` | Sampling temperature. Use `0.0` for deterministic security decisions. |
| `timeout_seconds` | float | `5.0` | Timeout for LLM API calls. If exceeded, the LLM check is skipped and rule-based scoring applies. |
| `provider` | string | `"anthropic"` | LLM provider backend. One of `"anthropic"`, `"openai"`, `"ollama"`. |
| `api_key` | string | `""` | Provider API key. Overrides the `ANTHROPIC_API_KEY` environment variable when set. |
| `base_url` | string | `""` | Custom API endpoint. Required for Ollama (e.g. `"http://localhost:11434"`). |

#### `[worker_model]`

Configuration for the general-purpose worker model (used for non-security LLM tasks).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `model` | string | `"claude-sonnet-4-6-20250220"` | Model identifier. |
| `max_tokens` | int | `4096` | Maximum tokens in response. |

#### `[circuit_breaker]`

Controls the circuit breaker that protects against cascading LLM failures.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `failure_threshold` | int | `5` | Consecutive failures before the circuit opens. Use `record_failure()` to increment. |
| `recovery_timeout_seconds` | float | `30.0` | Seconds before the circuit transitions from open to half-open. |
| `success_threshold` | int | `3` | Consecutive successes in half-open state required to close the circuit. |

#### `[risk]`

Risk scoring thresholds and decay behavior.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `lock_threshold` | float | `80.0` | Risk score at which the session is locked. Agent cannot make further tool calls. |
| `sandbox_threshold` | float | `60.0` | Risk score at which tool calls execute in a sandboxed environment. |
| `elevated_logging_threshold` | float | `40.0` | Risk score at which verbose logging activates. |
| `decay_rate_per_minute` | float | `2.0` | Points of risk removed per minute during idle periods. |
| `decay_idle_threshold_minutes` | float | `5.0` | Minutes of inactivity before risk decay begins. |

#### `[drift]`

Semantic drift detection settings (Pro tier).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `threshold` | float | `0.6` | Semantic similarity threshold between 0 and 1. Lower values are more strict (flag smaller deviations). |
| `max_risk_contribution` | float | `40.0` | Maximum risk points that drift detection can contribute to the total score. |

#### `[policy]`

Risk scoring policy and weighting parameters.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `llm_risk_weight` | float | `0.4` | Weight of the LLM classifier's risk assessment (0 to 1). Pro tier only. |
| `keyword_amplifier_cap` | float | `50.0` | Maximum total risk contribution from keyword detection. |
| `velocity_threshold_calls` | int | `10` | Number of calls within the velocity window before penalties apply. |
| `velocity_window_seconds` | float | `60.0` | Time window (seconds) for velocity measurement. |
| `velocity_penalty_per_call` | float | `3.0` | Risk points added per call exceeding the velocity threshold. |
| `velocity_penalty_cap` | float | `30.0` | Maximum total risk from velocity penalties. |
| `escalation_penalty_per_attempt` | float | `10.0` | Risk points per permission escalation attempt. |
| `escalation_penalty_cap` | float | `40.0` | Maximum total risk from escalation penalties. |

#### `[policy.keyword_amplifiers]`

A table of keyword-to-risk-score mappings. When a keyword is found in tool input for a sensitive tool, its risk value is added to the score (up to `keyword_amplifier_cap`).

```toml
[policy.keyword_amplifiers]
"rm -rf" = 35.0
"DROP TABLE" = 40.0
"eval(" = 25.0
"sudo" = 30.0
"curl" = 15.0
```

Only applies to tools in the sensitive tools list (`execute_code`, `write_file`, `database_query`, `api_call`, `send_email`, etc.). Read-only tools (`read_file`, `search_web`, `list_files`, `send_message`) are never penalized.

#### `[policy.keyword_sensitive_tools]`

Override the default set of tools considered "sensitive" (action tools that can modify state). By default, this includes:

- `execute_code`
- `write_file`
- `database_query`
- `api_call`
- `send_email`
- And others that perform mutations

Read-only tools never accumulate risk regardless of this setting.

#### `[exporters]`

Output and integration configuration for audit events.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `webhook_url` | string | `""` | URL to POST audit events. Requests are signed with HMAC-SHA256 via the `X-Janus-Signature` header. |
| `webhook_signing_secret` | string | `""` | Shared secret for HMAC-SHA256 webhook signatures. |
| `json_log_path` | string | `""` | Path to write JSON event logs. `""` disables, `"-"` writes to stdout. |
| `prometheus_enabled` | bool | `false` | Enable Prometheus metrics endpoint. |
| `otel_enabled` | bool | `false` | Enable OpenTelemetry tracing. |
| `otel_service_name` | string | `"janus"` | Service name reported to the OpenTelemetry collector. |

#### `[exporters.notifications.slack]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `webhook_url` | string | `""` | Slack incoming webhook URL. |
| `channel` | string | `""` | Optional channel override (e.g. `"#security-alerts"`). |
| `min_verdict` | string | `"block"` | Minimum verdict severity to trigger a notification. One of: `"block"`, `"challenge"`, `"sandbox"`, `"pause"`. |

#### `[exporters.notifications.email]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `smtp_host` | string | `""` | SMTP server hostname. |
| `smtp_port` | int | `587` | SMTP server port. |
| `smtp_user` | string | `""` | SMTP authentication username. |
| `smtp_password` | string | `""` | SMTP authentication password. |
| `from_addr` | string | `""` | Sender email address. |
| `to_addrs` | list[string] | `[]` | Recipient email addresses. |
| `min_verdict` | string | `"block"` | Minimum verdict severity to trigger a notification. |

#### `[exporters.notifications.telegram]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bot_token` | string | `""` | Telegram bot API token. |
| `chat_id` | string | `""` | Telegram chat or group ID. |
| `min_verdict` | string | `"block"` | Minimum verdict severity to trigger a notification. |

---

## Environment Variables

Environment variables override config file values where applicable. Secrets should always be provided via environment variables rather than committed to config files.

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key for LLM security checks | Required for Pro features |
| `JANUS_API_KEY` | Bearer token for API authentication | Unset (no auth required) |
| `JANUS_CONFIG_PATH` | Absolute or relative path to `janus.toml` | `janus.toml` in cwd |
| `JANUS_DB_PATH` | SQLite database file path | `~/.janus/janus.db` |
| `JANUS_LICENSE_SECRET` | License verification signing key | Built-in default |
| `STRIPE_SECRET_KEY` | Stripe API key for billing integration | Optional |
| `STRIPE_PRICE_ID` | Stripe price ID for subscription billing | Optional |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook endpoint secret | Optional |
| `JANUS_BASE_URL` | Public-facing URL for redirects and callbacks | `http://localhost:3000` |
| `RESEND_API_KEY` | Resend API key for sending license emails | Optional |
| `NEXT_PUBLIC_API_URL` | Backend API URL for the frontend dashboard | `http://localhost:8000` |
| `NEXT_PUBLIC_JANUS_API_KEY` | API key used by the frontend dashboard | Optional |
| `JANUS_MOCK_TOOLS` | Set to `"true"` to use mock tool execution instead of real webhook/MCP backends. Useful for development and testing. | Unset (real execution) |
| `JANUS_DEV_MODE` | Set to `"true"` to auto-activate PRO tier without a license key. Only use in development. | Unset |
| `JANUS_CORS_ORIGINS` | Comma-separated list of allowed CORS origins. For production, set to your actual frontend domain(s). | `http://localhost:3000,http://localhost:8000` |

---

## CLI Reference

The `janus` CLI provides commands for agent management, trace inspection, data export, configuration, and server operation.

```
janus --version              Show version
janus --help                 Show help
```

### Agent Management

#### `janus register`

Register a new agent identity in the Janus registry.

```
janus register --id <ID> --name <NAME> [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--id` | TEXT | Yes | Unique agent identifier. |
| `--name` | TEXT | Yes | Human-readable agent display name. |
| `--role` | CHOICE | No | Agent role. One of: `research`, `financial`, `code`, `admin`, `data_analysis`, `communication`, `custom`. |
| `--permissions` | TEXT | No | Comma-separated permission patterns (e.g. `"read_*,search_*"`). |
| `--db` | TEXT | No | Database path. Default: `janus.db`. |

#### `janus list-agents`

List all registered agents.

```
janus list-agents [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--role` | TEXT | No | Filter agents by role. |
| `--db` | TEXT | No | Database path. |

#### `janus lock`

Lock an agent, preventing all further tool calls.

```
janus lock <AGENT_ID> --reason <REASON> [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--reason` | TEXT | Yes | Human-readable reason for the lock. |
| `--db` | TEXT | No | Database path. |

**Note:** Use `registry.lock_agent()` to lock programmatically. Do not set `.is_locked` directly on the agent object.

#### `janus unlock`

Unlock a previously locked agent.

```
janus unlock <AGENT_ID> [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--db` | TEXT | No | Database path. |

### Security Traces

#### `janus traces`

Query the security audit trace log.

```
janus traces [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--session` | TEXT | No | Filter by session ID. |
| `--verdict` | TEXT | No | Filter by verdict (e.g. `allow`, `block`, `sandbox`). |
| `--limit` | INT | No | Maximum results to return. Default: `50`. |
| `--db` | TEXT | No | Database path. |

### Export

#### `janus export`

Export traces to a file in various formats.

```
janus export [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--format` | CHOICE | No | Output format: `json`, `jsonl`, `csv`. Default: `json`. |
| `--verdict` | TEXT | No | Filter by verdict. |
| `--agent` | TEXT | No | Filter by agent ID. |
| `--session` | TEXT | No | Filter by session ID. |
| `--from` | TEXT | No | Start date in ISO 8601 format. |
| `--to` | TEXT | No | End date in ISO 8601 format. |
| `--min-risk` | FLOAT | No | Minimum risk score filter. |
| `--limit` | INT | No | Maximum number of results. |
| `-o`, `--output` | TEXT | No | Output file path. Default: stdout. |
| `--db` | TEXT | No | Database path. |

### Configuration

#### `janus init`

Generate a `janus.toml` configuration file interactively.

```
janus init [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `-y`, `--non-interactive` | FLAG | No | Skip prompts and use all defaults. |

#### `janus keygen`

Generate a license key. This is a hidden command not shown in `--help`.

```
janus keygen [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--tier` | CHOICE | No | License tier: `pro` or `free`. |
| `--customer` | TEXT | No | Customer identifier. |
| `--days` | INT | No | License validity in days. |

### Server

#### `janus serve`

Start the Janus backend API server (FastAPI/Uvicorn).

```
janus serve [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--host` | TEXT | No | Bind host. Default: `0.0.0.0`. |
| `--port` | INT | No | Bind port. Default: `8000`. |
| `--config` | TEXT | No | Path to `janus.toml`. |

Alternatively, start the server directly with Uvicorn:

```bash
ANTHROPIC_API_KEY=... uvicorn janus.web.app:create_app --factory --host 0.0.0.0 --port 8000
```

**Note:** The `--factory` flag is required because `create_app()` is an application factory.

### Demos

#### `janus demo`

Run a built-in demo scenario to see the security pipeline in action.

```
janus demo <SCENARIO> [OPTIONS]
```

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `-v`, `--verbose` | FLAG | No | Enable verbose output. |

---

## Security Pipeline Tuning

The Janus security pipeline runs checks in priority order. Each check can contribute risk points to the session's cumulative score:

| Priority | Check | Tier |
|----------|-------|------|
| 5 | Injection detection | Free |
| 10 | Identity verification | Free |
| 20 | Permission enforcement | Free |
| 22 | Data volume analysis | Free |
| 25 | Deterministic risk scoring | Free |
| -- | Taint tracking | Pro |
| 30 | LLM risk classification | Pro |
| 38 | Predictive risk analysis | Pro |
| 40 | Semantic drift detection | Pro |
| 55 | Threat intelligence | Free |
| 60 | Identity threat detection (ITDR) | Free |

### Risk Thresholds

Risk thresholds determine what action is taken as a session's cumulative risk score increases.

| Threshold | Default | Behavior |
|-----------|---------|----------|
| `elevated_logging_threshold` | `40.0` | Verbose logging activates. All tool calls are logged with full context. |
| `sandbox_threshold` | `60.0` | Tool calls are executed in a sandboxed environment with restricted permissions. |
| `lock_threshold` | `80.0` | Session is locked. The agent cannot make any further tool calls until manually unlocked. |

**Important:** Access thresholds at runtime via the module-level singleton:

```python
from janus.risk import thresholds

# Correct -- reads the live value
if score >= thresholds.LOCK_THRESHOLD:
    ...
```

Do **not** import the constant directly, as this copies the value at import time and will not reflect runtime configuration changes:

```python
# WRONG -- captures value at import time
from janus.risk.thresholds import LOCK_THRESHOLD
```

Configure thresholds programmatically:

```python
from janus.risk import thresholds

thresholds.configure(
    risk={"lock_threshold": 90.0, "sandbox_threshold": 70.0},
    policy={"llm_risk_weight": 0.5}
)

# Reset to defaults
thresholds.reset()
```

### Risk Decay

Risk scores are not permanent. They decay over time when the agent is idle, preventing stale risk from accumulating indefinitely.

- **`decay_idle_threshold_minutes`** (default: `5.0`) -- The agent must be idle for this many minutes before decay begins.
- **`decay_rate_per_minute`** (default: `2.0`) -- Once decay starts, risk decreases by this many points per minute.

Example: An agent with a risk score of 50 that has been idle for 10 minutes will have decayed by `(10 - 5) * 2.0 = 10.0` points, bringing the effective score to 40.

### Keyword Amplifiers

Keyword amplifiers add risk points when specific strings are detected in tool call inputs. They only apply to sensitive (action) tools.

```toml
[policy.keyword_amplifiers]
"rm -rf" = 35.0
"DROP TABLE" = 40.0
"eval(" = 25.0
"sudo" = 30.0
"curl" = 15.0
```

- The total keyword risk contribution is capped at `keyword_amplifier_cap` (default: `50.0`).
- **Read-only tools never trigger keyword amplifiers.** This is a core design principle: tools like `read_file`, `search_web`, `list_files`, and `send_message` build pattern state but receive zero risk.

### Velocity Controls

Velocity checks penalize agents making tool calls at an unusually high rate, which may indicate automated exploitation or runaway behavior.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `velocity_threshold_calls` | `10` | Calls allowed per window before penalties begin. |
| `velocity_window_seconds` | `60.0` | The sliding time window for counting calls. |
| `velocity_penalty_per_call` | `3.0` | Risk points added per call exceeding the threshold. |
| `velocity_penalty_cap` | `30.0` | Maximum total velocity penalty. |

Example: If an agent makes 15 calls in 60 seconds with default settings, the velocity penalty is `(15 - 10) * 3.0 = 15.0` risk points.

### Escalation Penalties

Permission escalation attempts (requesting tools outside the agent's granted permissions) are penalized:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `escalation_penalty_per_attempt` | `10.0` | Risk points per escalation attempt. |
| `escalation_penalty_cap` | `40.0` | Maximum total escalation penalty. |

### LLM Classification (Pro)

The Pro tier adds an LLM-based security classifier that analyzes tool calls for suspicious intent beyond what rule-based checks can detect.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `llm_risk_weight` | `0.4` | Weight of the LLM classifier's output in the final score (0 to 1). |
| `guardian_model.provider` | `"anthropic"` | LLM provider. Options: `"anthropic"`, `"openai"`, `"ollama"`. |
| `guardian_model.model` | `"claude-haiku-4-5-20251001"` | Model identifier for the security classifier. |
| `guardian_model.timeout_seconds` | `5.0` | Timeout for LLM API calls. On timeout, the check is skipped gracefully. |

Provider-specific configuration:

**Anthropic** (default):
```toml
[guardian_model]
provider = "anthropic"
model = "claude-haiku-4-5-20251001"
# Uses ANTHROPIC_API_KEY env var, or set api_key below
```

**OpenAI**:
```toml
[guardian_model]
provider = "openai"
model = "gpt-4o-mini"
api_key = "sk-..."
```

**Ollama** (self-hosted):
```toml
[guardian_model]
provider = "ollama"
model = "llama3"
base_url = "http://localhost:11434"
```

### Drift Detection (Pro)

Semantic drift detection flags tool calls that deviate from the agent's established behavioral pattern.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `drift.threshold` | `0.6` | Similarity threshold (0 to 1). Lower values are stricter. |
| `drift.max_risk_contribution` | `40.0` | Maximum risk points drift can add. |

A threshold of `0.6` means a tool call must be at least 60% similar to the agent's recent behavior to avoid a drift penalty. Reduce this value for stricter monitoring of agents that should follow narrow, predictable patterns.

---

## Tiers

### Free (Open Source)

The Free tier provides the full rule-based security pipeline:

- Permission enforcement
- Deterministic risk scoring
- Keyword pattern matching
- Injection detection
- Data volume analysis
- Threat intelligence checks
- Identity threat detection and response (ITDR)
- Proof chain / audit trail
- Trace export (CSV, JSON, JSONL)
- Circuit breaker

### Pro

The Pro tier includes everything in Free, plus:

- LLM-based security classifier
- Semantic drift detection
- Taint tracking
- Predictive risk analysis
- Multi-model support (Anthropic, OpenAI, Ollama)
- Real-time notifications (Slack, Email, Telegram)

Activate Pro by adding a license key to your config:

```toml
license_key = "sk-janus-your-key-here"
```

License keys use the `sk-janus-` prefix. The legacy `sk-sentinel-` prefix is also accepted for backward compatibility.

---

## Quick Start Examples

### Minimal Free Tier Config

```toml
# janus.toml -- Free tier, defaults only
log_level = "INFO"
```

### Pro Tier with Slack Notifications

```toml
# janus.toml
license_key = "sk-janus-your-key-here"

[guardian_model]
provider = "anthropic"

[risk]
lock_threshold = 80.0
sandbox_threshold = 60.0

[exporters.notifications.slack]
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
channel = "#security-alerts"
min_verdict = "block"
```

### Self-Hosted with Ollama

```toml
# janus.toml
license_key = "sk-janus-your-key-here"

[guardian_model]
provider = "ollama"
model = "llama3"
base_url = "http://localhost:11434"
timeout_seconds = 10.0

[risk]
lock_threshold = 85.0
```

### High-Security Configuration

```toml
# janus.toml -- Strict settings for sensitive environments
license_key = "sk-janus-your-key-here"
log_level = "DEBUG"

[guardian_model]
provider = "anthropic"
model = "claude-haiku-4-5-20251001"
temperature = 0.0

[risk]
lock_threshold = 60.0
sandbox_threshold = 40.0
elevated_logging_threshold = 20.0

[drift]
threshold = 0.4
max_risk_contribution = 50.0

[policy]
llm_risk_weight = 0.6
velocity_threshold_calls = 5
velocity_window_seconds = 30.0
velocity_penalty_per_call = 5.0
velocity_penalty_cap = 40.0
keyword_amplifier_cap = 60.0

[policy.keyword_amplifiers]
"rm" = 30.0
"DROP" = 40.0
"sudo" = 35.0
"eval" = 30.0
"exec" = 30.0
"curl" = 20.0

[exporters]
webhook_url = "https://siem.internal/janus"
webhook_signing_secret = "whsec_your_secret"
json_log_path = "/var/log/janus/events.json"

[exporters.notifications.slack]
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
min_verdict = "sandbox"

[exporters.notifications.email]
smtp_host = "smtp.internal"
smtp_port = 587
smtp_user = "janus@internal"
smtp_password = "..."
from_addr = "janus@internal"
to_addrs = ["security-team@internal"]
min_verdict = "block"
```
