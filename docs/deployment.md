# Deployment and Production Setup Guide

This guide covers self-hosting Janus for production use, including backend and frontend configuration, database setup, authentication, notifications, monitoring, and security hardening.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Backend](#running-the-backend)
- [Running the Frontend](#running-the-frontend)
- [Running the MCP Proxy](#running-the-mcp-proxy)
- [Configuration](#configuration)
- [Database](#database)
- [Authentication](#authentication)
- [Notifications](#notifications)
- [Monitoring](#monitoring)
- [License Activation (Pro)](#license-activation-pro)
- [Docker](#docker)
- [Security Hardening Checklist](#security-hardening-checklist)
- [Architecture Diagram](#architecture-diagram)

---

## Prerequisites

| Dependency | Minimum Version | Notes |
|------------|----------------|-------|
| Python     | 3.11+          | 3.13 recommended |
| Node.js    | 18+            | Required for the frontend dashboard |
| SQLite     | Any            | Bundled with Python; no separate install needed |

---

## Installation

### Backend

Install the `janus-security` package from PyPI. Several optional extras are available depending on your use case.

```bash
# Core package (rule-based pipeline, REST API, CLI):
pip install janus-security

# With framework integrations (LangChain, CrewAI, OpenAI, MCP):
pip install janus-security[integrations]

# With billing support:
pip install janus-security[billing]

# With observability exporters (Prometheus, OpenTelemetry):
pip install janus-security[exporters]

# Everything:
pip install janus-security[integrations,exporters,billing]
```

### Frontend

```bash
cd frontend
npm install
```

---

## Running the Backend

### Development

```bash
# With default config:
ANTHROPIC_API_KEY=sk-ant-... janus serve

# With custom config:
ANTHROPIC_API_KEY=sk-ant-... \
JANUS_CONFIG_PATH=/path/to/janus.toml \
janus serve --port 8000

# With API auth enabled:
JANUS_API_KEY=your-secret-key \
ANTHROPIC_API_KEY=sk-ant-... \
janus serve
```

### Production (Uvicorn)

```bash
ANTHROPIC_API_KEY=sk-ant-... \
JANUS_API_KEY=your-api-key \
JANUS_DB_PATH=/var/lib/janus/janus.db \
JANUS_CORS_ORIGINS=https://your-frontend.example.com \
uvicorn janus.web.app:create_app --factory --host 0.0.0.0 --port 8000 --workers 1
```

> **Important:** Use `--workers 1` because in-process state (risk engine, session store) is not shared between workers. For multi-worker deployments, use `PersistentSessionStore` with a shared database path so that all workers read from and write to the same SQLite file.

---

## Running the Frontend

### Development

```bash
cd frontend
NEXT_PUBLIC_API_URL=http://localhost:8000 \
NEXT_PUBLIC_JANUS_API_KEY=your-api-key \
npm run dev
```

### Production

```bash
cd frontend
NEXT_PUBLIC_API_URL=https://your-backend.example.com \
NEXT_PUBLIC_JANUS_API_KEY=your-api-key \
npm run build
npm start
```

The `NEXT_PUBLIC_` prefix is required by Next.js for client-side environment variables. These values are embedded at build time, so you must rebuild after changing them.

---

## Running the MCP Proxy

The MCP proxy intercepts tool calls between an MCP client (Claude Desktop, Cursor, etc.) and upstream MCP tool servers, running each call through the Janus Guardian pipeline.

```bash
# 1. Create a config from the example:
cp sentinel-proxy.example.toml janus-proxy.toml

# 2. Edit janus-proxy.toml with your upstream server definitions.

# 3. Run the proxy:
ANTHROPIC_API_KEY=sk-ant-... janus-proxy janus-proxy.toml
```

See [docs/mcp-proxy-guide.md](mcp-proxy-guide.md) for full proxy configuration reference.

---

## Configuration

Generate a starter configuration file:

```bash
# Interactive mode (prompts for settings):
janus init

# Accept all defaults:
janus init -y
```

This creates a `janus.toml` file in the current directory. See [docs/configuration.md](configuration.md) for the full configuration reference.

### Key Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | API key for the Anthropic LLM provider | Required for LLM-based checks |
| `JANUS_API_KEY` | Secret key to protect the Janus REST API | Unset (auth disabled) |
| `JANUS_CONFIG_PATH` | Path to `janus.toml` config file | `./janus.toml` |
| `JANUS_DB_PATH` | Path to the SQLite database file | `~/.janus/janus.db` |
| `JANUS_MOCK_TOOLS` | Set to `"true"` to use mock tool execution instead of real webhook/MCP backends. Useful for development and testing. | Unset (real execution) |
| `JANUS_DEV_MODE` | Set to `"true"` to auto-activate PRO tier without a license key. Only use in development. | Unset |
| `JANUS_CORS_ORIGINS` | Comma-separated list of allowed CORS origins. **Required for production** -- set to your actual frontend domain(s), not a wildcard. | `http://localhost:3000,http://localhost:8000` |

---

## Database

Janus uses SQLite for session storage, audit logs, and event history. No external database server is required.

**Default path:** `~/.janus/janus.db`

Override with the `JANUS_DB_PATH` environment variable or the `database_path` key in `janus.toml`.

For production, always use a persistent, backed-up path:

```bash
export JANUS_DB_PATH=/var/lib/janus/janus.db
```

Migrations run automatically on startup. No manual migration step is required.

---

## Authentication

Set `JANUS_API_KEY` to require authentication on all API endpoints:

```bash
export JANUS_API_KEY=your-secret-key
```

All API requests must then include the key in the `Authorization` header:

```
Authorization: Bearer your-secret-key
```

When `JANUS_API_KEY` is unset, authentication is disabled. This is acceptable for local development but should never be used in production.

---

## Notifications

Janus can dispatch alerts to Slack, email, or Telegram when security events exceed a severity threshold. Configure these in `janus.toml`.

### Slack

```toml
[exporters.notifications.slack]
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
channel = "#security-alerts"
min_verdict = "block"
```

### Email

```toml
[exporters.notifications.email]
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_user = "alerts@company.com"
smtp_password = "app-password"
from_addr = "alerts@company.com"
to_addrs = ["security@company.com"]
min_verdict = "block"
```

### Telegram

```toml
[exporters.notifications.telegram]
bot_token = "123456:ABC-DEF..."
chat_id = "-1001234567890"
min_verdict = "block"
```

### Webhooks (SIEM Integration)

```toml
[exporters]
webhook_url = "https://your-siem.example.com/webhook"
webhook_signing_secret = "whsec_your_secret"
```

Janus signs every webhook payload with HMAC-SHA256. Verify incoming payloads by computing the HMAC of the raw request body using your signing secret and comparing it against the `X-Janus-Signature` header.

---

## Monitoring

### Health Check Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Basic liveness check. Returns `{ "status": "ok", "circuit_breaker": "closed", ... }` |
| `GET /api/health/full` | Detailed metrics including latency, error rate, and active session count |

### Prometheus

Enable the Prometheus metrics exporter in `janus.toml`:

```toml
[exporters]
prometheus_enabled = true
```

Metrics are exposed at the `/metrics` endpoint in Prometheus exposition format.

### OpenTelemetry

Enable OpenTelemetry trace and metric export:

```toml
[exporters]
otel_enabled = true
otel_service_name = "janus"
```

Configure the OTLP endpoint using standard OpenTelemetry environment variables (e.g., `OTEL_EXPORTER_OTLP_ENDPOINT`).

---

## License Activation (Pro)

The Pro tier unlocks LLM-based classification, drift detection, taint tracking, and predictive risk analysis. Activate it by adding your license key to `janus.toml`:

```toml
license_key = "sk-janus-your-key"
```

Pro features activate automatically when a valid license key is present. No restart is required if the key is set before the server starts.

License keys use the `sk-janus-` prefix. Legacy `sk-sentinel-` prefixed keys are also accepted.

### Tier Comparison

| Feature | Free | Pro |
|---------|------|-----|
| Rule-based pipeline (injection, identity, permission, data volume, deterministic risk) | Yes | Yes |
| LLM classifier | -- | Yes |
| Drift detection | -- | Yes |
| Taint tracking | -- | Yes |
| Predictive risk analysis | -- | Yes |
| Threat intelligence | Yes | Yes |
| ITDR | Yes | Yes |

---

## Docker

A `docker-compose.yml` is provided for running the full stack (backend + frontend):

```bash
docker-compose up
```

For production Docker deployments, ensure the following:

- Mount a persistent volume for the SQLite database (`JANUS_DB_PATH`).
- Pass all required environment variables (`ANTHROPIC_API_KEY`, `JANUS_API_KEY`, etc.) via `docker-compose.override.yml` or `.env` file.
- Do not store secrets in the image or Dockerfile.

---

## Security Hardening Checklist

Follow these steps before exposing Janus to production traffic:

| # | Action | Why |
|---|--------|-----|
| 1 | Set `JANUS_API_KEY` | Never run without authentication in production. |
| 2 | Use a persistent database path | Set `JANUS_DB_PATH` to a path that is regularly backed up. |
| 3 | Enable notifications | Configure Slack or email alerts for `block` events so your team is notified immediately. |
| 4 | Set a webhook signing secret | Verify webhook payloads to prevent spoofing. |
| 5 | Use the Pro tier | LLM classification catches prompt injection and social engineering attacks that rule-based checks miss. |
| 6 | Review risk thresholds | Tune `LOCK_THRESHOLD` and other thresholds for your specific use case and risk tolerance. |
| 7 | Set `original_goal` on sessions | Enables drift detection, which alerts when an agent deviates from its intended task. |
| 8 | Set `JANUS_CORS_ORIGINS` | Set to your actual frontend domain(s). Never use a wildcard (`*`) origin in production. |
| 9 | Restrict agent permissions | Never grant `["*"]` (all tools) in production. Explicitly list allowed tools per agent. |
| 10 | Monitor the dashboard | Watch for risk trends, unusual patterns, and blocked events. |
| 11 | Export audit logs regularly | Run `janus export --format jsonl` for compliance and forensic analysis. |

---

## Architecture Diagram

```
Customer Infrastructure:

+--------------------------+     +----------------------------+
|  AI Agent                |     |  MCP Client                |
|  (LangChain, CrewAI,    |     |  (Claude Desktop,          |
|   custom Python)         |     |   Cursor, etc.)            |
+-----------+--------------+     +-----------+----------------+
            | SDK                            | MCP
            v                                v
+--------------------------------------------------------------+
|                      Janus Backend                           |
|                                                              |
|  +-----------+  +----------------+  +--------------------+   |
|  | Guardian  |  | REST API       |  | MCP Proxy          |   |
|  | Pipeline  |  | (FastAPI)      |  | (janus-proxy)      |   |
|  +-----+-----+  +----------------+  +--------------------+   |
|        |                                                      |
|  +-----v----------------------------------------------------+ |
|  |  SQLite DB  |  Session Store  |  Event Broadcaster       | |
|  +--------------------------------------------------------------+
+-----------------------------+--------------------------------+
                              | WebSocket + API
                              v
+--------------------------------------------------------------+
|                Monitor Dashboard (Next.js)                    |
|  - Real-time security events                                 |
|  - Approval queue (human-in-the-loop)                        |
|  - Risk timelines                                            |
|  - Taint flow visualization                                  |
|  - Proof chain verification                                  |
+--------------------------------------------------------------+
```

### Data Flow

1. An AI agent or MCP client issues a tool call.
2. The Janus SDK or MCP Proxy intercepts the call and sends it to the Guardian pipeline.
3. The Guardian runs checks in priority order: injection (5) > identity (10) > permission (20) > data volume (22) > deterministic risk (25) > taint > predictive (38) > LLM risk (30) > drift (40) > threat intel (55) > ITDR (60).
4. The pipeline returns a verdict: `allow`, `flag`, `block`, or `ask` (human-in-the-loop).
5. Results are persisted to SQLite, broadcast to the dashboard via WebSocket, and dispatched to configured notification channels.
6. The original tool call is forwarded, held for approval, or blocked based on the verdict.
