# Sentinel V2 Expansion Design

## Overview

Expand Project Sentinel from a standalone Python library into a full demo-ready platform with:
1. **Live Demo UI** — Three-panel web interface with real-time chat + security dashboard
2. **Integration Adapters** — LangChain, CrewAI, OpenAI, and Claude MCP wrappers
3. **SIEM/Observability Exporters** — Webhook, JSON, OpenTelemetry, Prometheus

## Decisions

- **UI framework**: Next.js frontend + FastAPI backend + WebSocket
- **Worker agent**: Claude Sonnet via Anthropic API
- **Storage**: Keep SQLite/in-memory (no PostgreSQL/Redis for now)
- **Scope**: Demo-focused, not production SaaS

---

## 1. Live Demo UI

### Architecture

```
Next.js Frontend (3 panels)
        │ WebSocket + REST
        ▼
FastAPI Backend
        │
        ├── Claude Sonnet (worker agent via Anthropic API)
        ├── Guardian.intercept() (security evaluation)
        └── WebSocket broadcast (real-time events to frontend)
```

### Three-Panel Layout

| Panel | Width | Content |
|-------|-------|---------|
| **Chat** (left) | ~35% | User messages, agent responses, inline tool call badges (ALLOW/BLOCK) |
| **Security Dashboard** (center) | ~35% | Live risk gauge (0-100), verdict timeline, pattern detection alerts, agent identity card, session event log |
| **Pipeline Detail** (right) | ~30% | Raw JSON of each SecurityCheck result, pipeline context breakdown (IdentityCheck, PermissionScope, DeterministicRisk, LLM Risk, Drift, ITDR), session state, circuit breaker status |

### Backend API

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/chat` | POST | Send user message, get agent response + tool calls |
| `/api/ws/session/{id}` | WS | Real-time security event stream |
| `/api/sessions` | GET | List active sessions |
| `/api/sessions/{id}` | GET | Get session detail with risk history |
| `/api/traces/{session_id}` | GET | Get forensic traces for a session |
| `/api/agents` | GET | List registered agents |
| `/api/agents` | POST | Register a new agent |

### Data Flow (single chat message)

1. User types message in chat panel
2. Frontend POSTs to `/api/chat` with message + session_id
3. Backend sends message to Claude Sonnet (worker agent) with tool definitions
4. Claude responds — may include tool_use blocks
5. For each tool call:
   a. Guardian.intercept() evaluates the call
   b. SecurityVerdict pushed over WebSocket to frontend (dashboard updates live)
   c. If ALLOW: execute the mock tool, feed result back to Claude
   d. If BLOCK: tell Claude the tool was denied, feed denial back
6. Claude generates final text response
7. Response returned to frontend, chat panel updates

### Mock Tools for Demo

The worker agent has access to simulated tools that demonstrate Sentinel's detection:

- `read_file(path)` — returns mock file contents
- `search_web(query)` — returns mock search results
- `api_call(url, method, body)` — simulates HTTP calls
- `execute_code(code)` — simulates code execution
- `write_file(path, content)` — simulates file writes
- `database_query(query)` — simulates DB access

---

## 2. Integration Adapters

All adapters in `sentinel/integrations/`. Each wraps tool execution with `guardian.intercept()`.

### LangChain (`langchain.py`)

```python
class SentinelToolWrapper(BaseTool):
    """Wraps any LangChain tool with Guardian interception."""

def sentinel_guard(tools, guardian, agent_id, session_id):
    """Convenience: wrap a list of LangChain tools."""
```

### CrewAI (`crewai.py`)

```python
@sentinel_tool(guardian, agent_id, session_id)
def my_tool(input: str) -> str:
    """Decorator that intercepts before execution."""
```

### OpenAI (`openai.py`)

```python
class SentinelFunctionProxy:
    """Sits between OpenAI function calling and actual execution."""

    async def execute(self, function_name, arguments) -> result | denial
```

### Claude MCP (`mcp.py`)

```python
class SentinelMCPServer:
    """MCP server that wraps tool definitions with security."""

    # Tools defined here proxy to real tool servers
    # Guardian evaluates each call before forwarding
```

---

## 3. SIEM / Observability Exporters

All exporters in `sentinel/exporters/`. Each hooks into Guardian's verdict pipeline.

### Webhook (`webhook.py`)
- POSTs SecurityTrace as JSON to configurable URL
- Async, non-blocking, retry with exponential backoff
- Compatible with Slack webhooks, PagerDuty, custom endpoints

### JSON Logger (`json_logger.py`)
- Structured JSON lines to stdout or file
- Splunk/Elastic/Datadog compatible
- One line per verdict with all fields

### OpenTelemetry (`otel.py`)
- Spans for each `guardian.intercept()` call
- Attributes: verdict, risk_score, agent_id, tool_name, all check results
- Exportable to Jaeger, Zipkin, any OTLP collector

### Prometheus (`prometheus.py`)
- Gauges: `sentinel_session_risk_score`, `sentinel_circuit_breaker_state`
- Counters: `sentinel_verdicts_total{verdict}`, `sentinel_tool_calls_total`
- Histogram: `sentinel_intercept_duration_seconds`
- Exposes `/metrics` endpoint

---

## New Dependencies

```
# Backend
fastapi
uvicorn[standard]
websockets
python-multipart

# Frontend (Next.js — separate package.json)
next
react
tailwindcss
@radix-ui/react primitives
recharts (for risk gauge/charts)
lucide-react (icons)

# Integration adapters (optional)
langchain-core
crewai
openai

# Observability (optional)
opentelemetry-api
opentelemetry-sdk
prometheus-client
httpx (for webhook exporter)
```

## Out of Scope

- PostgreSQL / Redis (keep SQLite/in-memory)
- Production auth, deployment, CI/CD
- Mobile responsive design
- Grafana dashboards (custom UI replaces this)
