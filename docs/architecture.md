# Janus Architecture Overview

Janus is an autonomous security layer for AI agents. It intercepts every tool call
an agent makes, evaluates it through a multi-stage security pipeline, and returns a
verdict -- ALLOW, BLOCK, CHALLENGE, SANDBOX, or PAUSE -- before the tool ever executes.

The project ships as the `janus-security` Python package.

---

## Table of Contents

- [Deployment Models](#deployment-models)
- [System Architecture](#system-architecture)
- [Security Pipeline](#security-pipeline)
- [Verdict Types](#verdict-types)
- [Core Components](#core-components)
- [Risk Engine](#risk-engine)
- [Agent Identity](#agent-identity)
- [Taint Tracking (Pro)](#taint-tracking-pro)
- [Proof Chain](#proof-chain)
- [Approval Manager (HITL)](#approval-manager-hitl)
- [Circuit Breaker](#circuit-breaker)
- [Event Broadcasting](#event-broadcasting)
- [Exporters and Notifications](#exporters-and-notifications)
- [Tier System](#tier-system)
- [Database Schema](#database-schema)
- [Tool Registration & Execution](#tool-registration--execution)
- [Module Map](#module-map)
- [Configuration](#configuration)

---

## Deployment Models

Janus supports three entry points. All three share the same Guardian pipeline under
the hood.

### 1. Python SDK

Install with `pip install janus-security` and wrap tool calls directly in agent code:

```python
from janus import create_janus

janus = await create_janus(agent_id="my-agent", agent_role="code")

result = await janus.guard("execute_code", {"code": "print('hello')"})
if result.allowed:
    execute_tool(...)
else:
    print(f"Blocked: {result.reason}")
    if result.approval_id:
        print(f"Pending human review: {result.approval_id}")
```

The `Janus` SDK client wraps `Guardian`, handles agent registration, session
management, and (optionally) human-in-the-loop approval workflows.

### 2. MCP Proxy

Run `janus-proxy` as a middleware MCP server between any MCP client (Claude Desktop,
Cursor, etc.) and upstream MCP servers:

```
MCP Client  -->  janus-proxy  -->  Upstream MCP Servers
```

The proxy intercepts every `call_tool` request, runs it through Guardian, and only
forwards ALLOW verdicts to the real upstream server. BLOCK and CHALLENGE verdicts
return structured error content to the MCP client.

### 3. Monitor Dashboard + REST API

Both deployment paths can optionally run the monitoring backend:

```
janus serve
```

This starts:
- **FastAPI backend** at `http://localhost:8000` -- REST API + WebSocket events
- **Next.js frontend** at `http://localhost:3000` -- real-time monitoring dashboard

Key API endpoints:
- `POST /api/evaluate` -- evaluate a tool call through the Guardian pipeline
- `POST /api/chat` -- conversational agent that demonstrates Guardian in action
- `GET  /api/sessions` -- list active sessions with risk scores
- `GET  /api/traces` -- query the forensic audit trail
- `WS   /api/ws/{session_id}` -- real-time security events via WebSocket

---

## System Architecture

```
                          +-----------------------------------+
                          |          Entry Points             |
                          |                                   |
                          |  SDK (create_janus / Guardian)    |
                          |  MCP Proxy (janus-proxy)          |
                          |  REST API (POST /api/evaluate)    |
                          |  Chat Agent (POST /api/chat)      |
                          +----------------+------------------+
                                           |
                                           v
                          +-----------------------------------+
                          |           Guardian                |
                          |      (Security Pipeline)          |
                          +----------------+------------------+
                                           |
         +---------------------------------+---------------------------------+
         |                                 |                                 |
         v                                 v                                 v
   +------------+               +-----------------+               +----------------+
   | Free Tier  |               |    Pro Tier     |               |   Always-On    |
   | Checks     |               |    Checks       |               |   Systems      |
   +------------+               +-----------------+               +----------------+
   | Injection  |               | LLM Classifier  |               | Circuit Breaker|
   | Identity   |               | Drift Detection |               | Risk Engine    |
   | Permission |               | Taint Tracking  |               | Proof Chain    |
   | Data Volume|               | Predictive Risk |               | Threat Intel   |
   | Determ.Risk|               |                 |               | ITDR           |
   +------------+               +-----------------+               +----------------+
         |                                 |                                 |
         +---------------------------------+---------------------------------+
                                           |
                                           v
                          +-----------------------------------+
                          |        SecurityVerdict            |
                          |  ALLOW | BLOCK | CHALLENGE |      |
                          |  SANDBOX | PAUSE                  |
                          +----------------+------------------+
                                           |
                    +----------------------+----------------------+
                    |                      |                      |
                    v                      v                      v
            +--------------+      +----------------+      +----------------+
            |  Exporters   |      |   Approvals    |      |    Storage     |
            |  (Webhook,   |      |   (HITL)       |      |   (SQLite,     |
            |   Slack,     |      |                |      |    Traces,     |
            |   Email,     |      |                |      |    Sessions)   |
            |   Telegram,  |      |                |      |                |
            |   Prometheus,|      |                |      |                |
            |   OTel)      |      |                |      |                |
            +--------------+      +----------------+      +----------------+
```

---

## Security Pipeline

The Guardian runs security checks in strict priority order. Lower priority number
means the check runs first. If any check sets a `force_verdict` of BLOCK or
CHALLENGE, the pipeline short-circuits immediately -- remaining checks do not run.

| Priority | Check              | Tier | Description                                                      |
|----------|--------------------|------|------------------------------------------------------------------|
| 5        | Prompt Injection   | Free | Regex patterns + optional LLM detection of injection attempts    |
| 10       | Identity           | Free | Verifies agent is registered and not locked                      |
| 20       | Permission Scope   | Free | Glob-based tool permission enforcement                           |
| 22       | Data Volume        | Free | Tracks bulk data access patterns, detects exfiltration           |
| 25       | Deterministic Risk | Free | Rule-based risk scoring: keyword amplifiers, velocity, patterns  |
| 27       | Taint Analysis     | Pro  | Tracks sensitive data flow between tools, blocks exfiltration    |
| 30       | LLM Classifier     | Pro  | Claude Haiku contextual risk assessment with session history     |
| 38       | Predictive Risk    | Pro  | Matches tool sequences against known attack trajectories         |
| 40       | Drift Detection    | Pro  | Detects semantic drift from agent's stated goal                  |
| 55       | Threat Intel       | Free | Matches against built-in attack pattern database                 |
| 60       | ITDR               | Free | Anomaly detection, cross-agent collusion, privilege escalation   |

### Verdict Computation

After all checks run (or the pipeline short-circuits), the final verdict is computed:

1. If any check set `force_verdict = BLOCK` --> **BLOCK**
2. If any check set `force_verdict = CHALLENGE` --> **CHALLENGE**
3. If accumulated risk would push the session score to >= 80.0 (lock threshold) --> **BLOCK**
4. If accumulated risk would push the session score to >= 60.0 (sandbox threshold) --> **SANDBOX**
5. If the drift detector flagged a PAUSE --> **PAUSE**
6. Otherwise --> **ALLOW**

### Core Design Principle: Read-Only Tools Never Accumulate Risk

This is a foundational invariant across every subsystem:

- **Read-only tools** (`read_file`, `search_web`, `list_files`, `send_message`) build
  pattern state and session history but contribute **zero risk** to the session score.
- **Action tools** (`execute_code`, `write_file`, `database_query`, `api_call`,
  `send_email`, `delete_file`, `database_write`, `financial_transfer`,
  `modify_permissions`) are the only tools that accumulate risk.
- This applies to deterministic risk scoring, LLM classification, drift detection,
  taint analysis, and predictive risk matching.

The rationale: an agent reading files and searching the web is normal exploratory
work. Risk should only materialize when the agent attempts to **act** on what it
learned. Multi-step threats are still caught because pattern state builds up during
reads, then triggers when the action tool arrives.

---

## Verdict Types

| Verdict     | Meaning                | What Happens                                                      |
|-------------|------------------------|-------------------------------------------------------------------|
| `ALLOW`     | Safe to execute        | Tool call proceeds normally                                       |
| `BLOCK`     | Denied                 | Tool call is rejected; reasons returned to the caller             |
| `CHALLENGE` | Identity verification  | Agent must pass identity verification before retrying             |
| `SANDBOX`   | Isolate execution      | Tool executes in a sandboxed environment; results inspected       |
| `PAUSE`     | Human review required  | Approval request created; execution waits for human decision      |

Verdicts are represented by the `Verdict` enum in `janus/core/decision.py` and
returned inside a `SecurityVerdict` dataclass that includes the risk score, risk
delta, check results, trace ID, drift score, ITDR signals, and a recommended action
string.

---

## Core Components

### Guardian (`janus/core/guardian.py`)

The central orchestrator. Every tool call -- whether from the SDK, MCP proxy, or
REST API -- flows through `Guardian.intercept()`.

**Key methods:**
- `from_config()` -- async factory that wires all subsystems from a `JanusConfig`
- `intercept(request)` -- main entry point; runs the full security pipeline
- `wrap_tool_call(...)` -- high-level SDK convenience method
- `register_agent(identity)` -- registers an agent through the Guardian

**Execution flow of `intercept()`:**

```
1. Circuit breaker gate (BLOCK if circuit is OPEN)
2. Set session goal if this is the first request
3. Build PipelineContext (current risk score, agent identity)
4. Run SecurityPipeline (all checks in priority order)
5. Record tool call in session history
6. Update session risk score (current + risk_delta)
7. Record RiskEvent in session store
8. Record tool usage in agent registry
9. Execute sandbox simulation (if verdict is SANDBOX)
10. Record forensic trace (if recorder is configured)
11. Append to proof chain
12. Report success/failure to circuit breaker
13. Return SecurityVerdict
```

On any internal error, Guardian returns a BLOCK verdict as a fail-safe and reports
a failure to the circuit breaker.

### SecurityPipeline (`janus/core/pipeline.py`)

Chains `SecurityCheck` implementations in priority order. Each check receives a
`ToolCallRequest` and a mutable `PipelineContext`, and returns a `CheckResult`.

The `SecurityCheck` protocol requires three members:
- `name: str` -- human-readable identifier
- `priority: int` -- execution order (lower runs first)
- `evaluate(request, context) -> CheckResult` -- the check logic

---

## Risk Engine

**Module:** `janus/risk/engine.py`

The `RiskEngine` manages per-session risk scores. It combines three scoring
mechanisms:

### Risk Scoring (`janus/risk/scoring.py`)

The `RiskScorer` computes a deterministic base risk from:
- **Tool base risk** -- configurable per-tool static risk values
- **Keyword amplifiers** -- dangerous patterns in tool input (e.g. `rm -rf` = +30,
  `eval(` = +25, `/etc/shadow` = +35), capped at 60.0 by default
- **Velocity penalty** -- when call rate exceeds 12 calls per 60 seconds, each
  additional call adds +2.0, capped at 15.0
- **Escalation penalty** -- repeated out-of-scope tool attempts add +7.0 each,
  capped at 20.0

### Pattern Detection (`janus/risk/patterns.py`)

The `PatternDetector` tracks multi-step attack sequences. When a tool call matches
a step in a known attack pattern, the match state advances. When all steps are
completed, the full pattern risk contribution is applied.

Read-only tools advance pattern state but contribute zero risk. The risk only
materializes when an action tool completes the pattern.

### Risk Decay

Risk scores decay over idle time:
- After 5 minutes of inactivity, the score decays at 2.0 points per minute
- Minimum score is 0.0

### Thresholds (`janus/risk/thresholds.py`)

All risk thresholds are managed by a configurable singleton:

| Threshold                 | Default | Effect                                   |
|---------------------------|---------|------------------------------------------|
| `LOCK_THRESHOLD`          | 80.0    | Session is locked; all calls BLOCKED     |
| `SANDBOX_THRESHOLD`       | 60.0    | Tool calls routed to sandbox             |
| `ELEVATED_LOGGING_THRESHOLD` | 40.0 | Enhanced logging activated               |
| `MAX_RISK_SCORE`          | 100.0   | Score ceiling                            |
| `MIN_RISK_SCORE`          | 0.0     | Score floor                              |

Configure at startup via:
```python
from janus.risk import thresholds
thresholds.configure(risk=risk_config, policy=policy_config)
```

**Important:** Always access thresholds via module attribute
(`thresholds.LOCK_THRESHOLD`), never via `from janus.risk.thresholds import
LOCK_THRESHOLD` -- the latter copies the value at import time and will not reflect
runtime configuration changes.

---

## Agent Identity

**Modules:** `janus/identity/agent.py`, `janus/identity/registry.py`

### AgentIdentity

Each agent has a full identity record:
- `agent_id` -- unique identifier
- `name` -- human-readable display name
- `role` -- one of: `research`, `financial`, `code`, `admin`, `data_analysis`,
  `communication`, `custom`
- `permissions` -- list of `ToolPermission` entries with glob patterns
- `credential_hash` -- SHA-256 hash for identity verification
- `is_locked` / `lock_reason` -- lockout state

### ToolPermission

Permissions use glob patterns for flexible tool access control:
```python
ToolPermission(tool_pattern="read_*", allowed=True)          # Allow all read tools
ToolPermission(tool_pattern="execute_code", allowed=True,
               requires_sandbox=True)                         # Allow but sandbox
ToolPermission(tool_pattern="*", allowed=True)                # Wildcard (admin)
```

### AgentRegistry

SQLite-backed registry that handles:
- Agent registration and lookup
- Lock/unlock operations (use `registry.lock_agent()`, not direct field mutation)
- Glob-based permission checking
- Tool usage history tracking

---

## Taint Tracking (Pro)

**Module:** `janus/core/taint.py`

The `TaintTracker` implements causal data-flow analysis to prevent sensitive data
exfiltration.

### How It Works

1. **Source scanning** -- when a tool produces output, the taint tracker scans it for
   sensitive patterns using compiled regex matchers
2. **Label assignment** -- matched data gets one or more taint labels:
   - `pii` -- SSNs, email addresses, phone numbers
   - `credentials` -- API keys, passwords, tokens
   - `financial` -- credit card numbers, bank accounts
   - `internal` -- internal URLs, IP addresses
   - `source_code` -- code patterns
3. **Propagation** -- taint labels propagate through the session as data flows
   between tools
4. **Sink detection** -- when a tainted session attempts to use a sink tool
   (`send_email`, `api_call`, `write_file`), the check flags potential exfiltration

---

## Proof Chain

**Module:** `janus/core/proof.py`

Every security verdict is recorded as a `ProofNode` in a cryptographic audit chain.

Each node contains:
- The tool call details (tool name, input, verdict, risk score)
- A SHA-256 `content_hash` of the verdict data
- A `parent_hash` linking to the previous node
- A `node_id` derived from the content hash, parent hash, step number, and timestamp

This forms a Merkle-style chain where tampering with any historical node invalidates
all subsequent hashes. The chain is exportable and independently verifiable.

---

## Approval Manager (HITL)

**Module:** `janus/core/approval.py`

The `ApprovalManager` implements human-in-the-loop review for judgment-call verdicts.

### Routing Logic

Not all blocks warrant human review:

- **Hard blocks** (permission denied, identity failure, injection detected) are
  auto-rejected -- these are clear policy violations
- **Judgment calls** (high accumulated risk, LLM classifier flags, drift detection,
  threat intel matches) create approval requests for human review
- **CHALLENGE and PAUSE** verdicts without a hard-policy cause also go to human review

Hard-block check names: `permission_scope`, `identity_check`, `prompt_injection`.

### Workflow

1. Guardian returns a non-ALLOW verdict
2. SDK/proxy checks `needs_human_review(verdict, check_results)`
3. If true, an `ApprovalRequest` is created and persisted to SQLite
4. A `SecurityEvent` is broadcast to WebSocket subscribers
5. Human reviews in the Monitor dashboard or via the REST API
6. On approval, the original tool call executes and the result is returned
7. On rejection, the block stands

---

## Circuit Breaker

**Module:** `janus/circuit/breaker.py`

Implements a standard circuit breaker pattern to handle Guardian service degradation.

### State Machine

```
CLOSED --[5 failures]--> OPEN --[30s timeout]--> HALF_OPEN
                           ^                         |
                           |                         |
                      [any failure]           [3 successes]
                                                     |
                                                     v
                                                   CLOSED
```

| State      | Behavior                                                         |
|------------|------------------------------------------------------------------|
| `CLOSED`   | Normal operation; failures are counted                           |
| `OPEN`     | All tool calls are immediately BLOCKED (fail-safe)               |
| `HALF_OPEN`| A limited number of requests pass through to test recovery       |

Default configuration:
- Failure threshold: 5
- Recovery timeout: 30 seconds
- Success threshold to close: 3

The `HealthMonitor` (`janus/circuit/health.py`) tracks latency percentiles and
success rates alongside the circuit breaker.

---

## Tool Registration & Execution

**Module:** `janus/tools/`

Janus provides a tool registration and execution layer so that companies can register
their own tools and have Janus both guard and execute them in a single flow.

### Registering Tools

Companies register tools via the REST API or the Monitor dashboard. Each registered
tool is stored as a `RegisteredTool` (defined in `janus/tools/models.py`) and managed
by `ToolRegistry` (`janus/tools/registry.py`), which provides full CRUD operations.

Tools can be one of two types:

- **Webhook-based** -- the tool is backed by an HTTP endpoint. When executed, Janus
  makes an HTTP POST to the configured URL with the tool call payload.
- **MCP-based** -- the tool is served by an MCP server. When executed, Janus forwards
  the `call_tool` request to the appropriate upstream MCP server.

### Execution Flow

When an agent requests a tool call, the full lifecycle is:

1. **Register tool** -- the tool is registered once (via API or dashboard)
2. **Agent calls tool** -- the agent issues a tool call request
3. **Guardian evaluates** -- the request passes through the full security pipeline
   (11 checks in priority order)
4. **ToolExecutor executes** -- if the verdict is ALLOW, `ToolExecutor`
   (`janus/tools/executor.py`) routes to the correct backend
5. **Result returned** -- the tool output is returned to the agent

```
Agent requests tool call
         |
         v
   Guardian Pipeline
   (11 security checks)
         |
    +----+----+
    | ALLOW   | BLOCK/CHALLENGE
    v         v
ToolExecutor  HITL Approval
    |              |
+---+---+    (if approved)
|       |         |
v       v         v
Webhook  MCP   ToolExecutor
POST    Forward
```

If the verdict is BLOCK or CHALLENGE, the request may be routed to the Approval
Manager for human-in-the-loop review. If the human approves, the call is then
forwarded to ToolExecutor for execution.

### Webhook Execution

`WebhookExecutor` makes HTTP calls to the registered endpoint and supports three
authentication modes:

- **Bearer token** -- sends an `Authorization: Bearer <token>` header
- **API key** -- sends the key in a configurable header (e.g. `X-API-Key`)
- **HMAC** -- signs the request payload with HMAC-SHA256 and attaches the signature

### Mock Executor for Testing

Setting the environment variable `JANUS_MOCK_TOOLS=true` switches to
`MockToolExecutor`, which returns synthetic responses without making real HTTP calls
or MCP requests. This is useful for integration testing, CI pipelines, and local
development without external dependencies.

---

## Event Broadcasting

**Module:** `janus/web/events.py`

The `EventBroadcaster` provides async pub/sub for real-time security events.

- **Per-session subscriptions** -- WebSocket clients subscribe to a specific session ID
- **Global subscriptions** -- subscribing to `"*"` receives events from all sessions
  (used by the Monitor dashboard)
- **Event types** -- verdicts, approval requests, risk score changes

Events are `SecurityEvent` dataclasses containing the event type, session ID,
arbitrary data payload, and timestamp.

---

## Exporters and Notifications

**Module:** `janus/exporters/`

The `ExporterCoordinator` fires all enabled exporters after each verdict. Exporter
errors are caught and logged -- they never break the security pipeline.

### Available Exporters

| Exporter    | Module                        | Description                                  |
|-------------|-------------------------------|----------------------------------------------|
| Webhook     | `janus/exporters/webhook.py`  | HTTP POST with HMAC-SHA256 signing           |
| JSON Log    | `janus/exporters/json_log.py` | Append-only JSON log file (or stdout)        |
| Prometheus  | `janus/exporters/prometheus.py`| Prometheus metrics endpoint                  |
| OpenTelemetry| `janus/exporters/otel.py`    | Distributed tracing spans                    |
| Slack       | `janus/exporters/notifiers.py`| Slack webhook notifications                  |
| Email       | `janus/exporters/notifiers.py`| SMTP email alerts                            |
| Telegram    | `janus/exporters/notifiers.py`| Telegram bot notifications                   |

### Webhook Signing

Outbound webhooks are signed with HMAC-SHA256. The signature is sent in the
`X-Janus-Signature` header. Receivers should verify the signature against the
shared secret before trusting the payload.

---

## Tier System

**Module:** `janus/tier.py`

Janus uses an open-core model with two tiers:

### Free Tier
- Rule-based risk scoring
- Permission checks (glob-based)
- Identity management
- Prompt injection detection (regex)
- Circuit breaker
- Basic threat patterns
- Proof chain
- MCP proxy

### Pro Tier
All Free features plus:
- LLM classifier (Claude Haiku contextual risk assessment)
- Drift detection (semantic goal comparison)
- Taint tracking (data flow analysis)
- Predictive risk (attack trajectory matching)
- Crowd threat intelligence
- Dashboard
- Webhooks and integrations
- Compliance reports

Pro is activated with a license key (`sk-janus-` prefix, also accepts legacy
`sk-sentinel-` prefix). The `_TierState` singleton gates feature access at runtime
via `current_tier.check("feature_name")`.

---

## Database Schema

Janus uses SQLite for persistent storage. The schema is defined in
`janus/storage/database.py`.

| Table               | Purpose                                                    |
|---------------------|------------------------------------------------------------|
| `agents`            | Registered agent identities (ID, role, permissions, locks) |
| `tool_usage_log`    | Per-agent tool call audit records with timestamps          |
| `security_traces`   | Full security trace records (verdict, risk, reasons, goal) |
| `pattern_matches`   | Attack pattern match records with step progress            |
| `itdr_signals`      | Insider threat detection signals (anomaly, collusion, etc.)|
| `licenses`          | License key management (tier, Stripe IDs, expiry)          |
| `sessions`          | Session state (risk score, goal, tool call count)          |
| `session_events`    | Risk events per session (delta, score, tool, reason)       |
| `chat_messages`     | Conversation history for the chat agent                    |
| `approval_requests` | HITL approval workflow records                             |

### Session Storage

Two `SessionStore` implementations:
- **`InMemorySessionStore`** -- fast, non-persistent; used by the SDK by default
- **`PersistentSessionStore`** -- SQLite-backed with a write-through cache; used
  in server mode for durability across restarts

Both implement the same protocol: `get_or_create_session()`, `get_risk_score()`,
`set_risk_score()`, `add_event()`, `record_tool_call()`.

---

## Module Map

```
janus/
|-- __init__.py          # Public API: Guardian, Janus, create_janus, Verdict, etc.
|-- config.py            # Pydantic config models (JanusConfig, RiskConfig, etc.)
|-- tier.py              # Feature tier gating (Free/Pro)
|-- licensing.py         # License key generation and HMAC validation
|
|-- core/                # Security pipeline core
|   |-- guardian.py      # Guardian class -- main orchestrator
|   |-- pipeline.py      # SecurityPipeline, SecurityCheck protocol, IdentityCheck
|   |-- decision.py      # Verdict enum, ToolCallRequest, SecurityVerdict, CheckResult
|   |-- injection.py     # Prompt injection detection (regex + LLM)
|   |-- taint.py         # Taint tracking and exfiltration detection (Pro)
|   |-- proof.py         # Cryptographic proof chain (Merkle-style)
|   |-- predictor.py     # Predictive risk from attack trajectories (Pro)
|   |-- threat_intel.py  # Threat intelligence pattern database
|   |-- data_extraction.py # Data volume tracking and exfiltration detection
|   |-- approval.py      # Human-in-the-loop approval manager
|
|-- identity/            # Agent identity management
|   |-- agent.py         # AgentIdentity, AgentRole, ToolPermission dataclasses
|   |-- registry.py      # SQLite-backed agent registry
|
|-- risk/                # Risk scoring subsystem
|   |-- engine.py        # RiskEngine -- per-session score management
|   |-- scoring.py       # RiskScorer -- deterministic scoring rules
|   |-- patterns.py      # PatternDetector -- multi-step attack pattern matching
|   |-- thresholds.py    # Configurable threshold singleton
|
|-- drift/               # Semantic drift detection (Pro)
|   |-- detector.py      # SemanticDriftDetector -- LLM-powered goal comparison
|
|-- circuit/             # Reliability
|   |-- breaker.py       # CircuitBreaker state machine
|   |-- health.py        # HealthMonitor (latency, success rates)
|
|-- itdr/                # Insider Threat Detection and Response
|   |-- anomaly.py       # Behavioral anomaly detection
|   |-- collusion.py     # Cross-agent collusion detection
|   |-- escalation.py    # Privilege escalation tracking
|
|-- llm/                 # LLM integration
|   |-- classifier.py    # SecurityClassifier -- risk assessment via LLM
|   |-- client.py        # Anthropic client wrapper
|   |-- provider.py      # LLMProvider protocol
|   |-- guardian_prompts.py # System prompts for LLM classification
|   |-- providers/
|       |-- anthropic.py       # Anthropic (Claude) provider
|       |-- openai_provider.py # OpenAI provider
|       |-- ollama_provider.py # Ollama (local) provider
|
|-- mcp/                 # MCP proxy server
|   |-- proxy.py         # JanusMCPProxy -- intercepts MCP tool calls
|   |-- client.py        # UpstreamManager -- connects to upstream MCP servers
|   |-- config.py        # ProxyConfig
|   |-- runner.py        # CLI entry point for janus-proxy
|
|-- web/                 # FastAPI backend
|   |-- app.py           # create_app() factory, REST endpoints, WebSocket
|   |-- events.py        # EventBroadcaster -- async pub/sub for real-time events
|   |-- auth.py          # API key authentication middleware
|   |-- agent.py         # ChatAgent for the conversational demo
|   |-- schemas.py       # Pydantic request/response models
|
|-- storage/             # Persistence
|   |-- database.py      # DatabaseManager, SQLite schema, migrations
|   |-- session_store.py # InMemorySessionStore
|   |-- persistent_session_store.py # SQLite-backed SessionStore
|   |-- protocol.py      # SessionStore protocol
|
|-- forensics/           # Audit and compliance
|   |-- recorder.py      # BlackBoxRecorder -- writes security traces
|   |-- exporter.py      # CSV/JSON/JSONL trace export
|   |-- explainer.py     # TraceExplainer -- human-readable trace summaries
|
|-- exporters/           # External integrations
|   |-- coordinator.py   # ExporterCoordinator -- fires all enabled exporters
|   |-- webhook.py       # Webhook with HMAC-SHA256 signing
|   |-- json_log.py      # JSON log file exporter
|   |-- prometheus.py    # Prometheus metrics
|   |-- otel.py          # OpenTelemetry traces
|   |-- notifiers.py     # Slack, Email, Telegram notifications
|
|-- tools/                 # Tool registration and execution
|   |-- __init__.py
|   |-- models.py         # RegisteredTool dataclass
|   |-- registry.py       # ToolRegistry — CRUD for registered tools
|   |-- executor.py       # ToolExecutor — webhook/MCP routing
|
|-- integrations/        # Agent framework adapters
|   |-- __init__.py      # Janus SDK client, create_janus(), GuardResult
|   |-- langchain.py     # LangChain BaseTool wrapper
|   |-- openai.py        # OpenAI function calling proxy
|   |-- crewai.py        # CrewAI tool wrapper
|   |-- mcp.py           # MCP server wrapper
|
|-- sandbox/             # Sandboxed execution environment
|-- cli/                 # CLI commands (janus register, serve, proxy, etc.)
```

---

## Configuration

Janus is configured via a `JanusConfig` Pydantic model, which can be loaded from
a TOML file or constructed in code.

```toml
# janus.toml

[janus]
license_key = "sk-janus-..."
database_path = "~/.janus/janus.db"
log_level = "INFO"

[guardian_model]
model = "claude-haiku-4-5-20251001"
provider = "anthropic"      # "anthropic" | "openai" | "ollama"
timeout_seconds = 5.0

[risk]
lock_threshold = 80.0
sandbox_threshold = 60.0
elevated_logging_threshold = 40.0
decay_rate_per_minute = 2.0
decay_idle_threshold_minutes = 5.0

[drift]
threshold = 0.6
max_risk_contribution = 40.0

[circuit_breaker]
failure_threshold = 5
recovery_timeout_seconds = 30.0
success_threshold = 3

[policy]
keyword_sensitive_tools = [
    "execute_code", "database_write", "database_query",
    "send_email", "write_file", "api_call",
    "financial_transfer", "modify_permissions", "delete_file"
]

[policy.keyword_amplifiers]
"rm -rf" = 30.0
"eval(" = 25.0
"/etc/shadow" = 35.0

[exporters]
webhook_url = "https://example.com/hooks/janus"
webhook_signing_secret = "whsec_..."
prometheus_enabled = true
otel_enabled = true

[exporters.notifications.slack]
webhook_url = "https://hooks.slack.com/..."
min_verdict = "block"

[exporters.notifications.email]
smtp_host = "smtp.example.com"
from_addr = "janus@example.com"
to_addrs = ["security@example.com"]
```

### Environment Variables

| Variable            | Purpose                                          |
|---------------------|--------------------------------------------------|
| `JANUS_CONFIG_PATH` | Path to `janus.toml` configuration file          |
| `JANUS_DB_PATH`     | Override database file location                  |
| `JANUS_API_KEY`     | API key for authenticating REST API requests     |
| `ANTHROPIC_API_KEY` | API key for Claude (LLM classifier, drift)       |

### Starting the Backend

```bash
ANTHROPIC_API_KEY=sk-ant-... uvicorn janus.web.app:create_app --factory --host 0.0.0.0 --port 8000
```

Or via the CLI:

```bash
janus serve --host 0.0.0.0 --port 8000
```
