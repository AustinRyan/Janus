# Janus Security -- REST API Reference

> **Version:** 0.2.0
> **Base URL:** `http://localhost:8000`
> **Transport:** HTTP/1.1, WebSocket

This document covers every endpoint served by the Janus Security dashboard backend. Start the server with:

```bash
janus serve
# or
uvicorn janus.web.app:create_app --factory --host 0.0.0.0 --port 8000
```

---

## Table of Contents

- [Authentication](#authentication)
- [Health](#health)
- [Sessions](#sessions)
- [Chat](#chat)
- [Agents](#agents)
- [Tool Evaluation](#tool-evaluation)
- [Tool Management](#tool-management)
- [Security Traces](#security-traces)
- [Risk Events](#risk-events)
- [Taint Tracking](#taint-tracking)
- [Proof Chain](#proof-chain)
- [Threat Intelligence](#threat-intelligence)
- [Approvals (Human-in-the-Loop)](#approvals-human-in-the-loop)
- [Licensing](#licensing)
- [Billing (Stripe)](#billing-stripe)
- [WebSocket Streams](#websocket-streams)
- [Response Schema Reference](#response-schema-reference)
- [Error Responses](#error-responses)

---

## Authentication

All endpoints except `GET /api/health` require a Bearer token **when the `JANUS_API_KEY` environment variable is set**.

```
Authorization: Bearer <your-api-key>
```

When `JANUS_API_KEY` is **not** set, authentication is disabled (development mode). Any request is accepted.

**401 Response** (invalid or missing key):

```json
{
  "detail": "Invalid or missing API key"
}
```

---

## Health

### GET /api/health

Returns basic health status. **No authentication required.**

**Response** `200 OK` -- `HealthOut`

```json
{
  "status": "ok",
  "total_requests": 142,
  "error_rate": 0.02,
  "circuit_breaker": "closed"
}
```

| Field           | Type   | Description                                      |
|-----------------|--------|--------------------------------------------------|
| status          | string | Always `"ok"` when the server is running         |
| total_requests  | int    | Cumulative requests processed since startup       |
| error_rate      | float  | Ratio of failed requests to total (0.0 -- 1.0)   |
| circuit_breaker | string | Circuit breaker state: `closed`, `open`, `half_open` |

---

### GET /api/health/full

Returns detailed health metrics including latency percentiles and active session count.

**Response** `200 OK` -- `HealthFullOut`

```json
{
  "status": "ok",
  "total_requests": 142,
  "successful_requests": 139,
  "failed_requests": 3,
  "avg_latency_ms": 23.5,
  "p95_latency_ms": 45.2,
  "error_rate": 0.02,
  "circuit_breaker": "closed",
  "active_sessions": 5
}
```

| Field               | Type   | Description                                      |
|---------------------|--------|--------------------------------------------------|
| status              | string | Always `"ok"` when the server is running         |
| total_requests      | int    | Cumulative requests processed                    |
| successful_requests | int    | Requests that completed without error            |
| failed_requests     | int    | Requests that raised an error                    |
| avg_latency_ms      | float  | Mean latency across all requests (milliseconds)  |
| p95_latency_ms      | float  | 95th percentile latency (milliseconds)           |
| error_rate          | float  | Ratio of failed requests to total (0.0 -- 1.0)   |
| circuit_breaker     | string | Circuit breaker state: `closed`, `open`, `half_open` |
| active_sessions     | int    | Number of sessions currently tracked in memory   |

---

## Sessions

### POST /api/sessions

Create a new monitored session.

**Request Body** -- `SessionCreateRequest`

```json
{
  "agent_id": "demo-agent",
  "original_goal": "Analyze quarterly data"
}
```

| Field         | Type   | Required | Default        | Description                        |
|---------------|--------|----------|----------------|------------------------------------|
| agent_id      | string | No       | `"demo-agent"` | Registered agent identifier        |
| original_goal | string | No       | `""`           | The agent's declared objective     |

**Response** `200 OK` -- `SessionOut`

```json
{
  "session_id": "session-a1b2c3d4",
  "agent_id": "demo-agent",
  "original_goal": "Analyze quarterly data",
  "risk_score": 0.0
}
```

---

### GET /api/sessions

List all active sessions. Returns sessions from the persistent database if available, otherwise from the in-memory store.

**Response** `200 OK` -- `SessionOut[]`

```json
[
  {
    "session_id": "session-a1b2c3d4",
    "agent_id": "demo-agent",
    "original_goal": "Analyze quarterly data",
    "risk_score": 15.0
  }
]
```

---

## Chat

### POST /api/chat

Send a message to the chat agent. The agent processes the message, may invoke tools through the Guardian pipeline, and returns a response with any tool call results and their security verdicts.

If the session's chat agent is not in memory (e.g., after a server restart), it is reconstructed from the database and conversation history is restored.

**Request Body** -- `ChatRequest`

```json
{
  "session_id": "session-a1b2c3d4",
  "message": "Read the quarterly report"
}
```

| Field      | Type   | Required | Description                         |
|------------|--------|----------|-------------------------------------|
| session_id | string | Yes      | Session to send the message in      |
| message    | string | Yes      | User message text                   |

**Response** `200 OK` -- `ChatResponseOut`

```json
{
  "message": "I'll read the quarterly report for you.",
  "tool_calls": [
    {
      "tool_name": "read_file",
      "tool_input": { "path": "/reports/q4.pdf" },
      "verdict": "allow",
      "risk_score": 5.0,
      "risk_delta": 5.0,
      "result": { "content": "..." },
      "reasons": []
    }
  ],
  "session_id": "session-a1b2c3d4"
}
```

---

### GET /api/sessions/{session_id}/messages

Retrieve the full message history for a session, including tool call metadata.

**Path Parameters**

| Parameter  | Type   | Description        |
|------------|--------|--------------------|
| session_id | string | Session identifier |

**Response** `200 OK` -- `MessageOut[]`

```json
[
  {
    "role": "user",
    "content": "Read the quarterly report",
    "tool_calls": []
  },
  {
    "role": "assistant",
    "content": "I'll read the quarterly report for you.",
    "tool_calls": [
      {
        "tool_name": "read_file",
        "tool_input": { "path": "/reports/q4.pdf" },
        "verdict": "allow",
        "risk_score": 5.0,
        "risk_delta": 5.0,
        "result": null,
        "reasons": []
      }
    ]
  }
]
```

---

## Agents

### GET /api/agents

List all registered agent identities.

**Response** `200 OK` -- `AgentOut[]`

```json
[
  {
    "agent_id": "demo-agent",
    "name": "Demo Research Bot",
    "role": "research",
    "permissions": ["read_*", "search_*", "api_call", "execute_code", "write_file", "database_query"],
    "is_locked": false
  },
  {
    "agent_id": "admin-bot",
    "name": "Admin Bot",
    "role": "admin",
    "permissions": ["*"],
    "is_locked": false
  }
]
```

| Field       | Type     | Description                                       |
|-------------|----------|---------------------------------------------------|
| agent_id    | string   | Unique agent identifier                           |
| name        | string   | Human-readable agent name                         |
| role        | string   | Agent role: `research`, `code`, `communication`, `financial`, `admin` |
| permissions | string[] | Tool permission patterns (glob syntax)            |
| is_locked   | bool     | Whether the agent is currently locked out          |

---

## Tool Evaluation

### POST /api/evaluate

Evaluate a tool call directly through the full Guardian security pipeline without using the LLM chat agent. Useful for testing security decisions, integrating with external agent frameworks, or building custom orchestrators.

When the verdict is not `allow` and the blocked call qualifies for human review (judgment-call blocks, not hard policy violations), an approval request is automatically created and `approval_id` is returned.

**Request Body** -- `ToolEvalRequest`

```json
{
  "agent_id": "agent-1",
  "session_id": "session-1",
  "tool_name": "execute_code",
  "tool_input": { "code": "import os; os.system('rm -rf /')" },
  "original_goal": "Run analysis script"
}
```

| Field         | Type   | Required | Default | Description                              |
|---------------|--------|----------|---------|------------------------------------------|
| agent_id      | string | Yes      | --      | Agent making the tool call               |
| session_id    | string | Yes      | --      | Session context for risk accumulation    |
| tool_name     | string | Yes      | --      | Name of the tool being called            |
| tool_input    | object | No       | `{}`    | Arguments passed to the tool             |
| original_goal | string | No       | `""`    | Agent's declared goal for drift detection |

**Response** `200 OK` -- `ToolEvalResponse`

```json
{
  "verdict": "block",
  "risk_score": 85.0,
  "risk_delta": 45.0,
  "reasons": ["prompt_injection: Command injection detected"],
  "session_id": "session-1",
  "tool_name": "execute_code",
  "approval_id": "apr-abc123"
}
```

| Field       | Type         | Description                                                 |
|-------------|--------------|-------------------------------------------------------------|
| verdict     | string       | `allow`, `block`, `challenge`, `sandbox`, or `pause`        |
| risk_score  | float        | Cumulative session risk score after this call                |
| risk_delta  | float        | Risk contribution of this specific call                     |
| reasons     | string[]     | Human-readable explanations for the verdict                 |
| session_id  | string       | Session identifier                                          |
| tool_name   | string       | Tool that was evaluated                                     |
| approval_id | string/null  | Set when a human review request was created (judgment calls) |

---

## Tool Management

Register, update, and test-execute tools that agents can invoke through the Guardian pipeline. Tools can be webhook-based (HTTP calls to external services) or MCP-based (delegated to an MCP server).

### GET /api/tools

List registered tools.

**Query Parameters**

| Parameter   | Type | Required | Default | Description                              |
|-------------|------|----------|---------|------------------------------------------|
| active_only | bool | No       | `true`  | When true, only return active tools      |

**Response** `200 OK` -- `ToolOut[]`

```json
[
  {
    "id": "tool-a1b2c3d4e5f6",
    "name": "search_db",
    "description": "Search the customer database",
    "type": "webhook",
    "endpoint": "https://api.mycompany.com/tools/search_db",
    "method": "POST",
    "auth_type": "bearer",
    "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
    "timeout_seconds": 30.0,
    "mcp_server_name": "",
    "is_active": true,
    "created_at": "2026-02-25T10:00:00+00:00",
    "updated_at": "2026-02-25T10:00:00+00:00"
  }
]
```

---

### POST /api/tools

Register a new tool.

**Request Body** -- `ToolRegisterRequest`

```json
{
  "name": "search_db",
  "description": "Search the customer database",
  "type": "webhook",
  "endpoint": "https://api.mycompany.com/tools/search_db",
  "method": "POST",
  "auth_type": "bearer",
  "auth_credential": "$DB_TOKEN",
  "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
  "timeout_seconds": 30.0,
  "mcp_server_name": ""
}
```

| Field           | Type   | Required | Default                              | Description                                                  |
|-----------------|--------|----------|--------------------------------------|--------------------------------------------------------------|
| name            | string | Yes      | --                                   | Unique tool name (1--128 characters)                         |
| description     | string | No       | `""`                                 | Human-readable description                                   |
| type            | string | No       | `"webhook"`                          | Tool type: `webhook` or `mcp`                                |
| endpoint        | string | No       | `""`                                 | URL for webhook tools (required when `type` is `webhook`)    |
| method          | string | No       | `"POST"`                             | HTTP method for webhook calls                                |
| auth_type       | string | No       | `"none"`                             | Authentication type: `none`, `bearer`, `api_key`, or `hmac`  |
| auth_credential | string | No       | `""`                                 | Env var name (e.g., `$MY_TOKEN`) or raw credential value     |
| input_schema    | object | No       | `{"type": "object", "properties": {}}` | JSON Schema describing the tool's expected input           |
| timeout_seconds | float  | No       | `30.0`                               | Request timeout in seconds (1.0--300.0)                      |
| mcp_server_name | string | No       | `""`                                 | MCP server name (required when `type` is `mcp`)              |

**Response** `201 Created` -- `ToolOut`

```json
{
  "id": "tool-a1b2c3d4e5f6",
  "name": "search_db",
  "description": "Search the customer database",
  "type": "webhook",
  "endpoint": "https://api.mycompany.com/tools/search_db",
  "method": "POST",
  "auth_type": "bearer",
  "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
  "timeout_seconds": 30.0,
  "mcp_server_name": "",
  "is_active": true,
  "created_at": "2026-02-25T10:00:00+00:00",
  "updated_at": "2026-02-25T10:00:00+00:00"
}
```

**Error Responses**

- `400 Bad Request` -- Webhook tool missing `endpoint`, or MCP tool missing `mcp_server_name`.
- `409 Conflict` -- A tool with the same `name` already exists.

---

### GET /api/tools/{tool_id}

Get a single tool by ID.

**Path Parameters**

| Parameter | Type   | Description              |
|-----------|--------|--------------------------|
| tool_id   | string | Unique tool identifier   |

**Response** `200 OK` -- `ToolOut`

**Response** `404 Not Found`

```json
{
  "detail": "Tool not found"
}
```

---

### PUT /api/tools/{tool_id}

Update fields on an existing tool. Only include the fields you want to change; all fields are optional.

**Path Parameters**

| Parameter | Type   | Description              |
|-----------|--------|--------------------------|
| tool_id   | string | Unique tool identifier   |

**Request Body** -- `ToolUpdateRequest`

```json
{
  "description": "Updated description",
  "timeout_seconds": 60.0,
  "is_active": false
}
```

| Field           | Type        | Description                                                 |
|-----------------|-------------|-------------------------------------------------------------|
| name            | string/null | New tool name                                               |
| description     | string/null | Updated description                                         |
| type            | string/null | Tool type: `webhook` or `mcp`                               |
| endpoint        | string/null | Webhook URL                                                 |
| method          | string/null | HTTP method                                                 |
| auth_type       | string/null | Authentication type: `none`, `bearer`, `api_key`, or `hmac` |
| auth_credential | string/null | Credential or env var reference                             |
| input_schema    | object/null | JSON Schema for tool input                                  |
| timeout_seconds | float/null  | Request timeout in seconds (1.0--300.0)                     |
| mcp_server_name | string/null | MCP server name                                             |
| is_active       | bool/null   | Enable or disable the tool                                  |

**Response** `200 OK` -- `ToolOut` (the updated tool)

**Response** `404 Not Found`

```json
{
  "detail": "Tool not found"
}
```

---

### DELETE /api/tools/{tool_id}

Delete a registered tool.

**Path Parameters**

| Parameter | Type   | Description              |
|-----------|--------|--------------------------|
| tool_id   | string | Unique tool identifier   |

**Response** `204 No Content`

**Response** `404 Not Found`

```json
{
  "detail": "Tool not found"
}
```

---

### POST /api/tools/{tool_id}/test

Test-execute a registered tool with sample input. Runs the tool through the executor and returns the result. Useful for verifying connectivity and credentials before using a tool in production.

**Path Parameters**

| Parameter | Type   | Description              |
|-----------|--------|--------------------------|
| tool_id   | string | Unique tool identifier   |

**Request Body** -- `ToolTestRequest`

```json
{
  "input": {"query": "test search"}
}
```

| Field | Type   | Required | Default | Description                     |
|-------|--------|----------|---------|---------------------------------|
| input | object | No       | `{}`    | Input arguments for the tool    |

**Response** `200 OK` -- `ToolTestResponse`

```json
{
  "success": true,
  "result": {"rows": [{"id": 1, "name": "Acme Corp"}]},
  "tool_name": "search_db"
}
```

| Field     | Type   | Description                                             |
|-----------|--------|---------------------------------------------------------|
| success   | bool   | `true` if the tool executed without error               |
| result    | object | Raw output from the tool execution                      |
| tool_name | string | Name of the tool that was tested                        |

**Response** `404 Not Found`

```json
{
  "detail": "Tool not found"
}
```

---

## Security Traces

### GET /api/traces

Query the security trace audit log. Traces record every tool call evaluation with its verdict, risk score, and explanations.

**Query Parameters**

| Parameter  | Type   | Required | Default | Description                                        |
|------------|--------|----------|---------|----------------------------------------------------|
| session_id | string | No       | --      | Filter traces by session                           |
| verdict    | string | No       | --      | Filter by verdict: `allow`, `block`, `challenge`, `sandbox`, `pause` |
| limit      | int    | No       | 50      | Maximum number of traces to return                 |

When `session_id` is provided, all traces for that session are returned (up to `limit`). When `verdict` is provided without `session_id`, traces are filtered by verdict. When neither is provided, the most recent traces are returned.

**Response** `200 OK` -- `TraceOut[]`

```json
[
  {
    "trace_id": "trc-9f8e7d6c",
    "session_id": "session-a1b2c3d4",
    "agent_id": "demo-agent",
    "tool_name": "execute_code",
    "verdict": "block",
    "risk_score": 85.0,
    "risk_delta": 45.0,
    "explanation": "Code execution blocked due to destructive system command.",
    "timestamp": "2026-02-25T10:30:00",
    "reasons": ["prompt_injection: Command injection detected"]
  }
]
```

---

### GET /api/export/traces

Export traces as a downloadable file. Supports filtering by multiple criteria. Returns a file with `Content-Disposition: attachment`.

> **Requires PRO tier.** Returns `403 Forbidden` on FREE tier.

**Query Parameters**

| Parameter  | Type   | Required | Default  | Description                                |
|------------|--------|----------|----------|--------------------------------------------|
| format     | string | No       | `"json"` | Export format: `json`, `csv`, or `jsonl`   |
| verdict    | string | No       | --       | Filter by verdict                          |
| agent_id   | string | No       | --       | Filter by agent                            |
| session_id | string | No       | --       | Filter by session                          |
| date_from  | string | No       | --       | Start date (ISO format)                    |
| date_to    | string | No       | --       | End date (ISO format)                      |
| min_risk   | float  | No       | --       | Minimum risk score                         |
| limit      | int    | No       | 10000    | Maximum number of traces                   |

**Response** `200 OK` -- File download

| Format | Content-Type              | Filename       |
|--------|---------------------------|----------------|
| json   | `application/json`        | `traces.json`  |
| csv    | `text/csv`                | `traces.csv`   |
| jsonl  | `application/x-ndjson`    | `traces.jsonl` |

**Example:**

```bash
curl -H "Authorization: Bearer $API_KEY" \
  "http://localhost:8000/api/export/traces?format=csv&verdict=block&min_risk=50" \
  -o blocked_traces.csv
```

---

## Risk Events

### GET /api/sessions/{session_id}/events

Get the risk event timeline for a session. Each event represents a risk score change caused by a tool call evaluation. Powers the risk timeline chart in the dashboard.

**Path Parameters**

| Parameter  | Type   | Description        |
|------------|--------|--------------------|
| session_id | string | Session identifier |

**Response** `200 OK` -- `RiskEventOut[]`

```json
[
  {
    "risk_delta": 15.0,
    "new_score": 35.0,
    "tool_name": "execute_code",
    "reason": "Keyword amplifier: execute_code +15",
    "timestamp": "2026-02-25T10:30:00"
  }
]
```

| Field      | Type   | Description                                 |
|------------|--------|---------------------------------------------|
| risk_delta | float  | Risk contribution of this event             |
| new_score  | float  | Cumulative risk score after this event      |
| tool_name  | string | Tool that triggered the risk change         |
| reason     | string | Human-readable explanation                  |
| timestamp  | string | ISO 8601 timestamp                          |

---

## Taint Tracking

### GET /api/sessions/{session_id}/taint

Get active taint entries for a session. Taint tracking monitors data flow across tool calls to detect sensitive data propagation (PII, credentials, secrets, etc.).

> **Requires PRO tier.** Returns `403 Forbidden` on FREE tier.

**Path Parameters**

| Parameter  | Type   | Description        |
|------------|--------|--------------------|
| session_id | string | Session identifier |

**Response** `200 OK` -- `TaintEntryOut[]`

```json
[
  {
    "label": "pii",
    "source_tool": "read_file",
    "source_step": 3,
    "patterns_matched": ["email", "ssn"],
    "timestamp": "2026-02-25T10:30:00"
  }
]
```

| Field            | Type     | Description                                      |
|------------------|----------|--------------------------------------------------|
| label            | string   | Taint category: `pii`, `credential`, `secret`, etc. |
| source_tool      | string   | Tool call that introduced the taint              |
| source_step      | int      | Step number in the session when taint was added  |
| patterns_matched | string[] | Specific patterns detected (e.g., `email`, `ssn`) |
| timestamp        | string   | ISO 8601 timestamp                               |

---

## Proof Chain

### GET /api/sessions/{session_id}/proof

Get the cryptographic proof chain for a session. Each node in the chain records a security decision with a content hash linked to the previous node, forming a tamper-evident audit trail.

**Path Parameters**

| Parameter  | Type   | Description        |
|------------|--------|--------------------|
| session_id | string | Session identifier |

**Response** `200 OK` -- Proof node array

```json
[
  {
    "node_id": "pn-abc123",
    "parent_hash": "sha256:...",
    "step": 1,
    "timestamp": "2026-02-25T10:30:00",
    "session_id": "session-a1b2c3d4",
    "agent_id": "demo-agent",
    "tool_name": "read_file",
    "verdict": "allow",
    "risk_score": 0.0,
    "risk_delta": 0.0,
    "content_hash": "sha256:..."
  }
]
```

| Field        | Type   | Description                                    |
|--------------|--------|------------------------------------------------|
| node_id      | string | Unique identifier for this proof node          |
| parent_hash  | string | Hash of the previous node in the chain         |
| step         | int    | Sequential step number within the session      |
| timestamp    | string | ISO 8601 timestamp of the decision             |
| session_id   | string | Session this proof belongs to                  |
| agent_id     | string | Agent that triggered the decision              |
| tool_name    | string | Tool that was evaluated                        |
| verdict      | string | Security verdict for this step                 |
| risk_score   | float  | Cumulative risk score at this step             |
| risk_delta   | float  | Risk delta for this step                       |
| content_hash | string | SHA-256 hash of the node content               |

---

### POST /api/sessions/{session_id}/proof/verify

Verify the integrity of a session's proof chain. Walks the chain and validates that each node's hash correctly links to its parent.

**Path Parameters**

| Parameter  | Type   | Description        |
|------------|--------|--------------------|
| session_id | string | Session identifier |

**Response** `200 OK`

```json
{
  "valid": true,
  "chain_length": 12,
  "session_id": "session-a1b2c3d4"
}
```

| Field        | Type   | Description                                   |
|--------------|--------|-----------------------------------------------|
| valid        | bool   | `true` if the entire chain is intact          |
| chain_length | int    | Number of nodes in the proof chain            |
| session_id   | string | Session that was verified                     |

If the chain has been tampered with:

```json
{
  "valid": false,
  "chain_length": 12,
  "session_id": "session-a1b2c3d4"
}
```

---

## Threat Intelligence

### GET /api/threat-intel

List all threat intelligence patterns known to the system. Patterns represent recognized attack sequences (e.g., data exfiltration, privilege escalation).

> **Requires PRO tier.** Returns `403 Forbidden` on FREE tier.

**Response** `200 OK` -- Threat pattern array

```json
[
  {
    "pattern_id": "tip-001",
    "pattern_type": "data_exfiltration",
    "tool_sequence": ["read_file", "api_call"],
    "risk_contribution": 20.0,
    "confidence": 0.85,
    "first_seen": "2026-02-20T08:00:00",
    "times_seen": 7,
    "source": "builtin"
  }
]
```

| Field             | Type     | Description                                      |
|-------------------|----------|--------------------------------------------------|
| pattern_id        | string   | Unique pattern identifier                        |
| pattern_type      | string   | Category: `data_exfiltration`, `privilege_escalation`, etc. |
| tool_sequence     | string[] | Ordered sequence of tools that form the pattern  |
| risk_contribution | float    | Risk score added when this pattern is detected   |
| confidence        | float    | Detection confidence (0.0 -- 1.0)                |
| first_seen        | string   | ISO 8601 timestamp of first detection            |
| times_seen        | int      | Number of times this pattern has been observed   |
| source            | string   | Origin of the pattern (`builtin`, `learned`, etc.) |

---

### GET /api/threat-intel/stats

Aggregate threat intelligence statistics.

> **Requires PRO tier.** Returns `403 Forbidden` on FREE tier.

**Response** `200 OK`

```json
{
  "total_patterns": 12,
  "by_type": {
    "data_exfiltration": 3,
    "privilege_escalation": 2,
    "reconnaissance": 4,
    "lateral_movement": 3
  }
}
```

---

## Approvals (Human-in-the-Loop)

The approvals system enables human review of blocked tool calls that are judgment calls (not hard policy violations like prompt injection). When a tool call is blocked and qualifies for review, an approval request is created and can be resolved through these endpoints.

### GET /api/approvals

List approval requests with optional filtering.

**Query Parameters**

| Parameter  | Type   | Required | Default | Description                                     |
|------------|--------|----------|---------|-------------------------------------------------|
| status     | string | No       | --      | Filter by status: `pending`, `approved`, `rejected` |
| session_id | string | No       | --      | Filter by session                               |
| limit      | int    | No       | 50      | Maximum number of results                       |

**Response** `200 OK` -- `ApprovalRequestOut[]`

```json
[
  {
    "id": "apr-abc123",
    "session_id": "session-a1b2c3d4",
    "agent_id": "demo-agent",
    "tool_name": "execute_code",
    "tool_input": { "code": "subprocess.run(['ls', '-la'])" },
    "original_goal": "List project files",
    "verdict": "block",
    "risk_score": 55.0,
    "risk_delta": 25.0,
    "reasons": ["Elevated risk: cumulative score exceeds warning threshold"],
    "check_results": [
      {
        "check_name": "deterministic_risk",
        "passed": false,
        "risk_contribution": 25.0,
        "reason": "Keyword amplifier: execute_code +15",
        "metadata": {},
        "force_verdict": null
      }
    ],
    "trace_id": "trc-9f8e7d6c",
    "status": "pending",
    "decided_by": null,
    "decided_at": null,
    "decision_reason": "",
    "tool_result": null,
    "created_at": "2026-02-25T10:30:00",
    "expires_at": "2026-02-25T11:30:00"
  }
]
```

---

### GET /api/approvals/stats

Approval queue statistics.

**Response** `200 OK`

```json
{
  "pending": 3,
  "approved": 12,
  "rejected": 5
}
```

---

### GET /api/approvals/{approval_id}

Get a single approval request by ID.

**Path Parameters**

| Parameter   | Type   | Description                 |
|-------------|--------|-----------------------------|
| approval_id | string | Unique approval request ID  |

**Response** `200 OK` -- `ApprovalRequestOut`

**Response** `404 Not Found`

```json
{
  "detail": "Approval not found"
}
```

---

### POST /api/approvals/{approval_id}/approve

Approve a pending request. Upon approval, the tool call is executed and the result is returned.

**Path Parameters**

| Parameter   | Type   | Description                 |
|-------------|--------|-----------------------------|
| approval_id | string | Unique approval request ID  |

**Request Body** -- `ApprovalDecisionRequest`

```json
{
  "decided_by": "security-team",
  "reason": "Verified safe after manual review"
}
```

| Field      | Type   | Required | Default   | Description                     |
|------------|--------|----------|-----------|---------------------------------|
| decided_by | string | No       | `"human"` | Identity of the decision maker  |
| reason     | string | No       | `""`      | Justification for the decision  |

**Response** `200 OK` -- `ApprovalDecisionOut`

```json
{
  "id": "apr-abc123",
  "status": "approved",
  "decided_by": "security-team",
  "decided_at": "2026-02-25T10:35:00",
  "decision_reason": "Verified safe after manual review",
  "tool_result": { "output": "total 42\ndrwxr-xr-x ..." }
}
```

**Response** `404 Not Found`

```json
{
  "detail": "Approval not found or already resolved"
}
```

---

### POST /api/approvals/{approval_id}/reject

Reject a pending request. The tool call is not executed.

**Path Parameters**

| Parameter   | Type   | Description                 |
|-------------|--------|-----------------------------|
| approval_id | string | Unique approval request ID  |

**Request Body** -- `ApprovalDecisionRequest`

```json
{
  "decided_by": "security-team",
  "reason": "Suspicious tool input pattern"
}
```

**Response** `200 OK` -- `ApprovalDecisionOut`

```json
{
  "id": "apr-abc123",
  "status": "rejected",
  "decided_by": "security-team",
  "decided_at": "2026-02-25T10:35:00",
  "decision_reason": "Suspicious tool input pattern",
  "tool_result": null
}
```

**Response** `404 Not Found`

```json
{
  "detail": "Approval not found or already resolved"
}
```

---

## Licensing

### GET /api/license/status

Get the current license tier. No authentication required (separate from the auth-protected router).

**Response** `200 OK`

```json
{
  "tier": "pro",
  "is_pro": true
}
```

| Field  | Type   | Description                            |
|--------|--------|----------------------------------------|
| tier   | string | Current tier: `free` or `pro`          |
| is_pro | bool   | Convenience flag for Pro tier features |

---

### POST /api/license/activate

Activate a license key. License keys use the `sk-janus-` prefix (legacy `sk-sentinel-` prefix is also accepted).

**Request Body** -- `ActivateRequest`

```json
{
  "license_key": "sk-janus-abc123..."
}
```

**Response** `200 OK`

```json
{
  "tier": "pro",
  "is_pro": true
}
```

**Response** `400 Bad Request`

```json
{
  "detail": "Invalid or expired license key"
}
```

---

## Billing (Stripe)

These endpoints integrate with Stripe for subscription management. They require `STRIPE_SECRET_KEY` and `STRIPE_PRICE_ID` environment variables to be configured.

### POST /api/billing/checkout

Create a Stripe Checkout session for a Pro subscription (includes 14-day trial).

**Request Body** -- `CheckoutRequest`

```json
{
  "email": "user@example.com"
}
```

| Field | Type   | Required | Description                          |
|-------|--------|----------|--------------------------------------|
| email | string | No       | Pre-fills the checkout email field   |

**Response** `200 OK`

```json
{
  "checkout_url": "https://checkout.stripe.com/c/pay/cs_..."
}
```

**Response** `501 Not Implemented`

```json
{
  "detail": "Stripe billing not configured. Set STRIPE_SECRET_KEY and STRIPE_PRICE_ID."
}
```

---

### GET /api/billing/session/{session_id}

Look up a completed Stripe checkout session to retrieve the generated license key. Used by the success page after checkout.

**Path Parameters**

| Parameter  | Type   | Description                    |
|------------|--------|--------------------------------|
| session_id | string | Stripe Checkout session ID     |

**Response** `200 OK`

```json
{
  "license_key": "sk-janus-abc123...",
  "tier": "pro",
  "customer_email": "user@example.com",
  "trial_ends_at": "2026-03-11T10:30:00+00:00"
}
```

**Response** `404 Not Found`

```json
{
  "detail": "Session not found."
}
```

---

### POST /api/webhooks/stripe

Stripe webhook endpoint. Handles `checkout.session.completed` (generates license key and sends email) and `customer.subscription.deleted` (expires license). Stripe signs its own requests via the `stripe-signature` header -- this endpoint is **not** behind Janus API key authentication.

Requires the `STRIPE_WEBHOOK_SECRET` environment variable.

**Headers**

| Header           | Description                              |
|------------------|------------------------------------------|
| stripe-signature | Stripe webhook signature for verification |

**Response** `200 OK` (on successful processing)

```json
{
  "license_key": "sk-janus-abc123...",
  "tier": "pro"
}
```

**Response** `400 Bad Request` (invalid signature)

```json
{
  "detail": "Invalid signature"
}
```

---

## WebSocket Streams

WebSocket endpoints provide real-time event streaming for dashboards and monitoring tools. Events are delivered as JSON messages.

### WS /api/ws/session/{session_id}

Subscribe to real-time security events for a specific session.

**Connection:** `ws://localhost:8000/api/ws/session/{session_id}`

**Event Format:**

```json
{
  "event_type": "verdict",
  "session_id": "session-a1b2c3d4",
  "data": {
    "verdict": "block",
    "risk_score": 85.0,
    "risk_delta": 45.0,
    "tool_name": "execute_code",
    "tool_input": { "code": "..." },
    "reasons": ["prompt_injection: Command injection detected"],
    "drift_score": 0.3,
    "itdr_signals": [],
    "recommended_action": "",
    "trace_id": "trc-9f8e7d6c",
    "check_results": [
      {
        "check_name": "injection",
        "passed": false,
        "risk_contribution": 40.0,
        "reason": "Command injection detected",
        "metadata": {},
        "force_verdict": "block"
      }
    ]
  },
  "timestamp": "2026-02-25T10:30:00+00:00"
}
```

---

### WS /api/ws/monitor

Global event stream across **all** sessions. Used by the Monitor dashboard. Receives every event published to any session.

**Connection:** `ws://localhost:8000/api/ws/monitor`

**Event Types:**

| event_type       | Description                                      |
|------------------|--------------------------------------------------|
| verdict          | A tool call was evaluated by the Guardian        |
| approval_created | A new human review request was created           |
| approval_resolved| An approval request was approved or rejected     |

Events use the same JSON format as the session-scoped WebSocket above.

---

## Response Schema Reference

### SessionOut

| Field         | Type   | Description                         |
|---------------|--------|-------------------------------------|
| session_id    | string | Unique session identifier           |
| agent_id      | string | Agent that owns this session        |
| original_goal | string | Agent's stated goal                 |
| risk_score    | float  | Current cumulative risk score       |

### ToolCallOut

| Field      | Type        | Description                            |
|------------|-------------|----------------------------------------|
| tool_name  | string      | Name of the tool called                |
| tool_input | object      | Arguments passed to the tool           |
| verdict    | string      | Security verdict for this call         |
| risk_score | float       | Cumulative risk after this call        |
| risk_delta | float       | Risk contribution of this call         |
| result     | object/null | Tool execution result (if executed)    |
| reasons    | string[]    | Explanations for the verdict           |

### MessageOut

| Field      | Type          | Description                       |
|------------|---------------|-----------------------------------|
| role       | string        | `user` or `assistant`             |
| content    | string        | Message text                      |
| tool_calls | ToolCallOut[] | Tool calls made in this message   |

### AgentOut

| Field       | Type     | Description                                          |
|-------------|----------|------------------------------------------------------|
| agent_id    | string   | Unique agent identifier                              |
| name        | string   | Human-readable agent name                            |
| role        | string   | Agent role: `research`, `code`, `communication`, `financial`, `admin` |
| permissions | string[] | Tool permission patterns (glob syntax)               |
| is_locked   | bool     | Whether the agent is locked out                      |

### TraceOut

| Field       | Type     | Description                                    |
|-------------|----------|------------------------------------------------|
| trace_id    | string   | Unique trace identifier                        |
| session_id  | string   | Session this trace belongs to                  |
| agent_id    | string   | Agent that made the call                       |
| tool_name   | string   | Tool that was called                           |
| verdict     | string   | `allow`, `block`, `challenge`, `sandbox`, `pause` |
| risk_score  | float    | Cumulative risk score after this call          |
| risk_delta  | float    | Risk contribution of this call                 |
| explanation | string   | AI-generated explanation (Pro tier)            |
| timestamp   | string   | ISO 8601 timestamp                             |
| reasons     | string[] | List of reasons for the verdict                |

### RiskEventOut

| Field      | Type   | Description                            |
|------------|--------|----------------------------------------|
| risk_delta | float  | Risk score change                      |
| new_score  | float  | Cumulative score after this event      |
| tool_name  | string | Tool that triggered the change         |
| reason     | string | Human-readable explanation             |
| timestamp  | string | ISO 8601 timestamp                     |

### TaintEntryOut

| Field            | Type     | Description                                         |
|------------------|----------|-----------------------------------------------------|
| label            | string   | Taint category: `pii`, `credential`, `secret`, etc. |
| source_tool      | string   | Tool that introduced the taint                      |
| source_step      | int      | Session step when taint was introduced              |
| patterns_matched | string[] | Specific patterns detected                          |
| timestamp        | string   | ISO 8601 timestamp                                  |

### CheckResultOut

| Field             | Type        | Description                                        |
|-------------------|-------------|----------------------------------------------------|
| check_name        | string      | Pipeline check name (e.g., `injection`, `deterministic_risk`) |
| passed            | bool        | Whether the check passed                           |
| risk_contribution | float       | Risk score added by this check                     |
| reason            | string      | Explanation of the check result                    |
| metadata          | object      | Additional check-specific metadata                 |
| force_verdict     | string/null | If set, this check forced a specific verdict       |

### ApprovalRequestOut

| Field           | Type        | Description                                     |
|-----------------|-------------|-------------------------------------------------|
| id              | string      | Unique approval ID                              |
| session_id      | string      | Session context                                 |
| agent_id        | string      | Agent that made the call                        |
| tool_name       | string      | Blocked tool name                               |
| tool_input      | object      | Tool arguments                                  |
| original_goal   | string      | Agent's declared goal                           |
| verdict         | string      | Guardian verdict that triggered the review      |
| risk_score      | float       | Session risk score at time of block             |
| risk_delta      | float       | Risk delta of the blocked call                  |
| reasons         | string[]    | Verdict reasons                                 |
| check_results   | object[]    | Full pipeline check results                     |
| trace_id        | string      | Related security trace                          |
| status          | string      | `pending`, `approved`, or `rejected`            |
| decided_by      | string/null | Identity of the decision maker                  |
| decided_at      | string/null | ISO 8601 timestamp of the decision              |
| decision_reason | string      | Justification for the decision                  |
| tool_result     | object/null | Tool output (populated only when approved)      |
| created_at      | string      | ISO 8601 timestamp of creation                  |
| expires_at      | string/null | ISO 8601 expiration time (null if no expiry)    |

### ApprovalDecisionOut

| Field           | Type        | Description                                     |
|-----------------|-------------|-------------------------------------------------|
| id              | string      | Approval ID                                     |
| status          | string      | `approved` or `rejected`                        |
| decided_by      | string/null | Identity of the decision maker                  |
| decided_at      | string/null | ISO 8601 timestamp of the decision              |
| decision_reason | string      | Justification for the decision                  |
| tool_result     | object/null | Tool output (only set for approved requests)    |

### ToolOut

| Field           | Type   | Description                                          |
|-----------------|--------|------------------------------------------------------|
| id              | string | Unique tool identifier (e.g., `tool-a1b2c3d4e5f6`)  |
| name            | string | Tool name                                            |
| description     | string | Human-readable description                           |
| type            | string | Tool type: `webhook` or `mcp`                        |
| endpoint        | string | Webhook URL (empty for MCP tools)                    |
| method          | string | HTTP method for webhook calls                        |
| auth_type       | string | Authentication type: `none`, `bearer`, `api_key`, `hmac` |
| input_schema    | object | JSON Schema describing expected input                |
| timeout_seconds | float  | Request timeout in seconds                           |
| mcp_server_name | string | MCP server name (empty for webhook tools)            |
| is_active       | bool   | Whether the tool is active                           |
| created_at      | string | ISO 8601 creation timestamp                          |
| updated_at      | string | ISO 8601 last-update timestamp                       |

### ToolTestResponse

| Field     | Type   | Description                                    |
|-----------|--------|------------------------------------------------|
| success   | bool   | `true` if the tool executed without error      |
| result    | object | Raw output from the tool execution             |
| tool_name | string | Name of the tool that was tested               |

### HealthOut

| Field           | Type   | Description                                      |
|-----------------|--------|--------------------------------------------------|
| status          | string | Server status (`"ok"`)                           |
| total_requests  | int    | Cumulative requests since startup                |
| error_rate      | float  | Failed/total request ratio                       |
| circuit_breaker | string | `closed`, `open`, or `half_open`                 |

### HealthFullOut

Extends `HealthOut` with:

| Field               | Type   | Description                              |
|---------------------|--------|------------------------------------------|
| successful_requests | int    | Requests completed without error         |
| failed_requests     | int    | Requests that raised an error            |
| avg_latency_ms      | float  | Mean latency in milliseconds             |
| p95_latency_ms      | float  | 95th percentile latency in milliseconds  |
| active_sessions     | int    | Sessions currently tracked in memory     |

---

## Error Responses

All endpoints may return the following error responses:

### 401 Unauthorized

Returned when `JANUS_API_KEY` is set and the request is missing or has an invalid Bearer token.

```json
{
  "detail": "Invalid or missing API key"
}
```

### 404 Not Found

Returned when a requested resource does not exist.

```json
{
  "detail": "Approval not found"
}
```

### 422 Unprocessable Entity

Returned when the request body fails Pydantic validation.

```json
{
  "detail": [
    {
      "loc": ["body", "session_id"],
      "msg": "Field required",
      "type": "missing"
    }
  ]
}
```

### 500 Internal Server Error

Returned on unhandled exceptions. Check server logs for details.

---

## Endpoint Summary

| Method | Path                                       | Auth     | Description                          |
|--------|--------------------------------------------|----------|--------------------------------------|
| GET    | `/api/health`                              | No       | Basic health check                   |
| GET    | `/api/health/full`                         | Yes      | Detailed health metrics              |
| POST   | `/api/sessions`                            | Yes      | Create a new session                 |
| GET    | `/api/sessions`                            | Yes      | List all sessions                    |
| POST   | `/api/chat`                                | Yes      | Send chat message                    |
| GET    | `/api/sessions/{session_id}/messages`      | Yes      | Get message history                  |
| GET    | `/api/sessions/{session_id}/events`        | Yes      | Get risk events                      |
| GET    | `/api/sessions/{session_id}/taint`         | Yes      | Get taint entries                    |
| GET    | `/api/sessions/{session_id}/proof`         | Yes      | Get proof chain                      |
| POST   | `/api/sessions/{session_id}/proof/verify`  | Yes      | Verify proof chain                   |
| GET    | `/api/agents`                              | Yes      | List agents                          |
| POST   | `/api/evaluate`                            | Yes      | Evaluate a tool call                 |
| GET    | `/api/tools`                               | Yes      | List registered tools                |
| POST   | `/api/tools`                               | Yes      | Register a new tool                  |
| GET    | `/api/tools/{tool_id}`                     | Yes      | Get tool by ID                       |
| PUT    | `/api/tools/{tool_id}`                     | Yes      | Update a tool                        |
| DELETE | `/api/tools/{tool_id}`                     | Yes      | Delete a tool                        |
| POST   | `/api/tools/{tool_id}/test`                | Yes      | Test-execute a tool                  |
| GET    | `/api/traces`                              | Yes      | Query security traces                |
| GET    | `/api/export/traces`                       | Yes      | Export traces as file                |
| GET    | `/api/threat-intel`                        | Yes      | List threat patterns                 |
| GET    | `/api/threat-intel/stats`                  | Yes      | Threat intel statistics              |
| GET    | `/api/approvals`                           | Yes      | List approval requests               |
| GET    | `/api/approvals/stats`                     | Yes      | Approval statistics                  |
| GET    | `/api/approvals/{approval_id}`             | Yes      | Get single approval                  |
| POST   | `/api/approvals/{approval_id}/approve`     | Yes      | Approve a request                    |
| POST   | `/api/approvals/{approval_id}/reject`      | Yes      | Reject a request                     |
| GET    | `/api/license/status`                      | No       | Current license tier                 |
| POST   | `/api/license/activate`                    | No       | Activate a license key               |
| POST   | `/api/billing/checkout`                    | No       | Create Stripe checkout               |
| GET    | `/api/billing/session/{session_id}`        | No       | Lookup checkout session              |
| POST   | `/api/webhooks/stripe`                     | Stripe   | Stripe webhook receiver              |
| WS     | `/api/ws/session/{session_id}`             | No       | Session event stream                 |
| WS     | `/api/ws/monitor`                          | No       | Global event stream                  |
