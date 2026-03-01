# Real Tool Execution System Design

**Date:** 2026-02-26
**Status:** Approved

## Problem

All tool execution in Janus is mocked. `MockToolExecutor` returns hardcoded fake data. Customers cannot connect their real tools — the dashboard chat, HITL approval flow, and tool testing all use simulated results.

## Solution

Replace `MockToolExecutor` with a **ToolRegistry + ToolExecutor** system supporting two backends:

1. **Webhook tools** — Customer registers an HTTP endpoint, Janus POSTs to it
2. **MCP tools** — Customer connects MCP servers, Janus forwards via UpstreamManager

Mock tools remain available via `JANUS_MOCK_TOOLS=true` env var for testing/demo.

## Architecture

```
Customer registers tools (API or Dashboard UI)
         │
         ▼
   ┌─────────────┐
   │ Tool Registry│  ← SQLite: registered_tools table
   │  (database)  │
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │ToolExecutor  │  ← Routes by tool type
   │  (router)    │
   └──┬───────┬──┘
      │       │
      ▼       ▼
  Webhook   MCP
  Backend   Backend
      │       │
      ▼       ▼
  POST to   Forward to
  customer  real MCP
  endpoint  server
```

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS registered_tools (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    type TEXT NOT NULL CHECK(type IN ('webhook', 'mcp')),
    endpoint TEXT,
    method TEXT DEFAULT 'POST',
    auth_type TEXT DEFAULT 'none' CHECK(auth_type IN ('none', 'bearer', 'api_key', 'hmac')),
    auth_credential TEXT DEFAULT '',
    input_schema TEXT DEFAULT '{}',
    timeout_seconds REAL DEFAULT 30.0,
    mcp_server_name TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

## New Files

- `janus/tools/__init__.py` — Package init
- `janus/tools/registry.py` — ToolRegistry (CRUD against DB)
- `janus/tools/executor.py` — ToolExecutor protocol + WebhookExecutor + router
- `janus/tools/models.py` — RegisteredTool dataclass + Pydantic schemas
- `janus/web/tool_routes.py` — REST API for tool management
- `frontend/src/app/tools/page.tsx` — Dashboard tools management UI

## Modified Files

- `janus/storage/database.py` — Add migration for registered_tools table
- `janus/web/app.py` — Wire ToolExecutor into AppState, pass to ChatAgent/ApprovalManager
- `janus/web/agent.py` — Accept ToolExecutor instead of MockToolExecutor
- `janus/core/approval.py` — Use ToolExecutor for post-approval execution

## API Endpoints

- `GET /api/tools` — List registered tools
- `POST /api/tools` — Register a new tool
- `GET /api/tools/{tool_id}` — Get tool details
- `PUT /api/tools/{tool_id}` — Update tool config
- `DELETE /api/tools/{tool_id}` — Remove a tool
- `POST /api/tools/{tool_id}/test` — Test-execute with sample input

## Mock Fallback

`JANUS_MOCK_TOOLS=true` → Use MockToolExecutor for all execution
`JANUS_MOCK_TOOLS` unset/false → Use real ToolExecutor with registered tools

## Security

- Auth credentials stored as env var references (e.g. `$MY_API_TOKEN`), resolved at call time
- Webhook calls include `X-Janus-Request-Id` and `X-Janus-Session-Id` headers
- 30s default timeout, configurable per tool
- Response body capped at 1MB
