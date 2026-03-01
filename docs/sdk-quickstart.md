# Janus SDK Quickstart

This guide covers integrating Janus into your Python application as a security layer for AI agent tool calls. Janus intercepts tool invocations, evaluates risk through a multi-stage pipeline, and returns a verdict before execution proceeds.

---

## Table of Contents

- [Installation](#installation)
- [High-Level SDK (Recommended)](#high-level-sdk-recommended)
  - [Basic Usage](#basic-usage)
  - [create_janus() Parameters](#create_janus-parameters)
  - [GuardResult Fields](#guardresult-fields)
- [Low-Level SDK](#low-level-sdk)
- [Verdicts](#verdicts)
- [Human-in-the-Loop Approvals](#human-in-the-loop-approvals)
- [Quick Integration (Recommended)](#quick-integration-recommended)
  - [LangChain](#langchain)
  - [OpenAI Function Calling](#openai-function-calling)
  - [CrewAI](#crewai)
- [Framework Integrations (Detailed)](#framework-integrations-detailed)
  - [LangChain (Manual)](#langchain-manual)
  - [OpenAI Functions (Manual)](#openai-functions-manual)
  - [CrewAI (Manual)](#crewai-manual)
  - [MCP Server Wrapper](#mcp-server-wrapper)
- [Environment Variables](#environment-variables)

---

## Installation

```bash
pip install janus-security
```

To include framework integrations (LangChain, OpenAI, CrewAI, MCP):

```bash
pip install janus-security[integrations]
```

---

## High-Level SDK (Recommended)

The `create_janus()` factory is the fastest way to get started. It handles agent registration, session creation, database setup, and Guardian initialization in a single call.

### Basic Usage

```python
from janus import create_janus

janus = await create_janus(
    agent_id="my-agent",
    agent_name="My Agent",
    agent_role="code",
    permissions=["read_*", "search_*"],
    original_goal="Summarize quarterly earnings",
)

# Guard a tool call before executing it
result = await janus.guard("read_file", {"path": "/reports/q4.pdf"})

if result.allowed:
    output = execute_tool("read_file", {"path": "/reports/q4.pdf"})
else:
    print(f"Blocked: {result.reason}")
    if result.approval_id:
        print(f"Pending human review: {result.approval_id}")

# Cleanup when done
await janus.close()
```

Every call to `janus.guard()` runs the tool invocation through the full security pipeline -- injection detection, identity verification, permission checks, risk scoring, drift analysis, and more -- and returns a `GuardResult` with the verdict.

### create_janus() Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `agent_id` | `str` | `"default-agent"` | Unique identifier for the agent. |
| `agent_name` | `str` | `"Agent"` | Human-readable display name. |
| `agent_role` | `str` | `"code"` | Agent role. One of: `code`, `research`, `financial`, `admin`, `data_analysis`, `communication`, `custom`. |
| `permissions` | `list[str] \| None` | `None` | Glob patterns for allowed tools. Defaults to `["*"]` (all tools). |
| `session_id` | `str \| None` | `None` | Session identifier. Auto-generated if not provided. |
| `original_goal` | `str` | `""` | The agent's stated objective. Used by drift detection to flag deviations. |
| `config` | `JanusConfig \| None` | `None` | Full configuration override. Uses defaults if not provided. |
| `db_path` | `str \| None` | `None` | Path to the SQLite database. Falls back to env var `JANUS_DB_PATH`, then `":memory:"`. |
| `api_key` | `str \| None` | `None` | Anthropic API key for LLM-powered checks. Falls back to env var `ANTHROPIC_API_KEY`. |

### GuardResult Fields

| Field | Type | Description |
|---|---|---|
| `allowed` | `bool` | Whether the tool call is safe to execute. |
| `verdict` | `str` | One of `"allow"`, `"block"`, `"challenge"`, `"sandbox"`, `"pause"`. |
| `risk_score` | `float` | Cumulative session risk score (0--100). |
| `risk_delta` | `float` | Risk contribution of this individual call. |
| `reasons` | `list[str]` | List of reasons explaining the verdict. |
| `recommended_action` | `str` | Human-readable recommendation for what to do next. |
| `reason` | `str` | Alias for `recommended_action`. |
| `approval_id` | `str \| None` | Set when a human review request has been created. |
| `trace_id` | `str` | Unique trace identifier for audit logging. |

---

## Low-Level SDK

For full control over configuration, agent registration, and session management, use the Guardian class directly.

```python
from janus import (
    Guardian,
    JanusConfig,
    AgentIdentity,
    AgentRole,
    ToolPermission,
    AgentRegistry,
    Verdict,
)
from janus.storage.database import DatabaseManager
from janus.storage.session_store import InMemorySessionStore

# 1. Set up the database
config = JanusConfig()
db = DatabaseManager(":memory:")
await db.connect()
await db.apply_migrations()

# 2. Register the agent
registry = AgentRegistry(db)
agent = AgentIdentity(
    agent_id="agent-1",
    name="My Agent",
    role=AgentRole.CODE,
    permissions=[
        ToolPermission(tool_pattern="read_*"),
        ToolPermission(tool_pattern="search_*"),
    ],
)
await registry.register_agent(agent)

# 3. Create the Guardian
session_store = InMemorySessionStore()
guardian = await Guardian.from_config(
    config=config,
    registry=registry,
    session_store=session_store,
)

# 4. Guard tool calls
verdict = await guardian.wrap_tool_call(
    agent_id="agent-1",
    session_id="session-1",
    original_goal="Analyze data",
    tool_name="read_file",
    tool_input={"path": "/data.csv"},
)

if verdict.verdict == Verdict.ALLOW:
    result = execute_tool("read_file", {"path": "/data.csv"})
elif verdict.verdict == Verdict.BLOCK:
    print(f"Blocked: {verdict.reasons}")
```

Use the low-level SDK when you need to:

- Share a single Guardian instance across multiple agents or sessions.
- Customize the session store (e.g., use `PersistentSessionStore` for SQLite-backed sessions).
- Integrate with an existing database or registry.
- Fine-tune `JanusConfig` beyond the high-level defaults.

---

## Verdicts

Janus returns one of five verdicts for every guarded tool call:

| Verdict | Meaning | Typical Response |
|---|---|---|
| `allow` | The call is safe to execute. | Proceed with tool execution. |
| `block` | The call is denied due to excessive risk. | Do not execute. Log and notify. |
| `challenge` | The agent's identity needs verification. | Run identity verification before retrying. |
| `sandbox` | The call should run in an isolated environment. | Execute in a sandboxed context. |
| `pause` | A human must review and approve the call. | Wait for approval via `approval_id`. |

---

## Human-in-the-Loop Approvals

When a tool call triggers a judgment-call verdict -- such as gradual risk accumulation, goal drift, or a borderline classification -- Janus can create an approval request for human review instead of outright blocking.

The `approval_id` field on `GuardResult` is populated when an approval request has been created. Use this ID to check status or present a review interface to an operator.

```python
result = await janus.guard("execute_code", {"code": "rm -rf /tmp/cache"})

if not result.allowed and result.approval_id:
    print(f"Awaiting human review: {result.approval_id}")
    # Present to operator, poll for approval, etc.
```

**Hard blocks never generate approvals.** The following violation types are auto-rejected and will not produce an `approval_id`:

- Permission violations (tool not in the agent's allowed patterns)
- Prompt injection detection
- Identity check failures

---

## Quick Integration (Recommended)

Each framework integration provides a one-call factory function that handles Guardian setup, agent registration, session creation, and tool wrapping internally. This is the fastest way to add Janus security to an existing agent.

Install the integrations extra:

```bash
pip install janus-security[integrations]
```

### LangChain

```python
from janus.integrations.langchain import create_langchain_guard

# Wrap all your tools in one call
guarded = await create_langchain_guard(
    [search_tool, db_tool, email_tool],
    agent_id="my-agent",
    agent_role="research",
    original_goal="Analyze customer data",
)
agent = create_react_agent(llm, guarded)
```

### OpenAI Function Calling

```python
from janus.integrations.openai import create_openai_guard

proxy = await create_openai_guard(
    {"search": search_fn, "execute": exec_fn},
    agent_id="my-agent",
)
result = await proxy.execute("search", '{"query": "test"}')
if result.allowed:
    # feed result.output back to OpenAI
    ...
```

### CrewAI

```python
from janus.integrations.crewai import create_crewai_tool

search = await create_crewai_tool(
    "search", "Search the web", my_search_fn,
    agent_id="researcher",
)
```

All factory functions accept the same optional keyword arguments: `agent_name`, `agent_role`, `permissions`, `session_id`, `original_goal`, `config`, `db_path`, `api_key`. These mirror the parameters of `create_janus()` documented above.

---

## Framework Integrations (Detailed)

> For a simpler setup, see [Quick Integration (Recommended)](#quick-integration-recommended) above.

Install the integrations extra to use these wrappers:

```bash
pip install janus-security[integrations]
```

### LangChain (Manual)

> For a simpler setup, see [Quick Integration](#quick-integration-recommended) above.

Wrap any LangChain tool with `JanusToolWrapper` to guard invocations automatically.

```python
from janus.integrations.langchain import JanusToolWrapper

wrapped = JanusToolWrapper(
    tool=my_langchain_tool,
    guardian=guardian,
    agent_id="agent-1",
    session_id="session-1",
)

result = await wrapped.ainvoke({"query": "..."})
```

### OpenAI Functions (Manual)

> For a simpler setup, see [Quick Integration](#quick-integration-recommended) above.

Use `JanusFunctionProxy` to guard OpenAI function-calling workflows.

```python
from janus.integrations.openai import JanusFunctionProxy

proxy = JanusFunctionProxy(
    guardian=guardian,
    agent_id="agent-1",
    session_id="session-1",
)

proxy.register_function(
    "search",
    description="Search the web",
    parameters={...},
    handler=my_handler,
)

result = await proxy.execute("search", {"query": "..."})
```

### CrewAI (Manual)

> For a simpler setup, see [Quick Integration](#quick-integration-recommended) above.

Wrap CrewAI tool functions with `JanusCrewTool`.

```python
from janus.integrations.crewai import JanusCrewTool

tool = JanusCrewTool(
    name="search",
    description="Search the web",
    fn=my_search_function,
    guardian=guardian,
    agent_id="agent-1",
    session_id="session-1",
)

result = await tool.run({"query": "..."})
```

### MCP Server Wrapper

Guard tools exposed through a Model Context Protocol server.

```python
from janus.integrations.mcp import JanusMCPServer, MCPToolDefinition

server = JanusMCPServer(
    guardian=guardian,
    agent_id="agent-1",
    session_id="session-1",
)

server.add_tool(MCPToolDefinition(
    name="read_file",
    description="Read a file",
    input_schema={
        "type": "object",
        "properties": {"path": {"type": "string"}},
    },
    handler=my_read_handler,
))

result = await server.call_tool("read_file", {"path": "/test.txt"})
```

---

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key. Enables LLM-powered pipeline checks (drift detection, risk classifier). | None (LLM checks disabled) |
| `JANUS_DB_PATH` | Path to the SQLite database for persistent sessions and audit trails. | `":memory:"` |
| `JANUS_MOCK_TOOLS` | Set to `true` to use mock tool execution for testing. | `false` |
| `JANUS_DEV_MODE` | Set to `true` to auto-activate PRO tier in development. | `false` |
| `JANUS_CORS_ORIGINS` | Comma-separated CORS origins for the web server. | `http://localhost:3000,http://localhost:5173` |

Both `ANTHROPIC_API_KEY` and `JANUS_DB_PATH` can be overridden by passing `api_key` and `db_path` directly to `create_janus()`.
