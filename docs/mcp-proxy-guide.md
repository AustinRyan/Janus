# Janus MCP Proxy Guide

The `janus-proxy` command runs a security-gated MCP middleware that sits between MCP clients (Claude Desktop, Cursor, Azure AI, etc.) and upstream MCP tool servers. Every tool call passes through the Janus Guardian pipeline before reaching the upstream server, providing real-time risk scoring, drift detection, taint tracking, and human-in-the-loop approvals.

---

## Table of Contents

- [Installation](#installation)
- [How It Works](#how-it-works)
- [Configuration](#configuration)
  - [Root Configuration](#root-configuration)
  - [Agent Identity](#agent-identity)
  - [Session Management](#session-management)
  - [Transport](#transport)
  - [Upstream Servers](#upstream-servers)
  - [Janus Overrides](#janus-overrides)
- [Configuration Reference](#configuration-reference)
- [Running the Proxy](#running-the-proxy)
  - [stdio Mode (Claude Desktop / Cursor)](#stdio-mode-claude-desktop--cursor)
  - [HTTP Mode (Network)](#http-mode-network)
- [Features](#features)
  - [Tool Namespacing](#tool-namespacing)
  - [Environment Variable Resolution](#environment-variable-resolution)
  - [Taint Scanning](#taint-scanning)
  - [Human-in-the-Loop Approvals](#human-in-the-loop-approvals)
  - [Event Broadcasting](#event-broadcasting)
  - [LLM-Powered Checks](#llm-powered-checks)
- [Verdict Behavior](#verdict-behavior)
- [Environment Variables](#environment-variables)
- [Examples](#examples)
  - [Minimal Configuration](#minimal-configuration)
  - [Multi-Server with Namespacing](#multi-server-with-namespacing)
  - [Production Configuration](#production-configuration)
- [Troubleshooting](#troubleshooting)

---

## Installation

The MCP proxy requires the `integrations` extra:

```bash
pip install janus-security[integrations]
```

This installs the `mcp` SDK alongside the core Janus package. The `janus-proxy` command becomes available on your PATH after installation.

---

## How It Works

```
MCP Client (Claude Desktop, Cursor, etc.)
    |
    | tool call
    v
janus-proxy (MCP Server + Guardian pipeline)
    |
    | if ALLOW
    v
Upstream MCP Server (filesystem, github, etc.)
    |
    | result
    v
janus-proxy (taint scanning on result)
    |
    | result or blocked message
    v
MCP Client
```

The proxy operates as follows:

1. **Registers as an MCP server** that the client connects to (via stdio or HTTP).
2. **Discovers tools** from all configured upstream MCP servers on startup.
3. **Exposes all upstream tools** to the client, optionally namespaced to prevent collisions.
4. **Intercepts every tool call** through the Guardian security pipeline (injection detection, identity verification, permission checks, risk scoring, drift detection, taint tracking, and more).
5. **If ALLOW:** forwards the call to the upstream server, scans the result for sensitive data taints, and returns the result to the client.
6. **If BLOCK/CHALLENGE/PAUSE:** returns a blocked or challenge message with the verdict, risk score, reasons, and an optional `approval_id` for human review.

---

## Configuration

The proxy is configured via a TOML file, typically named `janus-proxy.toml`. Pass the path as the first argument to `janus-proxy`, or omit it to use `janus-proxy.toml` in the current directory.

### Root Configuration

```toml
server_name = "janus-proxy"        # MCP server name advertised to clients
server_version = "0.1.0"           # Version string
log_level = "INFO"                 # Logging level: DEBUG, INFO, WARNING, ERROR
database_path = ":memory:"         # SQLite path; use a file path for persistence
```

### Agent Identity

Defines the identity that Janus assigns to the connecting MCP client. This identity is used for permission checks, risk tracking, and drift detection.

```toml
[agent]
agent_id = "claude-desktop"
name = "Claude Desktop"
role = "code"                                    # code, research, financial, admin, etc.
permissions = ["read_*", "write_*", "search_*"]  # Glob patterns for allowed tools
original_goal = "Software development assistant" # Used for semantic drift detection
```

### Session Management

Controls how tool call history and risk scores are tracked across invocations.

```toml
[session]
session_id_prefix = "claude-desktop"
# persistent_session_id = "my-session"  # Use a fixed session ID instead of auto-generated
```

When `persistent_session_id` is set, the proxy reuses the same session ID across restarts. Otherwise, it generates a unique ID using the prefix and a random suffix (e.g., `claude-desktop-a1b2c3d4`).

### Transport

Configures how the proxy itself is served to the MCP client.

```toml
[transport]
type = "stdio"          # "stdio" for Claude Desktop/Cursor, "http" for network access
# host = "127.0.0.1"   # Only used with http transport
# port = 8100           # Only used with http transport
```

### Upstream Servers

Each `[[upstream_servers]]` block defines an MCP server the proxy connects to and proxies tools from.

**stdio transport** (spawns a subprocess):

```toml
[[upstream_servers]]
name = "filesystem"
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"]
timeout = 30.0
```

**HTTP transport** (connects to a running server):

```toml
[[upstream_servers]]
name = "remote-api"
transport = "http"
url = "http://localhost:9000/mcp"
timeout = 60.0
```

**With namespacing and environment variables:**

```toml
[[upstream_servers]]
name = "github"
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
namespace = "gh"

[upstream_servers.env]
GITHUB_TOKEN = "${GITHUB_TOKEN}"
```

### Janus Overrides

Optional overrides for Guardian security configuration. These map directly to `JanusConfig` fields.

```toml
[janus]

[janus.risk]
lock_threshold = 80.0
sandbox_threshold = 60.0

[janus.policy]
keyword_amplifiers = { "rm" = 25.0, "DROP TABLE" = 40.0 }
```

---

## Configuration Reference

### ProxyConfig (root)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server_name` | `str` | `"janus-proxy"` | MCP server name advertised to clients |
| `server_version` | `str` | `"0.1.0"` | Version string |
| `upstream_servers` | `list[UpstreamServerConfig]` | `[]` | Upstream MCP servers to proxy |
| `agent` | `AgentConfig` | (see below) | Identity of the connecting client |
| `session` | `SessionConfig` | (see below) | Session management settings |
| `transport` | `ProxyTransportConfig` | (see below) | How the proxy is served |
| `janus` | `dict` | `{}` | Optional `JanusConfig` overrides |
| `database_path` | `str` | `":memory:"` | SQLite database path |
| `log_level` | `str` | `"INFO"` | Logging level |

### UpstreamServerConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | *required* | Server identifier (used in log messages and tool descriptions) |
| `transport` | `"stdio"` or `"http"` | `"stdio"` | Connection type |
| `command` | `str` | `""` | Command to run (stdio transport only) |
| `args` | `list[str]` | `[]` | Command arguments (stdio transport only) |
| `env` | `dict[str, str]` | `{}` | Environment variables; supports `${VAR}` resolution |
| `url` | `str` | `""` | Server URL (http transport only) |
| `namespace` | `str` | `""` | Tool name prefix (e.g., `"gh"` produces `gh__tool_name`) |
| `timeout` | `float` | `30.0` | Request timeout in seconds |

### AgentConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `agent_id` | `str` | `"mcp-proxy-agent"` | Unique identifier for the agent |
| `name` | `str` | `"MCP Proxy Agent"` | Display name |
| `role` | `str` | `"code"` | Agent role (code, research, financial, admin, etc.) |
| `permissions` | `list[str]` | `["*"]` | Tool permission glob patterns |
| `original_goal` | `str` | `""` | Stated goal; used for semantic drift detection |

### SessionConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_id_prefix` | `str` | `"mcp-proxy"` | Prefix for auto-generated session IDs |
| `persistent_session_id` | `str` | `""` | Fixed session ID (overrides auto-generation) |

### ProxyTransportConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `"stdio"` or `"http"` | `"stdio"` | Transport type |
| `host` | `str` | `"127.0.0.1"` | Bind address (http only) |
| `port` | `int` | `8100` | Listen port (http only) |

---

## Running the Proxy

### stdio Mode (Claude Desktop / Cursor)

stdio mode is designed for MCP clients that manage the proxy as a subprocess.

```bash
janus-proxy /path/to/janus-proxy.toml
```

If no path argument is provided, the proxy looks for `janus-proxy.toml` in the current directory.

**Claude Desktop configuration** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "janus": {
      "command": "janus-proxy",
      "args": ["/path/to/janus-proxy.toml"]
    }
  }
}
```

**Cursor configuration** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "janus": {
      "command": "janus-proxy",
      "args": ["/path/to/janus-proxy.toml"]
    }
  }
}
```

### HTTP Mode (Network)

HTTP mode starts a Starlette/Uvicorn server that exposes an MCP endpoint at `/mcp`. This is useful for network-accessible deployments or clients that connect over HTTP.

```toml
[transport]
type = "http"
host = "0.0.0.0"
port = 8100
```

```bash
janus-proxy janus-proxy.toml
# Serves at http://0.0.0.0:8100/mcp
```

The HTTP transport uses the MCP Streamable HTTP protocol via `StreamableHTTPSessionManager`.

---

## Features

### Tool Namespacing

When `namespace` is set on an upstream server, all tools from that server are prefixed with the namespace and a double underscore separator:

- Server `github` with `namespace = "gh"` exposes tools as `gh__create_issue`, `gh__search_repos`, etc.
- Server `filesystem` with no namespace exposes tools with their original names.

This prevents name collisions when multiple upstream servers expose tools with the same name. Tool descriptions are also prefixed with the server name in square brackets (e.g., `[github] Create a new issue`).

If a name collision is detected (two servers exposing the same proxy tool name), the proxy logs a warning and the later server's tool overwrites the mapping.

### Environment Variable Resolution

Use `${VAR}` syntax in upstream server `env` values to resolve variables from the system environment at startup:

```toml
[upstream_servers.env]
GITHUB_TOKEN = "${GITHUB_TOKEN}"
API_KEY = "${MY_API_KEY}"
```

If the referenced environment variable is not set, the value resolves to an empty string. The resolved environment is merged with the current process environment when spawning stdio subprocesses.

### Taint Scanning

When a tool call is allowed and the upstream server returns a result, the proxy scans the output for sensitive data patterns through the Guardian's taint tracker. This detects:

- Personally identifiable information (PII)
- Credentials and API keys
- Financial data patterns

Taint entries are recorded against the session and factor into subsequent risk assessments. This ensures that even if a tool call is individually low-risk, the accumulation of sensitive data in a session is tracked.

### Human-in-the-Loop Approvals

When Guardian issues a non-ALLOW verdict that represents a judgment call (e.g., high risk accumulation, semantic drift, suspicious patterns), the proxy creates an approval request. The blocked response includes the `approval_id`:

```
[JANUS CHALLENGE] Tool 'write_file' requires verification. Risk: 67.5.
Reasons: Risk score above challenge threshold; semantic drift detected.
Action: require_approval. Approval ID: apr_a1b2c3d4.
A human reviewer has been notified and will approve or reject this action.
```

A security team member can approve or reject the request via the Janus Monitor dashboard or the REST API.

**Hard blocks do NOT create approval requests.** The following check types are treated as hard policy violations and are auto-rejected:

- Permission denied (identity/permission check)
- Prompt injection detected
- Identity verification failure

Only soft blocks and challenges (risk accumulation, drift, taint escalation) are routed for human review.

### Event Broadcasting

Every verdict is broadcast as a WebSocket event with `integration: "mcp"` in its metadata. Events include:

- Verdict (`allow`, `block`, `challenge`, `sandbox`, `pause`)
- Risk score and risk delta
- Tool name and input
- Drift score and ITDR signals
- Full check results from each pipeline stage
- Trace ID for forensic correlation

These events are visible in real time on the Janus Monitor dashboard.

### LLM-Powered Checks

When the `ANTHROPIC_API_KEY` environment variable is set, the proxy enables LLM-powered security checks:

- **Security Classifier:** Uses an LLM to classify tool calls that pass deterministic checks but may still be suspicious.
- **Semantic Drift Detector:** Compares each tool call against the agent's `original_goal` to detect goal drift over time.

Without the API key, the proxy runs with rule-based checks only (deterministic risk scoring, permission checks, injection detection, etc.).

---

## Verdict Behavior

The proxy handles each Guardian verdict differently:

| Verdict | Behavior |
|---------|----------|
| `ALLOW` | Forwards the call to the upstream server; scans the result for taints; returns the result to the client. |
| `CHALLENGE` | Returns a `[JANUS CHALLENGE]` message with risk score, reasons, and recommended action. Creates an approval request if the block is a judgment call. |
| `BLOCK` | Returns a `[JANUS BLOCKED]` message with verdict, risk score, and reasons. Creates an approval request only for soft blocks. |
| `SANDBOX` | Returns a `[JANUS BLOCKED]` message. Does not create an approval request (sandboxed execution is handled separately). |
| `PAUSE` | Returns a `[JANUS BLOCKED]` message. Creates an approval request for human review. |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | No | Enables LLM-powered security checks (classifier and drift detection). Without this, only rule-based checks run. |
| Any `${VAR}` references | Depends on config | Variables referenced in upstream server `env` blocks are resolved from the system environment at startup. |
| `JANUS_CONFIG_PATH` | No | Alternative path for Janus core configuration (used by the Guardian internally). |
| `JANUS_DB_PATH` | No | Default database path for Guardian (overridden by `database_path` in proxy config). |

---

## Examples

### Minimal Configuration

A bare-minimum setup proxying a single filesystem server:

```toml
[[upstream_servers]]
name = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"]
```

Everything else uses defaults: stdio transport, in-memory database, wildcard permissions, auto-generated session ID.

### Multi-Server with Namespacing

Proxy filesystem and GitHub servers with distinct namespaces:

```toml
server_name = "janus-dev-proxy"
database_path = "/tmp/janus-proxy.db"

[agent]
agent_id = "claude-desktop"
name = "Claude Desktop"
role = "code"
permissions = ["read_*", "write_*", "gh__*"]
original_goal = "Software development assistant for my projects"

[[upstream_servers]]
name = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"]

[[upstream_servers]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
namespace = "gh"

[upstream_servers.env]
GITHUB_TOKEN = "${GITHUB_TOKEN}"
```

### Production Configuration

A more locked-down setup with custom risk thresholds and HTTP transport:

```toml
server_name = "janus-prod-proxy"
server_version = "1.0.0"
log_level = "WARNING"
database_path = "/var/lib/janus/proxy.db"

[agent]
agent_id = "prod-agent"
name = "Production Agent"
role = "code"
permissions = ["read_*", "search_*"]
original_goal = "Read-only code review and search assistant"

[session]
persistent_session_id = "prod-session-001"

[transport]
type = "http"
host = "127.0.0.1"
port = 8100

[[upstream_servers]]
name = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/opt/repos"]
timeout = 10.0

[janus]
[janus.risk]
lock_threshold = 60.0
sandbox_threshold = 40.0

[janus.policy]
keyword_amplifiers = { "rm -rf" = 50.0, "DROP TABLE" = 40.0, "chmod 777" = 30.0 }
```

---

## Troubleshooting

**"MCP support requires the integrations extra"**
The `mcp` package is not installed. Run `pip install janus-security[integrations]`.

**"config_not_found" warning at startup**
The TOML file path passed to `janus-proxy` does not exist. The proxy falls back to default configuration. Verify the file path.

**"upstream_connect_failed" error**
The proxy could not connect to an upstream MCP server. Common causes:
- The `command` is not on your PATH (e.g., `npx` not installed).
- The upstream server package is not available (check `args` for the correct package name).
- For HTTP transport, the upstream server is not running at the specified `url`.

The proxy continues to start even if one upstream fails; only the failed server's tools are unavailable.

**"tool_name_collision" warning**
Two upstream servers expose tools with the same proxy name. Use `namespace` on one or both servers to disambiguate.

**No LLM checks running**
Set the `ANTHROPIC_API_KEY` environment variable before starting the proxy. Without it, only deterministic rule-based checks execute.

**Environment variables not resolving**
Only the `${VAR}` pattern (the entire value must be `${VAR_NAME}`) is resolved. Partial interpolation like `prefix_${VAR}_suffix` is not supported. Set the full value in the system environment instead.
