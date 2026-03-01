# Janus Documentation

**Autonomous Security Layer for AI Agents**

Janus intercepts every tool call your AI agent makes, running it through an 11-stage security pipeline before it reaches the real tool. Permissions, prompt injection detection, risk scoring, drift detection, taint tracking, and human-in-the-loop approvals -- all in real time.

---

## Getting Started

| Guide | Description |
|-------|-------------|
| [SDK Quickstart](sdk-quickstart.md) | Integrate Janus into your Python agent in 3 lines |
| [MCP Proxy Guide](mcp-proxy-guide.md) | Protect Claude Desktop, Cursor, or any MCP client |
| [Deployment Guide](deployment.md) | Self-host Janus for production use |

## Reference

| Document | Description |
|----------|-------------|
| [Architecture Overview](architecture.md) | System design, pipeline, components, data flow |
| [API Reference](api-reference.md) | All REST API endpoints with request/response schemas |
| [Configuration Reference](configuration.md) | TOML config, environment variables, CLI commands, tuning |

## Additional

| Document | Description |
|----------|-------------|
| [Stripe Billing Setup](STRIPE_SETUP.md) | Configure Stripe for Pro license billing |
| [Test Cases](test-cases.md) | Security pipeline test scenarios |

---

## Quick Links

### Installation
```bash
pip install janus-security                    # Core
pip install janus-security[integrations]      # + LangChain, CrewAI, OpenAI, MCP
pip install janus-security[integrations,exporters,billing]  # Everything
```

### Start the Backend
```bash
ANTHROPIC_API_KEY=sk-ant-... janus serve
```

### Start the MCP Proxy
```bash
janus-proxy janus-proxy.toml
```

### Run Tests
```bash
pytest tests/ -q
```

### Use the SDK
```python
from janus import create_janus

janus = await create_janus(agent_id="my-agent", agent_role="code")
result = await janus.guard("execute_code", {"code": "print('hello')"})
if result.allowed:
    run_tool(...)
await janus.close()
```

---

## Security Pipeline (11 Checks)

| # | Check | Priority | Tier | Purpose |
|---|-------|----------|------|---------|
| 1 | Prompt Injection | 5 | Free | Regex-based injection detection |
| 2 | Identity | 10 | Free | Agent registration + lock status |
| 3 | Permission Scope | 20 | Free | Glob-based tool access control |
| 4 | Data Volume | 22 | Free | Bulk data access detection |
| 5 | Deterministic Risk | 25 | Free | Keyword, velocity, escalation scoring |
| 6 | Taint Analysis | 27 | Pro | PII/credential flow tracking |
| 7 | LLM Classifier | 30 | Pro | Contextual risk via Claude Haiku |
| 8 | Predictive Risk | 38 | Pro | Attack trajectory matching |
| 9 | Drift Detection | 40 | Pro | Semantic goal drift |
| 10 | Threat Intel | 55 | Free | Known attack pattern matching |
| 11 | ITDR | 60 | Free | Anomaly, collusion, escalation |

## Verdicts

| Verdict | Meaning |
|---------|---------|
| **ALLOW** | Safe to execute |
| **BLOCK** | Denied |
| **CHALLENGE** | Identity verification required |
| **SANDBOX** | Execute in isolation |
| **PAUSE** | Awaiting human approval |
