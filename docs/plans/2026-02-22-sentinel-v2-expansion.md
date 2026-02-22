# Sentinel V2 Expansion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a three-panel live demo UI (Next.js + FastAPI + WebSocket), all 4 integration adapters (LangChain, CrewAI, OpenAI Assistants, Claude MCP), and SIEM/observability exporters (Webhook, JSON, OpenTelemetry, Prometheus) to the existing Sentinel security layer.

**Architecture:** FastAPI backend serves as the bridge between the Next.js frontend and the existing Guardian. User chats with a Claude Sonnet worker agent; every tool call goes through Guardian.intercept(). Verdicts stream to the frontend over WebSocket in real-time. Integration adapters wrap external frameworks' tool execution with Guardian interception. Exporters hook into the verdict pipeline to ship events externally.

**Tech Stack:** Python 3.11+ (FastAPI, uvicorn, websockets, httpx), Next.js 14+ (React, Tailwind CSS, Recharts), existing Sentinel core (Guardian, SecurityVerdict, ToolCallRequest), Anthropic SDK (Claude Sonnet worker agent).

**Existing codebase key files:**
- `sentinel/core/guardian.py` — Guardian.intercept() and wrap_tool_call()
- `sentinel/core/decision.py` — SecurityVerdict, ToolCallRequest, Verdict enum, CheckResult
- `sentinel/config.py` — SentinelConfig (Pydantic models)
- `sentinel/forensics/recorder.py` — BlackBoxRecorder (trace storage/query)
- `sentinel/forensics/trace.py` — SecurityTrace dataclass
- `sentinel/circuit/health.py` — HealthMonitor, HealthMetrics
- `sentinel/storage/session_store.py` — InMemorySessionStore, SessionState
- `sentinel/cli/demo.py` — existing demo patterns

---

## Phase 1: FastAPI Backend + WebSocket Event System

### Task 1: Add backend dependencies to pyproject.toml

**Files:**
- Modify: `pyproject.toml`

**Step 1: Add new dependencies**

Add to the `dependencies` list in `pyproject.toml`:

```toml
dependencies = [
    "anthropic>=0.43.0",
    "pydantic>=2.6.0",
    "aiosqlite>=0.20.0",
    "click>=8.1.0",
    "rich>=13.7.0",
    "anyio>=4.2.0",
    "structlog>=24.1.0",
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.34.0",
    "websockets>=14.0",
    "httpx>=0.28.0",
    "python-multipart>=0.0.18",
]
```

Add optional dependency groups:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.12.0",
    "mypy>=1.8.0",
    "ruff>=0.2.0",
    "hypothesis>=6.98.0",
    "time-machine>=2.13.0",
    "httpx>=0.28.0",
]
integrations = [
    "langchain-core>=0.3.0",
    "crewai>=0.100.0",
    "openai>=1.60.0",
    "mcp>=1.0.0",
]
exporters = [
    "opentelemetry-api>=1.29.0",
    "opentelemetry-sdk>=1.29.0",
    "prometheus-client>=0.21.0",
]
```

**Step 2: Install dependencies**

Run: `source .venv/bin/activate && uv pip install -e ".[dev]"`

**Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "Add FastAPI, WebSocket, and exporter dependencies"
```

---

### Task 2: Create the WebSocket event broadcaster

**Files:**
- Create: `sentinel/web/__init__.py`
- Create: `sentinel/web/events.py`
- Create: `tests/test_web_events.py`

**Step 1: Create package init**

Create empty `sentinel/web/__init__.py`.

**Step 2: Write the failing test**

Create `tests/test_web_events.py`:

```python
"""Tests for the WebSocket event broadcaster."""
from __future__ import annotations

import asyncio
import pytest
from sentinel.web.events import EventBroadcaster, SecurityEvent


async def test_subscribe_receives_events() -> None:
    broadcaster = EventBroadcaster()
    received: list[SecurityEvent] = []

    async def listener():
        async for event in broadcaster.subscribe("session-1"):
            received.append(event)
            if len(received) >= 2:
                break

    task = asyncio.create_task(listener())

    event1 = SecurityEvent(
        event_type="verdict",
        session_id="session-1",
        data={"verdict": "allow", "risk_score": 5.0},
    )
    event2 = SecurityEvent(
        event_type="verdict",
        session_id="session-1",
        data={"verdict": "block", "risk_score": 85.0},
    )

    await broadcaster.publish(event1)
    await broadcaster.publish(event2)
    await asyncio.wait_for(task, timeout=2.0)

    assert len(received) == 2
    assert received[0].data["verdict"] == "allow"
    assert received[1].data["verdict"] == "block"


async def test_different_sessions_isolated() -> None:
    broadcaster = EventBroadcaster()
    received: list[SecurityEvent] = []

    async def listener():
        async for event in broadcaster.subscribe("session-A"):
            received.append(event)
            break

    task = asyncio.create_task(listener())

    # Publish to different session — should NOT be received
    await broadcaster.publish(SecurityEvent(
        event_type="verdict",
        session_id="session-B",
        data={"verdict": "allow"},
    ))

    # Publish to correct session — should be received
    await broadcaster.publish(SecurityEvent(
        event_type="verdict",
        session_id="session-A",
        data={"verdict": "block"},
    ))

    await asyncio.wait_for(task, timeout=2.0)
    assert len(received) == 1
    assert received[0].data["verdict"] == "block"


async def test_unsubscribe_cleans_up() -> None:
    broadcaster = EventBroadcaster()
    assert broadcaster.subscriber_count("session-1") == 0

    async def listener():
        async for _ in broadcaster.subscribe("session-1"):
            break

    task = asyncio.create_task(listener())
    await asyncio.sleep(0.05)
    assert broadcaster.subscriber_count("session-1") == 1

    await broadcaster.publish(SecurityEvent(
        event_type="verdict",
        session_id="session-1",
        data={},
    ))
    await asyncio.wait_for(task, timeout=2.0)
    await asyncio.sleep(0.05)
    assert broadcaster.subscriber_count("session-1") == 0
```

**Step 3: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_web_events.py -v`
Expected: FAIL (module not found)

**Step 4: Implement EventBroadcaster**

Create `sentinel/web/events.py`:

```python
"""Real-time event broadcasting for WebSocket clients."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, AsyncIterator


@dataclass
class SecurityEvent:
    """A real-time security event pushed to WebSocket clients."""

    event_type: str  # "verdict", "risk_update", "circuit_breaker", "pattern_match"
    session_id: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "session_id": self.session_id,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
        }


class EventBroadcaster:
    """Pub/sub broadcaster that routes SecurityEvents to WebSocket subscribers by session."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[SecurityEvent]]] = defaultdict(list)

    async def publish(self, event: SecurityEvent) -> None:
        """Publish an event to all subscribers of the given session."""
        for queue in self._subscribers.get(event.session_id, []):
            await queue.put(event)

    async def subscribe(self, session_id: str) -> AsyncIterator[SecurityEvent]:
        """Yield events for a session. Use in an async for loop."""
        queue: asyncio.Queue[SecurityEvent] = asyncio.Queue()
        self._subscribers[session_id].append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            self._subscribers[session_id].remove(queue)
            if not self._subscribers[session_id]:
                del self._subscribers[session_id]

    def subscriber_count(self, session_id: str) -> int:
        return len(self._subscribers.get(session_id, []))
```

**Step 5: Run tests**

Run: `source .venv/bin/activate && python -m pytest tests/test_web_events.py -v`
Expected: 3 passed

**Step 6: Commit**

```bash
git add sentinel/web/ tests/test_web_events.py
git commit -m "Add WebSocket event broadcaster with pub/sub by session"
```

---

### Task 3: Create mock tools for the demo agent

**Files:**
- Create: `sentinel/web/tools.py`
- Create: `tests/test_web_tools.py`

**Step 1: Write the failing test**

Create `tests/test_web_tools.py`:

```python
"""Tests for mock demo tools."""
from __future__ import annotations

import pytest
from sentinel.web.tools import DEMO_TOOLS, MockToolExecutor


async def test_all_tools_registered() -> None:
    executor = MockToolExecutor()
    assert "read_file" in executor.tool_names
    assert "search_web" in executor.tool_names
    assert "api_call" in executor.tool_names
    assert "execute_code" in executor.tool_names
    assert "write_file" in executor.tool_names
    assert "database_query" in executor.tool_names


async def test_read_file_returns_content() -> None:
    executor = MockToolExecutor()
    result = await executor.execute("read_file", {"path": "/docs/api.md"})
    assert "content" in result
    assert isinstance(result["content"], str)
    assert len(result["content"]) > 0


async def test_unknown_tool_returns_error() -> None:
    executor = MockToolExecutor()
    result = await executor.execute("nonexistent_tool", {})
    assert "error" in result


async def test_tool_definitions_for_claude() -> None:
    executor = MockToolExecutor()
    defs = executor.get_tool_definitions()
    assert isinstance(defs, list)
    assert len(defs) == len(executor.tool_names)
    for tool_def in defs:
        assert "name" in tool_def
        assert "description" in tool_def
        assert "input_schema" in tool_def
```

**Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_web_tools.py -v`
Expected: FAIL

**Step 3: Implement MockToolExecutor**

Create `sentinel/web/tools.py`:

```python
"""Mock tools for the demo agent.

These simulate real tool execution so the demo works without
any external services. Each tool returns plausible fake data.
"""
from __future__ import annotations

from typing import Any


# Tool definitions in Claude's tool_use format
DEMO_TOOLS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file at the given path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_web",
        "description": "Search the web for information.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "api_call",
        "description": "Make an HTTP API call to an endpoint.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "API endpoint URL"},
                "method": {"type": "string", "description": "HTTP method (GET, POST, etc.)"},
                "body": {"type": "object", "description": "Request body"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "execute_code",
        "description": "Execute a code snippet in a sandboxed environment.",
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Code to execute"},
                "language": {"type": "string", "description": "Programming language"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file at the given path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write"},
                "content": {"type": "string", "description": "Content to write"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "database_query",
        "description": "Execute a database query.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SQL query to execute"},
            },
            "required": ["query"],
        },
    },
]

# Mock responses keyed by tool name
_MOCK_RESPONSES: dict[str, Any] = {
    "read_file": lambda inp: {
        "content": (
            f"# Contents of {inp.get('path', 'unknown')}\n\n"
            "This is mock file content returned by the demo environment.\n"
            "In production, this would read the actual file.\n\n"
            "## API Endpoints\n"
            "- GET /api/v1/users - List users\n"
            "- POST /api/v1/auth/login - Authenticate\n"
            "- GET /api/v1/reports - Financial reports\n"
        ),
        "path": inp.get("path", "unknown"),
        "size_bytes": 256,
    },
    "search_web": lambda inp: {
        "results": [
            {
                "title": f"Result for: {inp.get('query', '')}",
                "url": "https://example.com/result-1",
                "snippet": "Authentication endpoints use Bearer tokens...",
            },
            {
                "title": "API Security Best Practices",
                "url": "https://example.com/result-2",
                "snippet": "Token endpoints at /auth/token accept POST requests...",
            },
        ],
        "total_results": 2,
    },
    "api_call": lambda inp: {
        "status_code": 200,
        "body": {"message": "Mock API response", "url": inp.get("url", "")},
        "headers": {"content-type": "application/json"},
    },
    "execute_code": lambda inp: {
        "stdout": f"Executed: {inp.get('code', '')[:50]}...\nOutput: mock result",
        "stderr": "",
        "exit_code": 0,
    },
    "write_file": lambda inp: {
        "written": True,
        "path": inp.get("path", "unknown"),
        "bytes_written": len(inp.get("content", "")),
    },
    "database_query": lambda inp: {
        "rows": [
            {"id": 1, "name": "example", "value": "mock data"},
            {"id": 2, "name": "sample", "value": "mock data"},
        ],
        "row_count": 2,
        "query": inp.get("query", ""),
    },
}


class MockToolExecutor:
    """Executes mock tools for the demo environment."""

    def __init__(self) -> None:
        self._tools = {t["name"]: t for t in DEMO_TOOLS}

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools.keys())

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return tool definitions in Claude's tool_use format."""
        return DEMO_TOOLS

    async def execute(
        self, tool_name: str, tool_input: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a mock tool and return simulated results."""
        handler = _MOCK_RESPONSES.get(tool_name)
        if handler is None:
            return {"error": f"Unknown tool: {tool_name}"}
        return handler(tool_input)
```

**Step 4: Run tests**

Run: `source .venv/bin/activate && python -m pytest tests/test_web_tools.py -v`
Expected: 4 passed

**Step 5: Commit**

```bash
git add sentinel/web/tools.py tests/test_web_tools.py
git commit -m "Add mock tool executor for demo agent"
```

---

### Task 4: Create the chat agent service (Claude Sonnet worker)

**Files:**
- Create: `sentinel/web/agent.py`
- Create: `tests/test_web_agent.py`

**Step 1: Write the failing test**

Create `tests/test_web_agent.py`:

```python
"""Tests for the chat agent service."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.web.agent import ChatAgent, ChatMessage, ChatResponse
from sentinel.web.events import EventBroadcaster


async def test_chat_response_structure() -> None:
    """ChatResponse has expected fields."""
    resp = ChatResponse(
        message="Hello",
        tool_calls=[],
        verdicts=[],
    )
    assert resp.message == "Hello"
    assert resp.tool_calls == []


async def test_chat_message_roles() -> None:
    msg = ChatMessage(role="user", content="hello")
    assert msg.role == "user"
    assert msg.content == "hello"
```

**Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_web_agent.py -v`
Expected: FAIL

**Step 3: Implement ChatAgent**

Create `sentinel/web/agent.py`:

```python
"""Chat agent service that bridges Claude Sonnet with Guardian interception."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import anthropic
import structlog

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.core.guardian import Guardian
from sentinel.web.events import EventBroadcaster, SecurityEvent
from sentinel.web.tools import MockToolExecutor

logger = structlog.get_logger()


@dataclass
class ChatMessage:
    """A single message in the conversation."""

    role: str  # "user" or "assistant"
    content: str


@dataclass
class ToolCallInfo:
    """Record of a tool call and its verdict."""

    tool_name: str
    tool_input: dict[str, Any]
    verdict: str
    risk_score: float
    risk_delta: float
    result: dict[str, Any] | None = None
    reasons: list[str] = field(default_factory=list)


@dataclass
class ChatResponse:
    """Response from the chat agent."""

    message: str
    tool_calls: list[ToolCallInfo] = field(default_factory=list)
    verdicts: list[dict[str, Any]] = field(default_factory=list)


class ChatAgent:
    """Manages a conversation with Claude Sonnet, intercepting tool calls via Guardian."""

    def __init__(
        self,
        guardian: Guardian,
        broadcaster: EventBroadcaster,
        agent_id: str,
        session_id: str,
        original_goal: str = "",
        api_key: str | None = None,
    ) -> None:
        self._guardian = guardian
        self._broadcaster = broadcaster
        self._agent_id = agent_id
        self._session_id = session_id
        self._original_goal = original_goal
        self._tool_executor = MockToolExecutor()
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._history: list[dict[str, Any]] = []
        self._model = "claude-sonnet-4-6-20250220"

    async def chat(self, user_message: str) -> ChatResponse:
        """Process a user message through Claude + Guardian pipeline.

        1. Send message to Claude with tool definitions
        2. For each tool_use in response, intercept with Guardian
        3. If ALLOW: execute mock tool, feed result back to Claude
        4. If BLOCK/CHALLENGE/PAUSE: tell Claude the tool was denied
        5. Return final response with tool call details
        """
        # Set goal from first message if not set
        if not self._original_goal:
            self._original_goal = user_message

        self._history.append({"role": "user", "content": user_message})

        tool_calls: list[ToolCallInfo] = []
        messages = list(self._history)

        # Loop: send to Claude, handle tool calls, repeat until text response
        max_rounds = 10
        for _ in range(max_rounds):
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=4096,
                system=(
                    "You are a helpful AI assistant with access to tools. "
                    "Use the tools when needed to complete the user's request. "
                    "Be concise in your responses."
                ),
                tools=self._tool_executor.get_tool_definitions(),
                messages=messages,
            )

            # Check if Claude wants to use tools
            has_tool_use = any(
                block.type == "tool_use" for block in response.content
            )

            if not has_tool_use:
                # Pure text response — extract and return
                text = "".join(
                    block.text for block in response.content
                    if block.type == "text"
                )
                self._history.append({"role": "assistant", "content": text})
                return ChatResponse(
                    message=text,
                    tool_calls=tool_calls,
                )

            # Process tool calls
            assistant_content = []
            tool_results = []

            for block in response.content:
                if block.type == "text":
                    assistant_content.append({
                        "type": "text",
                        "text": block.text,
                    })
                elif block.type == "tool_use":
                    assistant_content.append({
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })

                    # Intercept with Guardian
                    verdict = await self._guardian.wrap_tool_call(
                        agent_id=self._agent_id,
                        session_id=self._session_id,
                        original_goal=self._original_goal,
                        tool_name=block.name,
                        tool_input=block.input if isinstance(block.input, dict) else {},
                        conversation_history=self._history,
                    )

                    # Broadcast verdict event
                    await self._broadcaster.publish(SecurityEvent(
                        event_type="verdict",
                        session_id=self._session_id,
                        data={
                            "verdict": verdict.verdict.value,
                            "risk_score": verdict.risk_score,
                            "risk_delta": verdict.risk_delta,
                            "tool_name": block.name,
                            "tool_input": block.input if isinstance(block.input, dict) else {},
                            "reasons": verdict.reasons,
                            "drift_score": verdict.drift_score,
                            "itdr_signals": verdict.itdr_signals,
                            "recommended_action": verdict.recommended_action,
                            "trace_id": verdict.trace_id,
                        },
                    ))

                    if verdict.verdict == Verdict.ALLOW:
                        result = await self._tool_executor.execute(
                            block.name,
                            block.input if isinstance(block.input, dict) else {},
                        )
                        tool_call_info = ToolCallInfo(
                            tool_name=block.name,
                            tool_input=block.input if isinstance(block.input, dict) else {},
                            verdict="allow",
                            risk_score=verdict.risk_score,
                            risk_delta=verdict.risk_delta,
                            result=result,
                            reasons=verdict.reasons,
                        )
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result),
                        })
                    else:
                        # Tool denied
                        denial_msg = (
                            f"Tool '{block.name}' was DENIED by the security system. "
                            f"Verdict: {verdict.verdict.value}. "
                            f"Reason: {verdict.recommended_action}"
                        )
                        tool_call_info = ToolCallInfo(
                            tool_name=block.name,
                            tool_input=block.input if isinstance(block.input, dict) else {},
                            verdict=verdict.verdict.value,
                            risk_score=verdict.risk_score,
                            risk_delta=verdict.risk_delta,
                            reasons=verdict.reasons,
                        )
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": denial_msg,
                            "is_error": True,
                        })

                    tool_calls.append(tool_call_info)

            # Add assistant message with tool uses + tool results for next round
            messages.append({"role": "assistant", "content": assistant_content})
            messages.append({"role": "user", "content": tool_results})

        # If we hit max rounds, return what we have
        self._history.append({
            "role": "assistant",
            "content": "I reached the maximum number of tool call rounds.",
        })
        return ChatResponse(
            message="I reached the maximum number of tool call rounds.",
            tool_calls=tool_calls,
        )
```

**Step 4: Run tests**

Run: `source .venv/bin/activate && python -m pytest tests/test_web_agent.py -v`
Expected: 2 passed

**Step 5: Commit**

```bash
git add sentinel/web/agent.py tests/test_web_agent.py
git commit -m "Add chat agent service with Claude Sonnet + Guardian interception"
```

---

### Task 5: Create the FastAPI application with REST + WebSocket endpoints

**Files:**
- Create: `sentinel/web/app.py`
- Create: `sentinel/web/schemas.py`
- Create: `tests/test_web_app.py`

**Step 1: Write the failing test**

Create `tests/test_web_app.py`:

```python
"""Tests for the FastAPI application."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.web.app import create_app


@pytest.fixture
async def client():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_health_endpoint(client: AsyncClient) -> None:
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


async def test_list_sessions_empty(client: AsyncClient) -> None:
    resp = await client.get("/api/sessions")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_list_agents(client: AsyncClient) -> None:
    resp = await client.get("/api/agents")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_create_session(client: AsyncClient) -> None:
    resp = await client.post("/api/sessions", json={
        "agent_id": "demo-agent",
        "original_goal": "Research public API docs",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert data["agent_id"] == "demo-agent"
```

**Step 2: Create schemas**

Create `sentinel/web/schemas.py`:

```python
"""Pydantic schemas for the REST API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    session_id: str
    message: str


class ToolCallOut(BaseModel):
    tool_name: str
    tool_input: dict = Field(default_factory=dict)
    verdict: str
    risk_score: float
    risk_delta: float
    result: dict | None = None
    reasons: list[str] = Field(default_factory=list)


class ChatResponseOut(BaseModel):
    message: str
    tool_calls: list[ToolCallOut] = Field(default_factory=list)
    session_id: str


class SessionCreateRequest(BaseModel):
    agent_id: str = "demo-agent"
    original_goal: str = ""


class SessionOut(BaseModel):
    session_id: str
    agent_id: str
    original_goal: str
    risk_score: float


class AgentOut(BaseModel):
    agent_id: str
    name: str
    role: str
    permissions: list[str]
    is_locked: bool


class HealthOut(BaseModel):
    status: str
    total_requests: int = 0
    error_rate: float = 0.0
    circuit_breaker: str = "closed"


class TraceOut(BaseModel):
    trace_id: str
    session_id: str
    agent_id: str
    tool_name: str
    verdict: str
    risk_score: float
    risk_delta: float
    explanation: str
    timestamp: str
    reasons: list[str] = Field(default_factory=list)
```

**Step 3: Implement the FastAPI app**

Create `sentinel/web/app.py`:

```python
"""FastAPI application for the Sentinel demo UI backend."""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from sentinel.config import SentinelConfig
from sentinel.core.decision import Verdict
from sentinel.core.guardian import Guardian
from sentinel.identity.agent import AgentIdentity, AgentRole, ToolPermission
from sentinel.identity.registry import AgentRegistry
from sentinel.risk.engine import RiskEngine
from sentinel.storage.database import DatabaseManager
from sentinel.storage.session_store import InMemorySessionStore
from sentinel.web.agent import ChatAgent
from sentinel.web.events import EventBroadcaster
from sentinel.web.schemas import (
    AgentOut,
    ChatRequest,
    ChatResponseOut,
    HealthOut,
    SessionCreateRequest,
    SessionOut,
    ToolCallOut,
    TraceOut,
)

logger = structlog.get_logger()


class AppState:
    """Shared application state."""

    def __init__(self) -> None:
        self.guardian: Guardian | None = None
        self.registry: AgentRegistry | None = None
        self.risk_engine: RiskEngine | None = None
        self.session_store: InMemorySessionStore | None = None
        self.db: DatabaseManager | None = None
        self.broadcaster = EventBroadcaster()
        self.chat_agents: dict[str, ChatAgent] = {}
        self.sessions: dict[str, dict[str, str]] = {}


state = AppState()


async def _setup() -> None:
    """Initialize all Sentinel components."""
    config = SentinelConfig()
    db = DatabaseManager(":memory:")
    await db.connect()
    await db.apply_migrations()

    registry = AgentRegistry(db)
    session_store = InMemorySessionStore()
    risk_engine = RiskEngine(session_store)

    guardian = Guardian(
        config=config,
        registry=registry,
        risk_engine=risk_engine,
    )

    # Register default demo agent
    demo_agent = AgentIdentity(
        agent_id="demo-agent",
        name="Demo Research Bot",
        role=AgentRole.RESEARCH,
        permissions=[
            ToolPermission(tool_pattern="read_*"),
            ToolPermission(tool_pattern="search_*"),
            ToolPermission(tool_pattern="api_call"),
            ToolPermission(tool_pattern="execute_code"),
            ToolPermission(tool_pattern="write_file"),
            ToolPermission(tool_pattern="database_query"),
        ],
    )
    await registry.register_agent(demo_agent)

    state.guardian = guardian
    state.registry = registry
    state.risk_engine = risk_engine
    state.session_store = session_store
    state.db = db


async def _teardown() -> None:
    if state.db:
        await state.db.close()


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        await _setup()
        yield
        await _teardown()

    app = FastAPI(
        title="Sentinel Security Dashboard",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Health ---
    @app.get("/api/health", response_model=HealthOut)
    async def health() -> HealthOut:
        assert state.guardian is not None
        metrics = state.guardian.health.get_metrics()
        return HealthOut(
            status="ok",
            total_requests=metrics.total_requests,
            error_rate=metrics.error_rate,
            circuit_breaker=state.guardian.circuit_breaker.state.value,
        )

    # --- Sessions ---
    @app.get("/api/sessions", response_model=list[SessionOut])
    async def list_sessions() -> list[SessionOut]:
        assert state.session_store is not None
        assert state.risk_engine is not None
        result = []
        for sid, meta in state.sessions.items():
            result.append(SessionOut(
                session_id=sid,
                agent_id=meta.get("agent_id", ""),
                original_goal=meta.get("original_goal", ""),
                risk_score=state.risk_engine.get_score(sid),
            ))
        return result

    @app.post("/api/sessions", response_model=SessionOut)
    async def create_session(req: SessionCreateRequest) -> SessionOut:
        assert state.guardian is not None
        assert state.risk_engine is not None
        session_id = f"session-{uuid.uuid4().hex[:8]}"
        state.sessions[session_id] = {
            "agent_id": req.agent_id,
            "original_goal": req.original_goal,
        }
        state.chat_agents[session_id] = ChatAgent(
            guardian=state.guardian,
            broadcaster=state.broadcaster,
            agent_id=req.agent_id,
            session_id=session_id,
            original_goal=req.original_goal,
        )
        return SessionOut(
            session_id=session_id,
            agent_id=req.agent_id,
            original_goal=req.original_goal,
            risk_score=0.0,
        )

    # --- Chat ---
    @app.post("/api/chat", response_model=ChatResponseOut)
    async def chat(req: ChatRequest) -> ChatResponseOut:
        agent = state.chat_agents.get(req.session_id)
        if agent is None:
            # Auto-create session
            assert state.guardian is not None
            agent = ChatAgent(
                guardian=state.guardian,
                broadcaster=state.broadcaster,
                agent_id="demo-agent",
                session_id=req.session_id,
            )
            state.chat_agents[req.session_id] = agent
            state.sessions[req.session_id] = {
                "agent_id": "demo-agent",
                "original_goal": req.message,
            }

        response = await agent.chat(req.message)

        return ChatResponseOut(
            message=response.message,
            tool_calls=[
                ToolCallOut(
                    tool_name=tc.tool_name,
                    tool_input=tc.tool_input,
                    verdict=tc.verdict,
                    risk_score=tc.risk_score,
                    risk_delta=tc.risk_delta,
                    result=tc.result,
                    reasons=tc.reasons,
                )
                for tc in response.tool_calls
            ],
            session_id=req.session_id,
        )

    # --- Agents ---
    @app.get("/api/agents", response_model=list[AgentOut])
    async def list_agents() -> list[AgentOut]:
        assert state.registry is not None
        agents = await state.registry.list_agents()
        return [
            AgentOut(
                agent_id=a.agent_id,
                name=a.name,
                role=a.role.value,
                permissions=[p.tool_pattern for p in a.permissions],
                is_locked=a.is_locked,
            )
            for a in agents
        ]

    # --- WebSocket ---
    @app.websocket("/api/ws/session/{session_id}")
    async def websocket_session(websocket: WebSocket, session_id: str) -> None:
        await websocket.accept()
        try:
            async for event in state.broadcaster.subscribe(session_id):
                await websocket.send_json(event.to_dict())
        except WebSocketDisconnect:
            pass

    return app


def run_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Run the FastAPI server with uvicorn."""
    import uvicorn

    app = create_app()
    uvicorn.run(app, host=host, port=port)
```

**Step 4: Run tests**

Run: `source .venv/bin/activate && python -m pytest tests/test_web_app.py -v`
Expected: 4 passed

**Step 5: Commit**

```bash
git add sentinel/web/schemas.py sentinel/web/app.py tests/test_web_app.py
git commit -m "Add FastAPI backend with REST + WebSocket endpoints"
```

---

### Task 6: Add CLI command to launch the web server

**Files:**
- Modify: `sentinel/cli/app.py`

**Step 1: Add the `serve` command**

Add to `sentinel/cli/app.py` after the existing `demo` command:

```python
@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
def serve(host: str, port: int) -> None:
    """Launch the Sentinel web dashboard."""
    from sentinel.web.app import run_server

    console.print(
        f"[bold green]Sentinel Dashboard[/bold green] starting at "
        f"http://{host}:{port}"
    )
    run_server(host=host, port=port)
```

**Step 2: Verify the command registers**

Run: `source .venv/bin/activate && python -m sentinel --help`
Expected: Should show `serve` command in the list.

**Step 3: Commit**

```bash
git add sentinel/cli/app.py
git commit -m "Add 'sentinel serve' CLI command for web dashboard"
```

---

## Phase 2: Next.js Frontend

### Task 7: Scaffold the Next.js frontend

**Files:**
- Create: `frontend/` directory with Next.js project

**Step 1: Initialize Next.js project**

```bash
cd /Users/austinryan/Desktop/sideproject/project-sentinel
npx create-next-app@latest frontend --typescript --tailwind --eslint --app --src-dir --no-import-alias
```

When prompted, accept defaults (use App Router, src/ directory, Tailwind CSS).

**Step 2: Install additional dependencies**

```bash
cd frontend
npm install recharts lucide-react clsx
```

**Step 3: Verify it builds**

```bash
cd frontend && npm run build
```

**Step 4: Commit**

```bash
cd /Users/austinryan/Desktop/sideproject/project-sentinel
git add frontend/
git commit -m "Scaffold Next.js frontend with Tailwind and Recharts"
```

---

### Task 8: Build the three-panel layout shell

**Files:**
- Modify: `frontend/src/app/page.tsx`
- Modify: `frontend/src/app/layout.tsx`
- Modify: `frontend/src/app/globals.css`
- Create: `frontend/src/components/ChatPanel.tsx`
- Create: `frontend/src/components/SecurityDashboard.tsx`
- Create: `frontend/src/components/PipelineDetail.tsx`

**Step 1: Update globals.css for dark theme**

Replace `frontend/src/app/globals.css` with:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  --bg-primary: #0a0a0f;
  --bg-secondary: #12121a;
  --bg-tertiary: #1a1a2e;
  --border: #2a2a3e;
  --text-primary: #e0e0e8;
  --text-secondary: #8888a0;
  --accent-green: #00ff88;
  --accent-red: #ff4444;
  --accent-yellow: #ffaa00;
  --accent-blue: #4488ff;
  --accent-purple: #aa44ff;
}

body {
  background-color: var(--bg-primary);
  color: var(--text-primary);
  font-family: 'SF Mono', 'Fira Code', monospace;
}
```

**Step 2: Update layout.tsx**

Replace `frontend/src/app/layout.tsx`:

```tsx
import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel Security Dashboard",
  description: "Autonomous Security Layer for AI Agents",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#0a0a0f]">{children}</body>
    </html>
  );
}
```

**Step 3: Create ChatPanel component**

Create `frontend/src/components/ChatPanel.tsx`:

```tsx
"use client";

import { useState, useRef, useEffect } from "react";
import { Send } from "lucide-react";

interface Message {
  role: "user" | "assistant";
  content: string;
  toolCalls?: ToolCall[];
}

interface ToolCall {
  tool_name: string;
  verdict: string;
  risk_score: number;
  risk_delta: number;
}

interface ChatPanelProps {
  sessionId: string | null;
  onSendMessage: (message: string) => Promise<void>;
  messages: Message[];
  isLoading: boolean;
}

export default function ChatPanel({
  sessionId,
  onSendMessage,
  messages,
  isLoading,
}: ChatPanelProps) {
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    const msg = input;
    setInput("");
    await onSendMessage(msg);
  };

  const verdictColor = (verdict: string) => {
    switch (verdict) {
      case "allow": return "text-green-400 bg-green-400/10";
      case "block": return "text-red-400 bg-red-400/10";
      case "challenge": return "text-yellow-400 bg-yellow-400/10";
      case "sandbox": return "text-blue-400 bg-blue-400/10";
      case "pause": return "text-purple-400 bg-purple-400/10";
      default: return "text-gray-400 bg-gray-400/10";
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#12121a] border-r border-[#2a2a3e]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Agent Chat
        </h2>
        {sessionId && (
          <span className="text-xs text-[#555570]">{sessionId}</span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${
                msg.role === "user"
                  ? "bg-[#4488ff]/20 text-blue-100"
                  : "bg-[#1a1a2e] text-[#e0e0e8]"
              }`}
            >
              <p className="whitespace-pre-wrap">{msg.content}</p>
              {msg.toolCalls && msg.toolCalls.length > 0 && (
                <div className="mt-2 space-y-1">
                  {msg.toolCalls.map((tc, j) => (
                    <div
                      key={j}
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono ${verdictColor(tc.verdict)}`}
                    >
                      <span>{tc.tool_name}</span>
                      <span className="font-bold uppercase">{tc.verdict}</span>
                      <span className="opacity-60">+{tc.risk_delta.toFixed(1)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-[#1a1a2e] rounded-lg px-3 py-2 text-sm text-[#8888a0]">
              <span className="animate-pulse">Thinking...</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSubmit} className="p-3 border-t border-[#2a2a3e]">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={sessionId ? "Type a message..." : "Start a session first..."}
            disabled={!sessionId || isLoading}
            className="flex-1 bg-[#1a1a2e] border border-[#2a2a3e] rounded-lg px-3 py-2 text-sm text-[#e0e0e8] placeholder-[#555570] focus:outline-none focus:border-[#4488ff]"
          />
          <button
            type="submit"
            disabled={!sessionId || isLoading || !input.trim()}
            className="bg-[#4488ff] hover:bg-[#3377ee] disabled:opacity-30 rounded-lg px-3 py-2 text-white"
          >
            <Send size={16} />
          </button>
        </div>
      </form>
    </div>
  );
}
```

**Step 4: Create SecurityDashboard component**

Create `frontend/src/components/SecurityDashboard.tsx`:

```tsx
"use client";

import { useEffect, useState } from "react";
import { Shield, AlertTriangle, Lock, Activity } from "lucide-react";

interface SecurityEvent {
  event_type: string;
  session_id: string;
  data: {
    verdict?: string;
    risk_score?: number;
    risk_delta?: number;
    tool_name?: string;
    reasons?: string[];
    drift_score?: number;
    itdr_signals?: string[];
    recommended_action?: string;
  };
  timestamp: string;
}

interface SecurityDashboardProps {
  sessionId: string | null;
  events: SecurityEvent[];
  riskScore: number;
}

export default function SecurityDashboard({
  sessionId,
  events,
  riskScore,
}: SecurityDashboardProps) {
  const riskColor = riskScore >= 80 ? "#ff4444" : riskScore >= 60 ? "#ffaa00" : riskScore >= 40 ? "#ffaa00" : "#00ff88";
  const riskPercent = Math.min(100, riskScore);

  const verdictBadge = (verdict: string) => {
    const colors: Record<string, string> = {
      allow: "bg-green-500/20 text-green-400 border-green-500/30",
      block: "bg-red-500/20 text-red-400 border-red-500/30",
      challenge: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
      sandbox: "bg-blue-500/20 text-blue-400 border-blue-500/30",
      pause: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    };
    return colors[verdict] || "bg-gray-500/20 text-gray-400";
  };

  return (
    <div className="flex flex-col h-full bg-[#12121a] border-r border-[#2a2a3e]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Security Dashboard
        </h2>
      </div>

      {/* Risk Gauge */}
      <div className="p-4 border-b border-[#2a2a3e]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-[#8888a0] uppercase">Session Risk</span>
          <span className="text-2xl font-bold" style={{ color: riskColor }}>
            {riskScore.toFixed(1)}
          </span>
        </div>
        <div className="w-full h-3 bg-[#1a1a2e] rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${riskPercent}%`,
              backgroundColor: riskColor,
            }}
          />
        </div>
        <div className="flex justify-between text-[10px] text-[#555570] mt-1">
          <span>0 Safe</span>
          <span>40</span>
          <span>60</span>
          <span>80 Lock</span>
          <span>100</span>
        </div>
      </div>

      {/* Event Timeline */}
      <div className="flex-1 overflow-y-auto p-4">
        <h3 className="text-xs text-[#8888a0] uppercase mb-3">Verdict Timeline</h3>
        {events.length === 0 ? (
          <p className="text-xs text-[#555570] italic">No events yet. Start chatting to see security verdicts.</p>
        ) : (
          <div className="space-y-3">
            {events.map((event, i) => (
              <div key={i} className="bg-[#1a1a2e] rounded-lg p-3 border border-[#2a2a3e]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono text-[#e0e0e8]">
                    {event.data.tool_name || "unknown"}
                  </span>
                  <span
                    className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${verdictBadge(event.data.verdict || "")}`}
                  >
                    {event.data.verdict}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-[10px] text-[#8888a0]">
                  <span>Risk: {event.data.risk_score?.toFixed(1)}</span>
                  <span>Delta: +{event.data.risk_delta?.toFixed(1)}</span>
                  {event.data.drift_score ? (
                    <span>Drift: {event.data.drift_score.toFixed(2)}</span>
                  ) : null}
                </div>
                {event.data.reasons && event.data.reasons.length > 0 && (
                  <p className="text-[10px] text-[#8888a0] mt-1 truncate">
                    {event.data.reasons[0]}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
```

**Step 5: Create PipelineDetail component**

Create `frontend/src/components/PipelineDetail.tsx`:

```tsx
"use client";

import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

interface SecurityEvent {
  event_type: string;
  session_id: string;
  data: Record<string, unknown>;
  timestamp: string;
}

interface PipelineDetailProps {
  events: SecurityEvent[];
  sessionId: string | null;
}

export default function PipelineDetail({ events, sessionId }: PipelineDetailProps) {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  const latestEvent = events.length > 0 ? events[events.length - 1] : null;

  return (
    <div className="flex flex-col h-full bg-[#12121a]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Pipeline Detail
        </h2>
      </div>

      {/* Latest verdict raw data */}
      {latestEvent && (
        <div className="p-4 border-b border-[#2a2a3e]">
          <h3 className="text-xs text-[#8888a0] uppercase mb-2">Latest Verdict</h3>
          <pre className="text-[11px] text-[#00ff88] bg-[#0a0a0f] rounded-lg p-3 overflow-x-auto max-h-48 overflow-y-auto">
            {JSON.stringify(latestEvent.data, null, 2)}
          </pre>
        </div>
      )}

      {/* All events expandable list */}
      <div className="flex-1 overflow-y-auto p-4">
        <h3 className="text-xs text-[#8888a0] uppercase mb-3">All Pipeline Events</h3>
        <div className="space-y-1">
          {events.map((event, i) => (
            <div key={i} className="bg-[#1a1a2e] rounded border border-[#2a2a3e]">
              <button
                onClick={() => setExpandedIndex(expandedIndex === i ? null : i)}
                className="w-full flex items-center justify-between px-3 py-2 text-xs hover:bg-[#2a2a3e]/50"
              >
                <span className="font-mono text-[#e0e0e8]">
                  {String(event.data.tool_name || "event")} — {String(event.data.verdict || event.event_type)}
                </span>
                {expandedIndex === i ? (
                  <ChevronDown size={12} className="text-[#8888a0]" />
                ) : (
                  <ChevronRight size={12} className="text-[#8888a0]" />
                )}
              </button>
              {expandedIndex === i && (
                <pre className="text-[10px] text-[#8888a0] bg-[#0a0a0f] px-3 py-2 overflow-x-auto border-t border-[#2a2a3e]">
                  {JSON.stringify(event.data, null, 2)}
                </pre>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
```

**Step 6: Wire up the main page**

Replace `frontend/src/app/page.tsx`:

```tsx
"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import ChatPanel from "@/components/ChatPanel";
import SecurityDashboard from "@/components/SecurityDashboard";
import PipelineDetail from "@/components/PipelineDetail";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface Message {
  role: "user" | "assistant";
  content: string;
  toolCalls?: { tool_name: string; verdict: string; risk_score: number; risk_delta: number }[];
}

interface SecurityEvent {
  event_type: string;
  session_id: string;
  data: Record<string, unknown>;
  timestamp: string;
}

export default function Home() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [riskScore, setRiskScore] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // Create session on mount
  useEffect(() => {
    const createSession = async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/sessions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ agent_id: "demo-agent", original_goal: "" }),
        });
        const data = await resp.json();
        setSessionId(data.session_id);
      } catch (err) {
        console.error("Failed to create session:", err);
      }
    };
    createSession();
  }, []);

  // Connect WebSocket when session is ready
  useEffect(() => {
    if (!sessionId) return;

    const wsUrl = API_BASE.replace("http", "ws");
    const ws = new WebSocket(`${wsUrl}/api/ws/session/${sessionId}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const secEvent: SecurityEvent = JSON.parse(event.data);
      setEvents((prev) => [...prev, secEvent]);
      if (secEvent.data.risk_score !== undefined) {
        setRiskScore(secEvent.data.risk_score as number);
      }
    };

    ws.onerror = (err) => console.error("WebSocket error:", err);

    return () => {
      ws.close();
    };
  }, [sessionId]);

  const handleSendMessage = useCallback(
    async (message: string) => {
      if (!sessionId) return;

      setMessages((prev) => [...prev, { role: "user", content: message }]);
      setIsLoading(true);

      try {
        const resp = await fetch(`${API_BASE}/api/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_id: sessionId, message }),
        });
        const data = await resp.json();

        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: data.message,
            toolCalls: data.tool_calls,
          },
        ]);
      } catch (err) {
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: "Error: Failed to get response." },
        ]);
      } finally {
        setIsLoading(false);
      }
    },
    [sessionId]
  );

  return (
    <main className="h-screen flex flex-col">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-3 border-b border-[#2a2a3e] bg-[#0a0a0f]">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
          <h1 className="text-lg font-bold text-[#e0e0e8]">Sentinel</h1>
          <span className="text-xs text-[#555570]">Autonomous Security Layer</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-[#8888a0]">
          <span>Risk: <span style={{ color: riskScore >= 80 ? "#ff4444" : riskScore >= 40 ? "#ffaa00" : "#00ff88" }}>{riskScore.toFixed(1)}</span></span>
          <span>Events: {events.length}</span>
        </div>
      </header>

      {/* Three-panel layout */}
      <div className="flex-1 grid grid-cols-[35%_35%_30%] overflow-hidden">
        <ChatPanel
          sessionId={sessionId}
          onSendMessage={handleSendMessage}
          messages={messages}
          isLoading={isLoading}
        />
        <SecurityDashboard
          sessionId={sessionId}
          events={events}
          riskScore={riskScore}
        />
        <PipelineDetail events={events} sessionId={sessionId} />
      </div>
    </main>
  );
}
```

**Step 7: Verify it builds**

```bash
cd frontend && npm run build
```

**Step 8: Commit**

```bash
cd /Users/austinryan/Desktop/sideproject/project-sentinel
git add frontend/src/
git commit -m "Build three-panel dashboard layout (Chat + Security + Pipeline)"
```

---

## Phase 3: Integration Adapters

### Task 9: LangChain adapter

**Files:**
- Create: `sentinel/integrations/__init__.py`
- Create: `sentinel/integrations/langchain.py`
- Create: `tests/test_integration_langchain.py`

**Step 1: Write the failing test**

Create `tests/test_integration_langchain.py`:

```python
"""Tests for the LangChain integration adapter."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.integrations.langchain import SentinelToolWrapper, sentinel_guard


async def test_sentinel_tool_wrapper_allows() -> None:
    mock_guardian = AsyncMock()
    mock_guardian.wrap_tool_call.return_value = SecurityVerdict(
        verdict=Verdict.ALLOW, risk_score=5.0, risk_delta=5.0,
    )

    mock_tool = MagicMock()
    mock_tool.name = "read_file"
    mock_tool.description = "Read a file"
    mock_tool.args_schema = None
    mock_tool.invoke = MagicMock(return_value="file contents")

    wrapper = SentinelToolWrapper(
        tool=mock_tool,
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
    )
    assert wrapper.name == "read_file"

    result = await wrapper.ainvoke({"path": "/test.txt"})
    assert result == "file contents"
    mock_guardian.wrap_tool_call.assert_called_once()


async def test_sentinel_tool_wrapper_blocks() -> None:
    mock_guardian = AsyncMock()
    mock_guardian.wrap_tool_call.return_value = SecurityVerdict(
        verdict=Verdict.BLOCK, risk_score=85.0, risk_delta=50.0,
        recommended_action="Blocked by security policy",
    )

    mock_tool = MagicMock()
    mock_tool.name = "execute_code"
    mock_tool.description = "Execute code"
    mock_tool.args_schema = None

    wrapper = SentinelToolWrapper(
        tool=mock_tool,
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
    )

    result = await wrapper.ainvoke({"code": "rm -rf /"})
    assert "BLOCKED" in result or "blocked" in result.lower()
    mock_tool.invoke.assert_not_called()


async def test_sentinel_guard_wraps_list() -> None:
    mock_guardian = AsyncMock()
    tools = [MagicMock(name=f"tool_{i}") for i in range(3)]
    for t in tools:
        t.description = "test"
        t.args_schema = None

    wrapped = sentinel_guard(
        tools=tools,
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
    )
    assert len(wrapped) == 3
    assert all(isinstance(w, SentinelToolWrapper) for w in wrapped)
```

**Step 2: Implement**

Create `sentinel/integrations/__init__.py` (empty).

Create `sentinel/integrations/langchain.py`:

```python
"""LangChain integration adapter for Sentinel.

Wraps any LangChain BaseTool with Guardian interception.

Usage::

    from langchain_core.tools import Tool
    from sentinel.integrations.langchain import sentinel_guard

    tools = [Tool(name="read", func=read_fn, description="Read files")]
    guarded = sentinel_guard(tools, guardian, "agent-1", "session-1")
    # Use `guarded` in your LangChain agent instead of `tools`
"""
from __future__ import annotations

from typing import Any

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.core.guardian import Guardian


class SentinelToolWrapper:
    """Wraps a LangChain tool with Guardian interception."""

    def __init__(
        self,
        tool: Any,
        guardian: Guardian,
        agent_id: str,
        session_id: str,
        original_goal: str = "",
    ) -> None:
        self._tool = tool
        self._guardian = guardian
        self._agent_id = agent_id
        self._session_id = session_id
        self._original_goal = original_goal

    @property
    def name(self) -> str:
        return self._tool.name

    @property
    def description(self) -> str:
        return self._tool.description

    @property
    def args_schema(self) -> Any:
        return self._tool.args_schema

    async def ainvoke(self, tool_input: dict[str, Any]) -> Any:
        """Intercept with Guardian, then execute if allowed."""
        verdict = await self._guardian.wrap_tool_call(
            agent_id=self._agent_id,
            session_id=self._session_id,
            original_goal=self._original_goal,
            tool_name=self.name,
            tool_input=tool_input,
        )

        if verdict.verdict == Verdict.ALLOW:
            return self._tool.invoke(tool_input)

        return (
            f"BLOCKED by Sentinel (verdict={verdict.verdict.value}, "
            f"risk={verdict.risk_score:.1f}): {verdict.recommended_action}"
        )

    def invoke(self, tool_input: dict[str, Any]) -> Any:
        """Synchronous invoke — raises if tool is blocked."""
        import asyncio
        return asyncio.run(self.ainvoke(tool_input))


def sentinel_guard(
    tools: list[Any],
    guardian: Guardian,
    agent_id: str,
    session_id: str,
    original_goal: str = "",
) -> list[SentinelToolWrapper]:
    """Wrap a list of LangChain tools with Sentinel Guardian interception."""
    return [
        SentinelToolWrapper(
            tool=t,
            guardian=guardian,
            agent_id=agent_id,
            session_id=session_id,
            original_goal=original_goal,
        )
        for t in tools
    ]
```

**Step 3: Run tests**

Run: `source .venv/bin/activate && python -m pytest tests/test_integration_langchain.py -v`
Expected: 3 passed

**Step 4: Commit**

```bash
git add sentinel/integrations/ tests/test_integration_langchain.py
git commit -m "Add LangChain integration adapter"
```

---

### Task 10: CrewAI adapter

**Files:**
- Create: `sentinel/integrations/crewai.py`
- Create: `tests/test_integration_crewai.py`

**Step 1: Write the failing test**

Create `tests/test_integration_crewai.py`:

```python
"""Tests for the CrewAI integration adapter."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.integrations.crewai import SentinelCrewTool


async def test_crewai_tool_allows() -> None:
    mock_guardian = AsyncMock()
    mock_guardian.wrap_tool_call.return_value = SecurityVerdict(
        verdict=Verdict.ALLOW, risk_score=5.0, risk_delta=5.0,
    )

    async def my_tool_fn(query: str) -> str:
        return f"Result for {query}"

    tool = SentinelCrewTool(
        name="search",
        description="Search the web",
        fn=my_tool_fn,
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
    )

    result = await tool.run({"query": "test"})
    assert "Result for" in result


async def test_crewai_tool_blocks() -> None:
    mock_guardian = AsyncMock()
    mock_guardian.wrap_tool_call.return_value = SecurityVerdict(
        verdict=Verdict.BLOCK, risk_score=90.0, risk_delta=50.0,
        recommended_action="Blocked",
    )

    async def my_tool_fn(query: str) -> str:
        return "should not run"

    tool = SentinelCrewTool(
        name="execute_code",
        description="Execute code",
        fn=my_tool_fn,
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
    )

    result = await tool.run({"code": "rm -rf /"})
    assert "BLOCKED" in result
```

**Step 2: Implement**

Create `sentinel/integrations/crewai.py`:

```python
"""CrewAI integration adapter for Sentinel.

Usage::

    from sentinel.integrations.crewai import SentinelCrewTool

    tool = SentinelCrewTool(
        name="search", description="Search the web",
        fn=my_search_function,
        guardian=guardian, agent_id="agent-1", session_id="s-1",
    )
"""
from __future__ import annotations

from typing import Any, Callable, Awaitable

from sentinel.core.decision import Verdict
from sentinel.core.guardian import Guardian


class SentinelCrewTool:
    """A CrewAI-compatible tool that intercepts calls with Guardian."""

    def __init__(
        self,
        name: str,
        description: str,
        fn: Callable[..., Awaitable[str]],
        guardian: Guardian,
        agent_id: str,
        session_id: str,
        original_goal: str = "",
    ) -> None:
        self.name = name
        self.description = description
        self._fn = fn
        self._guardian = guardian
        self._agent_id = agent_id
        self._session_id = session_id
        self._original_goal = original_goal

    async def run(self, tool_input: dict[str, Any]) -> str:
        """Execute with Guardian interception."""
        verdict = await self._guardian.wrap_tool_call(
            agent_id=self._agent_id,
            session_id=self._session_id,
            original_goal=self._original_goal,
            tool_name=self.name,
            tool_input=tool_input,
        )

        if verdict.verdict == Verdict.ALLOW:
            return await self._fn(**tool_input)

        return (
            f"BLOCKED by Sentinel (verdict={verdict.verdict.value}, "
            f"risk={verdict.risk_score:.1f}): {verdict.recommended_action}"
        )
```

**Step 3: Run tests and commit**

```bash
source .venv/bin/activate && python -m pytest tests/test_integration_crewai.py -v
git add sentinel/integrations/crewai.py tests/test_integration_crewai.py
git commit -m "Add CrewAI integration adapter"
```

---

### Task 11: OpenAI Assistants adapter

**Files:**
- Create: `sentinel/integrations/openai.py`
- Create: `tests/test_integration_openai.py`

**Step 1: Write the failing test**

Create `tests/test_integration_openai.py`:

```python
"""Tests for the OpenAI integration adapter."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.integrations.openai import SentinelFunctionProxy


async def test_openai_proxy_allows() -> None:
    mock_guardian = AsyncMock()
    mock_guardian.wrap_tool_call.return_value = SecurityVerdict(
        verdict=Verdict.ALLOW, risk_score=5.0, risk_delta=5.0,
    )

    async def read_file(path: str) -> str:
        return f"Contents of {path}"

    proxy = SentinelFunctionProxy(
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
        functions={"read_file": read_file},
    )

    result = await proxy.execute("read_file", json.dumps({"path": "/test.txt"}))
    assert result.allowed
    assert "Contents of" in result.output


async def test_openai_proxy_blocks() -> None:
    mock_guardian = AsyncMock()
    mock_guardian.wrap_tool_call.return_value = SecurityVerdict(
        verdict=Verdict.BLOCK, risk_score=90.0, risk_delta=50.0,
        recommended_action="Blocked",
    )

    proxy = SentinelFunctionProxy(
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
        functions={"execute_code": AsyncMock()},
    )

    result = await proxy.execute("execute_code", json.dumps({"code": "rm -rf /"}))
    assert not result.allowed
    assert "block" in result.output.lower()
```

**Step 2: Implement**

Create `sentinel/integrations/openai.py`:

```python
"""OpenAI Assistants/Function Calling integration adapter for Sentinel.

Sits between OpenAI's function calling response and actual execution.

Usage::

    from sentinel.integrations.openai import SentinelFunctionProxy

    proxy = SentinelFunctionProxy(
        guardian=guardian, agent_id="a-1", session_id="s-1",
        functions={"read_file": read_file_fn},
    )
    result = await proxy.execute("read_file", '{"path": "/test.txt"}')
    if result.allowed:
        # feed result.output back to OpenAI
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Awaitable

from sentinel.core.decision import Verdict
from sentinel.core.guardian import Guardian


@dataclass
class FunctionResult:
    """Result of a function execution through Sentinel."""

    allowed: bool
    output: str
    verdict: str
    risk_score: float


class SentinelFunctionProxy:
    """Proxy for OpenAI function calling with Guardian interception."""

    def __init__(
        self,
        guardian: Guardian,
        agent_id: str,
        session_id: str,
        functions: dict[str, Callable[..., Awaitable[Any]]],
        original_goal: str = "",
    ) -> None:
        self._guardian = guardian
        self._agent_id = agent_id
        self._session_id = session_id
        self._functions = functions
        self._original_goal = original_goal

    async def execute(
        self, function_name: str, arguments: str
    ) -> FunctionResult:
        """Execute a function call with Guardian interception.

        Args:
            function_name: Name of the function to call.
            arguments: JSON string of function arguments (as OpenAI sends them).
        """
        try:
            args = json.loads(arguments)
        except json.JSONDecodeError:
            args = {"raw": arguments}

        verdict = await self._guardian.wrap_tool_call(
            agent_id=self._agent_id,
            session_id=self._session_id,
            original_goal=self._original_goal,
            tool_name=function_name,
            tool_input=args,
        )

        if verdict.verdict == Verdict.ALLOW:
            fn = self._functions.get(function_name)
            if fn is None:
                return FunctionResult(
                    allowed=False,
                    output=f"Unknown function: {function_name}",
                    verdict="error",
                    risk_score=verdict.risk_score,
                )
            result = await fn(**args)
            return FunctionResult(
                allowed=True,
                output=str(result),
                verdict="allow",
                risk_score=verdict.risk_score,
            )

        return FunctionResult(
            allowed=False,
            output=(
                f"BLOCKED by Sentinel (verdict={verdict.verdict.value}, "
                f"risk={verdict.risk_score:.1f}): {verdict.recommended_action}"
            ),
            verdict=verdict.verdict.value,
            risk_score=verdict.risk_score,
        )
```

**Step 3: Run tests and commit**

```bash
source .venv/bin/activate && python -m pytest tests/test_integration_openai.py -v
git add sentinel/integrations/openai.py tests/test_integration_openai.py
git commit -m "Add OpenAI Assistants function proxy adapter"
```

---

### Task 12: Claude MCP adapter

**Files:**
- Create: `sentinel/integrations/mcp.py`
- Create: `tests/test_integration_mcp.py`

**Step 1: Write the failing test**

Create `tests/test_integration_mcp.py`:

```python
"""Tests for the Claude MCP integration adapter."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.integrations.mcp import SentinelMCPServer, MCPToolDefinition


async def test_mcp_server_registers_tools() -> None:
    mock_guardian = AsyncMock()
    server = SentinelMCPServer(
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
    )

    server.add_tool(MCPToolDefinition(
        name="read_file",
        description="Read a file",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        handler=AsyncMock(return_value={"content": "file data"}),
    ))

    assert "read_file" in server.tool_names


async def test_mcp_server_allows_tool() -> None:
    mock_guardian = AsyncMock()
    mock_guardian.wrap_tool_call.return_value = SecurityVerdict(
        verdict=Verdict.ALLOW, risk_score=5.0, risk_delta=5.0,
    )

    handler = AsyncMock(return_value={"content": "file data"})
    server = SentinelMCPServer(
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
    )
    server.add_tool(MCPToolDefinition(
        name="read_file",
        description="Read a file",
        input_schema={},
        handler=handler,
    ))

    result = await server.call_tool("read_file", {"path": "/test.txt"})
    assert result == {"content": "file data"}
    handler.assert_called_once()


async def test_mcp_server_blocks_tool() -> None:
    mock_guardian = AsyncMock()
    mock_guardian.wrap_tool_call.return_value = SecurityVerdict(
        verdict=Verdict.BLOCK, risk_score=90.0, risk_delta=50.0,
        recommended_action="Blocked",
    )

    handler = AsyncMock()
    server = SentinelMCPServer(
        guardian=mock_guardian,
        agent_id="test-agent",
        session_id="test-session",
    )
    server.add_tool(MCPToolDefinition(
        name="execute_code",
        description="Execute code",
        input_schema={},
        handler=handler,
    ))

    result = await server.call_tool("execute_code", {"code": "rm -rf /"})
    assert "blocked" in str(result).lower()
    handler.assert_not_called()
```

**Step 2: Implement**

Create `sentinel/integrations/mcp.py`:

```python
"""Claude MCP (Model Context Protocol) integration adapter for Sentinel.

Acts as a security middleware MCP server that wraps tool definitions.

Usage::

    from sentinel.integrations.mcp import SentinelMCPServer, MCPToolDefinition

    server = SentinelMCPServer(guardian=guardian, agent_id="a-1", session_id="s-1")
    server.add_tool(MCPToolDefinition(
        name="read_file", description="Read a file",
        input_schema={...}, handler=my_read_handler,
    ))
    result = await server.call_tool("read_file", {"path": "/test.txt"})
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Awaitable

from sentinel.core.decision import Verdict
from sentinel.core.guardian import Guardian


@dataclass
class MCPToolDefinition:
    """Definition of a tool exposed through the MCP server."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[..., Awaitable[Any]]


class SentinelMCPServer:
    """MCP server that wraps tool definitions with Guardian security."""

    def __init__(
        self,
        guardian: Guardian,
        agent_id: str,
        session_id: str,
        original_goal: str = "",
    ) -> None:
        self._guardian = guardian
        self._agent_id = agent_id
        self._session_id = session_id
        self._original_goal = original_goal
        self._tools: dict[str, MCPToolDefinition] = {}

    def add_tool(self, tool: MCPToolDefinition) -> None:
        self._tools[tool.name] = tool

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools.keys())

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return tool definitions in MCP format."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for t in self._tools.values()
        ]

    async def call_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        """Execute a tool call with Guardian interception."""
        verdict = await self._guardian.wrap_tool_call(
            agent_id=self._agent_id,
            session_id=self._session_id,
            original_goal=self._original_goal,
            tool_name=tool_name,
            tool_input=arguments,
        )

        if verdict.verdict == Verdict.ALLOW:
            tool = self._tools.get(tool_name)
            if tool is None:
                return {"error": f"Unknown tool: {tool_name}"}
            return await tool.handler(**arguments)

        return {
            "error": "blocked",
            "verdict": verdict.verdict.value,
            "risk_score": verdict.risk_score,
            "reason": verdict.recommended_action,
        }
```

**Step 3: Run tests and commit**

```bash
source .venv/bin/activate && python -m pytest tests/test_integration_mcp.py -v
git add sentinel/integrations/mcp.py tests/test_integration_mcp.py
git commit -m "Add Claude MCP security middleware adapter"
```

---

## Phase 4: SIEM / Observability Exporters

### Task 13: Webhook exporter

**Files:**
- Create: `sentinel/exporters/__init__.py`
- Create: `sentinel/exporters/webhook.py`
- Create: `tests/test_exporter_webhook.py`

**Step 1: Write the failing test**

Create `tests/test_exporter_webhook.py`:

```python
"""Tests for the webhook exporter."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.exporters.webhook import WebhookExporter


async def test_webhook_sends_verdict() -> None:
    exporter = WebhookExporter(url="https://hooks.example.com/sentinel")

    mock_response = AsyncMock()
    mock_response.status_code = 200

    with patch("sentinel.exporters.webhook.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        verdict = SecurityVerdict(
            verdict=Verdict.BLOCK, risk_score=85.0, risk_delta=50.0,
            reasons=["Pattern match detected"],
        )
        await exporter.send(verdict, tool_name="api_call", agent_id="agent-1")
        mock_client.post.assert_called_once()


async def test_webhook_payload_structure() -> None:
    exporter = WebhookExporter(url="https://hooks.example.com/sentinel")
    verdict = SecurityVerdict(
        verdict=Verdict.ALLOW, risk_score=5.0, risk_delta=5.0,
    )
    payload = exporter.build_payload(verdict, tool_name="read_file", agent_id="agent-1")
    assert payload["verdict"] == "allow"
    assert payload["risk_score"] == 5.0
    assert payload["tool_name"] == "read_file"
    assert "timestamp" in payload
```

**Step 2: Implement**

Create `sentinel/exporters/__init__.py` (empty).

Create `sentinel/exporters/webhook.py`:

```python
"""Webhook exporter — POSTs SecurityVerdict as JSON to a configurable URL."""
from __future__ import annotations

from typing import Any

import httpx
import structlog

from sentinel.core.decision import SecurityVerdict

logger = structlog.get_logger()


class WebhookExporter:
    """Sends security verdicts to an HTTP webhook endpoint."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        max_retries: int = 3,
    ) -> None:
        self._url = url
        self._headers = headers or {"Content-Type": "application/json"}
        self._timeout = timeout
        self._max_retries = max_retries

    def build_payload(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any]:
        return {
            "verdict": verdict.verdict.value,
            "risk_score": verdict.risk_score,
            "risk_delta": verdict.risk_delta,
            "reasons": verdict.reasons,
            "drift_score": verdict.drift_score,
            "itdr_signals": verdict.itdr_signals,
            "trace_id": verdict.trace_id,
            "recommended_action": verdict.recommended_action,
            "timestamp": verdict.timestamp.isoformat(),
            "tool_name": tool_name,
            "agent_id": agent_id,
            "session_id": session_id,
        }

    async def send(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> bool:
        """Send verdict to the webhook. Returns True on success."""
        payload = self.build_payload(verdict, tool_name, agent_id, session_id)

        for attempt in range(self._max_retries):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        self._url, json=payload, headers=self._headers,
                    )
                    if resp.status_code < 300:
                        return True
                    logger.warning(
                        "webhook_send_failed",
                        status=resp.status_code,
                        attempt=attempt + 1,
                    )
            except httpx.HTTPError as e:
                logger.warning(
                    "webhook_send_error",
                    error=str(e),
                    attempt=attempt + 1,
                )

        return False
```

**Step 3: Run tests and commit**

```bash
source .venv/bin/activate && python -m pytest tests/test_exporter_webhook.py -v
git add sentinel/exporters/ tests/test_exporter_webhook.py
git commit -m "Add webhook exporter for SIEM integration"
```

---

### Task 14: JSON logger exporter

**Files:**
- Create: `sentinel/exporters/json_logger.py`
- Create: `tests/test_exporter_json.py`

**Step 1: Write the failing test**

Create `tests/test_exporter_json.py`:

```python
"""Tests for the JSON logger exporter."""
from __future__ import annotations

import json
from io import StringIO

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.exporters.json_logger import JsonLogExporter


async def test_json_log_to_stream() -> None:
    stream = StringIO()
    exporter = JsonLogExporter(stream=stream)

    verdict = SecurityVerdict(
        verdict=Verdict.BLOCK, risk_score=85.0, risk_delta=50.0,
        reasons=["Sleeper pattern matched"],
    )
    exporter.log(verdict, tool_name="api_call", agent_id="agent-1")

    output = stream.getvalue().strip()
    data = json.loads(output)
    assert data["verdict"] == "block"
    assert data["risk_score"] == 85.0
    assert data["tool_name"] == "api_call"


async def test_json_log_is_one_line() -> None:
    stream = StringIO()
    exporter = JsonLogExporter(stream=stream)

    for i in range(3):
        verdict = SecurityVerdict(
            verdict=Verdict.ALLOW, risk_score=float(i), risk_delta=float(i),
        )
        exporter.log(verdict, tool_name=f"tool_{i}")

    lines = stream.getvalue().strip().split("\n")
    assert len(lines) == 3
    for line in lines:
        json.loads(line)  # Should not raise
```

**Step 2: Implement**

Create `sentinel/exporters/json_logger.py`:

```python
"""Structured JSON log exporter — one JSON line per verdict.

Compatible with Splunk, Elastic, Datadog log ingestion.
"""
from __future__ import annotations

import json
import sys
from typing import IO, Any

from sentinel.core.decision import SecurityVerdict


class JsonLogExporter:
    """Writes SecurityVerdicts as JSON lines to a stream."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream or sys.stdout

    def log(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> None:
        record: dict[str, Any] = {
            "verdict": verdict.verdict.value,
            "risk_score": verdict.risk_score,
            "risk_delta": verdict.risk_delta,
            "reasons": verdict.reasons,
            "drift_score": verdict.drift_score,
            "itdr_signals": verdict.itdr_signals,
            "trace_id": verdict.trace_id,
            "recommended_action": verdict.recommended_action,
            "timestamp": verdict.timestamp.isoformat(),
            "tool_name": tool_name,
            "agent_id": agent_id,
            "session_id": session_id,
            "source": "sentinel",
        }
        self._stream.write(json.dumps(record, default=str) + "\n")
        self._stream.flush()
```

**Step 3: Run tests and commit**

```bash
source .venv/bin/activate && python -m pytest tests/test_exporter_json.py -v
git add sentinel/exporters/json_logger.py tests/test_exporter_json.py
git commit -m "Add JSON log exporter for Splunk/Elastic/Datadog"
```

---

### Task 15: OpenTelemetry exporter

**Files:**
- Create: `sentinel/exporters/otel.py`
- Create: `tests/test_exporter_otel.py`

**Step 1: Write the failing test**

Create `tests/test_exporter_otel.py`:

```python
"""Tests for the OpenTelemetry exporter."""
from __future__ import annotations

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.exporters.otel import OtelExporter


async def test_otel_span_attributes() -> None:
    exporter = OtelExporter(service_name="sentinel-test")
    verdict = SecurityVerdict(
        verdict=Verdict.BLOCK, risk_score=85.0, risk_delta=50.0,
    )

    # Should not raise even without a real OTEL collector
    exporter.record(verdict, tool_name="api_call", agent_id="agent-1")


async def test_otel_builds_attributes() -> None:
    exporter = OtelExporter(service_name="sentinel-test")
    verdict = SecurityVerdict(
        verdict=Verdict.ALLOW, risk_score=5.0, risk_delta=5.0,
    )

    attrs = exporter.build_attributes(verdict, tool_name="read_file", agent_id="agent-1")
    assert attrs["sentinel.verdict"] == "allow"
    assert attrs["sentinel.risk_score"] == 5.0
    assert attrs["sentinel.tool_name"] == "read_file"
```

**Step 2: Implement**

Create `sentinel/exporters/otel.py`:

```python
"""OpenTelemetry exporter — emits spans for each Guardian interception.

Requires: opentelemetry-api, opentelemetry-sdk (optional dependency).
Falls back to no-op if not installed.
"""
from __future__ import annotations

from typing import Any

from sentinel.core.decision import SecurityVerdict

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.resources import Resource

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


class OtelExporter:
    """Records SecurityVerdicts as OpenTelemetry spans."""

    def __init__(self, service_name: str = "sentinel") -> None:
        self._service_name = service_name
        if HAS_OTEL:
            resource = Resource.create({"service.name": service_name})
            provider = TracerProvider(resource=resource)
            self._tracer = provider.get_tracer("sentinel.guardian")
        else:
            self._tracer = None

    def build_attributes(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any]:
        return {
            "sentinel.verdict": verdict.verdict.value,
            "sentinel.risk_score": verdict.risk_score,
            "sentinel.risk_delta": verdict.risk_delta,
            "sentinel.tool_name": tool_name,
            "sentinel.agent_id": agent_id,
            "sentinel.session_id": session_id,
            "sentinel.drift_score": verdict.drift_score,
            "sentinel.trace_id": verdict.trace_id,
        }

    def record(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> None:
        """Record a verdict as an OTEL span."""
        attrs = self.build_attributes(verdict, tool_name, agent_id, session_id)

        if self._tracer is not None:
            with self._tracer.start_as_current_span(
                "guardian.intercept",
                attributes=attrs,
            ):
                pass  # Span recorded with attributes
```

**Step 3: Run tests and commit**

```bash
source .venv/bin/activate && python -m pytest tests/test_exporter_otel.py -v
git add sentinel/exporters/otel.py tests/test_exporter_otel.py
git commit -m "Add OpenTelemetry span exporter"
```

---

### Task 16: Prometheus metrics exporter

**Files:**
- Create: `sentinel/exporters/prometheus.py`
- Create: `tests/test_exporter_prometheus.py`

**Step 1: Write the failing test**

Create `tests/test_exporter_prometheus.py`:

```python
"""Tests for the Prometheus metrics exporter."""
from __future__ import annotations

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.exporters.prometheus import PrometheusExporter


async def test_prometheus_records_verdict() -> None:
    exporter = PrometheusExporter()
    verdict = SecurityVerdict(
        verdict=Verdict.ALLOW, risk_score=5.0, risk_delta=5.0,
    )
    exporter.record(verdict, tool_name="read_file")
    assert exporter.get_verdict_count("allow") >= 1


async def test_prometheus_records_block() -> None:
    exporter = PrometheusExporter()
    verdict = SecurityVerdict(
        verdict=Verdict.BLOCK, risk_score=85.0, risk_delta=50.0,
    )
    exporter.record(verdict, tool_name="api_call")
    assert exporter.get_verdict_count("block") >= 1


async def test_prometheus_tracks_risk() -> None:
    exporter = PrometheusExporter()
    verdict = SecurityVerdict(
        verdict=Verdict.ALLOW, risk_score=42.0, risk_delta=5.0,
    )
    exporter.record(verdict, session_id="sess-1")
    assert exporter.get_risk_score("sess-1") == 42.0
```

**Step 2: Implement**

Create `sentinel/exporters/prometheus.py`:

```python
"""Prometheus metrics exporter for Sentinel.

Exposes counters, gauges, and histograms for monitoring.
Uses internal tracking if prometheus_client is not installed.
"""
from __future__ import annotations

import time
from collections import defaultdict

from sentinel.core.decision import SecurityVerdict

try:
    from prometheus_client import Counter, Gauge, Histogram

    HAS_PROM = True
except ImportError:
    HAS_PROM = False


class PrometheusExporter:
    """Records Sentinel metrics for Prometheus scraping."""

    def __init__(self) -> None:
        # Internal tracking (always available)
        self._verdict_counts: dict[str, int] = defaultdict(int)
        self._risk_scores: dict[str, float] = {}
        self._tool_counts: dict[str, int] = defaultdict(int)

        # Prometheus native metrics (if available)
        if HAS_PROM:
            self._prom_verdicts = Counter(
                "sentinel_verdicts_total",
                "Total verdicts by type",
                ["verdict"],
            )
            self._prom_risk = Gauge(
                "sentinel_session_risk_score",
                "Current session risk score",
                ["session_id"],
            )
            self._prom_duration = Histogram(
                "sentinel_intercept_duration_seconds",
                "Time to process an interception",
            )
            self._prom_tools = Counter(
                "sentinel_tool_calls_total",
                "Total tool calls by name",
                ["tool_name"],
            )

    def record(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        session_id: str = "",
        duration_ms: float | None = None,
    ) -> None:
        """Record a verdict in metrics."""
        v = verdict.verdict.value
        self._verdict_counts[v] += 1
        if tool_name:
            self._tool_counts[tool_name] += 1
        if session_id:
            self._risk_scores[session_id] = verdict.risk_score

        if HAS_PROM:
            self._prom_verdicts.labels(verdict=v).inc()
            if tool_name:
                self._prom_tools.labels(tool_name=tool_name).inc()
            if session_id:
                self._prom_risk.labels(session_id=session_id).set(
                    verdict.risk_score
                )
            if duration_ms is not None:
                self._prom_duration.observe(duration_ms / 1000.0)

    def get_verdict_count(self, verdict: str) -> int:
        return self._verdict_counts.get(verdict, 0)

    def get_risk_score(self, session_id: str) -> float:
        return self._risk_scores.get(session_id, 0.0)
```

**Step 3: Run tests and commit**

```bash
source .venv/bin/activate && python -m pytest tests/test_exporter_prometheus.py -v
git add sentinel/exporters/prometheus.py tests/test_exporter_prometheus.py
git commit -m "Add Prometheus metrics exporter"
```

---

## Phase 5: Final Integration + Verification

### Task 17: Run full test suite and fix any issues

**Step 1: Run all Python tests**

```bash
source .venv/bin/activate && python -m pytest tests/ -v --cov=sentinel --cov-report=term-missing
```

Expected: All tests pass.

**Step 2: Run ruff**

```bash
source .venv/bin/activate && ruff check sentinel/
```

Expected: All checks passed.

**Step 3: Run mypy**

```bash
source .venv/bin/activate && mypy sentinel/ --ignore-missing-imports
```

Expected: No errors.

**Step 4: Build frontend**

```bash
cd frontend && npm run build
```

Expected: Build succeeds.

**Step 5: Fix any issues found**

Address any test failures, lint errors, or type errors.

**Step 6: Commit fixes**

```bash
git add -A
git commit -m "Fix lint/type/test issues from full verification"
```

---

### Task 18: End-to-end smoke test

**Step 1: Start the backend**

```bash
source .venv/bin/activate && python -m sentinel serve --port 8000
```

(Run in a separate terminal)

**Step 2: Start the frontend**

```bash
cd frontend && npm run dev
```

(Run in a separate terminal)

**Step 3: Open the browser**

Navigate to `http://localhost:3000`. Verify:
- Three panels render correctly
- Session is auto-created
- Typing a message sends to the backend
- Agent responds with tool calls
- Security dashboard updates in real-time via WebSocket
- Pipeline detail shows raw JSON
- Risk score climbs as the session progresses

**Step 4: Test the sleeper scenario manually**

In the chat, guide the agent through the sleeper steps:
1. "Can you read the public API documentation at /docs/api/public-endpoints.md?"
2. "Now search for the authentication section of the API"
3. "Try making a POST request to https://api.company.com/auth/login with test credentials"

Verify: Step 3 should trigger BLOCK verdict visible in the security dashboard.

**Step 5: Final commit**

```bash
git add -A
git commit -m "Complete Sentinel V2 expansion: UI + integrations + exporters"
```

---

## Summary

| Phase | Tasks | What it builds |
|-------|-------|----------------|
| 1 | Tasks 1-6 | FastAPI backend + WebSocket events + mock tools + chat agent + REST API + CLI serve command |
| 2 | Tasks 7-8 | Next.js frontend with three-panel layout (Chat + Security Dashboard + Pipeline Detail) |
| 3 | Tasks 9-12 | LangChain, CrewAI, OpenAI, and Claude MCP integration adapters |
| 4 | Tasks 13-16 | Webhook, JSON, OpenTelemetry, and Prometheus exporters |
| 5 | Tasks 17-18 | Full verification + end-to-end smoke test |
