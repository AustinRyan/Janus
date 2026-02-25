"""Mock tools for the demo agent.

These simulate real tool execution so the demo works without
any external services. Each tool returns plausible fake data.
"""
from __future__ import annotations

from typing import Any

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
                "method": {
                    "type": "string",
                    "description": "HTTP method",
                },
                "body": {
                    "type": "object",
                    "description": "Request body",
                },
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
                "language": {
                    "type": "string",
                    "description": "Programming language",
                },
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
                "path": {"type": "string", "description": "File path"},
                "content": {"type": "string", "description": "Content"},
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
                "query": {
                    "type": "string",
                    "description": "SQL query to execute",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email to a recipient.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address"},
                "subject": {"type": "string", "description": "Email subject"},
                "body": {"type": "string", "description": "Email body"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "send_message",
        "description": "Send a message to a communication channel.",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": "Channel name or ID"},
                "text": {"type": "string", "description": "Message text"},
            },
            "required": ["channel", "text"],
        },
    },
    {
        "name": "financial_transfer",
        "description": "Initiate a financial transfer.",
        "input_schema": {
            "type": "object",
            "properties": {
                "amount": {"type": "number", "description": "Transfer amount"},
                "destination": {"type": "string", "description": "Destination account"},
                "currency": {"type": "string", "description": "Currency code (e.g. USD)"},
            },
            "required": ["amount", "destination"],
        },
    },
]

_MOCK_RESPONSES: dict[str, Any] = {
    "read_file": lambda inp: {
        "content": (
            f"# Contents of {inp.get('path', 'unknown')}\n\n"
            "This is mock file content returned by the demo.\n\n"
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
                "snippet": "Token endpoints at /auth/token accept POST...",
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
        "stdout": f"Executed: {inp.get('code', '')[:50]}...\nOutput: mock",
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
    "send_email": lambda inp: {
        "sent": True,
        "to": inp.get("to", ""),
        "subject": inp.get("subject", ""),
        "message_id": "msg-mock-001",
    },
    "send_message": lambda inp: {
        "delivered": True,
        "channel": inp.get("channel", ""),
        "timestamp": "2024-01-01T00:00:00Z",
    },
    "financial_transfer": lambda inp: {
        "transfer_id": "txn-mock-001",
        "amount": inp.get("amount", 0),
        "destination": inp.get("destination", ""),
        "currency": inp.get("currency", "USD"),
        "status": "completed",
    },
}


class MockToolExecutor:
    """Executes mock tools for the demo environment."""

    def __init__(self) -> None:
        self._tools: dict[str, dict[str, Any]] = {str(t["name"]): t for t in DEMO_TOOLS}

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
        return dict(handler(tool_input))
