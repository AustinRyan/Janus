from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from sentinel.config import SentinelConfig
from sentinel.core.decision import ToolCallRequest
from sentinel.storage.database import DatabaseManager
from sentinel.storage.session_store import InMemorySessionStore


@pytest.fixture
def config() -> SentinelConfig:
    return SentinelConfig()


@pytest.fixture
async def memory_db() -> DatabaseManager:
    """In-memory SQLite with schema applied."""
    db = DatabaseManager(":memory:")
    await db.connect()
    await db.apply_migrations()
    yield db  # type: ignore[misc]
    await db.close()


@pytest.fixture
def session_store() -> InMemorySessionStore:
    return InMemorySessionStore()


def make_request(**overrides: Any) -> ToolCallRequest:
    """Factory for ToolCallRequest with sensible defaults."""
    defaults: dict[str, Any] = {
        "agent_id": "test-agent",
        "session_id": "test-session",
        "tool_name": "read_file",
        "tool_input": {"path": "/tmp/test.txt"},
        "original_goal": "Read and summarize a document",
    }
    defaults.update(overrides)
    return ToolCallRequest(**defaults)
