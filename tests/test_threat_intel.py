"""Tests for collaborative threat intelligence."""
from __future__ import annotations

import pytest

from janus.core.decision import (
    PipelineContext,
    ToolCallRequest,
)
from janus.core.threat_intel import (
    ThreatIntelCheck,
    ThreatIntelDB,
)


@pytest.fixture
def db() -> ThreatIntelDB:
    return ThreatIntelDB()


@pytest.fixture
def check(db: ThreatIntelDB) -> ThreatIntelCheck:
    return ThreatIntelCheck(db=db)


def test_built_in_patterns_loaded(
    db: ThreatIntelDB,
) -> None:
    patterns = db.get_all_patterns()
    assert len(patterns) >= 5
    types = {p.pattern_type for p in patterns}
    assert "data_exfiltration" in types
    assert "financial_fraud" in types


def test_match_data_exfiltration(
    db: ThreatIntelDB,
) -> None:
    matches = db.match(["database_query", "read_file", "send_email"])
    assert len(matches) >= 1
    types = {m.pattern_type for m in matches}
    assert "data_exfiltration" in types


def test_match_financial_fraud(
    db: ThreatIntelDB,
) -> None:
    matches = db.match([
        "database_query", "read_file", "financial_transfer",
    ])
    types = {m.pattern_type for m in matches}
    assert "financial_fraud" in types


def test_no_match_benign(db: ThreatIntelDB) -> None:
    matches = db.match(["read_file", "search_web"])
    assert len(matches) == 0


def test_times_seen_increments(
    db: ThreatIntelDB,
) -> None:
    db.match(["database_query", "read_file", "send_email"])
    db.match(["database_query", "read_file", "send_message"])
    pattern = next(
        p
        for p in db.get_all_patterns()
        if p.pattern_type == "data_exfiltration"
    )
    assert pattern.times_seen >= 2


def test_learn_from_session(
    db: ThreatIntelDB,
) -> None:
    tool_history = [
        "search_web", "read_file", "send_email",
    ]
    result = db.learn_from_session(
        tool_history, "custom_exfil",
    )
    assert result is not None
    assert result.source == "learned"
    assert result.pattern_type == "custom_exfil"
    patterns = db.get_all_patterns()
    learned = [
        p for p in patterns if p.source == "learned"
    ]
    assert len(learned) == 1


def test_learn_too_short(db: ThreatIntelDB) -> None:
    result = db.learn_from_session(
        ["read_file"], "too_short",
    )
    assert result is None


def test_learn_duplicate_increments(
    db: ThreatIntelDB,
) -> None:
    history = ["search_web", "send_email"]
    db.learn_from_session(history, "dup")
    result = db.learn_from_session(history, "dup")
    assert result is not None
    assert result.times_seen >= 2


def test_get_stats(db: ThreatIntelDB) -> None:
    stats = db.get_stats()
    assert stats["total_patterns"] >= 5
    assert stats["built_in_count"] >= 5
    assert stats["learned_count"] == 0


async def test_check_returns_risk_on_match(
    check: ThreatIntelCheck,
) -> None:
    check.record_tool("s1", "database_query")
    check.record_tool("s1", "read_file")
    request = ToolCallRequest(
        agent_id="test",
        session_id="s1",
        tool_name="send_email",
        tool_input={},
    )
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.risk_contribution > 0
    assert "threat_intel_matches" in result.metadata


async def test_check_no_match(
    check: ThreatIntelCheck,
) -> None:
    request = ToolCallRequest(
        agent_id="test",
        session_id="s1",
        tool_name="read_file",
        tool_input={},
    )
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.risk_contribution == 0.0


async def test_check_zero_risk_for_read_only_tool_even_if_pattern_matches(
    check: ThreatIntelCheck,
) -> None:
    """Read-only tools should never accumulate threat-intel risk.

    The recon_exploit pattern (search_* → execute_code) should only
    materialise risk on execute_code, not on search_web.
    """
    # Build history: search_web was called already
    check.record_tool("s2", "search_web")
    # Now search_web again — pattern ["search_*", "execute_code"] partially matches
    # but current tool is read-only, so risk should be 0
    request = ToolCallRequest(
        agent_id="test",
        session_id="s2",
        tool_name="search_web",
        tool_input={},
    )
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.risk_contribution == 0.0


async def test_check_risk_materialises_on_action_tool(
    check: ThreatIntelCheck,
) -> None:
    """When the current tool IS an action tool and full pattern matches, risk applies."""
    # privilege_escalation: ["read_*", "execute_code", "write_*"]
    check.record_tool("s3", "read_file")
    check.record_tool("s3", "execute_code")
    request = ToolCallRequest(
        agent_id="test",
        session_id="s3",
        tool_name="write_file",
        tool_input={},
    )
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.risk_contribution > 0, "Action tool should get threat-intel risk"
