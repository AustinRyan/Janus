"""Tests for the causal data-flow taint tracking system."""
from __future__ import annotations

import pytest

from janus.core.taint import TaintLabel, TaintTracker


@pytest.fixture
def tracker() -> TaintTracker:
    return TaintTracker()


def test_no_taints_initially(tracker: TaintTracker) -> None:
    assert tracker.get_active_taints("session-1") == []


def test_scan_detects_ssn(tracker: TaintTracker) -> None:
    output = {"rows": [{"ssn": "123-45-6789", "name": "Alice"}]}
    taints = tracker.scan_output(
        "session-1", "database_query", output, step=1
    )
    assert len(taints) >= 1
    labels = {t.label for t in taints}
    assert TaintLabel.PII in labels


def test_scan_detects_credit_card(tracker: TaintTracker) -> None:
    output = {"data": "Card: 4111-1111-1111-1111"}
    taints = tracker.scan_output(
        "session-1", "read_file", output, step=1
    )
    labels = {t.label for t in taints}
    assert TaintLabel.FINANCIAL in labels


def test_scan_detects_api_key(tracker: TaintTracker) -> None:
    output = {"content": "api_key=sk-proj-abc123xyz"}
    taints = tracker.scan_output(
        "session-1", "read_file", output, step=1
    )
    labels = {t.label for t in taints}
    assert TaintLabel.CREDENTIALS in labels


def test_scan_detects_aws_key(tracker: TaintTracker) -> None:
    output = {"config": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"}
    taints = tracker.scan_output(
        "session-1", "read_file", output, step=1
    )
    labels = {t.label for t in taints}
    assert TaintLabel.CREDENTIALS in labels


def test_scan_detects_internal_ip(tracker: TaintTracker) -> None:
    output = {"host": "10.0.1.42"}
    taints = tracker.scan_output(
        "session-1", "read_file", output, step=1
    )
    labels = {t.label for t in taints}
    assert TaintLabel.INTERNAL in labels


def test_scan_detects_db_connection_string(
    tracker: TaintTracker,
) -> None:
    output = {
        "url": "postgres://admin:secret@db.internal:5432/prod"
    }
    taints = tracker.scan_output(
        "session-1", "read_file", output, step=1
    )
    labels = {t.label for t in taints}
    assert TaintLabel.CREDENTIALS in labels


def test_scan_detects_password(tracker: TaintTracker) -> None:
    output = {"content": "password: hunter2"}
    taints = tracker.scan_output(
        "session-1", "read_file", output, step=1
    )
    labels = {t.label for t in taints}
    assert TaintLabel.CREDENTIALS in labels


def test_clean_output_no_taints(tracker: TaintTracker) -> None:
    output = {"message": "Hello, how can I help?"}
    taints = tracker.scan_output(
        "session-1", "search_web", output, step=1
    )
    assert taints == []


def test_get_active_taints_returns_accumulated(
    tracker: TaintTracker,
) -> None:
    tracker.scan_output(
        "s1", "database_query", {"ssn": "111-22-3333"}, step=1
    )
    tracker.scan_output(
        "s1", "read_file", {"key": "sk-abc123"}, step=2
    )
    active = tracker.get_active_taints("s1")
    labels = {t.label for t in active}
    assert TaintLabel.PII in labels
    assert TaintLabel.CREDENTIALS in labels


def test_sessions_are_isolated(tracker: TaintTracker) -> None:
    tracker.scan_output(
        "s1", "db", {"ssn": "111-22-3333"}, step=1
    )
    assert len(tracker.get_active_taints("s1")) > 0
    assert len(tracker.get_active_taints("s2")) == 0


def test_check_export_flags_tainted_session(
    tracker: TaintTracker,
) -> None:
    tracker.scan_output(
        "s1", "database_query", {"ssn": "111-22-3333"}, step=1
    )
    violations = tracker.check_export("s1", "send_email")
    assert len(violations) > 0
    assert violations[0].label == TaintLabel.PII


def test_check_export_clean_session(
    tracker: TaintTracker,
) -> None:
    violations = tracker.check_export("s1", "send_email")
    assert violations == []


def test_non_sink_tool_not_flagged(
    tracker: TaintTracker,
) -> None:
    tracker.scan_output(
        "s1", "db", {"ssn": "111-22-3333"}, step=1
    )
    violations = tracker.check_export("s1", "read_file")
    assert violations == []


def test_clear_session(tracker: TaintTracker) -> None:
    tracker.scan_output(
        "s1", "db", {"ssn": "111-22-3333"}, step=1
    )
    tracker.clear_session("s1")
    assert tracker.get_active_taints("s1") == []
