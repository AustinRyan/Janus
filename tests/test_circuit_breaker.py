from __future__ import annotations

import time

import pytest

from sentinel.circuit.breaker import CircuitBreaker, CircuitState
from sentinel.config import CircuitBreakerConfig


@pytest.fixture
def breaker() -> CircuitBreaker:
    return CircuitBreaker(
        CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout_seconds=0.1,
            success_threshold=2,
        )
    )


def test_starts_closed(breaker: CircuitBreaker) -> None:
    assert breaker.state == CircuitState.CLOSED
    assert breaker.allow_request() is True


def test_stays_closed_below_threshold(breaker: CircuitBreaker) -> None:
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.allow_request() is True


def test_opens_after_threshold_failures(breaker: CircuitBreaker) -> None:
    for _ in range(3):
        breaker.record_failure()
    assert breaker.state == CircuitState.OPEN
    assert breaker.allow_request() is False


def test_transitions_to_half_open_after_timeout(breaker: CircuitBreaker) -> None:
    for _ in range(3):
        breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    time.sleep(0.15)
    assert breaker.state == CircuitState.HALF_OPEN
    assert breaker.allow_request() is True


def test_half_open_to_closed_on_successes(breaker: CircuitBreaker) -> None:
    for _ in range(3):
        breaker.record_failure()
    time.sleep(0.15)
    assert breaker.state == CircuitState.HALF_OPEN

    breaker.record_success()
    breaker.record_success()
    assert breaker.state == CircuitState.CLOSED


def test_half_open_to_open_on_failure(breaker: CircuitBreaker) -> None:
    for _ in range(3):
        breaker.record_failure()
    time.sleep(0.15)
    assert breaker.state == CircuitState.HALF_OPEN

    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN


def test_success_resets_failure_count(breaker: CircuitBreaker) -> None:
    breaker.record_failure()
    breaker.record_failure()
    breaker.record_success()
    assert breaker.failure_count == 0
    # Should not be open since success reset the count
    breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED


def test_full_cycle(breaker: CircuitBreaker) -> None:
    # CLOSED -> OPEN
    for _ in range(3):
        breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    # OPEN -> HALF_OPEN (after timeout)
    time.sleep(0.15)
    assert breaker.state == CircuitState.HALF_OPEN

    # HALF_OPEN -> CLOSED (after successes)
    breaker.record_success()
    breaker.record_success()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.allow_request() is True


def test_state_change_callback(breaker: CircuitBreaker) -> None:
    transitions: list[tuple[CircuitState, CircuitState]] = []
    breaker.on_state_change(lambda old, new: transitions.append((old, new)))

    for _ in range(3):
        breaker.record_failure()

    assert len(transitions) == 1
    assert transitions[0] == (CircuitState.CLOSED, CircuitState.OPEN)


def test_manual_reset(breaker: CircuitBreaker) -> None:
    for _ in range(3):
        breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    breaker.reset()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0
