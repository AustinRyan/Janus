from __future__ import annotations

import time
from collections.abc import Callable
from enum import Enum

import structlog

from sentinel.config import CircuitBreakerConfig

logger = structlog.get_logger()


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker state machine for Guardian fail-safe.

    State transitions:
        CLOSED --[failure_threshold exceeded]--> OPEN
        OPEN   --[recovery_timeout elapsed]----> HALF_OPEN
        HALF_OPEN --[success_threshold met]----> CLOSED
        HALF_OPEN --[any failure]--------------> OPEN

    When OPEN: all tool calls are immediately BLOCKED (fail-safe).
    """

    def __init__(self, config: CircuitBreakerConfig | None = None) -> None:
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0.0
        self._state_change_callbacks: list[Callable[[CircuitState, CircuitState], None]] = []

    @property
    def state(self) -> CircuitState:
        """Current state, with auto-transition from OPEN to HALF_OPEN on timeout."""
        if self._state == CircuitState.OPEN and self._last_failure_time > 0:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self._config.recovery_timeout_seconds:
                self._transition_to(CircuitState.HALF_OPEN)
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    def on_state_change(
        self, callback: Callable[[CircuitState, CircuitState], None]
    ) -> None:
        """Register a callback for state transitions."""
        self._state_change_callbacks.append(callback)

    def allow_request(self) -> bool:
        """Check if a request should be allowed through."""
        current = self.state
        if current == CircuitState.CLOSED:
            return True
        if current == CircuitState.HALF_OPEN:
            return True
        return False

    def record_success(self) -> None:
        """Record a successful Guardian evaluation."""
        self._failure_count = 0
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self._config.success_threshold:
                self._transition_to(CircuitState.CLOSED)

    def record_failure(self) -> None:
        """Record a failed Guardian evaluation."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.OPEN)
        elif self._failure_count >= self._config.failure_threshold:
            self._transition_to(CircuitState.OPEN)

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED."""
        self._transition_to(CircuitState.CLOSED)

    def _transition_to(self, new_state: CircuitState) -> None:
        old = self._state
        if old == new_state:
            return
        self._state = new_state
        logger.info(
            "circuit_breaker_transition",
            from_state=old.value,
            to_state=new_state.value,
        )
        if new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            self._success_count = 0
        for cb in self._state_change_callbacks:
            cb(old, new_state)
