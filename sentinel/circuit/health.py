from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass


@dataclass
class HealthMetrics:
    """Snapshot of Guardian health metrics."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    error_rate: float = 0.0


class HealthMonitor:
    """Tracks Guardian latency and error rates for circuit breaker decisions."""

    def __init__(self, window_size: int = 100) -> None:
        self._window_size = window_size
        self._latencies: deque[float] = deque(maxlen=window_size)
        self._total_requests = 0
        self._successful = 0
        self._failed = 0

    def record_latency(self, latency_ms: float, success: bool) -> None:
        self._latencies.append(latency_ms)
        self._total_requests += 1
        if success:
            self._successful += 1
        else:
            self._failed += 1

    def get_metrics(self) -> HealthMetrics:
        latencies = sorted(self._latencies)
        avg = sum(latencies) / len(latencies) if latencies else 0.0
        p95_idx = int(len(latencies) * 0.95)
        p95 = latencies[p95_idx] if latencies else 0.0
        error_rate = self._failed / self._total_requests if self._total_requests else 0.0

        return HealthMetrics(
            total_requests=self._total_requests,
            successful_requests=self._successful,
            failed_requests=self._failed,
            avg_latency_ms=avg,
            p95_latency_ms=p95,
            error_rate=error_rate,
        )

    def start_timer(self) -> _Timer:
        return _Timer()


class _Timer:
    """Context-manager style timer for measuring request latency."""

    def __init__(self) -> None:
        self._start = time.monotonic()

    @property
    def elapsed_ms(self) -> float:
        return (time.monotonic() - self._start) * 1000
