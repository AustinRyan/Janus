"""API key authentication and tier gating for the Janus dashboard."""
from __future__ import annotations

import os
import secrets
import time
from collections import defaultdict

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware

_bearer = HTTPBearer(auto_error=False)


async def require_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """FastAPI dependency: enforce API key when JANUS_API_KEY is set.

    If the env var is unset, auth is disabled (dev mode).
    """
    api_key = os.environ.get("JANUS_API_KEY")
    if api_key is None:
        return  # dev mode — no auth required

    if credentials is None or not secrets.compare_digest(
        credentials.credentials, api_key
    ):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


async def require_pro_tier() -> None:
    """FastAPI dependency: require PRO tier for premium endpoints."""
    from janus.tier import current_tier

    if not current_tier.is_pro:
        raise HTTPException(
            status_code=403,
            detail="This feature requires Janus Pro. Upgrade at https://janus-security.dev/pricing",
        )


class RateLimiter:
    """Simple in-memory rate limiter keyed by client IP."""

    def __init__(self, max_calls: int = 10, window_seconds: int = 60) -> None:
        self._max_calls = max_calls
        self._window = window_seconds
        self._calls: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str) -> bool:
        now = time.time()
        calls = self._calls[key]
        self._calls[key] = [t for t in calls if now - t < self._window]
        if len(self._calls[key]) >= self._max_calls:
            return False
        self._calls[key].append(now)
        return True


_license_limiter = RateLimiter(max_calls=10, window_seconds=60)


async def rate_limit_license(request: Request) -> None:
    """Rate limit license activation attempts by client IP."""
    client_ip = request.client.host if request.client else "unknown"
    if not _license_limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")


# ── General API rate limiting middleware ────────────────────────────

_RATE_LIMIT_GROUPS: list[tuple[str, int]] = [
    ("/api/chat", 30),
    ("/api/evaluate", 60),
    ("/api/billing", 10),
    ("/api/license", 10),
]
_DEFAULT_API_LIMIT = 120


def _classify_request(path: str) -> tuple[str, int] | None:
    """Return (group_name, max_calls_per_min) or None for non-API paths."""
    if not path.startswith("/api/"):
        return None
    for prefix, limit in _RATE_LIMIT_GROUPS:
        if path.startswith(prefix):
            return prefix, limit
    return "/api", _DEFAULT_API_LIMIT


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limiting for API endpoints.

    Groups endpoints by path prefix and applies per-group limits.
    Non-API paths and WebSocket connections are not limited.
    """

    def __init__(self, app, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(app, **kwargs)
        self._limiters: dict[int, RateLimiter] = {}

    def _get_limiter(self, max_calls: int) -> RateLimiter:
        if max_calls not in self._limiters:
            self._limiters[max_calls] = RateLimiter(max_calls=max_calls, window_seconds=60)
        return self._limiters[max_calls]

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        classification = _classify_request(request.url.path)
        if classification is None:
            return await call_next(request)

        group, max_calls = classification
        client_ip = request.client.host if request.client else "unknown"
        key = f"{client_ip}:{group}"

        limiter = self._get_limiter(max_calls)
        if not limiter.check(key):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Try again later."},
            )

        return await call_next(request)
