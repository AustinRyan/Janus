"""API key authentication for the Janus dashboard."""
from __future__ import annotations

import os
import secrets

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

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
