"""Webhook exporter — POSTs SecurityVerdict as JSON to a configurable URL."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
import structlog

from janus.core.decision import SecurityVerdict

logger = structlog.get_logger()


class WebhookExporter:
    """Sends security verdicts to an HTTP webhook endpoint."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        signing_secret: str = "",
    ) -> None:
        self._url = url
        self._headers = headers or {"Content-Type": "application/json"}
        self._timeout = timeout
        self._max_retries = max_retries
        self._signing_secret = signing_secret

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
        body = json.dumps(payload, default=str)

        headers = dict(self._headers)
        if self._signing_secret:
            ts = str(int(time.time()))
            sig = hmac.new(
                self._signing_secret.encode(),
                f"{ts}.{body}".encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Janus-Timestamp"] = ts
            headers["X-Janus-Signature"] = sig

        for attempt in range(self._max_retries):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        self._url, content=body, headers=headers,
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
