"""Notification dispatchers for Slack, Email, and Telegram."""
from __future__ import annotations

import smtplib
from email.mime.text import MIMEText
from typing import Any

import httpx
import structlog

from janus.core.decision import SecurityVerdict

logger = structlog.get_logger()

# Verdict severity ordering (lowest to highest)
_VERDICT_SEVERITY = {"allow": 0, "sandbox": 1, "challenge": 2, "pause": 3, "block": 4, "lock": 5}


def should_notify(verdict_value: str, min_verdict: str) -> bool:
    """Return True if the verdict meets or exceeds the minimum severity."""
    return _VERDICT_SEVERITY.get(verdict_value, 0) >= _VERDICT_SEVERITY.get(min_verdict, 4)


def _build_message(
    verdict: SecurityVerdict,
    tool_name: str,
    agent_id: str,
    session_id: str,
) -> str:
    reasons = "; ".join(verdict.reasons) if verdict.reasons else "none"
    return (
        f"[{verdict.verdict.value.upper()}] agent={agent_id} "
        f"tool={tool_name} risk={verdict.risk_score:.1f} "
        f"session={session_id} reasons={reasons}"
    )


class SlackNotifier:
    """Sends alerts to a Slack channel via incoming webhook."""

    def __init__(self, webhook_url: str, channel: str = "", min_verdict: str = "block") -> None:
        self._url = webhook_url
        self._channel = channel
        self._min_verdict = min_verdict

    async def notify(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> bool:
        if not should_notify(verdict.verdict.value, self._min_verdict):
            return False

        text = _build_message(verdict, tool_name, agent_id, session_id)
        payload: dict[str, Any] = {"text": text}
        if self._channel:
            payload["channel"] = self._channel

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self._url, json=payload)
                return resp.status_code < 300
        except httpx.HTTPError as e:
            logger.warning("slack_notify_error", error=str(e))
            return False


class EmailNotifier:
    """Sends alert emails via SMTP."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        from_addr: str = "",
        to_addrs: list[str] | None = None,
        min_verdict: str = "block",
    ) -> None:
        self._host = smtp_host
        self._port = smtp_port
        self._user = smtp_user
        self._password = smtp_password
        self._from = from_addr
        self._to = to_addrs or []
        self._min_verdict = min_verdict

    async def notify(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> bool:
        if not should_notify(verdict.verdict.value, self._min_verdict):
            return False

        subject = f"Janus Alert: {verdict.verdict.value.upper()} — {tool_name}"
        body = _build_message(verdict, tool_name, agent_id, session_id)

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self._from
        msg["To"] = ", ".join(self._to)

        try:
            import asyncio
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._send_sync, msg)
            return True
        except Exception as e:
            logger.warning("email_notify_error", error=str(e))
            return False

    def _send_sync(self, msg: MIMEText) -> None:
        with smtplib.SMTP(self._host, self._port) as server:
            server.ehlo()
            if self._port != 25:
                server.starttls()
            if self._user:
                server.login(self._user, self._password)
            server.sendmail(self._from, self._to, msg.as_string())


class TelegramNotifier:
    """Sends alerts to a Telegram chat via Bot API."""

    def __init__(self, bot_token: str, chat_id: str, min_verdict: str = "block") -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._min_verdict = min_verdict

    async def notify(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> bool:
        if not should_notify(verdict.verdict.value, self._min_verdict):
            return False

        text = _build_message(verdict, tool_name, agent_id, session_id)
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json={
                    "chat_id": self._chat_id,
                    "text": text,
                })
                return resp.status_code < 300
        except httpx.HTTPError as e:
            logger.warning("telegram_notify_error", error=str(e))
            return False
