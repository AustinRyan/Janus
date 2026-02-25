"""Central exporter dispatch — fires all enabled exporters after each verdict."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from janus.config import ExporterConfig
    from janus.core.decision import SecurityVerdict
    from janus.exporters.notifiers import EmailNotifier, SlackNotifier, TelegramNotifier

logger = structlog.get_logger()


class ExporterCoordinator:
    """Holds all enabled exporters and fires them after each verdict.

    All errors are caught and logged — exporters must never break the pipeline.
    """

    def __init__(self, config: ExporterConfig) -> None:
        self._webhook = None
        self._json_log = None
        self._prometheus = None
        self._otel = None
        self._notifiers: list[SlackNotifier | EmailNotifier | TelegramNotifier] = []

        if config.webhook_url:
            from janus.exporters.webhook import WebhookExporter

            self._webhook = WebhookExporter(
                url=config.webhook_url,
                signing_secret=config.webhook_signing_secret,
            )

        if config.json_log_path:
            from janus.exporters.json_log import JsonLogExporter

            self._json_log = JsonLogExporter(path=config.json_log_path)

        if config.prometheus_enabled:
            from janus.exporters.prometheus import PrometheusExporter

            self._prometheus = PrometheusExporter()

        if config.otel_enabled:
            from janus.exporters.otel import OtelExporter

            self._otel = OtelExporter(service_name=config.otel_service_name)

        # Notification channels
        nc = config.notifications
        if nc.slack is not None:
            from janus.exporters.notifiers import SlackNotifier

            self._notifiers.append(SlackNotifier(
                webhook_url=nc.slack.webhook_url,
                channel=nc.slack.channel,
                min_verdict=nc.slack.min_verdict,
            ))
        if nc.email is not None:
            from janus.exporters.notifiers import EmailNotifier

            self._notifiers.append(EmailNotifier(
                smtp_host=nc.email.smtp_host,
                smtp_port=nc.email.smtp_port,
                smtp_user=nc.email.smtp_user,
                smtp_password=nc.email.smtp_password,
                from_addr=nc.email.from_addr,
                to_addrs=nc.email.to_addrs,
                min_verdict=nc.email.min_verdict,
            ))
        if nc.telegram is not None:
            from janus.exporters.notifiers import TelegramNotifier

            self._notifiers.append(TelegramNotifier(
                bot_token=nc.telegram.bot_token,
                chat_id=nc.telegram.chat_id,
                min_verdict=nc.telegram.min_verdict,
            ))

    @property
    def enabled_count(self) -> int:
        return sum(
            1
            for e in (self._webhook, self._json_log, self._prometheus, self._otel)
            if e is not None
        ) + len(self._notifiers)

    async def export(
        self,
        verdict: SecurityVerdict,
        tool_name: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> None:
        """Fire all enabled exporters. Errors are logged, never propagated."""
        loop = asyncio.get_running_loop()

        # Webhook is async — fire as background task
        if self._webhook is not None:
            try:
                asyncio.create_task(
                    self._webhook.send(
                        verdict,
                        tool_name=tool_name,
                        agent_id=agent_id,
                        session_id=session_id,
                    )
                )
            except Exception:
                logger.exception("exporter_webhook_error")

        # Sync exporters — run in executor to avoid blocking
        if self._json_log is not None:
            try:
                await loop.run_in_executor(
                    None,
                    self._json_log.log,
                    verdict,
                    tool_name,
                    agent_id,
                    session_id,
                )
            except Exception:
                logger.exception("exporter_json_log_error")

        if self._prometheus is not None:
            try:
                await loop.run_in_executor(
                    None,
                    self._prometheus.record,
                    verdict,
                    tool_name,
                    session_id,
                )
            except Exception:
                logger.exception("exporter_prometheus_error")

        if self._otel is not None:
            try:
                await loop.run_in_executor(
                    None,
                    self._otel.record,
                    verdict,
                    tool_name,
                    agent_id,
                    session_id,
                )
            except Exception:
                logger.exception("exporter_otel_error")

        # Notifiers — fire as background tasks
        for notifier in self._notifiers:
            try:
                asyncio.create_task(
                    notifier.notify(
                        verdict,
                        tool_name=tool_name,
                        agent_id=agent_id,
                        session_id=session_id,
                    )
                )
            except Exception:
                logger.exception("exporter_notifier_error")
