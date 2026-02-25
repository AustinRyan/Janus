"""Transactional email delivery via Resend for license key fulfillment."""
from __future__ import annotations

import os

import structlog

logger = structlog.get_logger()


def send_license_email(to: str, license_key: str, tier: str = "pro") -> bool:
    """Send license key email via Resend. Returns True on success, False on failure (never raises)."""
    api_key = os.environ.get("RESEND_API_KEY")
    if not api_key:
        logger.warning("resend_not_configured", reason="RESEND_API_KEY not set")
        return False

    try:
        import resend  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("resend_not_installed", reason="resend package not installed")
        return False

    try:
        resend.api_key = api_key
        resend.Emails.send(
            {
                "from": "Janus Security <noreply@janus-security.dev>",
                "to": [to],
                "subject": f"Your Janus {tier.title()} License Key",
                "html": _build_email_html(license_key, tier),
            }
        )
        logger.info("license_email_sent", to=to, tier=tier)
        return True
    except Exception:
        logger.warning("license_email_failed", to=to, exc_info=True)
        return False


def _build_email_html(license_key: str, tier: str) -> str:
    return f"""\
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 560px; margin: 0 auto; padding: 40px 20px; color: #e2e8f0; background: #06080e;">
  <h1 style="font-size: 24px; color: #5eead4; margin-bottom: 8px;">Janus {tier.title()}</h1>
  <p style="color: #94a3b8; margin-bottom: 32px;">Your license key is ready. Keep this email for your records.</p>

  <div style="background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 32px;">
    <p style="font-size: 12px; color: #64748b; margin: 0 0 8px 0; text-transform: uppercase; letter-spacing: 0.05em;">License Key</p>
    <code style="font-family: 'Fira Code', monospace; font-size: 14px; color: #5eead4; word-break: break-all;">{license_key}</code>
  </div>

  <h2 style="font-size: 16px; color: #e2e8f0; margin-bottom: 16px;">Activation</h2>
  <p style="color: #94a3b8; line-height: 1.6;">
    <strong>Option 1:</strong> Add to your <code style="color: #5eead4;">janus.toml</code>:<br>
    <code style="font-family: 'Fira Code', monospace; font-size: 13px; color: #a78bfa;">[license]<br>key = "{license_key}"</code>
  </p>
  <p style="color: #94a3b8; line-height: 1.6; margin-top: 16px;">
    <strong>Option 2:</strong> Call the API:<br>
    <code style="font-family: 'Fira Code', monospace; font-size: 13px; color: #a78bfa;">POST /api/license/activate<br>{{"license_key": "{license_key}"}}</code>
  </p>

  <hr style="border: none; border-top: 1px solid #1e293b; margin: 32px 0;">
  <p style="font-size: 12px; color: #475569;">
    Need help? Visit <a href="https://janus-security.dev/docs" style="color: #5eead4;">janus-security.dev/docs</a>
  </p>
</div>"""
