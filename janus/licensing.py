"""HMAC-signed license key validation for Janus Pro."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

# Production deployments MUST set JANUS_LICENSE_SECRET to a unique value.
# The defaults here are for development/testing only.
_VERIFICATION_KEY = os.environ.get("JANUS_LICENSE_SECRET", "janus-v1-verification-key").encode()
_LEGACY_VERIFICATION_KEY = os.environ.get(
    "JANUS_LEGACY_LICENSE_SECRET", "sentinel-v1-verification-key"
).encode()


def validate_license(key: str) -> tuple[bool, str]:
    """Validate an HMAC-signed license key.

    Accepts both sk-janus- and legacy sk-sentinel- prefixes.
    Returns (is_valid, tier).
    """
    if key.startswith("sk-janus-"):
        prefix = "sk-janus-"
        verification_key = _VERIFICATION_KEY
    elif key.startswith("sk-sentinel-"):
        prefix = "sk-sentinel-"
        verification_key = _LEGACY_VERIFICATION_KEY
    else:
        return False, "free"

    remainder = key[len(prefix):]
    parts = remainder.rsplit("-", 1)
    if len(parts) != 2:
        return False, "free"

    payload_b64, sig_hex = parts

    expected = hmac.new(
        verification_key, payload_b64.encode(), hashlib.sha256
    ).hexdigest()[:16]

    if not hmac.compare_digest(sig_hex, expected):
        return False, "free"

    try:
        payload = json.loads(
            base64.urlsafe_b64decode(payload_b64 + "==")
        )
    except (ValueError, json.JSONDecodeError):
        return False, "free"

    if payload.get("exp", 0) and time.time() > payload["exp"]:
        return False, "free"

    return True, payload.get("tier", "pro")


def generate_license(
    tier: str = "pro",
    customer_id: str = "",
    expiry_days: int = 365,
    signing_key: bytes = _VERIFICATION_KEY,
) -> str:
    """Generate a signed license key. For internal use."""
    payload = {
        "tier": tier,
        "cid": customer_id,
        "exp": int(time.time()) + expiry_days * 86400,
    }
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode())
        .rstrip(b"=")
        .decode()
    )
    sig = hmac.new(
        signing_key, payload_b64.encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"sk-janus-{payload_b64}-{sig}"
