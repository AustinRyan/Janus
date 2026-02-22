from __future__ import annotations

# ── Verdict thresholds ──────────────────────────────────────────────
LOCK_THRESHOLD = 80.0
SANDBOX_THRESHOLD = 60.0
ELEVATED_LOGGING_THRESHOLD = 40.0
MAX_RISK_SCORE = 100.0
MIN_RISK_SCORE = 0.0

# ── Base risk by tool category ──────────────────────────────────────
TOOL_BASE_RISK: dict[str, float] = {
    "read_file": 2.0,
    "search_web": 3.0,
    "list_files": 1.0,
    "write_file": 15.0,
    "execute_code": 25.0,
    "send_email": 30.0,
    "send_message": 25.0,
    "api_call": 20.0,
    "database_query": 20.0,
    "database_write": 35.0,
    "financial_transfer": 50.0,
    "delete_file": 20.0,
    "modify_permissions": 40.0,
}

# ── Keyword amplifiers scanned in tool_input values ─────────────────
KEYWORD_AMPLIFIERS: dict[str, float] = {
    "password": 15.0,
    "api_key": 15.0,
    "secret": 15.0,
    "credentials": 15.0,
    "authentication": 10.0,
    "auth": 8.0,
    "login": 10.0,
    "token": 10.0,
    "sudo": 20.0,
    "rm -rf": 25.0,
    "transfer": 10.0,
    "admin": 10.0,
    "root": 15.0,
    "private_key": 20.0,
    "/etc/shadow": 25.0,
    "/etc/passwd": 20.0,
    "ssh_key": 20.0,
    "wallet": 15.0,
    "credit_card": 20.0,
}

KEYWORD_AMPLIFIER_CAP = 25.0
DEFAULT_TOOL_BASE_RISK = 5.0
LLM_RISK_WEIGHT = 0.3

# ── Velocity detection ──────────────────────────────────────────────
VELOCITY_THRESHOLD_CALLS = 5
VELOCITY_WINDOW_SECONDS = 60.0
VELOCITY_PENALTY_PER_CALL = 3.0
VELOCITY_PENALTY_CAP = 15.0

# ── Escalation detection ────────────────────────────────────────────
ESCALATION_WINDOW_MINUTES = 30
ESCALATION_PENALTY_PER_ATTEMPT = 7.0
ESCALATION_PENALTY_CAP = 20.0

# ── Score decay ─────────────────────────────────────────────────────
DECAY_RATE_PER_MINUTE = 2.0
DECAY_IDLE_THRESHOLD_MINUTES = 5.0
