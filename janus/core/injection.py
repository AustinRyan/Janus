"""Prompt injection detection check for the security pipeline.

Two-tier detection:
  Tier 1: Rule-based regex patterns (zero latency, zero cost)
    - Original text + decoded/normalized variants
    - Scans both conversation_history and tool_input values
    - Multi-turn fragment tracking across session messages
  Tier 2: LLM-based analysis (if classifier available)
"""
from __future__ import annotations

import base64
import re
import unicodedata
from typing import Any

import structlog

from janus.core.decision import (
    CheckResult,
    PipelineContext,
    ToolCallRequest,
    Verdict,
)
from janus.llm.classifier import SecurityClassifier

logger = structlog.get_logger()

_I = re.IGNORECASE  # shorthand

# Zero-width characters to strip before scanning
_ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\ufeff\u00ad")

# Common Unicode confusables (homoglyphs) mapped to their ASCII equivalents.
# Only includes characters commonly used to bypass text filters.
_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у (visually similar)
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0455": "s",  # Cyrillic ѕ
    "\u04bb": "h",  # Cyrillic һ
    "\u0501": "d",  # Cyrillic ԁ
    "\uff41": "a",  # Fullwidth a
    "\uff45": "e",  # Fullwidth e
    "\uff49": "i",  # Fullwidth i
    "\uff4f": "o",  # Fullwidth o
    "\uff55": "u",  # Fullwidth u
}

# Base64-like substring detector (at least 20 chars of valid base64)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Hex escape sequences: \x69\x67\x6e...
_HEX_ESCAPE_RE = re.compile(r"(\\x[0-9a-fA-F]{2}){3,}")

# Unicode escape sequences: \u0069\u0067\u006e...
_UNICODE_ESCAPE_RE = re.compile(r"(\\u[0-9a-fA-F]{4}){3,}")

# Compiled regex patterns for common prompt injection techniques
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)"
            r"\s+(instructions|prompts|rules|directives)",
            _I,
        ),
        "ignore previous instructions",
    ),
    (
        re.compile(
            r"disregard\s+(all\s+|your\s+)?"
            r"(previous|prior|above|earlier|your)"
            r"\s+(instructions|prompts|rules|directives|programming)",
            _I,
        ),
        "disregard instructions",
    ),
    (
        re.compile(r"you\s+are\s+now\s+(a|an|the|my)\s+", _I),
        "role reassignment",
    ),
    (
        re.compile(
            r"from\s+now\s+on[\s,]+(you|act|behave|respond|pretend)",
            _I,
        ),
        "behavioral override",
    ),
    (
        re.compile(r"system\s*prompt\s*:", _I),
        "system prompt injection",
    ),
    (re.compile(r"\[system\]", _I), "system tag injection"),
    (re.compile(r"<\s*system\s*>", _I), "system XML injection"),
    (re.compile(r"jailbreak", _I), "jailbreak attempt"),
    (re.compile(r"do\s+anything\s+now", _I), "DAN prompt"),
    (
        re.compile(
            r"pretend\s+(you\s+)?(are|can|have|don'?t\s+have)"
            r"\s+(no\s+)?"
            r"(restrictions|limitations|rules|filters|boundaries)",
            _I,
        ),
        "restriction bypass",
    ),
    (
        re.compile(
            r"act\s+as\s+(if\s+)?(you\s+)?(have\s+)?"
            r"(no|without)"
            r"\s+(restrictions|limitations|rules|filters|safety)",
            _I,
        ),
        "restriction bypass",
    ),
    (
        re.compile(
            r"bypass\s+(the\s+)?"
            r"(safety|security|content|filter|guard|restriction)",
            _I,
        ),
        "safety bypass",
    ),
    (
        re.compile(
            r"override\s+(the\s+)?"
            r"(safety|security|content|filter|guard|restriction|system)",
            _I,
        ),
        "override attempt",
    ),
    (
        re.compile(
            r"enter\s+(developer|debug|admin|god|sudo|root)\s+mode",
            _I,
        ),
        "privilege escalation",
    ),
    (
        re.compile(
            r"reveal\s+(your|the|system)"
            r"\s+(prompt|instructions|rules|programming)",
            _I,
        ),
        "prompt extraction",
    ),
    (
        re.compile(
            r"(what|show|tell|give|repeat|print|display)"
            r"\s+(me\s+)?(your|the)\s+(system\s+)?"
            r"(prompt|instructions|rules)",
            _I,
        ),
        "prompt extraction",
    ),
    (
        re.compile(
            r"forget\s+(everything|all|your)"
            r"\s+(you\s+)?(know|learned|were\s+told|instructions)",
            _I,
        ),
        "memory wipe",
    ),
    # --- New patterns (2C) ---
    (
        re.compile(
            r"(ignorar|ignorez|ignora|ignorieren)\s+.*(instruc|prompt|regla)",
            _I,
        ),
        "language_switch_injection",
    ),
    (
        re.compile(
            r"</\s*(task|goal|instruction|context)\s*>",
            _I,
        ),
        "task_boundary_injection",
    ),
    (
        re.compile(r"```system\b", _I),
        "markdown_system_injection",
    ),
    (
        re.compile(
            r"</?(?:system|admin|root|prompt)\s*>",
            _I,
        ),
        "delimiter_injection",
    ),
]

# Multi-turn fragment sequences (2D)
_MULTI_TURN_SEQUENCES: list[tuple[list[re.Pattern[str]], str]] = [
    (
        [re.compile(r"ignore", _I), re.compile(r"previous\s+instructions", _I)],
        "multi_turn_ignore_instructions",
    ),
    (
        [re.compile(r"you\s+are\s+now", _I), re.compile(r"no\s+restrictions", _I)],
        "multi_turn_role_no_restrictions",
    ),
    (
        [re.compile(r"forget\s+everything", _I), re.compile(r"new\s+(goal|task|instructions)", _I)],
        "multi_turn_forget_new_goal",
    ),
]


def _decode_and_normalize(text: str) -> list[str]:
    """Return candidate decoded/normalized strings for scanning.

    Always includes the original text as the first candidate so existing
    patterns continue to match unchanged.
    """
    candidates: list[str] = [text]

    # 1. Strip zero-width characters
    stripped = "".join(ch for ch in text if ch not in _ZERO_WIDTH_CHARS)
    if stripped != text:
        candidates.append(stripped)

    # 2. Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", stripped)
    if normalized not in candidates:
        candidates.append(normalized)

    # 2b. Confusable/homoglyph folding (Cyrillic → Latin, fullwidth → ASCII)
    folded = "".join(_CONFUSABLES.get(ch, ch) for ch in normalized)
    if folded not in candidates:
        candidates.append(folded)

    # 3. Base64 decode
    for match in _BASE64_RE.finditer(text):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            if decoded and len(decoded) >= 5:
                candidates.append(decoded)
        except Exception:
            pass

    # 4. Hex escape decode: \x69\x67\x6e\x6f\x72\x65 → "ignore"
    #    Replace in-place so surrounding text is preserved for pattern matching
    hex_replaced = normalized
    for match in _HEX_ESCAPE_RE.finditer(normalized):
        try:
            decoded = match.group().encode("utf-8").decode("unicode_escape")
            if decoded:
                hex_replaced = hex_replaced.replace(match.group(), decoded)
        except Exception:
            pass
    if hex_replaced != normalized and hex_replaced not in candidates:
        candidates.append(hex_replaced)

    # 5. Unicode escape decode: \u0069\u0067\u006e → "ign"
    #    Replace in-place so surrounding text is preserved
    uni_replaced = normalized
    for match in _UNICODE_ESCAPE_RE.finditer(normalized):
        try:
            decoded = match.group().encode("utf-8").decode("unicode_escape")
            if decoded:
                uni_replaced = uni_replaced.replace(match.group(), decoded)
        except Exception:
            pass
    if uni_replaced != normalized and uni_replaced not in candidates:
        candidates.append(uni_replaced)

    return candidates


def _extract_tool_input_text(request: ToolCallRequest) -> str:
    """Recursively collect all string values from tool_input."""
    strings: list[str] = []

    def _collect(value: Any) -> None:
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                _collect(v)
        elif isinstance(value, (list, tuple)):
            for item in value:
                _collect(item)

    _collect(request.tool_input)
    return " ".join(strings)


class PromptInjectionCheck:
    """Security check that detects prompt injection in user messages.

    Priority 5: runs before all other checks.
    """

    name: str = "prompt_injection"
    priority: int = 5

    def __init__(
        self, classifier: SecurityClassifier | None = None
    ) -> None:
        self._classifier = classifier
        self._session_fragments: dict[str, list[str]] = {}

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> CheckResult:
        # Build list of (source, text) pairs to scan
        texts_to_scan: list[tuple[str, str]] = []

        user_message = self._extract_latest_user_message(request)
        if user_message:
            texts_to_scan.append(("user_message", user_message))

        tool_input_text = _extract_tool_input_text(request)
        if tool_input_text:
            texts_to_scan.append(("tool_input", tool_input_text))

        if not texts_to_scan:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason="No user message to scan.",
            )

        # Tier 1: Rule-based detection with encoding/normalization
        for source, text in texts_to_scan:
            candidates = _decode_and_normalize(text)
            for candidate in candidates:
                for pattern, description in _INJECTION_PATTERNS:
                    if pattern.search(candidate):
                        logger.warning(
                            "injection_detected",
                            tier="rule",
                            pattern=description,
                            source=source,
                            agent_id=request.agent_id,
                        )
                        return CheckResult(
                            check_name=self.name,
                            passed=False,
                            risk_contribution=40.0,
                            reason=(
                                "Prompt injection detected"
                                f" (rule: {description})"
                            ),
                            force_verdict=Verdict.BLOCK,
                            metadata={
                                "tier": "rule",
                                "pattern": description,
                                "source": source,
                            },
                        )

        # Multi-turn fragment tracking (2D)
        if user_message:
            result = self._check_multi_turn(request.session_id, user_message)
            if result is not None:
                return result

        # Tier 2: LLM-based detection (fails open)
        if self._classifier and user_message:
            try:
                result = await self._classifier.classify_injection(
                    user_message
                )
                confidence = result.get("confidence", 0)
                if (
                    result.get("is_injection", False)
                    and confidence >= 0.7
                ):
                    logger.warning(
                        "injection_detected",
                        tier="llm",
                        confidence=confidence,
                        agent_id=request.agent_id,
                    )
                    reasoning = result.get("reasoning", "")
                    return CheckResult(
                        check_name=self.name,
                        passed=False,
                        risk_contribution=40.0,
                        reason=(
                            "Prompt injection detected"
                            f" (LLM, confidence:"
                            f" {confidence:.0%}):"
                            f" {reasoning}"
                        ),
                        force_verdict=Verdict.BLOCK,
                        metadata={
                            "tier": "llm",
                            "confidence": confidence,
                        },
                    )
            except Exception as exc:
                logger.debug(
                    "injection_llm_check_failed", error=str(exc)
                )
                # Fail open: rule-based check already ran

        return CheckResult(
            check_name=self.name,
            passed=True,
            risk_contribution=0.0,
            reason="No injection patterns detected.",
        )

    def _check_multi_turn(
        self, session_id: str, message: str
    ) -> CheckResult | None:
        """Track message fragments per session and check for multi-turn injection."""
        fragments = self._session_fragments.setdefault(session_id, [])
        fragments.append(message)

        # Keep only last 10 messages to bound memory
        if len(fragments) > 10:
            self._session_fragments[session_id] = fragments[-10:]
            fragments = self._session_fragments[session_id]

        # Check each multi-turn sequence
        for sequence_patterns, description in _MULTI_TURN_SEQUENCES:
            if self._sequence_matches(fragments, sequence_patterns):
                logger.warning(
                    "injection_detected",
                    tier="multi_turn",
                    pattern=description,
                    session_id=session_id,
                )
                return CheckResult(
                    check_name=self.name,
                    passed=False,
                    risk_contribution=30.0,
                    reason=(
                        "Prompt injection detected"
                        f" (multi-turn: {description})"
                    ),
                    force_verdict=Verdict.BLOCK,
                    metadata={
                        "tier": "multi_turn",
                        "pattern": description,
                    },
                )

        return None

    @staticmethod
    def _sequence_matches(
        fragments: list[str], sequence: list[re.Pattern[str]]
    ) -> bool:
        """Check if the fragment history contains all patterns in order."""
        seq_idx = 0
        for fragment in fragments:
            if seq_idx < len(sequence) and sequence[seq_idx].search(fragment):
                seq_idx += 1
            if seq_idx >= len(sequence):
                return True
        return False

    @staticmethod
    def _extract_latest_user_message(
        request: ToolCallRequest,
    ) -> str:
        """Extract the most recent user message from history."""
        for msg in reversed(request.conversation_history):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    return " ".join(
                        str(block.get("text", ""))
                        for block in content
                        if isinstance(block, dict)
                        and block.get("type") == "text"
                    )
        return ""
