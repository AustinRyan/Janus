"""LLMProvider protocol for multi-model support."""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol that all LLM providers must satisfy.

    Both ``classify`` (JSON response) and ``generate`` (raw text) are required.
    """

    async def classify(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "",
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> dict[str, Any]: ...

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> str: ...
