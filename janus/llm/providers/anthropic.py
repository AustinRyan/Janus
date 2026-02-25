"""Anthropic provider — wraps existing AnthropicClientWrapper."""
from __future__ import annotations

from typing import Any

from janus.llm.client import AnthropicClientWrapper


class AnthropicProvider:
    """LLMProvider implementation wrapping the Anthropic SDK."""

    def __init__(self, api_key: str | None = None) -> None:
        self._client = AnthropicClientWrapper(api_key=api_key)

    async def classify(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "claude-haiku-4-5-20251001",
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        return await self._client.classify(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "claude-sonnet-4-6-20250220",
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> str:
        return await self._client.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
        )
