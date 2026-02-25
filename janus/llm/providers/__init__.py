"""LLM provider implementations and factory."""
from __future__ import annotations

from typing import Any

from janus.llm.provider import LLMProvider


def create_provider(
    provider: str = "anthropic",
    api_key: str = "",
    base_url: str = "",
    **kwargs: Any,
) -> LLMProvider:
    """Create an LLMProvider by name.

    Args:
        provider: One of "anthropic", "openai", "ollama".
        api_key: API key (required for anthropic/openai).
        base_url: Custom base URL (optional for openai, required for ollama).
    """
    if provider == "anthropic":
        from janus.llm.providers.anthropic import AnthropicProvider
        return AnthropicProvider(api_key=api_key or None)

    if provider == "openai":
        from janus.llm.providers.openai_provider import OpenAIProvider
        return OpenAIProvider(api_key=api_key, base_url=base_url or None)

    if provider == "ollama":
        from janus.llm.providers.ollama_provider import OllamaProvider
        return OllamaProvider(base_url=base_url or "http://localhost:11434")

    raise ValueError(f"Unknown provider: {provider!r}. Must be 'anthropic', 'openai', or 'ollama'.")
