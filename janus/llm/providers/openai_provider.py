"""OpenAI provider — uses the openai SDK with json_object response_format."""
from __future__ import annotations

import json
import re
from typing import Any

import structlog

logger = structlog.get_logger()

_JSON_OBJECT_RE = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)


class OpenAIProvider:
    """LLMProvider implementation using the OpenAI SDK."""

    def __init__(self, api_key: str = "", base_url: str | None = None) -> None:
        try:
            from openai import AsyncOpenAI
        except ImportError:
            raise ImportError(
                "openai package is required for OpenAIProvider. "
                "Install it with: pip install openai"
            )
        kwargs: dict[str, Any] = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        self._client = AsyncOpenAI(**kwargs)

    async def classify(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "gpt-4o-mini",
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        from janus.core.exceptions import ClassificationError

        try:
            response = await self._client.chat.completions.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            text = response.choices[0].message.content or ""
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                match = _JSON_OBJECT_RE.search(text)
                if match:
                    return json.loads(match.group())
                raise
        except json.JSONDecodeError as e:
            raise ClassificationError(f"Invalid JSON from OpenAI: {e}") from e
        except Exception as e:
            if "ClassificationError" in type(e).__name__:
                raise
            raise ClassificationError(f"OpenAI API error: {e}") from e

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "gpt-4o-mini",
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> str:
        response = await self._client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content or ""
