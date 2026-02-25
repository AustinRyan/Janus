"""Ollama provider — uses httpx to call the Ollama REST API."""
from __future__ import annotations

import json
import re
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_JSON_OBJECT_RE = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)


class OllamaProvider:
    """LLMProvider implementation using the Ollama local API."""

    def __init__(self, base_url: str = "http://localhost:11434") -> None:
        self._base_url = base_url.rstrip("/")

    async def classify(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "llama3.2",
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        from janus.core.exceptions import ClassificationError

        try:
            text = await self._chat(
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                format_json=True,
            )
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                match = _JSON_OBJECT_RE.search(text)
                if match:
                    return json.loads(match.group())
                raise
        except json.JSONDecodeError as e:
            raise ClassificationError(f"Invalid JSON from Ollama: {e}") from e
        except Exception as e:
            if "ClassificationError" in type(e).__name__:
                raise
            raise ClassificationError(f"Ollama API error: {e}") from e

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "llama3.2",
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> str:
        return await self._chat(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            format_json=False,
        )

    async def _chat(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        format_json: bool,
    ) -> str:
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": temperature},
        }
        if format_json:
            payload["format"] = "json"

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]
