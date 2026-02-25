from __future__ import annotations

import json
import re
from typing import Any

import anthropic
import structlog

logger = structlog.get_logger()

# Regex to extract the first JSON object from text that may contain extra content
_JSON_OBJECT_RE = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)


class AnthropicClientWrapper:
    """Unified wrapper around the Anthropic SDK for Guardian and Worker calls."""

    def __init__(self, api_key: str | None = None) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    async def classify(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "claude-haiku-4-5-20251001",
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        """Send a classification request expecting JSON response.

        Returns parsed JSON dict. Raises ClassificationError on failure.
        """
        from janus.core.exceptions import ClassificationError

        try:
            response = await self._client.messages.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )

            block = response.content[0]
            text = block.text  # type: ignore[union-attr]
            # Strip markdown code fences if present
            if text.startswith("```"):
                lines = text.split("\n")
                if lines[-1].strip() == "```":
                    text = "\n".join(lines[1:-1])
                else:
                    text = "\n".join(lines[1:])

            try:
                return json.loads(text)  # type: ignore[no-any-return]
            except json.JSONDecodeError:
                # LLM sometimes returns JSON followed by extra explanation.
                # Extract the first valid JSON object from the response.
                match = _JSON_OBJECT_RE.search(text)
                if match:
                    return json.loads(match.group())  # type: ignore[no-any-return]
                raise

        except json.JSONDecodeError as e:
            raise ClassificationError(f"Invalid JSON from classifier: {e}") from e
        except anthropic.APIError as e:
            raise ClassificationError(f"Anthropic API error: {e}") from e

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "claude-sonnet-4-6-20250220",
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> str:
        """Send a generation request and return raw text."""
        response = await self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text  # type: ignore[union-attr]
