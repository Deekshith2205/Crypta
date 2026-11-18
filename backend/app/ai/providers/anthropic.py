"""Anthropic Claude Provider implementation via standard REST API.
Uses httpx without introducing external client SDKs.
"""

import json
import logging
from typing import Optional
import httpx

from app.ai.providers.base import (
    BaseAIProvider,
    AIProviderError,
    AIProviderTimeoutError,
    AIProviderRateLimitError,
    AIProviderUnavailableError,
)

logger = logging.getLogger("quantumshield.ai.anthropic")

DEFAULT_ANTHROPIC_MODEL = "claude-3-5-haiku-20241022"
ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"


class AnthropicProvider(BaseAIProvider):
    """Integrates Anthropic Messages API."""

    def __init__(
        self,
        api_key: Optional[str],
        model: Optional[str] = None,
        timeout_seconds: float = 12.0,
        max_output_tokens: int = 1500,
    ):
        self._api_key = api_key
        self._model = model or DEFAULT_ANTHROPIC_MODEL
        self._timeout_seconds = timeout_seconds
        self._max_output_tokens = max_output_tokens

    def is_configured(self) -> bool:
        return bool(self._api_key and self._api_key.strip())

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, prompt: str, system_prompt: str) -> str:
        if not self.is_configured():
            raise AIProviderUnavailableError("Anthropic API key is not configured.")

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self._model,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": self._max_output_tokens,
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(
                    ANTHROPIC_MESSAGES_URL,
                    headers=headers,
                    json=payload,
                )

            if response.status_code == 429:
                raise AIProviderRateLimitError("Anthropic quota or rate limit exceeded.")

            if response.status_code != 200:
                logger.error(
                    "Anthropic API returned HTTP status %s.",
                    response.status_code,
                )
                raise AIProviderError(f"Anthropic API request failed with HTTP {response.status_code}")

            data = response.json()
            content_blocks = data.get("content") or []
            if not content_blocks:
                raise AIProviderError("Anthropic API returned empty content blocks.")

            text = content_blocks[0].get("text", "").strip()
            return text

        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError(f"Anthropic API call timed out after {self._timeout_seconds}s") from exc
        except (AIProviderError, AIProviderUnavailableError, AIProviderRateLimitError, AIProviderTimeoutError):
            raise
        except Exception as exc:
            raise AIProviderError(
                "Unexpected error communicating with Anthropic API."
            ) from exc