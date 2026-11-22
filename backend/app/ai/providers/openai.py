"""OpenAI Provider implementation via standard REST API.
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
from app.ai.providers.resilience import execute_http_with_resilience

logger = logging.getLogger("quantumshield.ai.openai")

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
OPENAI_CHAT_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIProvider(BaseAIProvider):
    """Integrates OpenAI chat completions API."""

    def __init__(
        self,
        api_key: Optional[str],
        model: Optional[str] = None,
        timeout_seconds: float = 12.0,
        max_output_tokens: int = 1500,
    ):
        self._api_key = api_key
        self._model = model or DEFAULT_OPENAI_MODEL
        self._timeout_seconds = timeout_seconds
        self._max_output_tokens = max_output_tokens

    def is_configured(self) -> bool:
        return bool(self._api_key and self._api_key.strip())

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, prompt: str, system_prompt: str) -> str:
        if not self.is_configured():
            raise AIProviderUnavailableError("OpenAI API key is not configured.")

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": self._max_output_tokens,
            "response_format": {"type": "json_object"},
        }

        async def _call() -> httpx.Response:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                return await client.post(
                    OPENAI_CHAT_URL,
                    headers=headers,
                    json=payload,
                )

        response = await execute_http_with_resilience(
            _call,
            provider_name=self.provider_name,
        )

        data = response.json()
        choices = data.get("choices") or []
        if not choices:
            raise AIProviderError("OpenAI API returned no completion choices.")

        message = choices[0].get("message", {})
        content = message.get("content", "").strip()
        return content