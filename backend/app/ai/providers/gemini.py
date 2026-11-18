"""Google Gemini AI Provider implementation via standard REST API.
Uses httpx without introducing external heavy client SDKs.
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

logger = logging.getLogger("quantumshield.ai.gemini")

DEFAULT_GEMINI_MODEL = "gemini-1.5-flash"
GEMINI_API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


class GeminiAIProvider(BaseAIProvider):
    """Integrates Google Gemini via REST API."""

    def __init__(
        self,
        api_key: Optional[str],
        model: Optional[str] = None,
        timeout_seconds: float = 12.0,
        max_output_tokens: int = 1500,
    ):
        self._api_key = api_key
        self._model = model or DEFAULT_GEMINI_MODEL
        self._timeout_seconds = timeout_seconds
        self._max_output_tokens = max_output_tokens

    def is_configured(self) -> bool:
        return bool(self._api_key and self._api_key.strip())

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, prompt: str, system_prompt: str) -> str:
        if not self.is_configured():
            raise AIProviderUnavailableError("Gemini API key is not configured.")

        url = GEMINI_API_URL_TEMPLATE.format(model=self._model)
        params = {"key": self._api_key}

        payload = {
            "system_instruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": self._max_output_tokens,
                "responseMimeType": "application/json",
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(
                    url,
                    params=params,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

            if response.status_code == 429:
                raise AIProviderRateLimitError("Gemini API quota or rate limit exceeded.")

            if response.status_code != 200:
                logger.error(
                    "Gemini API returned HTTP status %s.",
                    response.status_code,
                )
                raise AIProviderError(f"Gemini API request failed with HTTP {response.status_code}")

            data = response.json()
            candidates = data.get("candidates") or []
            if not candidates:
                raise AIProviderError("Gemini API returned empty candidates.")

            first_candidate = candidates[0]
            content = first_candidate.get("content", {})
            parts = content.get("parts", [])
            if not parts:
                raise AIProviderError("Gemini API candidate contained no parts.")

            text = parts[0].get("text", "").strip()
            return text

        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError(f"Gemini API call timed out after {self._timeout_seconds}s") from exc
        except (AIProviderError, AIProviderUnavailableError, AIProviderRateLimitError, AIProviderTimeoutError):
            raise
        except Exception as exc:
            raise AIProviderError(
                "Unexpected error communicating with Gemini API."
            ) from exc