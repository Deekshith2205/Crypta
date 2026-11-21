"""Configuration for QuantumShield AI Intelligence Layer.
Reads settings and API credentials safely from environment variables.
Credentials are never logged, serialized into API responses, or exposed to the frontend.
"""

import os
from typing import Optional
from pydantic import BaseModel, Field


class AISettings(BaseModel):
    """Configuration settings for AI provider integration."""
    provider: str = Field(
        default="none",
        description="Active provider identifier: none, mock, gemini, openai, anthropic"
    )
    gemini_api_key: Optional[str] = Field(default=None, repr=False)
    openai_api_key: Optional[str] = Field(default=None, repr=False)
    anthropic_api_key: Optional[str] = Field(default=None, repr=False)
    model: Optional[str] = Field(default=None, description="Model identifier override")
    timeout_seconds: float = Field(default=12.0, ge=1.0, le=60.0)
    max_output_tokens: int = Field(default=1500, ge=100, le=4096)
    max_input_length: int = Field(default=4000, ge=200, le=16000)

    @classmethod
    def from_env(cls) -> "AISettings":
        """Loads AI settings from process environment variables."""
        provider = (os.getenv("AI_PROVIDER") or "").strip().lower()
        gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        openai_key = os.getenv("OPENAI_API_KEY")
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        model = os.getenv("AI_MODEL")

        timeout_env = os.getenv("AI_TIMEOUT_SECONDS")
        timeout = float(timeout_env) if timeout_env else 12.0

        max_tokens_env = os.getenv("AI_MAX_OUTPUT_TOKENS")
        max_tokens = int(max_tokens_env) if max_tokens_env else 1500

        max_input_env = os.getenv("AI_MAX_INPUT_LENGTH")
        max_input = int(max_input_env) if max_input_env else 4000

        # Autodetection if AI_PROVIDER is not explicitly specified
        if not provider or provider == "auto":
            if os.getenv("AI_MOCK_ENABLED", "").lower() in ("true", "1", "yes"):
                provider = "mock"
            elif gemini_key:
                provider = "gemini"
            elif openai_key:
                provider = "openai"
            elif anthropic_key:
                provider = "anthropic"
            else:
                provider = "none"

        return cls(
            provider=provider,
            gemini_api_key=gemini_key,
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key,
            model=model,
            timeout_seconds=timeout,
            max_output_tokens=max_tokens,
            max_input_length=max_input,
        )


DEFAULT_AI_SETTINGS = AISettings.from_env()

