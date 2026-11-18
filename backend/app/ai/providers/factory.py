"""Factory for instantiating QuantumShield AI providers.
Selects the active provider based on configuration without hardcoded coupling.
"""

import logging
from typing import Optional

from app.ai.config import AISettings, DEFAULT_AI_SETTINGS
from app.ai.providers.base import BaseAIProvider
from app.ai.providers.gemini import GeminiAIProvider
from app.ai.providers.openai import OpenAIProvider
from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.mock import MockAIProvider
from app.ai.providers.none import NoneAIProvider

logger = logging.getLogger("quantumshield.ai.factory")


def get_ai_provider(settings: Optional[AISettings] = None) -> BaseAIProvider:
    """
    Creates and returns an AI provider based on configuration.
    If no provider or key is configured, safely returns a NoneAIProvider.
    """
    cfg = settings or DEFAULT_AI_SETTINGS
    provider_name = (cfg.provider or "none").strip().lower()

    if provider_name == "mock":
        return MockAIProvider(model_name=cfg.model or "mock-quantum-advisor")

    elif provider_name == "gemini":
        if not cfg.gemini_api_key:
            logger.warning("Gemini provider selected but GEMINI_API_KEY is missing.")
            return NoneAIProvider("Gemini API key is not configured.")
        return GeminiAIProvider(
            api_key=cfg.gemini_api_key,
            model=cfg.model,
            timeout_seconds=cfg.timeout_seconds,
            max_output_tokens=cfg.max_output_tokens,
        )

    elif provider_name == "openai":
        if not cfg.openai_api_key:
            logger.warning("OpenAI provider selected but OPENAI_API_KEY is missing.")
            return NoneAIProvider("OpenAI API key is not configured.")
        return OpenAIProvider(
            api_key=cfg.openai_api_key,
            model=cfg.model,
            timeout_seconds=cfg.timeout_seconds,
            max_output_tokens=cfg.max_output_tokens,
        )

    elif provider_name == "anthropic":
        if not cfg.anthropic_api_key:
            logger.warning("Anthropic provider selected but ANTHROPIC_API_KEY is missing.")
            return NoneAIProvider("Anthropic API key is not configured.")
        return AnthropicProvider(
            api_key=cfg.anthropic_api_key,
            model=cfg.model,
            timeout_seconds=cfg.timeout_seconds,
            max_output_tokens=cfg.max_output_tokens,
        )

    elif provider_name in ("none", ""):
        return NoneAIProvider("AI provider is not configured.")

    else:
        logger.warning("Unrecognized AI provider '%s'; falling back to NoneAIProvider.", provider_name)
        return NoneAIProvider(f"Unrecognized AI provider '{provider_name}'.")

