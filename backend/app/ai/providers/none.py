"""Null AI provider for unconfigured or disabled state.
Fails safely and immediately without network calls or fabricated output.
"""

from app.ai.providers.base import BaseAIProvider, AIProviderUnavailableError


class NoneAIProvider(BaseAIProvider):
    """Represents a state where no AI provider is configured."""

    def __init__(self, reason: str = "AI provider is not configured."):
        self._reason = reason

    def is_configured(self) -> bool:
        return False

    @property
    def provider_name(self) -> str:
        return "none"

    @property
    def model_name(self) -> str:
        return "none"

    async def generate(self, prompt: str, system_prompt: str) -> str:
        raise AIProviderUnavailableError(self._reason)

