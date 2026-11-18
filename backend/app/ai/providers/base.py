"""Base AI Provider interface and exception definitions.
Abstracts underlying AI model vendors (Gemini, OpenAI, Anthropic, Mock).
"""

from abc import ABC, abstractmethod


class AIProviderError(Exception):
    """Base exception for AI provider errors."""
    pass


class AIProviderUnavailableError(AIProviderError):
    """Raised when an AI provider is not configured or disabled."""
    pass


class AIProviderTimeoutError(AIProviderError):
    """Raised when an AI provider call times out."""
    pass


class AIProviderRateLimitError(AIProviderError):
    """Raised when an AI provider returns rate limiting or quota exhaustion."""
    pass


class AIResponseFormatError(AIProviderError):
    """Raised when an AI provider returns malformed non-JSON output."""
    pass


class BaseAIProvider(ABC):
    """Abstract interface for all QuantumShield AI providers."""

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the provider has valid configuration credentials."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the canonical provider name (e.g. 'gemini', 'openai', 'mock')."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Returns the active model name."""
        pass

    @abstractmethod
    async def generate(self, prompt: str, system_prompt: str) -> str:
        """
        Executes a prompt against the AI provider and returns the raw response string (typically JSON).
        Must respect timeout and error handling constraints.
        """
        pass

