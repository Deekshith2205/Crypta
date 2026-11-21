
import httpx
import pytest

import app.ai.providers.anthropic as anthropic_module
import app.ai.providers.gemini as gemini_module
import app.ai.providers.openai as openai_module

from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.base import (
    AIProviderError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
)
from app.ai.providers.gemini import GeminiAIProvider
from app.ai.providers.openai import OpenAIProvider


# ---------------------------------------------------------------------------
# Successful authentication and request handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gemini_sends_api_key_in_header_not_url(monkeypatch):
    """Gemini credentials must not be transmitted through URL parameters."""

    api_key = "synthetic-gemini-test-key"
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url_query"] = request.url.query
        captured["api_key_header"] = request.headers.get("x-goog-api-key")
        captured["content_type"] = request.headers.get("content-type")

        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": '{"status": "SUCCESS"}'}]
                        }
                    }
                ]
            },
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def mock_async_client(*, timeout):
        return real_async_client(
            transport=transport,
            timeout=timeout,
        )

    monkeypatch.setattr(
        gemini_module.httpx,
        "AsyncClient",
        mock_async_client,
    )

    provider = GeminiAIProvider(api_key=api_key)

    result = await provider.generate(
        prompt="Test prompt",
        system_prompt="Test system instructions",
    )

    assert result == '{"status": "SUCCESS"}'
    assert captured["url_query"] == b""
    assert captured["api_key_header"] == api_key
    assert captured["content_type"] == "application/json"


@pytest.mark.asyncio
async def test_openai_sends_api_key_in_authorization_header(monkeypatch):
    """OpenAI credentials must use the Authorization header."""

    api_key = "synthetic-openai-test-key"
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url_query"] = request.url.query
        captured["authorization"] = request.headers.get("authorization")

        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": '{"status": "SUCCESS"}'}}
                ]
            },
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def mock_async_client(*, timeout):
        return real_async_client(
            transport=transport,
            timeout=timeout,
        )

    monkeypatch.setattr(
        openai_module.httpx,
        "AsyncClient",
        mock_async_client,
    )

    provider = OpenAIProvider(api_key=api_key)

    result = await provider.generate(
        "Test prompt",
        "Test system instructions",
    )

    assert result == '{"status": "SUCCESS"}'
    assert captured["url_query"] == b""
    assert captured["authorization"] == f"Bearer {api_key}"


@pytest.mark.asyncio
async def test_anthropic_sends_api_key_in_header(monkeypatch):
    """Anthropic credentials must use the x-api-key header."""

    api_key = "synthetic-anthropic-test-key"
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url_query"] = request.url.query
        captured["api_key_header"] = request.headers.get("x-api-key")

        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": '{"status": "SUCCESS"}'}
                ]
            },
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def mock_async_client(*, timeout):
        return real_async_client(
            transport=transport,
            timeout=timeout,
        )

    monkeypatch.setattr(
        anthropic_module.httpx,
        "AsyncClient",
        mock_async_client,
    )

    provider = AnthropicProvider(api_key=api_key)

    result = await provider.generate(
        "Test prompt",
        "Test system instructions",
    )

    assert result == '{"status": "SUCCESS"}'
    assert captured["url_query"] == b""
    assert captured["api_key_header"] == api_key


# ---------------------------------------------------------------------------
# HTTP rate-limit handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider_module", "provider_class", "api_key"),
    [
        (gemini_module, GeminiAIProvider, "synthetic-gemini-key"),
        (openai_module, OpenAIProvider, "synthetic-openai-key"),
        (anthropic_module, AnthropicProvider, "synthetic-anthropic-key"),
    ],
)
@pytest.mark.asyncio
async def test_providers_raise_rate_limit_error_on_http_429(
    monkeypatch,
    provider_module,
    provider_class,
    api_key,
):
    """All external providers must handle HTTP 429 consistently."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={"error": "Synthetic rate limit response"},
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def mock_async_client(*, timeout):
        return real_async_client(
            transport=transport,
            timeout=timeout,
        )

    monkeypatch.setattr(
        provider_module.httpx,
        "AsyncClient",
        mock_async_client,
    )

    provider = provider_class(api_key=api_key)

    with pytest.raises(AIProviderRateLimitError):
        await provider.generate(
            prompt="Test prompt",
            system_prompt="Test system instructions",
        )


# ---------------------------------------------------------------------------
# HTTP error response sanitization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider_module", "provider_class", "api_key"),
    [
        (gemini_module, GeminiAIProvider, "synthetic-gemini-key"),
        (openai_module, OpenAIProvider, "synthetic-openai-key"),
        (anthropic_module, AnthropicProvider, "synthetic-anthropic-key"),
    ],
)
@pytest.mark.asyncio
async def test_providers_do_not_expose_non_200_response_bodies(
    monkeypatch,
    provider_module,
    provider_class,
    api_key,
):
    """Provider error bodies must not appear in raised exceptions."""

    synthetic_secret = "SYNTHETIC-DO-NOT-EXPOSE-987654"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            json={"error": f"Internal failure: {synthetic_secret}"},
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def mock_async_client(*, timeout):
        return real_async_client(
            transport=transport,
            timeout=timeout,
        )

    monkeypatch.setattr(
        provider_module.httpx,
        "AsyncClient",
        mock_async_client,
    )

    provider = provider_class(api_key=api_key)

    with pytest.raises(AIProviderError) as exc_info:
        await provider.generate(
            prompt="Test prompt",
            system_prompt="Test system instructions",
        )

    assert synthetic_secret not in str(exc_info.value)


# ---------------------------------------------------------------------------
# HTTP timeout handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider_module", "provider_class", "api_key"),
    [
        (gemini_module, GeminiAIProvider, "synthetic-gemini-key"),
        (openai_module, OpenAIProvider, "synthetic-openai-key"),
        (anthropic_module, AnthropicProvider, "synthetic-anthropic-key"),
    ],
)
@pytest.mark.asyncio
async def test_providers_convert_http_timeouts_to_provider_timeout_error(
    monkeypatch,
    provider_module,
    provider_class,
    api_key,
):
    """All providers must expose a consistent timeout exception."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Synthetic timeout")

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def mock_async_client(*, timeout):
        return real_async_client(
            transport=transport,
            timeout=timeout,
        )

    monkeypatch.setattr(
        provider_module.httpx,
        "AsyncClient",
        mock_async_client,
    )

    provider = provider_class(api_key=api_key)

    with pytest.raises(AIProviderTimeoutError):
        await provider.generate(
            prompt="Test prompt",
            system_prompt="Test system instructions",
        )


# ---------------------------------------------------------------------------
# Provider logging security
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider_module", "provider_class", "api_key"),
    [
        (gemini_module, GeminiAIProvider, "synthetic-gemini-secret"),
        (openai_module, OpenAIProvider, "synthetic-openai-secret"),
        (anthropic_module, AnthropicProvider, "synthetic-anthropic-secret"),
    ],
)
@pytest.mark.asyncio
async def test_provider_errors_do_not_log_credentials_or_response_bodies(
    monkeypatch,
    caplog,
    provider_module,
    provider_class,
    api_key,
):
    """Provider error handling must not log credentials or response bodies."""

    synthetic_response_secret = "SYNTHETIC-RESPONSE-SECRET-123456"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            json={"error": synthetic_response_secret},
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def mock_async_client(*, timeout):
        return real_async_client(
            transport=transport,
            timeout=timeout,
        )

    monkeypatch.setattr(
        provider_module.httpx,
        "AsyncClient",
        mock_async_client,
    )

    provider = provider_class(api_key=api_key)

    with caplog.at_level("DEBUG"):
        with pytest.raises(AIProviderError):
            await provider.generate(
                prompt="SYNTHETIC-PROMPT-DO-NOT-LOG",
                system_prompt="SYNTHETIC-SYSTEM-PROMPT-DO-NOT-LOG",
            )

    assert api_key not in caplog.text
    assert synthetic_response_secret not in caplog.text
    assert "SYNTHETIC-PROMPT-DO-NOT-LOG" not in caplog.text
    assert "SYNTHETIC-SYSTEM-PROMPT-DO-NOT-LOG" not in caplog.text
