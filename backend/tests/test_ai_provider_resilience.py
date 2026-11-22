"""Tests for AI provider HTTP resilience, retry strategies, and JSON output schema repair.
Verifies Task D6 requirements.
"""

import asyncio
import json
import httpx
import pytest

from app.ai.providers.base import (
    AIProviderError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
)
from app.ai.providers.openai import OpenAIProvider
from app.ai.providers.gemini import GeminiAIProvider
from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.resilience import (
    execute_http_with_resilience,
    parse_retry_after,
)
from app.ai.service import _extract_clean_json


# ---------------------------------------------------------------------------
# 1. JSON Extraction and Repair Tests
# ---------------------------------------------------------------------------


def test_extract_clean_json_plain():
    """Standard valid JSON passes through intact."""
    raw = '{"rule_id": "TEST_001", "status": "ACTIVE"}'
    cleaned = _extract_clean_json(raw)
    assert json.loads(cleaned) == {"rule_id": "TEST_001", "status": "ACTIVE"}


def test_extract_clean_json_markdown_fences():
    """Markdown ```json code blocks are cleanly extracted."""
    raw = """Here is the result:
```json
{
  "rule_id": "TEST_002",
  "meaning": "Cryptographic finding."
}
```
Hope this is helpful!"""
    cleaned = _extract_clean_json(raw)
    data = json.loads(cleaned)
    assert data["rule_id"] == "TEST_002"
    assert data["meaning"] == "Cryptographic finding."


def test_extract_clean_json_conversational_preamble_and_postamble():
    """Extracts JSON object when surrounded by conversational text without markdown."""
    raw = 'Sure thing! Here is the JSON: {"system_id": "SYS_99", "score": 85} Thanks for asking!'
    cleaned = _extract_clean_json(raw)
    data = json.loads(cleaned)
    assert data["system_id"] == "SYS_99"
    assert data["score"] == 85


def test_extract_clean_json_smart_quotes():
    """Normalizes Unicode smart / curly quotes to standard ASCII double quotes."""
    raw = '{“system_name”: “Core Banking Engine”, “risk”: “HIGH”}'
    cleaned = _extract_clean_json(raw)
    data = json.loads(cleaned)
    assert data["system_name"] == "Core Banking Engine"
    assert data["risk"] == "HIGH"


def test_extract_clean_json_trailing_commas():
    """Strips trailing commas before closing braces and brackets."""
    raw = """{
      "items": [
        "item1",
        "item2",
      ],
      "active": true,
    }"""
    cleaned = _extract_clean_json(raw)
    data = json.loads(cleaned)
    assert data["items"] == ["item1", "item2"]
    assert data["active"] is True


def test_extract_clean_json_combined_repairs():
    """Handles conversational text, markdown fences, smart quotes, and trailing commas combined."""
    raw = """Understood. Here is the requested structured assessment:
```json
{
  “rule_id”: “RSA_2048”,
  “quantum_relevance”: “Broken by Shor’s algorithm.”,
  “tags”: [“finance”, “pqc”,],
}
```
Let me know if you need any adjustments."""
    cleaned = _extract_clean_json(raw)
    data = json.loads(cleaned)
    assert data["rule_id"] == "RSA_2048"
    assert "Shor" in data["quantum_relevance"]
    assert data["tags"] == ["finance", "pqc"]


# ---------------------------------------------------------------------------
# 2. Retry-After Header Parsing
# ---------------------------------------------------------------------------


def test_parse_retry_after_seconds():
    """Parses integer and decimal seconds."""
    assert parse_retry_after("3") == 3.0
    assert parse_retry_after("1.5") == 1.5
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None
    assert parse_retry_after("invalid") is None


def test_parse_retry_after_http_date():
    """Parses HTTP date format."""
    # Past date returns 0.0
    assert parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT") == 0.0


# ---------------------------------------------------------------------------
# 3. HTTP Resilience Unit Tests (execute_http_with_resilience)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resilience_succeeds_on_first_try():
    """HTTP 200 returns immediately with zero retries."""
    call_count = 0

    async def mock_call():
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"result": "ok"})

    response = await execute_http_with_resilience(
        mock_call,
        provider_name="test_provider",
        max_retries=2,
        initial_backoff=0.01,
    )
    assert response.status_code == 200
    assert call_count == 1


@pytest.mark.asyncio
async def test_resilience_retries_transient_502_503_504():
    """Retries transient 502/503/504 and returns success if recovery occurs."""
    call_count = 0

    async def mock_call():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(502, text="Bad Gateway")
        if call_count == 2:
            return httpx.Response(503, text="Service Unavailable")
        return httpx.Response(200, json={"status": "recovered"})

    response = await execute_http_with_resilience(
        mock_call,
        provider_name="test_provider",
        max_retries=2,
        initial_backoff=0.01,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "recovered"
    assert call_count == 3


@pytest.mark.asyncio
async def test_resilience_exhausts_retries_on_persistent_503():
    """Raises AIProviderError when transient errors persist beyond max_retries."""
    call_count = 0

    async def mock_call():
        nonlocal call_count
        call_count += 1
        return httpx.Response(503, text="Service Unavailable")

    with pytest.raises(AIProviderError) as exc_info:
        await execute_http_with_resilience(
            mock_call,
            provider_name="test_provider",
            max_retries=2,
            initial_backoff=0.01,
        )
    assert "temporarily unavailable" in str(exc_info.value)
    assert call_count == 3  # Initial + 2 retries


@pytest.mark.asyncio
async def test_resilience_retries_rate_limit_with_short_retry_after():
    """Retries HTTP 429 when Retry-After is <= 5.0 seconds."""
    call_count = 0

    async def mock_call():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "0.02"},
                text="Too Many Requests",
            )
        return httpx.Response(200, json={"status": "rate_limit_recovered"})

    response = await execute_http_with_resilience(
        mock_call,
        provider_name="test_provider",
        max_retries=2,
        initial_backoff=0.01,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rate_limit_recovered"
    assert call_count == 2


@pytest.mark.asyncio
async def test_resilience_rejects_rate_limit_with_long_or_missing_retry_after():
    """Raises AIProviderRateLimitError immediately when Retry-After > 5.0 or absent."""
    call_count = 0

    async def mock_call():
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            429,
            headers={"Retry-After": "10.0"},
            text="Too Many Requests",
        )

    with pytest.raises(AIProviderRateLimitError):
        await execute_http_with_resilience(
            mock_call,
            provider_name="test_provider",
            max_retries=2,
            initial_backoff=0.01,
        )
    assert call_count == 1  # No retry


@pytest.mark.asyncio
async def test_resilience_fails_fast_on_client_errors():
    """Client errors (400, 401, 403, 404) fail fast without retrying."""
    for code, expected_exc in [
        (400, AIProviderError),
        (401, AIProviderUnavailableError),
        (403, AIProviderUnavailableError),
        (404, AIProviderError),
    ]:
        call_count = 0

        async def mock_call():
            nonlocal call_count
            call_count += 1
            return httpx.Response(code, text="Client Error")

        with pytest.raises(expected_exc):
            await execute_http_with_resilience(
                mock_call,
                provider_name="test_provider",
                max_retries=2,
                initial_backoff=0.01,
            )
        assert call_count == 1, f"Status code {code} should not retry."


@pytest.mark.asyncio
async def test_resilience_retries_network_connection_drops():
    """Retries httpx.ConnectError and succeeds upon reconnect."""
    call_count = 0

    async def mock_call():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise httpx.ConnectError("Connection reset by peer")
        return httpx.Response(200, json={"status": "reconnected"})

    response = await execute_http_with_resilience(
        mock_call,
        provider_name="test_provider",
        max_retries=2,
        initial_backoff=0.01,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "reconnected"
    assert call_count == 2


@pytest.mark.asyncio
async def test_resilience_converts_timeout_to_ai_provider_timeout_error():
    """Converts httpx.TimeoutException to AIProviderTimeoutError immediately."""
    async def mock_call():
        raise httpx.ReadTimeout("Socket read timed out")

    with pytest.raises(AIProviderTimeoutError):
        await execute_http_with_resilience(
            mock_call,
            provider_name="test_provider",
            max_retries=2,
            initial_backoff=0.01,
        )


# ---------------------------------------------------------------------------
# 4. Provider End-to-End Integration with Resilience
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openai_provider_with_transient_retry(monkeypatch):
    """OpenAIProvider recovers from initial 502 Bad Gateway."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(502, text="Bad Gateway")
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"result": "openai_recovered"}'}}]},
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    monkeypatch.setattr(
        "app.ai.providers.openai.httpx.AsyncClient",
        lambda *, timeout: real_async_client(transport=transport, timeout=timeout),
    )

    provider = OpenAIProvider(api_key="test-openai-key")
    result = await provider.generate("prompt", "system")
    assert result == '{"result": "openai_recovered"}'
    assert call_count == 2


@pytest.mark.asyncio
async def test_gemini_provider_with_transient_retry(monkeypatch):
    """GeminiAIProvider recovers from initial 503 Service Unavailable."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(503, text="Service Unavailable")
        return httpx.Response(
            200,
            json={"candidates": [{"content": {"parts": [{"text": '{"result": "gemini_recovered"}'}]}}]},
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    monkeypatch.setattr(
        "app.ai.providers.gemini.httpx.AsyncClient",
        lambda *, timeout: real_async_client(transport=transport, timeout=timeout),
    )

    provider = GeminiAIProvider(api_key="test-gemini-key")
    result = await provider.generate("prompt", "system")
    assert result == '{"result": "gemini_recovered"}'
    assert call_count == 2


@pytest.mark.asyncio
async def test_anthropic_provider_with_transient_retry(monkeypatch):
    """AnthropicProvider recovers from initial 504 Gateway Timeout."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(504, text="Gateway Timeout")
        return httpx.Response(
            200,
            json={"content": [{"type": "text", "text": '{"result": "anthropic_recovered"}'}]},
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    monkeypatch.setattr(
        "app.ai.providers.anthropic.httpx.AsyncClient",
        lambda *, timeout: real_async_client(transport=transport, timeout=timeout),
    )

    provider = AnthropicProvider(api_key="test-anthropic-key")
    result = await provider.generate("prompt", "system")
    assert result == '{"result": "anthropic_recovered"}'
    assert call_count == 2
