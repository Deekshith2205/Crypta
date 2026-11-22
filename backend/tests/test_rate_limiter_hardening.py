"""Regression tests for Task B2: API Rate Limiter Hardening.
Verifies that:
- Repeated requests to scan and AI endpoints receive HTTP 429 with Retry-After header.
- Scan and AI endpoints use stricter, separate rate limit buckets.
- Rate limiter storage is bounded (max_clients) to prevent memory exhaustion from randomized IPs.
- Expired/idle client entries are pruned safely.
- Untrusted X-Forwarded-For headers cannot bypass rate limits.
- Trusted proxy configuration (TRUSTED_PROXY_COUNT) is enforced strictly and safely.
"""

import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.security.rate_limiter import (
    InMemoryRateLimiter,
    DEFAULT_RATE_LIMITER,
    UPLOAD_SCAN_RATE_LIMITER,
    AI_RATE_LIMITER,
    get_client_ip,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_all_limiters():
    """Reset rate limiters before each test."""
    DEFAULT_RATE_LIMITER.reset()
    if hasattr(UPLOAD_SCAN_RATE_LIMITER, "reset"):
        UPLOAD_SCAN_RATE_LIMITER.reset()
    if hasattr(AI_RATE_LIMITER, "reset"):
        AI_RATE_LIMITER.reset()


def test_repeated_requests_receive_429_with_retry_after():
    """Repeated requests to /api/scan/config must trigger rate limit and return 429 with Retry-After header."""
    valid_payload = {
        "files": [{"name": "app.yaml", "content": "tls:\n  version: TLSv1.3\n"}]
    }

    # Limit is 5 requests per minute for upload scans
    responses = [client.post("/api/scan/config", json=valid_payload) for _ in range(7)]

    # At least the 6th and 7th requests should receive 429
    assert responses[-1].status_code == 429
    assert "Retry-After" in responses[-1].headers
    retry_after = int(responses[-1].headers["Retry-After"])
    assert retry_after > 0
    assert responses[-1].json()["error"] == "RATE_LIMIT_EXCEEDED"


def test_ai_endpoint_rate_limiting():
    """AI endpoints must have strict rate limiting and return 429 when exceeded."""
    payload = {
        "rule_id": "TLS-VERSION",
        "title": "Deprecated TLS Version",
        "value": "TLSv1.0",
        "role": "KEY_EXCHANGE",
        "source": "EXTERNAL_SCAN",
        "evidence_status": "OBSERVED",
        "severity": "CRITICAL",
        "risk": "QUANTUM",
    }

    responses = [client.post("/api/ai/explain/finding", json=payload) for _ in range(7)]
    assert responses[-1].status_code == 429
    assert "Retry-After" in responses[-1].headers


def test_different_endpoints_use_separate_buckets():
    """Upload scan endpoints and live scan endpoints must use separate rate limiting buckets."""
    # Exhaust upload bucket (limit 5)
    valid_payload = {
        "files": [{"name": "app.yaml", "content": "tls:\n  version: TLSv1.3\n"}]
    }
    for _ in range(5):
        resp = client.post("/api/scan/config", json=valid_payload)
        assert resp.status_code == 200

    # 6th upload scan is rate limited
    assert client.post("/api/scan/config", json=valid_payload).status_code == 429

    # But DEFAULT_RATE_LIMITER (live scan / audit) is not exhausted yet
    # Live scan should still proceed past rate limiting (may fail validation, but NOT 429)
    scan_resp = client.post("/api/scan", json={"domain": ""})
    assert scan_resp.status_code != 429


def test_expired_client_entries_are_pruned():
    """Expired timestamps must be pruned from client history."""
    limiter = InMemoryRateLimiter(max_requests=5, window_seconds=1.0)
    client_ip = "192.0.2.1"

    # Make requests
    allowed, _ = limiter.is_allowed(client_ip)
    assert allowed is True
    assert client_ip in limiter._history

    # Fast forward beyond window
    limiter._history[client_ip] = [time.time() - 10.0]
    limiter.prune_expired()

    # The client entry should be completely removed if all timestamps are expired
    assert client_ip not in limiter._history


def test_storage_is_strictly_bounded_against_ip_flooding():
    """Rate limiter must enforce max_clients to prevent unbounded memory growth."""
    limiter = InMemoryRateLimiter(max_requests=5, window_seconds=60.0, max_clients=100)

    # Generate 500 distinct client IPs
    for i in range(500):
        limiter.is_allowed(f"10.0.{i // 256}.{i % 256}")

    # History size must not exceed max_clients
    assert len(limiter._history) <= 100


def test_untrusted_forwarded_for_cannot_bypass_rate_limits():
    """When TRUSTED_PROXY_COUNT is 0 (default), X-Forwarded-For is ignored and cannot bypass rate limits."""
    valid_payload = {
        "files": [{"name": "app.yaml", "content": "tls:\n  version: TLSv1.3\n"}]
    }

    # Exhaust limit with changing X-Forwarded-For headers
    for i in range(5):
        resp = client.post(
            "/api/scan/config",
            json=valid_payload,
            headers={"X-Forwarded-For": f"198.51.100.{i}"},
        )
        assert resp.status_code == 200

    # 6th request with a new spoofed X-Forwarded-For must still be blocked (429)
    blocked_resp = client.post(
        "/api/scan/config",
        json=valid_payload,
        headers={"X-Forwarded-For": "203.0.113.99"},
    )
    assert blocked_resp.status_code == 429


def test_trusted_proxy_ip_extraction():
    """get_client_ip correctly extracts client IP only when trusted_proxy_count is explicitly configured."""
    class MockClient:
        host = "10.0.0.1"  # Proxy IP

    class MockRequest:
        def __init__(self, xff: str = ""):
            self.client = MockClient()
            self.headers = {"x-forwarded-for": xff} if xff else {}

    # Case 1: No trusted proxy configured (trusted_proxy_count=0)
    req = MockRequest(xff="203.0.113.5, 198.51.100.1")
    assert get_client_ip(req, trusted_proxy_count=0) == "10.0.0.1"

    # Case 2: 1 trusted proxy configured (trusted_proxy_count=1)
    req = MockRequest(xff="203.0.113.5, 198.51.100.1")
    assert get_client_ip(req, trusted_proxy_count=1) == "198.51.100.1"

    # Case 3: 2 trusted proxies configured (trusted_proxy_count=2)
    req = MockRequest(xff="203.0.113.5, 198.51.100.1, 10.0.0.2")
    assert get_client_ip(req, trusted_proxy_count=2) == "198.51.100.1"
