"""Tests for request size limits and security headers (Task B6).

Verifies:
- Standard security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
  are attached to all API responses.
- Sensitive endpoints (/api/scan, /api/audit, /api/banking, /api/ai) include strict Cache-Control.
- Error responses also include security headers.
- Requests with bodies exceeding 5 MiB are rejected with HTTP 413 (PAYLOAD_TOO_LARGE).
- Requests within size limits are accepted normally.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_standard_security_headers_present():
    """All responses must contain standard baseline security headers."""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert "geolocation=()" in response.headers.get("permissions-policy", "")


def test_sensitive_endpoints_have_no_store_cache_control():
    """Sensitive assessment, banking, and AI endpoints must disable caching."""
    for path in ["/api/banking/profiles", "/api/ai/status"]:
        response = client.get(path)
        assert response.status_code == 200
        cache_control = response.headers.get("cache-control", "").lower()
        assert "no-store" in cache_control
        assert "no-cache" in cache_control


def test_security_headers_on_error_responses():
    """Error responses (e.g. 404, 400) must also include security headers."""
    response = client.get("/api/non-existent-endpoint")
    assert response.status_code == 404
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"


def test_oversized_content_length_rejected_with_413():
    """Requests with Content-Length exceeding 5 MiB (5,242,880 bytes) must return HTTP 413."""
    oversized_length = 5 * 1024 * 1024 + 1  # 5 MiB + 1 byte

    # Upload endpoint returns UPLOAD_TOO_LARGE
    upload_resp = client.post(
        "/api/scan/config",
        headers={"Content-Length": str(oversized_length)},
        content=b"test",
    )
    assert upload_resp.status_code == 413
    assert upload_resp.json()["error"] == "UPLOAD_TOO_LARGE"

    # Non-upload endpoint returns PAYLOAD_TOO_LARGE
    non_upload_resp = client.post(
        "/api/banking/risk/what-if",
        headers={"Content-Length": str(oversized_length)},
        content=b"test",
    )
    assert non_upload_resp.status_code == 413
    assert non_upload_resp.json()["error"] == "PAYLOAD_TOO_LARGE"


def test_normal_sized_request_not_rejected_with_413():
    """Normal requests within the 5 MiB limit must not be blocked by size limiter."""
    response = client.post(
        "/api/scan/config",
        json={"files": [{"name": "test.yaml", "content": "key: value"}]},
    )
    assert response.status_code != 413
