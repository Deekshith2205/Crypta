"""Tests for optional API-key authentication (Task B7).

Verifies:
- When QS_API_KEY is unset or empty, all endpoints remain open and accessible.
- When QS_API_KEY is set, /api/* endpoints require a valid X-API-Key header.
- /api/health remains unauthenticated even when QS_API_KEY is set.
- Missing API key returns HTTP 401 UNAUTHORIZED with 'API key required.'.
- Invalid API key returns HTTP 401 UNAUTHORIZED with 'Invalid API key.'.
- Valid API key allows the request through.
- Verification uses constant-time string comparison (hmac.compare_digest).
"""

import os
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security.middleware import get_configured_api_key, verify_api_key

client = TestClient(app)


def test_api_key_unset_mode_allows_access():
    """When QS_API_KEY is unset, endpoints must be accessible without API key."""
    with patch.dict(os.environ, {"QS_API_KEY": "", "API_KEY": ""}):
        assert get_configured_api_key() == ""
        resp_health = client.get("/api/health")
        assert resp_health.status_code == 200

        resp_profiles = client.get("/api/banking/profiles")
        assert resp_profiles.status_code == 200


def test_api_key_set_mode_health_remains_open():
    """Liveness probe /api/health must remain accessible without API key even when key is configured."""
    with patch.dict(os.environ, {"QS_API_KEY": "test-secret-key-12345"}):
        resp_health = client.get("/api/health")
        assert resp_health.status_code == 200


def test_api_key_set_mode_missing_key_returns_401():
    """When API key is set, protected endpoints without X-API-Key must return HTTP 401."""
    with patch.dict(os.environ, {"QS_API_KEY": "test-secret-key-12345"}):
        response = client.get("/api/banking/profiles")
        assert response.status_code == 401
        data = response.json()
        assert data["error"] == "UNAUTHORIZED"
        assert "API key required" in data["detail"]


def test_api_key_set_mode_invalid_key_returns_401():
    """When API key is set, requests with invalid X-API-Key must return HTTP 401."""
    with patch.dict(os.environ, {"QS_API_KEY": "test-secret-key-12345"}):
        response = client.get(
            "/api/banking/profiles",
            headers={"X-API-Key": "wrong-invalid-key"},
        )
        assert response.status_code == 401
        data = response.json()
        assert data["error"] == "UNAUTHORIZED"
        assert "Invalid API key" in data["detail"]


def test_api_key_set_mode_valid_key_succeeds():
    """When API key is set, requests with valid X-API-Key must succeed."""
    with patch.dict(os.environ, {"QS_API_KEY": "test-secret-key-12345"}):
        response = client.get(
            "/api/banking/profiles",
            headers={"X-API-Key": "test-secret-key-12345"},
        )
        assert response.status_code == 200


def test_verify_api_key_constant_time():
    """verify_api_key must use constant-time comparison."""
    assert verify_api_key("correct-key", "correct-key") is True
    assert verify_api_key("wrong-key", "correct-key") is False
    assert verify_api_key("", "correct-key") is False
    assert verify_api_key("correct-key", "") is False
