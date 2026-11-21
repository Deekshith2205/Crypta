"""Tests for CORS configuration hardening (Task B5).

Verifies:
- Wildcard origin is never combined with allow_credentials=True.
- Safe local origins (localhost:5173, 127.0.0.1:5173) are allowed by default.
- Unauthorized origins do not receive CORS allow headers.
- CORS origins are configurable via QS_ALLOWED_ORIGINS environment variable.
"""

import os
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_cors_middleware_does_not_combine_wildcard_with_credentials():
    """CORSMiddleware must not combine allow_origins=['*'] with allow_credentials=True."""
    from starlette.middleware.cors import CORSMiddleware
    # Inspect registered middlewares on app
    cors_middleware = None
    for middleware in app.user_middleware:
        if middleware.cls == CORSMiddleware:
            cors_middleware = middleware
            break

    assert cors_middleware is not None, "CORSMiddleware must be registered on app"
    options = cors_middleware.kwargs
    allow_origins = options.get("allow_origins", [])
    allow_credentials = options.get("allow_credentials", False)

    if "*" in allow_origins:
        assert not allow_credentials, "Wildcard origin '*' must NOT have allow_credentials=True"


def test_authorized_origin_receives_cors_headers():
    """Authorized local origins must receive CORS allow headers."""
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_unauthorized_origin_does_not_receive_cors_headers():
    """Untrusted / malicious origins must NOT receive access-control-allow-origin."""
    response = client.options(
        "/api/health",
        headers={
            "Origin": "https://evil-hacker.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # The response must NOT reflect the evil origin
    allow_origin = response.headers.get("access-control-allow-origin")
    assert allow_origin != "https://evil-hacker.com"
    assert allow_origin != "*"


def test_get_cors_origins_configurable():
    """get_cors_origins must read from QS_ALLOWED_ORIGINS or default to safe origins."""
    from app.main import get_cors_origins

    # Test default
    defaults = get_cors_origins(None)
    assert "http://localhost:5173" in defaults
    assert "http://127.0.0.1:5173" in defaults
    assert "*" not in defaults

    # Test custom env
    custom = get_cors_origins("https://quantum.internal.bank, https://audit.bank.org")
    assert custom == ["https://quantum.internal.bank", "https://audit.bank.org"]
