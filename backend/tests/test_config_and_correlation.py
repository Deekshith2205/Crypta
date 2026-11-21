"""Unit tests for centralized configuration and request correlation tracking (Phase G)."""

import os
from unittest.mock import patch
import logging
import pytest
from httpx import AsyncClient, ASGITransport

from app.config import AppConfig, ServerConfig, get_app_config
from app.security.correlation import (
    get_current_request_id,
    sanitize_log_dict,
    CorrelationIdLogFilter,
    REQUEST_ID_CTX_VAR,
)
from app.main import app


class TestCentralizedConfig:
    """Verifies AppConfig loading, validation, and secret protection."""

    def test_default_config_loading(self):
        """Default configuration loads safely with development defaults."""
        config = AppConfig.from_env()
        assert config.server.host == "0.0.0.0"
        assert config.server.port == 8000
        assert config.server.environment == "development"
        assert config.is_production is False
        assert len(config.server.allowed_origins) >= 4
        assert 443 in config.security.allowed_scan_ports

    def test_custom_env_config_loading(self):
        """Custom environment variables are parsed correctly."""
        env_vars = {
            "HOST": "127.0.0.1",
            "PORT": "9000",
            "ENVIRONMENT": "production",
            "QS_ALLOWED_ORIGINS": "https://bank.example.com,https://audit.example.com",
            "QS_API_KEY": "super-secret-api-key-xyz",
            "QS_MAX_REQUEST_SIZE_BYTES": "10485760",
            "QS_ALLOWED_SCAN_PORTS": "443,8443",
            "QS_TRUSTED_PROXY_COUNT": "2",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = AppConfig.from_env()
            assert config.server.host == "127.0.0.1"
            assert config.server.port == 9000
            assert config.server.environment == "production"
            assert config.is_production is True
            assert config.server.allowed_origins == [
                "https://bank.example.com",
                "https://audit.example.com",
            ]
            assert config.server.api_key == "super-secret-api-key-xyz"
            assert config.server.max_request_size_bytes == 10485760
            assert config.security.allowed_scan_ports == {443, 8443}
            assert config.security.trusted_proxy_count == 2

    def test_secrets_redacted_in_repr(self):
        """Sensitive fields like api_key and signing_key are omitted from repr."""
        env_vars = {
            "QS_API_KEY": "my-secret-key-12345",
            "QS_AUDIT_SIGNING_KEY": "my-signing-key-67890",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = AppConfig.from_env()
            config_repr = repr(config)
            assert "my-secret-key-12345" not in config_repr
            assert "my-signing-key-67890" not in config_repr

    def test_production_startup_validation(self):
        """Startup validation audits production misconfigurations."""
        # Insecure production: wildcard CORS and no API key
        env_vars = {
            "ENVIRONMENT": "production",
            "QS_ALLOWED_ORIGINS": "*",
            "QS_API_KEY": "",
            "QS_REQUIRE_EXTERNAL_CHECKPOINT": "true",
            "QS_EXTERNAL_CHECKPOINT_URL": "",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = AppConfig.from_env()
            warnings = config.validate_startup()
            assert any("Wildcard CORS" in w for w in warnings)
            assert any("No API key" in w for w in warnings)
            assert any("QS_REQUIRE_EXTERNAL_CHECKPOINT is True" in w for w in warnings)


class TestRequestCorrelationAndLogging:
    """Verifies request correlation ID generation, propagation, and log filtering."""

    @pytest.mark.asyncio
    async def test_generates_request_id_when_absent(self):
        """Attaches a newly generated X-Request-ID header to responses."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/health")
            assert res.status_code == 200
            assert "x-request-id" in res.headers
            assert len(res.headers["x-request-id"]) >= 16

    @pytest.mark.asyncio
    async def test_propagates_incoming_request_id(self):
        """Echoes back safe incoming X-Request-ID headers."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/health", headers={"x-request-id": "req-client-12345"})
            assert res.status_code == 200
            assert res.headers.get("x-request-id") == "req-client-12345"

    def test_correlation_log_filter(self):
        """Filter injects the active request ID into log records."""
        token = REQUEST_ID_CTX_VAR.set("test-correlation-uuid")
        try:
            log_filter = CorrelationIdLogFilter()
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="test.py",
                lineno=10,
                msg="Hello %s",
                args=("world",),
                exc_info=None,
            )
            assert log_filter.filter(record) is True
            assert record.request_id == "test-correlation-uuid"
        finally:
            REQUEST_ID_CTX_VAR.reset(token)

    def test_sanitize_log_dict(self):
        """Scrubs password, token, and secret fields from logged dictionaries."""
        data = {
            "username": "auditor_1",
            "password": "Password123!",
            "api_key": "sk-12345678",
            "nested": {
                "auth_token": "bearer-token-abc",
                "system_id": "BANK-PROF-CORE-BANKING",
            },
        }
        sanitized = sanitize_log_dict(data)
        assert sanitized["username"] == "auditor_1"
        assert sanitized["password"] == "[REDACTED_CREDENTIAL]"
        assert sanitized["api_key"] == "[REDACTED_CREDENTIAL]"
        assert sanitized["nested"]["auth_token"] == "[REDACTED_CREDENTIAL]"
        assert sanitized["nested"]["system_id"] == "BANK-PROF-CORE-BANKING"
