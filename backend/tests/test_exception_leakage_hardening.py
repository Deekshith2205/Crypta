"""Tests for sensitive exception leakage prevention (Task B4).

Verifies:
- 500 responses return generic user-safe error messages and never leak raw exception strings.
- Stack traces, filesystem paths (Windows/Linux), connection strings, and credentials
  are never leaked in API error responses.
- Unhandled exceptions trigger the global exception handler and return standardized JSON.
- Full exception details are logged internally with appropriate log levels.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security.error_handler import sanitize_error_detail

client = TestClient(app, raise_server_exceptions=False)


def test_sanitize_error_detail_redacts_sensitive_patterns():
    """Sanitizer must strip filesystem paths, DB connection strings, and credentials."""
    samples = [
        ("Failed to read C:\\Users\\Admin\\AppData\\keys\\secret.key", "[REDACTED_PATH]"),
        ("Error accessing /etc/passwd or /var/secrets/token", "[REDACTED_PATH]"),
        ("Connection failed to postgresql://postgres:mypassword@db.internal:5432/quantum", "[REDACTED_URI]"),
        ("Auth error with password=SuperSecretPassword! in payload", "[REDACTED_SECRET]"),
        ("Failed with token=ghp_abcdef1234567890", "[REDACTED_SECRET]"),
        ("API key rejected: api_key=sk-ant-api03-abcdef123456", "[REDACTED_SECRET]"),
    ]
    for raw, expected_token in samples:
        sanitized = sanitize_error_detail(raw)
        assert expected_token in sanitized
        # The sensitive raw pattern must not be present
        if "SuperSecretPassword!" in raw:
            assert "SuperSecretPassword!" not in sanitized
        if "postgres:mypassword" in raw:
            assert "postgres:mypassword" not in sanitized
        if "C:\\Users\\Admin" in raw:
            assert "C:\\Users\\Admin" not in sanitized
        if "/etc/passwd" in raw:
            assert "/etc/passwd" not in sanitized


def test_500_response_in_what_if_does_not_leak_exception_string():
    """Simulated internal error in /api/banking/risk/what-if must not leak internal details."""
    sensitive_msg = "Database connection to postgresql://admin:p@ss@db:5432/core failed at C:\\app\\secret.py"
    with patch("app.services.migration_simulator.simulate_migration", side_effect=RuntimeError(sensitive_msg)):
        response = client.post(
            "/api/banking/risk/what-if",
            json={
                "asset_id": "core-banking",
                "changes": [
                    {
                        "component": "KEY_WRAPPING",
                        "current_algorithm": "RSA-2048",
                        "target_algorithm": "ML-KEM-768",
                    }
                ],
            },
        )
        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "SIMULATION_INTERNAL_ERROR"
        # Sensitive details MUST NOT leak
        assert "postgresql://" not in data["detail"]
        assert "p@ss" not in data["detail"]
        assert "C:\\app" not in data["detail"]
        assert "secret.py" not in data["detail"]
        assert "internal error occurred" in data["detail"].lower()


def test_global_exception_handler_catches_unhandled_route_exception():
    """Any unhandled exception in an API route must return generic 500 JSON, not a stack trace."""
    sensitive_msg = "Corrupted file at /etc/shadow with token=tok_live_12345"
    with patch("app.models.profiles.get_synthetic_banking_profiles", side_effect=ZeroDivisionError(sensitive_msg)):
        response = client.get("/api/banking/profiles")
        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "INTERNAL_SERVER_ERROR"
        assert "/etc/shadow" not in str(data)
        assert "tok_live_12345" not in str(data)
        assert "ZeroDivisionError" not in str(data)
        assert "Traceback" not in str(data)


def test_full_exception_logged_internally(caplog):
    """Internal logger must record the full exception traceback for debugging."""
    import logging
    with patch("app.models.profiles.get_synthetic_banking_profiles", side_effect=ValueError("Internal diagnostic failure")):
        with caplog.at_level(logging.ERROR):
            response = client.get("/api/banking/profiles")
            assert response.status_code == 500
            assert "Internal diagnostic failure" in caplog.text


def test_scan_config_500_does_not_leak_internal_paths():
    """500 error in config scan must return generic message without server paths."""
    with patch("app.scanners.config_scanner.parsers.SafeConfigParser.parse_file", side_effect=OSError("Disk failed at /var/data/conf.yaml")):
        response = client.post(
            "/api/scan/config",
            json={"files": [{"name": "test.yaml", "content": "key: value"}]},
        )
        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "CONFIG_SCAN_FAILED"
        assert "/var/data" not in data["detail"]
