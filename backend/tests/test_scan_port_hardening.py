"""Tests for live scan port allowlisting and hardening (Task B3).

Verifies:
- Live scan restricts target ports to standard TLS ports (443, 8443, 993, 995, 465).
- Disallowed ports (e.g. 22, 3306, 6379, 80) return HTTP 400 with DISALLOWED_PORT.
- Invalid ports (e.g. 0, negative, >65535, non-integer) return HTTP 400 with INVALID_PORT.
- Disallowed ports do not attempt DNS resolution or network connection.
- Port allowlist is configurable via QS_ALLOWED_SCAN_PORTS environment variable.
"""

import os
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security.network import (
    DEFAULT_ALLOWED_SCAN_PORTS,
    get_allowed_scan_ports,
    validate_scan_port,
    DisallowedPortError,
    InvalidPortError,
)
from app.scanners.tls_scanner import TlsScanner

client = TestClient(app)


def test_allowed_default_ports_accepted():
    """Default allowed scan ports (443, 8443, 993, 995, 465) must be valid."""
    assert DEFAULT_ALLOWED_SCAN_PORTS == {443, 8443, 993, 995, 465}
    for port in [443, 8443, 993, 995, 465]:
        assert validate_scan_port(port) == port
        assert validate_scan_port(str(port)) == port


def test_disallowed_ports_rejected():
    """Non-TLS or risky ports must raise DisallowedPortError."""
    disallowed = [22, 23, 25, 80, 110, 143, 3306, 5432, 6379, 8080, 9200, 27017]
    for port in disallowed:
        with pytest.raises(DisallowedPortError):
            validate_scan_port(port)


def test_invalid_ports_rejected():
    """Invalid, zero, negative, out-of-range, and non-integer ports must raise InvalidPortError."""
    invalid = [0, -1, -443, 65536, 100000, "abc", "443abc", True, False, 443.5, None]
    for port in invalid:
        with pytest.raises(InvalidPortError):
            validate_scan_port(port)


def test_api_scan_disallowed_ports():
    """POST /api/scan with disallowed ports must return HTTP 400 with DISALLOWED_PORT."""
    for port in [22, 3306, 6379, 80]:
        response = client.post(
            "/api/scan",
            json={"domain": "example.com", "port": port},
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"] == "DISALLOWED_PORT"
        assert str(port) in data["detail"]


def test_api_scan_invalid_ports():
    """POST /api/scan with invalid ports must return HTTP 400 with INVALID_PORT."""
    for port in [0, -1, 70000, "not_a_port"]:
        response = client.post(
            "/api/scan",
            json={"domain": "example.com", "port": port},
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"] == "INVALID_PORT"


def test_api_audit_disallowed_and_invalid_ports():
    """POST /api/audit must also enforce port allowlisting and validity."""
    # Disallowed port
    resp_disallowed = client.post(
        "/api/audit",
        json={"domain": "example.com", "port": 22},
    )
    assert resp_disallowed.status_code == 400
    assert resp_disallowed.json()["error"] == "DISALLOWED_PORT"

    # Invalid port
    resp_invalid = client.post(
        "/api/audit",
        json={"domain": "example.com", "port": 0},
    )
    assert resp_invalid.status_code == 400
    assert resp_invalid.json()["error"] == "INVALID_PORT"


def test_disallowed_port_causes_no_network_or_dns_activity():
    """Disallowed ports must be rejected before attempting DNS resolution or socket connection."""
    with patch("app.security.network.dns.resolver.Resolver") as mock_resolver, \
         patch("socket.create_connection") as mock_connect:
        response = client.post(
            "/api/scan",
            json={"domain": "example.com", "port": 22},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "DISALLOWED_PORT"
        mock_resolver.assert_not_called()
        mock_connect.assert_not_called()


def test_tls_scanner_rejects_disallowed_port_before_network():
    """TlsScanner.scan must reject disallowed ports before DNS or socket calls."""
    scanner = TlsScanner()
    with patch("app.scanners.tls_scanner.resolve_and_validate_hostname") as mock_resolve:
        with pytest.raises(DisallowedPortError):
            scanner.scan("example.com", port=22)
        mock_resolve.assert_not_called()


def test_configurable_allowed_ports_via_env():
    """Port allowlist must be configurable via QS_ALLOWED_SCAN_PORTS."""
    original_env = os.environ.get("QS_ALLOWED_SCAN_PORTS")
    try:
        os.environ["QS_ALLOWED_SCAN_PORTS"] = "443,8443,10443"
        allowed = get_allowed_scan_ports()
        assert allowed == {443, 8443, 10443}

        # Port 10443 is now allowed
        assert validate_scan_port(10443) == 10443

        # Port 993 was in default but not in custom list -> disallowed
        with pytest.raises(DisallowedPortError):
            validate_scan_port(993)
    finally:
        if original_env is None:
            os.environ.pop("QS_ALLOWED_SCAN_PORTS", None)
        else:
            os.environ["QS_ALLOWED_SCAN_PORTS"] = original_env
