"""Phase F TLS Assessment & Network Safety Hardening Tests.

Validates:
- F5: Passive, non-invasive TLS handshake, certificate parsing, cipher negotiation.
- F6: Network safety & SSRF defenses:
      - Blocking loopback, private, link-local, cloud metadata (169.254.169.254), and multicast.
      - Disallowed ports and invalid port ranges rejected before connection.
      - Socket cleanup on errors to prevent resource leakage.
      - Handling of untrusted/self-signed certificates (falls back to unverified to extract parameters).
"""

import socket
import ssl
from unittest.mock import patch, MagicMock
import pytest

from app.scanners.tls_scanner import (
    TlsScanner,
    TlsScanError,
    TlsTimeoutError,
    TlsConnectionError,
    TlsHandshakeError,
)
from app.security.network import (
    UnsafeTargetError,
    DisallowedPortError,
    InvalidPortError,
    SafeResolutionResult,
    is_safe_public_ip,
    validate_scan_port,
)


class TestTlsScannerHardening:
    """Network safety, SSRF protection, and error resilience for TLS scanner."""

    def test_ssrf_blocks_private_and_loopback_ips(self):
        """Rejects loopback, private, link-local, and cloud metadata IPs."""
        prohibited_ips = [
            "127.0.0.1",
            "127.0.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.100",
            "169.254.169.254",  # AWS metadata
            "224.0.0.1",        # Multicast
            "0.0.0.0",
            "::1",              # IPv6 loopback
            "fe80::1",          # IPv6 link-local
            "fc00::1",          # IPv6 ULA
        ]

        for ip in prohibited_ips:
            safe, reason = is_safe_public_ip(ip)
            assert safe is False, f"Expected {ip} to be rejected, but passed. Reason: {reason}"
            assert len(reason) > 0

    def test_ssrf_allows_safe_public_ips(self):
        """Allows globally routable public addresses."""
        safe_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",     # example.com
            "2606:4700:4700::1111", # Cloudflare DNS IPv6
        ]

        for ip in safe_ips:
            safe, reason = is_safe_public_ip(ip)
            assert safe is True, f"Expected {ip} to be safe, but rejected: {reason}"

    def test_port_validation_disallowed_and_invalid_ports(self):
        """Rejects non-whitelisted ports (e.g. SSH, HTTP, MySQL) and out-of-range ports."""
        disallowed_ports = [21, 22, 23, 25, 80, 139, 445, 3306, 5432, 6379, 8080]
        for port in disallowed_ports:
            with pytest.raises(DisallowedPortError):
                validate_scan_port(port)

        invalid_ports = [-1, 0, 65536, 100000, "invalid", None, 443.5]
        for port in invalid_ports:
            with pytest.raises(InvalidPortError):
                validate_scan_port(port)

        allowed_ports = [443, 8443, 993, 995, 465]
        for port in allowed_ports:
            assert validate_scan_port(port) == port

    def test_tls_scanner_rejects_ssrf_target_before_socket_creation(self):
        """Scanner raises UnsafeTargetError when domain resolves to a private IP."""
        scanner = TlsScanner()

        with patch("app.scanners.tls_scanner.resolve_and_validate_hostname") as mock_resolve:
            mock_resolve.side_effect = UnsafeTargetError("Address '127.0.0.1' belongs to loopback range.")

            with pytest.raises(UnsafeTargetError):
                scanner.scan("ssrf-test.example.com", port=443)

    def test_tls_scanner_handles_timeout_safely(self):
        """Scanner handles connection timeout and ensures socket resources are cleaned up."""
        scanner = TlsScanner(connect_timeout=0.1, handshake_timeout=0.1)

        with patch("app.scanners.tls_scanner.resolve_and_validate_hostname") as mock_resolve, \
             patch("socket.socket") as mock_socket_cls:

            mock_resolve.return_value = SafeResolutionResult(
                hostname="public.example.com",
                selected_ip="93.184.216.34",
                all_resolved_ips=["93.184.216.34"],
                ip_version="IPv4",
            )

            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.timeout("Connect timed out")
            mock_socket_cls.return_value = mock_sock

            with pytest.raises(TlsTimeoutError):
                scanner.scan("public.example.com", port=443)

            # Confirm socket.close() was called in finally block
            mock_sock.close.assert_called_once()

    def test_tls_scanner_handles_connection_refused_safely(self):
        """Scanner handles ConnectionRefusedError cleanly with socket close."""
        scanner = TlsScanner()

        with patch("app.scanners.tls_scanner.resolve_and_validate_hostname") as mock_resolve, \
             patch("socket.socket") as mock_socket_cls:

            mock_resolve.return_value = SafeResolutionResult(
                hostname="public.example.com",
                selected_ip="93.184.216.34",
                all_resolved_ips=["93.184.216.34"],
                ip_version="IPv4",
            )

            mock_sock = MagicMock()
            mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")
            mock_socket_cls.return_value = mock_sock

            with pytest.raises(TlsConnectionError):
                scanner.scan("public.example.com", port=443)

            mock_sock.close.assert_called_once()

    def test_tls_scanner_retries_unverified_on_cert_error(self):
        """When TLS verification fails (e.g. self-signed or expired), retries unverified to extract cert parameters."""
        scanner = TlsScanner()

        with patch("app.scanners.tls_scanner.resolve_and_validate_hostname") as mock_resolve, \
             patch.object(scanner, "_connect_tls") as mock_connect:

            mock_resolve.return_value = SafeResolutionResult(
                hostname="self-signed.example.com",
                selected_ip="93.184.216.34",
                all_resolved_ips=["93.184.216.34"],
                ip_version="IPv4",
            )

            # First verified call raises verification error, second unverified succeeds
            mock_connect.side_effect = [
                ssl.SSLCertVerificationError("certificate has expired"),
                {
                    "certificate": {
                        "subject": {"CN": "self-signed.example.com"},
                        "is_trusted": False,
                        "verification_status": "Certificate verification failed: certificate has expired",
                    },
                    "tls": {
                        "negotiated_protocol": "TLSv1.3",
                        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
                    },
                },
            ]

            result = scanner.scan("self-signed.example.com", port=443)

            assert mock_connect.call_count == 2
            assert result["certificate"]["is_trusted"] is False
            assert "expired" in result["certificate"]["verification_status"]
            assert result["tls"]["negotiated_protocol"] == "TLSv1.3"
