"""Deterministic Tests for TLS Scanner DNS Rebinding & SSRF Protection (Task 3 Remediation).

Verifies:
1. TCP socket connects directly to validated IP literal (not hostname).
2. SNI server_hostname is strictly preserved during TLS wrap.
3. DNS rebinding prevention via one-time validation and IP binding.
4. Immediate rejection of mixed public/private DNS answers.
5. Strict rejection of IPv4-mapped IPv6 private/loopback/metadata addresses.
6. Strict rejection of cloud metadata endpoints (169.254.169.254, fd00:ec2::254).
7. Redirect refusal: raw TLS socket connection never follows HTTP redirects.
8. DNS timeout and failure fail-closed behavior.
"""

import socket
import ssl
from unittest.mock import MagicMock, patch
import pytest

from app.scanners.tls_scanner import TlsScanner, TlsHandshakeError
from app.security.network import (
    DnsResolutionError,
    SafeResolutionResult,
    UnsafeTargetError,
    is_safe_public_ip,
    resolve_and_validate_hostname,
)


class TestTlsDnsRebindingAndSsrf:
    """SSRF and DNS rebinding test suite for TLS scanner."""

    def test_socket_connects_directly_to_validated_ip(self):
        """TlsScanner._connect_tls must connect the raw TCP socket to the validated IP literal,

        NOT the domain name, preventing DNS rebinding between check and connect.
        """
        scanner = TlsScanner(connect_timeout=2.0, handshake_timeout=2.0)
        target_hostname = "secure-bank.example.com"
        validated_ip = "93.184.216.34"
        port = 443

        mock_raw_socket = MagicMock(spec=socket.socket)
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_socket.version.return_value = "TLSv1.3"
        mock_ssl_socket.selected_alpn_protocol.return_value = "h2"
        mock_ssl_socket.session_reused = False
        mock_ssl_socket.getpeercert.return_value = {"subject": ((("commonName", target_hostname),),)}

        with patch("socket.socket", return_value=mock_raw_socket), \
             patch("ssl.create_default_context") as mock_ctx_factory, \
             patch("app.scanners.tls_scanner.parse_der_certificate", return_value={"subject_cn": target_hostname}):
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_ssl_socket
            mock_ctx_factory.return_value = mock_ctx

            res = scanner._connect_tls(
                hostname=target_hostname,
                resolved_ip=validated_ip,
                port=port,
                verify=True,
                is_trusted=True,
                verification_status="Trusted",
            )

            # Assert raw TCP socket connected directly to the validated IP literal
            mock_raw_socket.connect.assert_called_once_with((validated_ip, port))

            # Assert SNI server_hostname remained the original domain name
            mock_ctx.wrap_socket.assert_called_once()
            _, kwargs = mock_ctx.wrap_socket.call_args
            assert kwargs.get("server_hostname") == target_hostname

    def test_dns_rebinding_prevention_flow(self):
        """Simulates end-to-end scan where DNS resolves once and connects to the returned IP,

        ignoring any subsequent changes to DNS.
        """
        scanner = TlsScanner(connect_timeout=2.0, handshake_timeout=2.0)
        hostname = "api.bank.com"
        safe_ip = "198.51.100.10"  # Safe public candidate

        mock_resolution = SafeResolutionResult(
            hostname=hostname,
            selected_ip=safe_ip,
            all_resolved_ips=[safe_ip],
            ip_version="IPv4",
        )

        mock_tls_data = {
            "tls": {"negotiated_protocol": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384"},
            "certificate": {"subject_cn": hostname, "is_valid": True},
        }

        with patch("app.scanners.tls_scanner.resolve_and_validate_hostname", return_value=mock_resolution) as mock_resolve, \
             patch.object(scanner, "_perform_handshake", return_value=mock_tls_data) as mock_handshake:

            result = scanner.scan(hostname, port=443)

            mock_resolve.assert_called_once_with(hostname, timeout_seconds=scanner.connect_timeout)
            mock_handshake.assert_called_once_with(hostname, safe_ip, 443)

            assert result["target"]["resolved_ip"] == safe_ip
            assert result["target"]["domain"] == hostname

    def test_mixed_dns_response_rejected(self):
        """If DNS returns multiple records where even ONE address is non-public,

        resolve_and_validate_hostname must reject the target entirely.
        """
        with patch("dns.resolver.Resolver") as mock_resolver_cls:
            mock_resolver = MagicMock()
            mock_resolver_cls.return_value = mock_resolver

            ans_public = MagicMock()
            ans_public.address = "93.184.216.34"

            ans_private = MagicMock()
            ans_private.address = "192.168.1.100"  # RFC 1918 Private

            mock_resolver.resolve.return_value = [ans_public, ans_private]

            with pytest.raises(UnsafeTargetError, match="prohibited, private, or non-public address"):
                resolve_and_validate_hostname("mixed-dns.evil.com", timeout_seconds=2.0)

    def test_ipv4_mapped_ipv6_prohibited_targets_rejected(self):
        """IPv4-mapped IPv6 addresses representing private/loopback/metadata ranges

        must be strictly detected and rejected.
        """
        prohibited_mapped_ips = [
            "::ffff:127.0.0.1",       # Loopback
            "::ffff:10.0.0.1",        # RFC 1918 Private
            "::ffff:172.16.0.1",      # RFC 1918 Private
            "::ffff:192.168.1.1",     # RFC 1918 Private
            "::ffff:169.254.169.254", # Cloud metadata
            "::ffff:0.0.0.0",         # Unspecified
        ]

        for ip_str in prohibited_mapped_ips:
            is_safe, reason = is_safe_public_ip(ip_str)
            assert is_safe is False, f"Expected {ip_str} to be rejected, but passed! Reason: {reason}"
            assert len(reason) > 0

    def test_cloud_metadata_endpoints_rejected(self):
        """Well-known cloud instance metadata endpoints (IPv4 and IPv6) must be rejected."""
        metadata_ips = [
            "169.254.169.254",  # AWS/GCP/Azure link-local metadata
            "169.254.170.2",    # AWS ECS task metadata
            "fd00:ec2::254",    # AWS IPv6 IMDS
            "::ffff:169.254.169.254",
        ]

        for ip_str in metadata_ips:
            is_safe, reason = is_safe_public_ip(ip_str)
            assert is_safe is False, f"Metadata IP {ip_str} was not rejected! Reason: {reason}"

    def test_raw_socket_never_follows_http_redirects(self):
        """The TLS scanner establishes a raw TLS connection for certificate/cipher inspection

        and does not parse HTTP responses or follow HTTP 301/302 redirects.
        """
        scanner = TlsScanner(connect_timeout=2.0, handshake_timeout=2.0)
        # Verify scanner only performs TLS handshakes via socket, without any HTTP redirect mechanisms
        assert hasattr(scanner, "_connect_tls")
        assert not hasattr(scanner, "follow_redirects")
        assert not hasattr(scanner, "max_redirects")

    def test_dns_resolution_timeout_fails_closed(self):
        """DNS resolution timeouts fail closed by raising DnsResolutionError."""
        import dns.exception

        with patch("dns.resolver.Resolver") as mock_resolver_cls:
            mock_resolver = MagicMock()
            mock_resolver_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.exception.Timeout("DNS timed out")

            with pytest.raises(DnsResolutionError, match="DNS resolution timed out"):
                resolve_and_validate_hostname("slow-timeout.com", timeout_seconds=1.0)
