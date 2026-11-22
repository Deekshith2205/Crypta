"""Regression tests for Task A2: Diffie-Hellman Classification Correctness.
Verifies canonical family, key size extraction, cryptographic role, weak vs standard
severity differentiation, and ML-KEM hybrid recommendations for Diffie-Hellman variants.
"""

import pytest
from types import SimpleNamespace
from app.security.crypto_catalog import (
    ALGORITHM_CATALOG,
    QuantumThreatVector,
    get_algorithm_profile,
    classify_risk_domain,
    PQC_STANDARDS,
)
try:
    from app.security.crypto_catalog import parse_dh_parameter
except ImportError:
    parse_dh_parameter = None

from app.services.finding_normalizer import normalize_config_finding
from app.scanners.config_scanner.scanner import BankingConfigScanner
from app.scanners.config_scanner.models import CryptoRole


def test_dh_canonical_family_and_role():
    """
    Task A2: Verify DH-1024, DH-2048, diffie-hellman-group1-sha1, and dh1024.pem
    are all correctly identified under the canonical 'Diffie-Hellman' family
    with the 'Key Establishment' / 'KEY_EXCHANGE' cryptographic role.
    """
    assert parse_dh_parameter is not None, "parse_dh_parameter must be implemented in crypto_catalog.py"
    test_cases = [
        "DH-1024",
        "DH-2048",
        "diffie-hellman-group1-sha1",
        "dh1024.pem",
        "dh2048.pem",
        "FFDHE2048",
    ]
    for variant in test_cases:
        info = parse_dh_parameter(variant)
        assert info is not None, f"Failed to parse DH variant: {variant}"
        assert info["family"] == "Diffie-Hellman", f"Expected family 'Diffie-Hellman' for {variant}, got {info.get('family')}"
        assert info["role"] in ("Key Establishment", "KEY_EXCHANGE"), f"Expected key establishment role for {variant}, got {info.get('role')}"


def test_dh_key_size_extraction():
    """
    Task A2: Verify key size is accurately parsed across naming variants:
    - DH-1024, diffie-hellman-group1-sha1, dh1024.pem -> 1024 bits
    - DH-2048, diffie-hellman-group14-sha256, dh2048.pem, FFDHE2048 -> 2048 bits
    - FFDHE3072, DH-3072 -> 3072 bits
    - FFDHE4096, DH-4096 -> 4096 bits
    """
    assert parse_dh_parameter is not None, "parse_dh_parameter must be implemented in crypto_catalog.py"
    key_size_map = {
        "DH-1024": 1024,
        "diffie-hellman-group1-sha1": 1024,
        "dh1024.pem": 1024,
        "ssl_dhparam /etc/ssl/dh1024.pem": 1024,
        "DH-2048": 2048,
        "diffie-hellman-group14-sha256": 2048,
        "dh2048.pem": 2048,
        "FFDHE2048": 2048,
        "DH-3072": 3072,
        "FFDHE3072": 3072,
        "DH-4096": 4096,
        "FFDHE4096": 4096,
    }
    for variant, expected_size in key_size_map.items():
        info = parse_dh_parameter(variant)
        assert info is not None, f"Failed to parse DH parameter for {variant}"
        assert info["key_size"] == expected_size, (
            f"Expected key size {expected_size} for '{variant}', but got {info.get('key_size')}"
        )


def test_weak_vs_standard_dh_severity_differentiation():
    """
    Task A2: Ensure weak DH configurations (<= 1024 bits or SHA-1) are classified as CRITICAL,
    while standard DH (2048-bit) configurations are classified as HIGH (quantum vulnerable,
    classical acceptable). They must NOT have identical severity.
    """
    weak_obs = SimpleNamespace(
        rule_id="CFG-DH-1024",
        title="Diffie-Hellman Key Exchange",
        parsed_value="DH-1024",
        role="KEY_EXCHANGE",
        evidence_status="OBSERVED",
        severity="HIGH",  # Old unhardened default
    )
    standard_obs = SimpleNamespace(
        rule_id="CFG-DH-2048",
        title="Diffie-Hellman Key Exchange",
        parsed_value="DH-2048",
        role="KEY_EXCHANGE",
        evidence_status="OBSERVED",
        severity="HIGH",
    )

    weak_norm = normalize_config_finding(weak_obs)
    standard_norm = normalize_config_finding(standard_obs)

    # Weak DH (1024 bits) must be CRITICAL due to classical Logjam vulnerability
    assert weak_norm.severity == "CRITICAL", f"Expected weak DH-1024 to be CRITICAL, got {weak_norm.severity}"
    # Standard DH (2048 bits) is HIGH for quantum vulnerability, not CRITICAL
    assert standard_norm.severity == "HIGH", f"Expected standard DH-2048 to be HIGH, got {standard_norm.severity}"
    # Must never be treated as having identical severity
    assert weak_norm.severity != standard_norm.severity, "Weak DH and standard DH must not share identical severity"

    # Also test file-based parameter naming: dh1024.pem vs dh2048.pem
    weak_file_obs = SimpleNamespace(
        rule_id="CFG-DHPARAM-01",
        title="SSL DH Parameter File",
        parsed_value="/etc/nginx/ssl/dh1024.pem",
        role="KEY_EXCHANGE",
        evidence_status="OBSERVED",
        severity="MEDIUM",  # Unhardened scanner input
    )
    norm_weak_file = normalize_config_finding(weak_file_obs)
    assert norm_weak_file.severity == "CRITICAL", (
        f"Expected dh1024.pem to be normalized to CRITICAL severity, got {norm_weak_file.severity}"
    )


def test_dh_recommendations_appropriate_for_key_establishment():
    """
    Task A2: Verify recommendations for all DH variants explicitly point to
    NIST FIPS 203 (ML-KEM / Kyber) or a suitable hybrid key exchange path.
    """
    variants = ["DH-1024", "DH-2048", "diffie-hellman-group1-sha1", "dh1024.pem"]
    for variant in variants:
        obs = SimpleNamespace(
            rule_id=f"CFG-DH-{variant}",
            title=f"Diffie-Hellman {variant}",
            parsed_value=variant,
            role="KEY_EXCHANGE",
            evidence_status="OBSERVED",
            severity="HIGH",
        )
        norm = normalize_config_finding(obs)
        rec_upper = norm.recommendation.upper()
        assert any(target in rec_upper for target in ["ML-KEM", "KYBER", "HYBRID"]), (
            f"Recommendation for {variant} does not reference ML-KEM or hybrid key exchange: '{norm.recommendation}'"
        )


def test_config_scanner_dh_parameter_and_group_detection(tmp_path):
    """
    Task A2: BankingConfigScanner must detect explicit DH parameter directives (ssl_dhparam)
    and SSH/TLS kex group configurations (diffie-hellman-group1-sha1).
    """
    conf_content = """
ssl_dhparam /etc/ssl/dh1024.pem;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
kex_algorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha256;
"""
    conf_file = tmp_path / "nginx_dh.conf"
    conf_file.write_text(conf_content)

    scanner = BankingConfigScanner()
    results = scanner.scan_directory(str(tmp_path))

    obs_values = [o.value for o in results.observations]
    # Check that dh1024.pem is detected
    assert any("dh1024.pem" in val or "DH-1024" in val for val in obs_values), (
        f"Expected dh1024.pem or DH-1024 in detected observations, got: {obs_values}"
    )
    # Check that diffie-hellman-group1-sha1 is detected
    assert any("diffie-hellman-group1-sha1" in val.lower() for val in obs_values), (
        f"Expected diffie-hellman-group1-sha1 in detected observations, got: {obs_values}"
    )
