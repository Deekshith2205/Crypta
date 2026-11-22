"""Regression tests for Task A3: Unknown Algorithm Classification.
Verifies unknown or unrecognized cryptographic algorithms are explicitly preserved
as unknown / not observable, never silently discarded, and never assigned invented
vulnerabilities, roles, or HIGH/CRITICAL severities.
"""

import pytest
from types import SimpleNamespace
from app.security.crypto_catalog import (
    classify_risk_domain,
    get_algorithm_profile,
)
try:
    from app.security.crypto_catalog import is_known_algorithm
except ImportError:
    is_known_algorithm = None
from app.services.finding_normalizer import (
    normalize_config_finding,
    normalize_tls_finding,
    normalize_profile_evidence_item,
    collect_unified_findings,
)
from app.models.banking import (
    BankingAsset,
    EvidenceItem,
    EvidenceSource,
    ObservabilityState,
    SecurityLayer,
)


def test_is_known_algorithm_helper():
    """
    Task A3: crypto_catalog must provide is_known_algorithm helper to reliably
    distinguish established algorithms from unknown or proprietary identifiers.
    """
    assert is_known_algorithm("AES-256") is True
    assert is_known_algorithm("RSA-2048") is True
    assert is_known_algorithm("diffie-hellman-group14-sha256") is True
    assert is_known_algorithm("ML-KEM-768") is True
    assert is_known_algorithm("3DES") is True

    # Unknown algorithms
    assert is_known_algorithm("CUSTOM-ALGO-X") is False
    assert is_known_algorithm("SUPER-CIPHER-9000") is False
    assert is_known_algorithm("FROB-ENCRYPT-v2.1") is False
    assert is_known_algorithm("") is False
    assert is_known_algorithm(None) is False
    assert is_known_algorithm("N/A") is False


def test_completely_unknown_algorithm_normalization():
    """
    Task A3: Completely unknown algorithm must:
    1. Not be discarded.
    2. Preserve original value as evidence.
    3. Not receive HIGH or CRITICAL severity.
    4. Not be assumed to be quantum vulnerable (risk == UNKNOWN).
    5. Not receive fabricated PQC migration recommendations.
    """
    obs = SimpleNamespace(
        rule_id="CFG-CUSTOM-01",
        title="Custom Encryption Algorithm",
        parsed_value="CUSTOM-ALGO-X",
        role="DATA_ENCRYPTION",
        evidence_status="OBSERVED",
        severity="HIGH",  # External scanner guessed HIGH
    )
    norm = normalize_config_finding(obs)

    assert norm.value == "CUSTOM-ALGO-X"
    assert norm.severity in ("INFORMATIONAL", "LOW"), f"Unknown algorithm received unearned severity: {norm.severity}"
    assert norm.risk == "UNKNOWN", f"Unknown algorithm assumed risk domain: {norm.risk}"
    # Honest explanation and non-fabricated recommendation
    assert "unrecognized" in norm.message.lower() or "unknown" in norm.message.lower()
    assert not any(pqc in norm.recommendation.upper() for pqc in ["ML-KEM", "ML-DSA", "AES-256"])


def test_unknown_algorithm_with_unusual_name_and_numeric_suffix():
    """
    Task A3: Unusual names with numeric suffixes (e.g. SUPER-CIPHER-9000)
    must remain unknown and not falsely match known numeric suffixes (like 128, 256, 1024, etc.).
    """
    variants = ["SUPER-CIPHER-9000", "FROB-ENCRYPT-v2.1", "MY_PROPRIETARY_MAC_2026"]
    for variant in variants:
        obs = SimpleNamespace(
            rule_id=f"CFG-{variant}",
            title=f"Configured Algorithm {variant}",
            parsed_value=variant,
            role="DATA_ENCRYPTION",
            evidence_status="OBSERVED",
            severity="CRITICAL",
        )
        norm = normalize_config_finding(obs)
        assert norm.value == variant
        assert norm.severity in ("INFORMATIONAL", "LOW"), f"Expected neutral severity for {variant}, got {norm.severity}"
        assert norm.risk == "UNKNOWN", f"Expected UNKNOWN risk domain for {variant}, got {norm.risk}"


def test_empty_or_missing_algorithm_value():
    """
    Task A3: Empty or missing algorithm values must be explicitly mapped to NOT_OBSERVABLE
    with INFORMATIONAL severity, upholding the invariant NOT_OBSERVABLE != VULNERABLE.
    """
    for empty_val in ["", None, "N/A", "Not observable", "UNKNOWN"]:
        obs = SimpleNamespace(
            rule_id="CFG-MISSING",
            title="Empty Algorithm Parameter",
            parsed_value=empty_val,
            role="CONFIGURATION",
            evidence_status="OBSERVED",
            severity="HIGH",
        )
        norm = normalize_config_finding(obs)
        assert norm.evidence_status in ("NOT_OBSERVABLE", "UNKNOWN")
        assert norm.severity == "INFORMATIONAL"
        assert norm.risk == "UNKNOWN"


def test_unknown_algorithm_in_banking_profile_evidence():
    """
    Task A3: Unknown algorithms declared in banking profiles must not receive
    fabricated vulnerabilities or severity elevations.
    """
    item = EvidenceItem(
        id="BANK-UNKNOWN-01",
        control="Internal Messaging Cipher",
        value="PROPRIETARY_SECURE_CIPHER",
        source=EvidenceSource.OPERATOR_DECLARED,
        observability=ObservabilityState.OBSERVED,
        layer=SecurityLayer.SERVICE_TO_SERVICE,
    )
    norm = normalize_profile_evidence_item(item)
    assert norm.value == "PROPRIETARY_SECURE_CIPHER"
    assert norm.severity in ("INFORMATIONAL", "LOW")
    assert norm.risk == "UNKNOWN"


def test_unknown_algorithm_in_tls_finding():
    """
    Task A3: TLS findings with unknown ciphers must not automatically default to QUANTUM
    or receive HIGH severity simply because is_quantum_vulnerable was unset or defaulted.
    """
    class RawTLSFinding:
        id = "TLS-UNKNOWN-CIPHER"
        title = "TLS Negotiated Unknown Cipher"
        category = "Perimeter Cryptography"
        value = "TLS_UNKNOWN_PROPRIETARY_CIPHER_0xFFFF"
        source = "EXTERNAL_SCAN"
        evidence = "OBSERVED"
        risk_level = "HIGH"
        is_quantum_vulnerable = True  # Defective scanner default

    norm = normalize_tls_finding(RawTLSFinding())
    assert norm.value == "TLS_UNKNOWN_PROPRIETARY_CIPHER_0xFFFF"
    assert norm.severity in ("INFORMATIONAL", "LOW")
    assert norm.risk == "UNKNOWN"


def test_unknown_algorithms_retained_in_unified_findings():
    """
    Task A3: Unknown algorithms must be retained in unified findings collections
    and never silently discarded.
    """
    obs = SimpleNamespace(
        rule_id="CFG-UNKNOWN-RETENTION",
        title="Custom In-House Algorithm",
        parsed_value="IN_HOUSE_TOKEN_CIPHER",
        role="DATA_ENCRYPTION",
        evidence_status="OBSERVED",
        severity="MEDIUM",
    )
    unified = collect_unified_findings(
        system_id="BANK-PROF-CUSTOM",
        config_findings=[obs],
    )
    matched = [f for f in unified if f.value == "IN_HOUSE_TOKEN_CIPHER"]
    assert len(matched) == 1, "Unknown algorithm finding was silently dropped from unified collection!"
    assert matched[0].risk == "UNKNOWN"
    assert matched[0].severity in ("INFORMATIONAL", "LOW")
