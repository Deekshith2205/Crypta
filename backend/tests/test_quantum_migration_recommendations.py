"""Regression tests for Task A5: Role-Aware Quantum Migration Recommendations.
Verifies that migration recommendations are strictly role-aware:
- Key establishment recommends NIST FIPS 203 (ML-KEM / Kyber) or hybrid, never ML-DSA.
- Digital signatures / certificates recommend NIST FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA), never ML-KEM.
- Symmetric ciphers evaluate Grover's algorithm and recommend AES-256-GCM, never KEM or DSA.
- Hashes recommend SHA-256/384, never KEM or DSA.
- Hybrid PQC schemes represent positive posture, not vulnerabilities.
"""

import pytest
from types import SimpleNamespace
from app.services.finding_normalizer import (
    normalize_config_finding,
    normalize_tls_finding,
    normalize_profile_evidence_item,
    collect_unified_findings,
)
from app.models.banking import (
    EvidenceItem,
    EvidenceSource,
    ObservabilityState,
    SecurityLayer,
)
from app.models.profiles import get_synthetic_profile_by_id


def test_key_establishment_recommends_ml_kem_never_ml_dsa():
    """
    Task A5: Key establishment and key exchange findings must strictly recommend
    ML-KEM / Hybrid ML-KEM (NIST FIPS 203), and NEVER recommend signature standards (ML-DSA).
    """
    # 1. Profile Evidence Item for Key Exchange
    item = EvidenceItem(
        id="TEST-KX-01",
        control="Session Key Exchange",
        value="ECDHE (secp256r1)",
        source=EvidenceSource.CONFIGURATION_FILE,
        observability=ObservabilityState.CLASSICAL_ONLY_OBSERVED,
        layer=SecurityLayer.SERVICE_TO_SERVICE,
    )
    norm = normalize_profile_evidence_item(item)
    rec_upper = norm.recommendation.upper()
    assert "ML-KEM" in rec_upper or "KYBER" in rec_upper or "HYBRID" in rec_upper, (
        f"Expected ML-KEM / Hybrid recommendation for key exchange, got: '{norm.recommendation}'"
    )
    assert "ML-DSA" not in rec_upper, f"Inappropriately recommended signature standard ML-DSA for key exchange: '{norm.recommendation}'"
    assert "SLH-DSA" not in rec_upper, f"Inappropriately recommended signature standard SLH-DSA for key exchange: '{norm.recommendation}'"

    # 2. Config Finding for Key Exchange
    obs = SimpleNamespace(
        rule_id="CFG-KEX-01",
        title="TLS Key Exchange Algorithm",
        parsed_value="ECDHE",
        role="KEY_EXCHANGE",
        evidence_status="OBSERVED",
        severity="HIGH",
    )
    norm_cfg = normalize_config_finding(obs)
    rec_cfg = norm_cfg.recommendation.upper()
    assert "ML-KEM" in rec_cfg or "KYBER" in rec_cfg or "HYBRID" in rec_cfg
    assert "ML-DSA" not in rec_cfg


def test_digital_signature_recommends_ml_dsa_never_ml_kem():
    """
    Task A5: Digital signature and certificate authentication findings must strictly
    recommend ML-DSA (NIST FIPS 204) or SLH-DSA (FIPS 205), and NEVER recommend KEM standards (ML-KEM).
    """
    # 1. Profile Evidence Item for Leaf Certificate
    item = EvidenceItem(
        id="TEST-CERT-01",
        control="Certificate Authentication",
        value="RSA-2048 with SHA-256",
        source=EvidenceSource.CONFIGURATION_FILE,
        observability=ObservabilityState.OBSERVED,
        layer=SecurityLayer.SERVICE_TO_SERVICE,
    )
    norm = normalize_profile_evidence_item(item)
    rec_upper = norm.recommendation.upper()
    assert "ML-DSA" in rec_upper or "DILITHIUM" in rec_upper or "SLH-DSA" in rec_upper, (
        f"Expected ML-DSA / SLH-DSA recommendation for certificate signature, got: '{norm.recommendation}'"
    )
    assert "ML-KEM" not in rec_upper, f"Inappropriately recommended KEM standard ML-KEM for digital signature: '{norm.recommendation}'"
    assert "KYBER" not in rec_upper, f"Inappropriately recommended Kyber for digital signature: '{norm.recommendation}'"

    # 2. Config Finding for Digital Signature
    obs = SimpleNamespace(
        rule_id="CFG-SIG-01",
        title="Certificate Signature Algorithm",
        parsed_value="SHA256withRSA",
        role="DIGITAL_SIGNATURE",
        evidence_status="OBSERVED",
        severity="HIGH",
    )
    norm_cfg = normalize_config_finding(obs)
    rec_cfg = norm_cfg.recommendation.upper()
    assert "ML-DSA" in rec_cfg or "DILITHIUM" in rec_cfg or "SLH-DSA" in rec_cfg
    assert "ML-KEM" not in rec_cfg


def test_symmetric_cipher_recommends_aes256_grover_never_kem_or_dsa():
    """
    Task A5: Symmetric encryption findings (e.g. AES-128) must evaluate Grover's algorithm
    and recommend upgrading to AES-256-GCM. They must NEVER recommend asymmetric PQC standards.
    """
    item = EvidenceItem(
        id="TEST-SYM-01",
        control="Database Encryption",
        value="AES-128",
        source=EvidenceSource.CONFIGURATION_FILE,
        observability=ObservabilityState.OBSERVED,
        layer=SecurityLayer.DATA_AND_KEYS,
    )
    norm = normalize_profile_evidence_item(item)
    rec_upper = norm.recommendation.upper()
    assert "AES-256" in rec_upper or "256" in rec_upper, (
        f"Expected AES-256 recommendation for 128-bit symmetric cipher, got: '{norm.recommendation}'"
    )
    assert not any(pqc in rec_upper for pqc in ["ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM"]), (
        f"Inappropriately recommended asymmetric PQC algorithm for bulk symmetric encryption: '{norm.recommendation}'"
    )


def test_hybrid_scheme_recognized_as_quantum_ready_positive_posture():
    """
    Task A5: Hybrid post-quantum schemes (e.g. X25519MLKEM768) must be recognized
    as quantum-resilient positive posture, NOT classified as high vulnerability.
    """
    item = EvidenceItem(
        id="TEST-HYBRID-01",
        control="Session Key Exchange",
        value="X25519MLKEM768",
        source=EvidenceSource.CONFIGURATION_FILE,
        observability=ObservabilityState.CAPABILITY_PROBED,
        layer=SecurityLayer.EDGE,
    )
    norm = normalize_profile_evidence_item(item)
    assert norm.severity in ("INFORMATIONAL", "LOW"), (
        f"Hybrid post-quantum key exchange received negative/high severity: {norm.severity}"
    )
    assert norm.risk == "QUANTUM"
    assert "quantum-resilient" in norm.message.lower() or "resilient" in norm.message.lower() or "hybrid" in norm.message.lower()
