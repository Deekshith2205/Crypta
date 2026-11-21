"""Regression and invariant tests for Task D3:
Multi-Tier Key Protection Chain & Crypto-Agility Engine.

Verifies:
1. 4-tier chain analysis (Data Encryption, Key Wrapping, Key Storage, Authentication).
2. AES-256 Grover resilience invariant in Key Protection Chain.
3. Weak links identified strictly in asymmetric wrapping, legacy ciphers, and plaintext storage.
4. Deterministic cryptographic agility scoring (0-100) and ratings (HIGH, MODERATE, LOW).
5. Hardcoded monolithic systems receive LOW agility; configurable systems receive HIGH agility.
6. Incomplete evidence returns INSUFFICIENT_EVIDENCE / UNKNOWN without false panic.
"""

import pytest
from app.models.banking import KeyProtectionChain, BankingAsset, BankingAssetType
from app.models.risk import KeyChainStatus
from app.services.banking_risk_engine import (
    analyze_key_protection_chain,
    compute_crypto_agility_score,
)


def test_key_chain_four_tier_analysis_hybrid_pqc():
    """Verify that a modern hybrid PQC key chain is fully analyzed as QUANTUM_READY with high agility."""
    chain = KeyProtectionChain(
        data_encryption="AES-256-GCM",
        key_wrapping="ML-KEM-768",
        key_storage="Cloud KMS",
        authentication="ML-DSA-65",
    )
    analysis = analyze_key_protection_chain(chain)

    assert analysis.status == KeyChainStatus.QUANTUM_READY
    assert analysis.data_encryption_status == "ADEQUATE_GROVER_RESILIENT"
    assert analysis.key_wrapping_status == "QUANTUM_READY"
    assert analysis.key_storage_status == "CLOUD_KMS_PROTECTED"
    assert analysis.authentication_status == "QUANTUM_READY"
    assert len(analysis.weak_links) == 0

    # Agility must be evaluated deterministically
    assert analysis.agility_score is not None
    assert analysis.agility_score >= 80
    assert analysis.agility_rating == "HIGH"


def test_key_chain_four_tier_analysis_classical_vulnerable():
    """Verify that classical asymmetric wrapping and authentication are flagged as weak links, while AES-256 remains adequate."""
    chain = KeyProtectionChain(
        data_encryption="AES-256-CBC",
        key_wrapping="RSA-2048",
        key_storage="Software file",
        authentication="ECDSA-P256",
    )
    analysis = analyze_key_protection_chain(chain)

    assert analysis.status == KeyChainStatus.QUANTUM_EXPOSED
    assert analysis.data_encryption_status == "ADEQUATE_GROVER_RESILIENT"
    assert analysis.key_wrapping_status == "QUANTUM_VULNERABLE"
    assert analysis.key_storage_status == "SOFTWARE_UNPROTECTED"
    assert analysis.authentication_status == "QUANTUM_VULNERABLE"

    # Weak links must capture key wrapping, storage, and authentication, but NOT AES-256
    assert any("RSA-2048" in w for w in analysis.weak_links)
    assert any("Software file" in w for w in analysis.weak_links)
    assert any("ECDSA-P256" in w for w in analysis.weak_links)
    assert not any("AES-256" in w for w in analysis.weak_links)

    # Agility score must reflect legacy software storage and rigid RSA/ECDSA
    assert analysis.agility_score is not None
    assert analysis.agility_score < 50
    assert analysis.agility_rating == "LOW"


def test_key_chain_legacy_deprecated_ciphers():
    """Verify that 3DES data encryption and plaintext storage are flagged as weak links."""
    chain = KeyProtectionChain(
        data_encryption="3DES",
        key_wrapping="DES-EDE3",
        key_storage="Plaintext Configuration File",
        authentication="None",
    )
    analysis = analyze_key_protection_chain(chain)

    assert analysis.data_encryption_status == "DEPRECATED_LEGACY"
    assert analysis.key_wrapping_status == "LEGACY_VULNERABLE"
    assert analysis.key_storage_status == "SOFTWARE_UNPROTECTED"
    assert any("3DES" in w for w in analysis.weak_links)
    assert any("DES-EDE3" in w for w in analysis.weak_links)
    assert any("Plaintext" in w for w in analysis.weak_links)

    assert analysis.agility_score is not None
    assert analysis.agility_score <= 35
    assert analysis.agility_rating == "LOW"


def test_compute_crypto_agility_score_deterministic_formula():
    """Test compute_crypto_agility_score directly with various configurations."""
    # 1. Full PQC with Cloud KMS
    pqc_chain = KeyProtectionChain(
        data_encryption="AES-256-GCM",
        key_wrapping="ML-KEM-768",
        key_storage="AWS KMS",
        authentication="ML-DSA-65",
    )
    score, rating, rat = compute_crypto_agility_score(pqc_chain, declared_agility="CONFIGURABLE")
    assert score == 100
    assert rating == "HIGH"

    # 2. Hardcoded monolithic override
    score_mono, rating_mono, _ = compute_crypto_agility_score(pqc_chain, declared_agility="HARDCODED_MONOLITHIC")
    assert score_mono <= 35
    assert rating_mono == "LOW"

    # 3. Empty chain returns UNKNOWN
    score_empty, rating_empty, _ = compute_crypto_agility_score(None)
    assert score_empty == 0
    assert rating_empty == "UNKNOWN"


def test_key_chain_insufficient_evidence_preserves_invariants():
    """Verify that an empty or missing key chain correctly yields INSUFFICIENT_EVIDENCE without false panic."""
    empty_chain = KeyProtectionChain()
    analysis = analyze_key_protection_chain(empty_chain)

    assert analysis.status == KeyChainStatus.INSUFFICIENT_EVIDENCE
    assert analysis.data_encryption_status == "UNKNOWN"
    assert analysis.key_wrapping_status == "UNKNOWN"
    assert len(analysis.weak_links) == 0
    assert analysis.agility_rating == "UNKNOWN"
