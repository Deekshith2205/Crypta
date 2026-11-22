"""Regression tests for Task A1: Backend Cryptographic Classification Hardening.
Verifies centralized, consistent risk domain classification across all normalization paths.
"""

import pytest
from types import SimpleNamespace
from app.services.finding_normalizer import (
    normalize_config_finding,
    normalize_tls_finding,
    normalize_profile_evidence_item,
    normalize_crypto_misuse_finding,
)
from app.models.banking import EvidenceItem, EvidenceSource, ObservabilityState, SecurityLayer
try:
    from app.security.crypto_catalog import classify_risk_domain, QuantumThreatVector
except ImportError:
    classify_risk_domain = None
    QuantumThreatVector = None


def test_config_finding_aes128_grover_quantum_classification():
    """
    Task A1: Configuration findings specifying AES-128 must be classified as QUANTUM
    because 128-bit symmetric ciphers are subject to Grover algorithm quadratic search.
    """
    observation = SimpleNamespace(
        rule_id="CFG-CORE-CIPHER-01",
        title="Symmetric Cipher AES-128",
        parsed_value="AES-128-CBC",
        role="DATA_ENCRYPTION",
        evidence_status="OBSERVED",
        severity="HIGH",
        description="Core database uses AES-128-CBC for payload encryption.",
        recommendation="Upgrade to AES-256-GCM.",
    )
    finding = normalize_config_finding(observation, system_id="BANK-PROF-CORE-BANKING")
    
    # Must be classified under the QUANTUM risk domain due to Grover's speedup
    assert finding.risk == "QUANTUM", (
        f"Expected AES-128 config finding to have risk 'QUANTUM', but got '{finding.risk}'"
    )


def test_config_finding_aes256_quantum_domain_classification():
    """
    Task A1: Configuration findings specifying AES-256 must be classified under QUANTUM
    (the post-quantum assessment domain) rather than falling back to CLASSICAL.
    """
    observation = SimpleNamespace(
        rule_id="CFG-CORE-CIPHER-02",
        title="Symmetric Cipher AES-256",
        parsed_value="AES-256-GCM",
        role="DATA_ENCRYPTION",
        evidence_status="OBSERVED",
        severity="INFORMATIONAL",
        description="Database uses AES-256-GCM.",
        recommendation="Maintain AES-256-GCM.",
    )
    finding = normalize_config_finding(observation, system_id="BANK-PROF-PAYMENT-GATEWAY")
    
    # Must be classified under QUANTUM assessment domain (as resistant)
    assert finding.risk == "QUANTUM", (
        f"Expected AES-256 config finding to have risk 'QUANTUM', but got '{finding.risk}'"
    )


def test_threat_vector_domain_consistency():
    """
    Task A1: Threat vectors must deterministically map to their proper security domains:
    - SHOR, GROVER, SNDL, RESISTANT, POST_QUANTUM -> QUANTUM
    - CLASSICAL_BROKEN -> CLASSICAL
    """
    assert classify_risk_domain is not None, "classify_risk_domain must be defined in crypto_catalog.py"
    assert classify_risk_domain(threat_vector=QuantumThreatVector.SHOR.value) == "QUANTUM"
    assert classify_risk_domain(threat_vector=QuantumThreatVector.GROVER.value) == "QUANTUM"
    assert classify_risk_domain(threat_vector=QuantumThreatVector.SNDL.value) == "QUANTUM"
    assert classify_risk_domain(threat_vector=QuantumThreatVector.RESISTANT.value) == "QUANTUM"
    assert classify_risk_domain(threat_vector=QuantumThreatVector.POST_QUANTUM.value) == "QUANTUM"
    assert classify_risk_domain(threat_vector=QuantumThreatVector.CLASSICAL_BROKEN.value) == "CLASSICAL"


def test_cross_source_classification_consistency_for_primitives():
    """
    Task A1: The same primitive across TLS, Config, and Profile sources must yield
    the exact same risk domain classification.
    """
    # 1. Classical broken: 3DES
    cfg_3des = normalize_config_finding(
        SimpleNamespace(
            rule_id="CFG-3DES",
            title="3DES Cipher in Use",
            parsed_value="3DES",
            role="DATA_ENCRYPTION",
            evidence_status="OBSERVED",
            severity="CRITICAL",
        )
    )
    prof_3des = normalize_profile_evidence_item(
        EvidenceItem(
            id="ATM-3DES",
            control="Key Wrapping",
            value="3DES",
            source=EvidenceSource.CONFIGURATION_FILE,
            observability=ObservabilityState.OBSERVED,
            layer=SecurityLayer.DATA_AND_KEYS,
        )
    )
    assert cfg_3des.risk == "CLASSICAL"
    assert prof_3des.risk == "CLASSICAL"

    # 2. Asymmetric quantum broken: RSA-2048
    cfg_rsa = normalize_config_finding(
        SimpleNamespace(
            rule_id="CFG-RSA",
            title="RSA-2048 Asymmetric Key",
            parsed_value="RSA-2048",
            role="KEY_WRAPPING",
            evidence_status="OBSERVED",
            severity="HIGH",
        )
    )
    prof_rsa = normalize_profile_evidence_item(
        EvidenceItem(
            id="CORE-RSA",
            control="Key Wrapping",
            value="RSA-2048",
            source=EvidenceSource.OPERATOR_DECLARED,
            observability=ObservabilityState.OBSERVED,
            layer=SecurityLayer.DATA_AND_KEYS,
        )
    )
    assert cfg_rsa.risk == "QUANTUM"
    assert prof_rsa.risk == "QUANTUM"
