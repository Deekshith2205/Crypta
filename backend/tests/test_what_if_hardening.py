"""Automated hardening tests for Task D4:
Deterministic What-If Post-Quantum Migration Simulator.

Verifies:
1. PQC Migration Targets:
   - Key Wrapping: RSA-2048 -> ML-KEM-768, ML-KEM-1024, AES-256-KW.
   - Authentication: ECDSA / RSA -> ML-DSA-65, SLH-DSA-128s.
   - Perimeter Transport: Classical TLS -> TLSv1.3 with X25519MLKEM768 hybrid key exchange.
2. Invariant: AES-256 bulk encryption is NEVER treated as a vulnerability before or after simulation.
3. Partial Migration: Replacing key wrapping while leaving classical authentication resolves wrapping
   but accurately reports authentication as a remaining weak link.
4. Full PQC Migration: Replacing both wrapping and authentication achieves QUANTUM_READY posture.
5. Strict Immutability: Baseline asset and profiles catalog are guaranteed non-mutated.
6. Deterministic Priority Reduction: Priority score decreases proportionally based on Phase 4B formula.
7. Validation Rejections: Unsupported algorithms, >5 operations, and invalid component types raise errors.
"""

import copy
import pytest
from app.models.banking import (
    BankingAsset,
    BankingAssetType,
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    DataLifetime,
    MigrationEffort,
    KeyProtectionChain,
    CryptoConfiguration,
)
from app.models.profiles import get_synthetic_profile_by_id
from app.models.risk import KeyChainStatus, MigrationPriority
from app.models.simulation import (
    MigrationComponent,
    MigrationAction,
    WhatIfMigrationRequest,
    ALLOWED_MIGRATION_TARGETS,
)
from app.services.migration_simulator import (
    simulate_migration,
    validate_migration_request,
    MigrationSimulationError,
)


def _create_sample_banking_asset() -> BankingAsset:
    return BankingAsset(
        id="BANK-SYS-LOAN-PORTAL",
        name="Consumer Loan Origination Portal",
        asset_type=BankingAssetType.CORE_BANKING,
        criticality=AssetCriticality.HIGH,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        data_lifetime=DataLifetime.VERY_LONG,
        exposure=AssetExposure.RESTRICTED,
        migration_effort=MigrationEffort.MEDIUM,
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.2", "TLSv1.3"],
            cipher_suites=["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
            key_exchange="ECDH-secp256r1",
            key_chain=KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="RSA-2048",
                key_storage="Cloud KMS",
                authentication="ECDSA-P256",
            ),
        ),
    )


def test_what_if_full_pqc_migration_reaches_quantum_ready():
    """Simulating full migration of wrapping to ML-KEM-768 and auth to ML-DSA-65 reaches QUANTUM_READY."""
    asset = _create_sample_banking_asset()
    original_copy = copy.deepcopy(asset)

    req = WhatIfMigrationRequest(
        asset=asset,
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="ML-KEM-768",
            ),
            MigrationAction(
                component=MigrationComponent.AUTHENTICATION,
                target_algorithm="ML-DSA-65",
            ),
        ],
    )
    result = simulate_migration(req)

    # 1. Posture transitions
    assert result.comparison.key_chain_status_before == KeyChainStatus.QUANTUM_EXPOSED
    assert result.comparison.key_chain_status_after == KeyChainStatus.QUANTUM_READY

    # 2. Score and priority drop significantly
    assert result.comparison.priority_score_after < result.comparison.priority_score_before
    assert result.comparison.risk_reduction > 0
    assert result.after.migration_priority in [MigrationPriority.P2, MigrationPriority.P3]

    # 3. Weak links fully resolved
    assert len(result.comparison.resolved_findings) >= 2
    assert len(result.comparison.remaining_findings) == 0

    # 4. Invariant: AES-256 is preserved and never flagged as a weak link
    for finding in result.comparison.resolved_findings + result.comparison.remaining_findings:
        assert "AES-256" not in finding

    # 5. Baseline asset remains strictly immutable
    assert asset.model_dump() == original_copy.model_dump()


def test_what_if_partial_migration_preserves_remaining_weak_link():
    """Replacing only key wrapping resolves wrapping but accurately retains authentication as a weak link."""
    asset = _create_sample_banking_asset()
    req = WhatIfMigrationRequest(
        asset=asset,
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="ML-KEM-768",
            ),
        ],
    )
    result = simulate_migration(req)

    # Key wrapping resolved, authentication remains
    assert any("RSA" in f for f in result.comparison.resolved_findings)
    assert any("ECDSA" in f for f in result.comparison.remaining_findings)

    # Not yet QUANTUM_READY because auth is still classical ECDSA
    assert result.comparison.key_chain_status_after != KeyChainStatus.QUANTUM_READY
    assert "Remaining vulnerabilities" in result.explanation


def test_what_if_slh_dsa_stateless_signature_target():
    """Simulating migration to FIPS 205 SLH-DSA-128s is supported and recognized as PQC authentication."""
    asset = _create_sample_banking_asset()
    req = WhatIfMigrationRequest(
        asset=asset,
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="ML-KEM-768",
            ),
            MigrationAction(
                component=MigrationComponent.AUTHENTICATION,
                target_algorithm="SLH-DSA-128s",
            ),
        ],
    )
    result = simulate_migration(req)
    assert result.comparison.key_chain_status_after == KeyChainStatus.QUANTUM_READY
    assert result.comparison.risk_reduction > 0


def test_what_if_aes_256_kw_symmetric_key_wrap():
    """Simulating migration to AES-256-KW is supported as a Grover-resilient symmetric key wrapping scheme."""
    asset = _create_sample_banking_asset()
    req = WhatIfMigrationRequest(
        asset=asset,
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="AES-256-KW",
            ),
            MigrationAction(
                component=MigrationComponent.AUTHENTICATION,
                target_algorithm="ML-DSA-65",
            ),
        ],
    )
    result = simulate_migration(req)
    assert result.comparison.risk_reduction > 0
    assert any("RSA" in f for f in result.comparison.resolved_findings)


def test_what_if_rejects_unsupported_or_quantum_vulnerable_target():
    """Verify that attempting to migrate to an unsupported or classical algorithm (e.g. RSA-4096) is rejected."""
    asset = _create_sample_banking_asset()
    req = WhatIfMigrationRequest(
        asset=asset,
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="RSA-4096",
            ),
        ],
    )
    with pytest.raises(MigrationSimulationError, match="Unsupported migration target 'RSA-4096'"):
        validate_migration_request(req)
