"""Automated tests for Task D5:
Zero-Trust NIST SP 800-207 Architecture Assessment Integration.

Verifies:
1. All 6 NIST SP 800-207 Zero Trust pillars are formalized and present:
   - Identity (mTLS / Client Auth)
   - Device Context (Endpoint Health)
   - Resource (Microsegmentation & Transport Encryption)
   - Policy (Dynamic PDP/PEP Access Decision)
   - Least Privilege (Scope & Role Restriction)
   - Continuous Verification (Session Integrity)
2. Observability Honesty Invariant:
   - Internal controls default to NOT_OBSERVABLE_EXTERNALLY from external scans.
   - NOT_OBSERVABLE_EXTERNALLY does NOT penalize security scores or mark controls as UNVERIFIED.
3. Edge Resource Control verification aligns with negotiated TLS version.
4. Asset-aware Zero Trust evaluation updates controls when internal evidence is declared.
5. ZeroTrustAssessment summary metrics and pillar enumeration helper functions.
"""

import pytest
from app.models.zero_trust import (
    ZeroTrustPillar,
    ZeroTrustControlStatus,
    ZeroTrustControl,
    ZeroTrustAssessment,
    build_default_zero_trust_assessment,
    build_zero_trust_assessment,
)
from app.models.audit import ObservabilityState
from app.models.banking import (
    BankingAsset,
    BankingAssetType,
    SecurityLayer,
    EvidenceItem,
    EvidenceSource,
)


def test_six_nist_sp_800_207_pillars_present():
    """Verify all 6 NIST SP 800-207 Zero Trust pillars are formalized in ZeroTrustAssessment."""
    zt = build_default_zero_trust_assessment("BANK-ASSET-01", tls_version="TLSv1.3")

    controls = zt.get_all_controls()
    assert len(controls) == 6

    pillars = {c.pillar for c in controls}
    expected_pillars = {
        ZeroTrustPillar.IDENTITY,
        ZeroTrustPillar.DEVICE_CONTEXT,
        ZeroTrustPillar.RESOURCE,
        ZeroTrustPillar.POLICY,
        ZeroTrustPillar.LEAST_PRIVILEGE,
        ZeroTrustPillar.CONTINUOUS_VERIFICATION,
    }
    assert pillars == expected_pillars


def test_observability_honesty_invariant():
    """
    INVARIANT:
    Internal controls cannot be probed from the perimeter and must be marked NOT_OBSERVABLE_EXTERNALLY.
    They must NEVER be marked as UNVERIFIED or assign artificial vulnerability.
    """
    zt = build_default_zero_trust_assessment("BANK-ASSET-01", tls_version="TLSv1.3")

    # Edge transport is observable and verified
    assert zt.resource_control.status == ZeroTrustControlStatus.VERIFIED
    assert zt.resource_control.observability == ObservabilityState.OBSERVED

    # All internal controls must be NOT_OBSERVABLE_EXTERNALLY
    internal_controls = [
        zt.identity_control,
        zt.context_control,
        zt.policy_control,
        zt.least_privilege_control,
        zt.continuous_verification_control,
    ]
    for ctrl in internal_controls:
        assert ctrl.status == ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY
        assert ctrl.observability == ObservabilityState.NOT_OBSERVABLE
        assert ctrl.status != ZeroTrustControlStatus.UNVERIFIED

    # Check summary metrics
    summary = zt.compute_zero_trust_summary()
    assert summary["verified_count"] == 1
    assert summary["not_observable_count"] == 5
    assert summary["unverified_count"] == 0
    assert summary["posture_label"] == "EDGE_ENCRYPTED_INTERNAL_UNKNOWN"
    assert "NOT_OBSERVABLE_EXTERNALLY" in summary["observational_honesty_statement"]


def test_resource_control_reflects_tls_version():
    """Resource control status is VERIFIED for modern TLS and UNVERIFIED for obsolete protocols."""
    zt_modern = build_default_zero_trust_assessment("BANK-ASSET-MODERN", tls_version="TLSv1.3")
    assert zt_modern.resource_control.status == ZeroTrustControlStatus.VERIFIED

    zt_legacy = build_default_zero_trust_assessment("BANK-ASSET-LEGACY", tls_version="TLSv1.0")
    assert zt_legacy.resource_control.status == ZeroTrustControlStatus.UNVERIFIED


def test_asset_aware_zero_trust_evaluation():
    """When internal evidence is present in BankingAsset layers, controls are updated accordingly."""
    asset = BankingAsset(
        id="BANK-INTERNAL-PAYMENT",
        name="Internal Payment Processor",
        asset_type=BankingAssetType.CORE_BANKING,
        layers={
            SecurityLayer.SERVICE_TO_SERVICE: [
                EvidenceItem(
                    id="EV-MTLS-01",
                    control="mTLS Identity",
                    value="Enforced via SPIFFE/SPIRE with ML-DSA certificates",
                    source=EvidenceSource.CONFIGURATION_FILE,
                    observability=ObservabilityState.OBSERVED,
                )
            ],
            SecurityLayer.API_GATEWAY: [
                EvidenceItem(
                    id="EV-PDP-01",
                    control="Policy Decision Point",
                    value="Open Policy Agent (OPA) dynamic RBAC",
                    source=EvidenceSource.OPERATOR_DECLARED,
                    observability=ObservabilityState.OBSERVED,
                )
            ],
        },
    )

    zt = build_zero_trust_assessment(asset.id, tls_version="TLSv1.3", asset=asset)

    # Identity control should now be VERIFIED due to internal mTLS evidence
    assert zt.identity_control.status == ZeroTrustControlStatus.VERIFIED
    assert zt.identity_control.observability == ObservabilityState.OBSERVED
    assert "SPIFFE/SPIRE" in (zt.identity_control.evidence or "")

    # Policy control should now be VERIFIED due to OPA PDP evidence
    assert zt.policy_control.status == ZeroTrustControlStatus.VERIFIED
    assert "Open Policy Agent" in (zt.policy_control.evidence or "")

    # Unconfigured controls remain NOT_OBSERVABLE_EXTERNALLY
    assert zt.context_control.status == ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY
