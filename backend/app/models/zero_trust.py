"""Zero Trust Architecture domain model.
Phase 0 - Banking Security Audit Architecture
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from app.models.audit import AuditFinding, ObservabilityState


class ZeroTrustPillar(str, Enum):
    IDENTITY = "IDENTITY"
    DEVICE_CONTEXT = "DEVICE_CONTEXT"
    RESOURCE = "RESOURCE"
    POLICY = "POLICY"
    LEAST_PRIVILEGE = "LEAST_PRIVILEGE"
    CONTINUOUS_VERIFICATION = "CONTINUOUS_VERIFICATION"


class ZeroTrustControlStatus(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    NOT_OBSERVABLE_EXTERNALLY = "NOT_OBSERVABLE_EXTERNALLY"
    UNVERIFIED = "UNVERIFIED"


class ZeroTrustControl(BaseModel):
    """Represents an individual Zero Trust control assessment."""
    pillar: ZeroTrustPillar
    control_id: str
    name: str
    status: ZeroTrustControlStatus = ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY
    observability: ObservabilityState = ObservabilityState.NOT_OBSERVABLE
    description: str
    evidence: Optional[str] = None
    notes: Optional[str] = None


class ZeroTrustAssessment(BaseModel):
    """
    Zero Trust Architecture Readiness Assessment for a Banking Asset.
    Models the 6 NIST SP 800-207 Zero Trust pillars.
    External TLS assessment can only observe edge transport properties;
    internal authorization, mTLS, and policy enforcement remain transparently
    marked as NOT_OBSERVABLE_EXTERNALLY without assigning artificial vulnerability.
    """
    asset_id: str = Field(..., description="Target banking asset identifier")
    identity_control: ZeroTrustControl = Field(..., description="Authentication & Client Identity Verification")
    context_control: ZeroTrustControl = Field(..., description="Device Health & Environmental Context Enforcement")
    resource_control: ZeroTrustControl = Field(..., description="Microsegmentation & Asset Protection")
    policy_control: ZeroTrustControl = Field(..., description="Dynamic Access Policy Engine")
    least_privilege_control: ZeroTrustControl = Field(..., description="Least Privilege & Scope Restriction")
    continuous_verification_control: ZeroTrustControl = Field(..., description="Session Integrity & Continuous Re-evaluation")
    findings: List[AuditFinding] = Field(default_factory=list, description="Zero Trust audit findings")

    def get_all_controls(self) -> List[ZeroTrustControl]:
        """Returns all 6 NIST SP 800-207 Zero Trust controls."""
        return [
            self.identity_control,
            self.context_control,
            self.resource_control,
            self.policy_control,
            self.least_privilege_control,
            self.continuous_verification_control,
        ]

    def compute_zero_trust_summary(self) -> Dict[str, Any]:
        """Calculates honest Zero Trust posture metrics across the 6 pillars."""
        controls = self.get_all_controls()
        verified = sum(1 for c in controls if c.status == ZeroTrustControlStatus.VERIFIED)
        unverified = sum(1 for c in controls if c.status == ZeroTrustControlStatus.UNVERIFIED)
        not_observable = sum(1 for c in controls if c.status == ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY)
        partially = sum(1 for c in controls if c.status == ZeroTrustControlStatus.PARTIALLY_VERIFIED)

        if self.resource_control.status == ZeroTrustControlStatus.VERIFIED and not_observable >= 4:
            posture_label = "EDGE_ENCRYPTED_INTERNAL_UNKNOWN"
        elif verified == 6:
            posture_label = "FULLY_VERIFIED_ZERO_TRUST"
        elif unverified > 0:
            posture_label = "DEFICIENT_ZERO_TRUST"
        else:
            posture_label = "PARTIALLY_VERIFIED"

        return {
            "verified_count": verified,
            "partially_verified_count": partially,
            "not_observable_count": not_observable,
            "unverified_count": unverified,
            "posture_label": posture_label,
            "observational_honesty_statement": (
                "NOT_OBSERVABLE_EXTERNALLY controls reflect external perimeter vantage point limitations "
                "and are NOT penalized as vulnerabilities per NIST SP 800-207 guidelines."
            ),
        }


def build_zero_trust_assessment(
    asset_id: str,
    tls_version: str = "TLSv1.3",
    asset: Optional[Any] = None,
) -> ZeroTrustAssessment:
    """
    Constructs an observability-honest NIST SP 800-207 Zero Trust assessment.
    Integrates observable edge TLS and incorporates declared asset evidence where available.
    """
    zt = build_default_zero_trust_assessment(asset_id, tls_version=tls_version)

    if not asset:
        return zt

    # Inspect asset layers and evidence items if available
    layers = getattr(asset, "layers", {}) or {}
    evidence_items = getattr(asset, "evidence_items", []) or []

    all_evidence = list(evidence_items)
    for layer_items in layers.values():
        if isinstance(layer_items, list):
            all_evidence.extend(layer_items)

    for item in all_evidence:
        ctrl_name = getattr(item, "control", "") or ""
        val = getattr(item, "value", "") or ""
        obs = getattr(item, "observability", None)
        obs_val = getattr(obs, "value", str(obs)) if obs else "OBSERVED"

        # Check for internal mTLS / identity evidence
        if any(kw in ctrl_name.lower() or kw in val.lower() for kw in ["mtls", "spiffe", "spire", "client cert"]):
            zt.identity_control.status = ZeroTrustControlStatus.VERIFIED
            zt.identity_control.observability = ObservabilityState.OBSERVED
            zt.identity_control.evidence = f"Internal identity verified: {val}"
            zt.identity_control.notes = f"Sourced from {getattr(item, 'source', 'internal evidence')}"

        # Check for dynamic PDP / policy evidence
        if any(kw in ctrl_name.lower() or kw in val.lower() for kw in ["pdp", "policy decision", "opa", "open policy agent", "rbac"]):
            zt.policy_control.status = ZeroTrustControlStatus.VERIFIED
            zt.policy_control.observability = ObservabilityState.OBSERVED
            zt.policy_control.evidence = f"Policy engine verified: {val}"

        # Check for device posture / context
        if any(kw in ctrl_name.lower() or kw in val.lower() for kw in ["edr", "device posture", "mdm", "device context"]):
            zt.context_control.status = ZeroTrustControlStatus.VERIFIED
            zt.context_control.observability = ObservabilityState.OBSERVED
            zt.context_control.evidence = f"Device posture verified: {val}"

        # Check for least privilege
        if any(kw in ctrl_name.lower() or kw in val.lower() for kw in ["least privilege", "scope restriction", "abac"]):
            zt.least_privilege_control.status = ZeroTrustControlStatus.VERIFIED
            zt.least_privilege_control.observability = ObservabilityState.OBSERVED
            zt.least_privilege_control.evidence = f"Least privilege verified: {val}"

        # Check for continuous session verification
        if any(kw in ctrl_name.lower() or kw in val.lower() for kw in ["continuous verification", "re-authentication", "continuous session"]):
            zt.continuous_verification_control.status = ZeroTrustControlStatus.VERIFIED
            zt.continuous_verification_control.observability = ObservabilityState.OBSERVED
            zt.continuous_verification_control.evidence = f"Continuous verification verified: {val}"

    return zt


def build_default_zero_trust_assessment(asset_id: str, tls_version: str = "TLSv1.3") -> ZeroTrustAssessment:
    """
    Constructs an observability-honest baseline Zero Trust assessment for an external asset.
    Distinguishes verifiable edge transport properties from internal policy controls.
    """
    return ZeroTrustAssessment(
        asset_id=asset_id,
        identity_control=ZeroTrustControl(
            pillar=ZeroTrustPillar.IDENTITY,
            control_id="ZT-ID-01",
            name="Mutual TLS / Strong Client Authentication",
            status=ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY,
            observability=ObservabilityState.NOT_OBSERVABLE,
            description="Client identity verification (mTLS / certificate-based authentication) at the edge.",
            notes="Standard external server probing inspects server credentials only; client identity policy is internal."
        ),
        context_control=ZeroTrustControl(
            pillar=ZeroTrustPillar.DEVICE_CONTEXT,
            control_id="ZT-CTX-01",
            name="Client Device Posture & Context Enforcement",
            status=ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY,
            observability=ObservabilityState.NOT_OBSERVABLE,
            description="Evaluating device security posture, EDR signals, and network context before granting resource access.",
            notes="Device context inspection requires internal endpoint telemetries not observable via external TLS."
        ),
        resource_control=ZeroTrustControl(
            pillar=ZeroTrustPillar.RESOURCE,
            control_id="ZT-RES-01",
            name="Transport Encryption & Edge Microsegmentation",
            status=ZeroTrustControlStatus.VERIFIED if tls_version in ["TLSv1.3", "TLSv1.2"] else ZeroTrustControlStatus.UNVERIFIED,
            observability=ObservabilityState.OBSERVED,
            description="Mandatory modern cryptographic encapsulation for all inbound banking traffic.",
            evidence=f"Observed external edge TLS negotiation: {tls_version}",
            notes="Public ingress terminates TLS securely; internal microsegmentation is unobservable from external vantage."
        ),
        policy_control=ZeroTrustControl(
            pillar=ZeroTrustPillar.POLICY,
            control_id="ZT-POL-01",
            name="Dynamic Policy Decision Point (PDP) Enforcement",
            status=ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY,
            observability=ObservabilityState.NOT_OBSERVABLE,
            description="Centralized dynamic authorization evaluating attributes per transaction.",
            notes="PDP/PEP architecture is internal to banking infrastructure."
        ),
        least_privilege_control=ZeroTrustControl(
            pillar=ZeroTrustPillar.LEAST_PRIVILEGE,
            control_id="ZT-LP-01",
            name="Least Privilege Access Scoping",
            status=ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY,
            observability=ObservabilityState.NOT_OBSERVABLE,
            description="Restricting access strictly to authorized resources and scopes.",
            notes="API scopes and RBAC/ABAC cannot be evaluated via passive external TLS scan."
        ),
        continuous_verification_control=ZeroTrustControl(
            pillar=ZeroTrustPillar.CONTINUOUS_VERIFICATION,
            control_id="ZT-CV-01",
            name="Continuous Session Verification & Re-authentication",
            status=ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY,
            observability=ObservabilityState.NOT_OBSERVABLE,
            description="Real-time re-evaluation of trust throughout the entire transaction lifecycle.",
            notes="Session management logic resides in application layer behind TLS termination."
        ),
        findings=[]
    )

