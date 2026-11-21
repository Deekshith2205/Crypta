"""Pydantic schemas for the QuantumShield AI Intelligence Layer.
Strictly typed request and response contracts conforming to Task 10 requirements.
"""

from typing import Optional, List, Dict, Any, Generic, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")

DEFAULT_ADVISORY_DISCLAIMER = (
    "AI Advisory — Informational Explanation. The deterministic QuantumShield scanner "
    "is the sole authoritative source for findings, severity, evidence, and risk scores."
)


class AIStatusResponse(BaseModel):
    """Current status of the AI intelligence layer."""
    is_available: bool = Field(..., description="Whether an AI provider is active and available")
    provider: str = Field(..., description="Configured AI provider (e.g., 'gemini', 'openai', 'anthropic', 'mock', 'none')")
    model: Optional[str] = Field(default=None, description="Active AI model identifier")
    message: str = Field(..., description="Status message")


class FindingExplanationRequest(BaseModel):
    """Input payload to explain an individual cryptographic finding."""
    rule_id: str = Field(..., description="Unique rule or finding ID (e.g., 'TLS-1.3-KEX-ABSENT')")
    title: str = Field(..., description="Finding title")
    value: str = Field(..., description="Observed cryptographic algorithm or parameter")
    role: str = Field(..., description="Cryptographic role (e.g., 'KEY_EXCHANGE', 'DIGITAL_SIGNATURE', 'DATA_ENCRYPTION')")
    source: str = Field(..., description="Evidence origin (e.g., 'EXTERNAL_SCAN', 'CONFIGURATION_FILE', 'CODE_ANALYSIS')")
    evidence_status: str = Field(..., description="Evidence state (OBSERVED, INFERRED, NOT_OBSERVABLE, etc.)")
    severity: str = Field(..., description="Deterministic severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)")
    risk: str = Field(..., description="Risk domain (QUANTUM, CLASSICAL, BOTH)")
    message: Optional[str] = Field(default=None, description="Deterministic engine narrative")
    recommendation: Optional[str] = Field(default=None, description="Deterministic engine remediation")
    system_id: Optional[str] = Field(default=None, description="Optional banking system identifier")
    asset_id: Optional[str] = Field(default=None, description="Optional target asset identifier")


class FindingExplanationResponse(BaseModel):
    """AI-powered contextual explanation for a finding."""
    rule_id: str = Field(..., description="Echoed rule identifier")
    meaning: str = Field(..., description="What the finding means in plain technical terms")
    why_it_matters: str = Field(..., description="Why this finding matters to security operations")
    quantum_relevance: str = Field(..., description="Relevance to Shor's or Grover's quantum threat models")
    crypto_component: str = Field(..., description="Cryptographic primitive or mechanism involved")
    what_evidence_establishes: str = Field(..., description="What the verified evidence explicitly confirms")
    what_evidence_does_not_establish: str = Field(..., description="What the evidence does NOT establish (NOT_OBSERVABLE != VULNERABLE)")
    banking_impact: str = Field(..., description="Potential operational or regulatory impact on banking infrastructure")
    remediation: str = Field(..., description="Prescriptive remediation guidance")
    migration_considerations: str = Field(..., description="Migration roadmap and dependency considerations")
    standards_guidance: str = Field(..., description="Applicable NIST FIPS 203/204/205 or NSA CNSA 2.0 guidance")
    advisory_disclaimer: str = Field(default=DEFAULT_ADVISORY_DISCLAIMER)


class BankingRiskExplanationRequest(BaseModel):
    """Input payload to explain a banking system risk assessment and ranking."""
    system_id: str = Field(..., description="Banking system identifier")
    system_name: str = Field(..., description="Human-readable system name")
    priority_score: int = Field(..., ge=0, le=100, description="Deterministic priority score (0-100)")
    priority_band: str = Field(..., description="Priority band (P0, P1, P2, P3)")
    quantum_risk_level: Optional[str] = Field(default=None, description="Quantum risk label")
    classical_risk_level: Optional[str] = Field(default=None, description="Classical risk label")
    criticality: Optional[str] = Field(default=None, description="Business criticality tier")
    data_sensitivity: Optional[str] = Field(default=None, description="Data sensitivity tier")
    data_lifetime: Optional[str] = Field(default=None, description="Data retention horizon (SNDL exposure)")
    exposure: Optional[str] = Field(default=None, description="Network boundary exposure")
    migration_effort: Optional[str] = Field(default=None, description="Migration complexity tier")
    top_findings: List[str] = Field(default_factory=list, description="Top deterministic findings")
    weak_links: List[str] = Field(default_factory=list, description="Identified weak links in key protection chain")
    evidence_gaps: List[str] = Field(default_factory=list, description="Observability gaps requiring verification")


class BankingRiskExplanationResponse(BaseModel):
    """AI-powered explanation for banking risk score and upgrade queue placement."""
    system_id: str = Field(..., description="Echoed banking system ID")
    system_name: str = Field(..., description="Echoed banking system name")
    score_rationale: str = Field(..., description="Reasoning behind the deterministic priority score")
    contributing_factors: List[str] = Field(..., description="Deterministic factors that drove this score")
    severity_weighting_explanation: str = Field(..., description="Why certain findings have higher priority than others")
    upgrade_queue_position_reason: str = Field(..., description="Why this system appears at its current upgrade rank")
    supporting_evidence: List[str] = Field(..., description="Verified evidence supporting the risk posture")
    evidence_gaps_needed: List[str] = Field(..., description="Internal evidence still required to close observability gaps")
    advisory_disclaimer: str = Field(default=DEFAULT_ADVISORY_DISCLAIMER)


class MigrationAdvisoryRequest(BaseModel):
    """Input payload for AI migration advisory."""
    system_id: str = Field(..., description="Banking system identifier")
    system_name: str = Field(..., description="Banking system name")
    baseline_priority_score: int = Field(..., ge=0, le=100)
    baseline_priority_band: str = Field(...)
    target_replacement: Optional[str] = Field(default=None, description="Simulated or proposed PQC primitive")
    simulated_changes: List[Dict[str, Any]] = Field(default_factory=list)
    projected_priority_score: Optional[int] = Field(default=None, ge=0, le=100)
    projected_priority_band: Optional[str] = Field(default=None)
    crypto_agility: Optional[str] = Field(default="NOT_OBSERVABLE")
    migration_impact: Optional[str] = Field(default="MEDIUM")
    dependencies: List[str] = Field(default_factory=list)


class MigrationAdvisoryResponse(BaseModel):
    """AI-powered post-quantum migration advisory."""
    system_id: str = Field(...)
    system_name: str = Field(...)
    migration_justification: str = Field(..., description="Why this asset requires migration")
    target_cryptographic_roles: List[str] = Field(..., description="Cryptographic roles needing attention")
    pqc_direction: str = Field(..., description="Recommended post-quantum cryptographic standards direction")
    operational_impact_assessment: str = Field(..., description="Latency, packet fragmentation, and HSM considerations")
    interoperability_and_testing: str = Field(..., description="Hybrid transition and backward compatibility guidance")
    suggested_migration_phases: List[str] = Field(..., description="Sequenced migration milestones")
    pre_deployment_validation_steps: List[str] = Field(..., description="Verification and audit checks before production")
    advisory_disclaimer: str = Field(default=DEFAULT_ADVISORY_DISCLAIMER)


class ReportExplanationRequest(BaseModel):
    """Input payload to generate AI narrative summaries for an assessment report."""
    system_id: str = Field(..., description="Banking system identifier")


class ReportExplanationResponse(BaseModel):
    """AI executive and technical summaries for an assessment report."""
    system_id: str = Field(...)
    executive_summary: Dict[str, str] = Field(
        ...,
        description="Keys: overall_situation, primary_risks, critical_assets, high_level_actions"
    )
    technical_summary: Dict[str, str] = Field(
        ...,
        description="Keys: cryptographic_findings, evidence_distinctions, algorithm_migration, dependencies, sequence"
    )
    management_recommendations: Dict[str, str] = Field(
        ...,
        description="Keys: prioritization_rationale, migration_planning, governance_and_validation"
    )
    advisory_disclaimer: str = Field(default=DEFAULT_ADVISORY_DISCLAIMER)


class AIExplanationResult(BaseModel, Generic[T]):
    """Standard generic wrapper returned by the AI intelligence layer."""
    success: bool = Field(..., description="Whether explanation was generated successfully")
    is_available: bool = Field(..., description="Whether an AI provider is configured and reachable")
    provider: str = Field(..., description="Provider used (e.g. 'gemini', 'openai', 'mock', 'none')")
    data: Optional[T] = Field(default=None, description="Structured explanation response payload")
    error: Optional[str] = Field(default=None, description="Error message if generation failed or unavailable")
    disclaimer: str = Field(default=DEFAULT_ADVISORY_DISCLAIMER)

