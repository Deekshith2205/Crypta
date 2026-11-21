"""Mock AI Provider for automated tests and offline evaluation.
Generates fully schema-compliant, grounded explanations without external network calls or fees.
Preserves all deterministic invariants:
- NOT_OBSERVABLE != VULNERABLE
- AES-256 is not described as quantum-broken
- Does not modify scores, severities, or rankings.
"""

import json
from typing import Dict, Any
from app.ai.providers.base import BaseAIProvider


class MockAIProvider(BaseAIProvider):
    """Deterministic mock provider generating realistic banking PQC advisory output."""

    def __init__(self, model_name: str = "mock-quantum-advisor"):
        self._model = model_name

    def is_configured(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, prompt: str, system_prompt: str) -> str:
        """Parses the input prompt and synthesizes an appropriate schema-valid JSON string."""
        # Detect the requested explanation type from prompt
        if "Explain Individual Cryptographic Finding" in prompt:
            return self._generate_finding_explanation(prompt)
        elif "Explain Banking System Risk Assessment" in prompt:
            return self._generate_banking_risk_explanation(prompt)
        elif "Post-Quantum Migration Advisory" in prompt:
            return self._generate_migration_advisory(prompt)
        elif "Assessment Report Summaries" in prompt:
            return self._generate_report_explanation(prompt)

        # Default fallback JSON
        return json.dumps({
            "status": "SUCCESS",
            "message": "Deterministic mock explanation generated successfully.",
            "advisory_disclaimer": "AI Advisory — Informational Explanation. The deterministic QuantumShield scanner is the sole authoritative assessment source."
        })

    def _generate_finding_explanation(self, prompt: str) -> str:
        # Check specific field markers in the structured prompt
        is_not_observable = "- Evidence Status: NOT_OBSERVABLE" in prompt
        is_symmetric = (
            "DATA_ENCRYPTION" in prompt
            or "SYM-AES" in prompt
            or "AES-256" in prompt
            or "- Cryptographic Component / Role: DATA_ENCRYPTION" in prompt
        )
        is_kex = "KEY_EXCHANGE" in prompt or "KEX" in prompt
        is_signature = "DIGITAL_SIGNATURE" in prompt or "SIGNATURE" in prompt or "RSA" in prompt

        if is_not_observable:
            what_establishes = (
                "The scanner verified that this cryptographic setting cannot be passively observed "
                "or probed from the external perimeter interface."
            )
            what_does_not_establish = (
                "Crucially, the absence of perimeter observability does NOT establish that this configuration "
                "is insecure or vulnerable (NOT_OBSERVABLE != VULNERABLE). Internal configuration review is required."
            )
            remediation = (
                "Review internal service configurations, TLS termination appliances, and deployment manifests "
                "to verify the exact operational parameters deployed behind the perimeter."
            )
        else:
            what_establishes = (
                "The scanner observed active cryptographic parameters from the inspection interface, confirming "
                "the algorithm and mechanism currently in production."
            )
            what_does_not_establish = (
                "The observation confirms perimeter parameter negotiation but does not indicate whether "
                "internal compensating controls (such as HSM physical boundaries or isolated VLANs) are in effect."
            )
            if is_kex:
                remediation = (
                    "Deploy post-quantum key establishment conforming to NIST FIPS 203 (ML-KEM) or an "
                    "interoperable hybrid mechanism (e.g., X25519MLKEM768) to protect against Store Now, Decrypt Later."
                )
            elif is_signature:
                remediation = (
                    "Plan migration to NIST FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA) stateful/stateless hash-based "
                    "signatures, or deploy hybrid certificates during the transition window."
                )
            elif is_symmetric:
                remediation = (
                    "Ensure symmetric encryption utilizes AES-256 with modern authenticated modes (GCM). "
                    "Note: AES-256 retains 128-bit quantum security against Grover's algorithm and is NOT quantum-broken."
                )
            else:
                remediation = (
                    "Upgrade deprecated cryptographic primitives to post-quantum standards aligned with NIST FIPS and NSA CNSA 2.0."
                )

        response = {
            "rule_id": "FINDING-EVAL",
            "meaning": "Cryptographic primitive evaluated against quantum threat models (Shor's and Grover's algorithms).",
            "why_it_matters": "Financial systems handle long-term confidential transactions susceptible to retrospective decryption.",
            "quantum_relevance": (
                "AES-256 maintains strong quantum security against Grover's algorithm, whereas RSA, ECDSA, and DH "
                "are fully compromised by Shor's algorithm on a cryptanalytically relevant quantum computer."
                if is_symmetric else
                "Vulnerable to Shor's algorithm, allowing a cryptanalytically relevant quantum computer (CRQC) to compute private keys."
            ),
            "crypto_component": "Key Establishment / Transport Layer" if is_kex else ("Digital Signature" if is_signature else "Symmetric Encryption"),
            "what_evidence_establishes": what_establishes,
            "what_evidence_does_not_establish": what_does_not_establish,
            "banking_impact": "Potential exposure of payment data, interbank messaging integrity, or customer confidentiality.",
            "remediation": remediation,
            "migration_considerations": "Coordinate firmware updates on hardware security modules (HSMs) and evaluate TLS client compatibility.",
            "standards_guidance": "Aligned with NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and NSA CNSA 2.0.",
            "advisory_disclaimer": "AI Advisory — Informational Explanation. The deterministic QuantumShield scanner is the sole authoritative assessment source."
        }
        return json.dumps(response)

    def _generate_banking_risk_explanation(self, prompt: str) -> str:
        response = {
            "system_id": "BANK-EVAL",
            "system_name": "Banking System",
            "score_rationale": (
                "The deterministic priority score is computed by combining Technical Risk Factor (quantum and classical "
                "vulnerabilities) with the Business Exposure Factor (system criticality, data sensitivity, SNDL retention lifetime, "
                "network exposure, and migration effort)."
            ),
            "contributing_factors": [
                "Governing Technical Risk: High technical exposure driven by quantum-vulnerable public key algorithms.",
                "Store Now, Decrypt Later (SNDL) exposure: Data retention horizon extends beyond estimated CRQC arrival.",
                "Business Criticality: Core processing component with direct financial transaction routing.",
                "Network Exposure: External perimeter or cross-institution interbank connectivity."
            ],
            "severity_weighting_explanation": (
                "Critical findings involving asymmetric key establishment on long-lived customer data are weighted higher "
                "than ephemeral session configurations because adversaries can harvest and store encrypted traffic today."
            ),
            "upgrade_queue_position_reason": (
                "This system is prioritized in its current queue rank due to the combination of high SNDL exposure, "
                "core transaction volume, and key protection chain dependencies."
            ),
            "supporting_evidence": [
                "Observed or declared cryptographic mechanisms in the banking profile.",
                "Verified multi-dimensional risk scores from the deterministic assessment engine."
            ],
            "evidence_gaps_needed": [
                "Detailed internal HSM firmware inventory and FIPS 140-3 certification records.",
                "Hardware acceleration capabilities for lattice-based polynomial multiplication."
            ],
            "advisory_disclaimer": "AI Advisory — Informational Explanation. The deterministic QuantumShield scanner is the sole authoritative assessment source."
        }
        return json.dumps(response)

    def _generate_migration_advisory(self, prompt: str) -> str:
        response = {
            "system_id": "MIG-EVAL",
            "system_name": "Banking System",
            "migration_justification": (
                "System handles sensitive banking data that must remain confidential across a multi-year horizon, "
                "making it a prime target for Store Now, Decrypt Later attacks."
            ),
            "target_cryptographic_roles": [
                "Key Establishment (NIST FIPS 203 ML-KEM)",
                "Digital Signatures and Authentication (NIST FIPS 204 ML-DSA)",
                "Key Protection Chain / Master Key Wrapping"
            ],
            "pqc_direction": "Transition to NIST FIPS 203 ML-KEM-768 for general key establishment, or hybrid X25519MLKEM768.",
            "operational_impact_assessment": (
                "ML-KEM public keys and ciphertexts are larger than classical ECC (1,184 bytes vs 32 bytes), "
                "which may cause TCP packet fragmentation if MTU settings are not tuned. Minimal latency impact."
            ),
            "interoperability_and_testing": (
                "Implement dual-stack or hybrid transitions initially to ensure legacy banking partners and ATM clients "
                "can negotiate classical connections while quantum-capable peers utilize PQC."
            ),
            "suggested_migration_phases": [
                "Phase 1: Cryptographic inventory and CBOM generation across all endpoints.",
                "Phase 2: Hybrid deployment (X25519 + ML-KEM) in sandbox and staging environments.",
                "Phase 3: Production rollout with HSM firmware upgrades and mutual TLS validation."
            ],
            "pre_deployment_validation_steps": [
                "Validate TLS 1.3 handshake completion under degraded network conditions.",
                "Verify HSM FIPS 140-3 compliance for lattice-based algorithms.",
                "Perform stress testing on peak transaction throughput with enlarged certificate chains."
            ],
            "advisory_disclaimer": "AI Advisory — Informational Explanation. The deterministic QuantumShield scanner is the sole authoritative assessment source."
        }
        return json.dumps(response)

    def _generate_report_explanation(self, prompt: str) -> str:
        response = {
            "system_id": "REP-EVAL",
            "executive_summary": {
                "overall_situation": "The banking system exhibits moderate to high exposure to future quantum cryptanalysis, primarily in key exchange and key-wrapping hierarchies.",
                "primary_risks": "Asymmetric encryption algorithms (RSA/ECDSA) are vulnerable to Shor's algorithm, exposing long-term transaction archives to Store Now, Decrypt Later.",
                "critical_assets": "Core transaction routing, payment settlement databases, and root key wrapping require priority remediation.",
                "high_level_actions": "Initiate hybrid PQC pilots, upgrade hardware security module firmware, and audit cryptographic agility across legacy dependencies."
            },
            "technical_summary": {
                "cryptographic_findings": "Observed classical algorithms include RSA-2048 and ECDHE; symmetric ciphers utilize AES-256-GCM which remains robust against Grover's algorithm.",
                "evidence_distinctions": "Perimeter findings are verified via live telemetry (OBSERVED), while internal HSM states are verified via configuration declarations.",
                "algorithm_migration": "Target ML-KEM-768 for key encapsulation (FIPS 203) and ML-DSA-65 for digital signatures (FIPS 204).",
                "dependencies": "Requires TLS 1.3 client library upgrades and hardware HSM lattice acceleration.",
                "sequence": "Sequence key-exchange migration first (mitigating SNDL), followed by certificate authority and authentication signing keys."
            },
            "management_recommendations": {
                "prioritization_rationale": "Prioritization is driven by data retention lifetime: assets with data lifespans exceeding 7 years require immediate P0/P1 migration planning.",
                "migration_planning": "Establish a multi-year phased transition roadmap aligned with regulatory deadlines and vendor hardware refresh cycles.",
                "governance_and_validation": "Maintain continuous CBOM tracking and cryptographic hash verification to guarantee tamper-evident audit trails."
            },
            "advisory_disclaimer": "AI Advisory — Informational Explanation. The deterministic QuantumShield scanner is the sole authoritative assessment source."
        }
        return json.dumps(response)
