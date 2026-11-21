"""Deterministic Explanation Fallback Service (Task D3).

Generates expert-level cryptographic explanations directly from deterministic
findings and scan evidence without relying on external AI providers.

Engaged automatically when:
1. AI provider is unconfigured, disabled, or unavailable.
2. AI provider times out or encounters rate limits.
3. AI provider returns malformed or invalid JSON.
4. AI output fails deterministic trust validation.
"""

from typing import Any, Dict, List, Optional
from app.ai.schemas import (
    FindingExplanationRequest,
    FindingExplanationResponse,
    BankingRiskExplanationRequest,
    BankingRiskExplanationResponse,
    MigrationAdvisoryRequest,
    MigrationAdvisoryResponse,
    ReportExplanationRequest,
    ReportExplanationResponse,
    AIExplanationResult,
    DEFAULT_ADVISORY_DISCLAIMER,
)

FALLBACK_PROVIDER_NAME = "DETERMINISTIC_FALLBACK"


class DeterministicExplanationService:
    """Rule-based engine providing deterministic explanations for cryptographic telemetry."""

    @staticmethod
    def explain_finding(
        request: FindingExplanationRequest,
    ) -> AIExplanationResult[FindingExplanationResponse]:
        """Generates a rule-based technical explanation for an individual finding."""
        rule_id = request.rule_id
        val = (request.value or "").upper()
        role = (request.role or "").upper()
        status = (request.evidence_status or "").upper()
        severity = (request.severity or "").upper()
        risk = (request.risk or "").upper()

        is_unobservable = status == "NOT_OBSERVABLE"
        is_symmetric = "AES" in val or "CHACHA" in val or "3DES" in val or "DES" in val or role == "DATA_ENCRYPTION"
        is_hash = "SHA" in val or "MD5" in val or role == "HASH_FUNCTION"
        is_rsa = "RSA" in val or "PKCS" in val
        is_ecc = "ECDSA" in val or "ECDH" in val or "SECP" in val or "P-256" in val or "ED25519" in val

        # 1. Meaning & Component
        if is_unobservable:
            meaning = (
                f"The parameter '{request.value or request.title}' could not be directly observed "
                f"from external inspection of the endpoint or configuration."
            )
            what_establishes = "External scan reached the boundary but could not inspect internal cryptographic parameters."
            what_not_establishes = "NOT_OBSERVABLE does not establish vulnerability, nor does it confirm a security flaw."
        elif "AES-256" in val:
            meaning = "AES-256 symmetric block cipher in use for bulk data protection."
            what_establishes = f"Observed use of AES-256 in {request.source}."
            what_not_establishes = "Does not establish key lifecycle management or key storage security."
        elif is_rsa:
            meaning = f"RSA public-key algorithm ({val or 'classical'}) configured for {request.role}."
            what_establishes = f"Observed RSA parameters in {request.source}."
            what_not_establishes = "Does not establish whether private key material has been compromised."
        elif is_ecc:
            meaning = f"Elliptic-curve cryptography ({val or 'ECC'}) configured for {request.role}."
            what_establishes = f"Observed elliptic curve parameters in {request.source}."
            what_not_establishes = "Does not establish whether ephemeral session keys were retained."
        else:
            meaning = f"Cryptographic primitive '{request.value or request.title}' identified in {request.source}."
            what_establishes = f"Observed cryptographic evidence in {request.source}."
            what_not_establishes = "Does not establish unobserved internal key governance controls."

        # 2. Why it matters
        if is_unobservable:
            why_it_matters = "Observability gaps prevent complete risk verification and must be confirmed via internal telemetry."
        elif severity in ("CRITICAL", "HIGH"):
            why_it_matters = "High-priority cryptographic weakness exposes long-lived financial data to harvest-now-decrypt-later attacks."
        else:
            why_it_matters = "Cryptographic configurations must align with modernization timelines and regulatory requirements."

        # 3. Quantum Relevance
        if is_unobservable:
            quantum_relevance = "Quantum risk cannot be definitively evaluated without verifying the underlying algorithm."
        elif "AES-256" in val:
            quantum_relevance = (
                "Under Grover's algorithm, brute-force key search complexity is halved to 128 bits of security, "
                "which remains cryptographically secure against anticipated quantum computing capabilities."
            )
        elif is_rsa or is_ecc:
            quantum_relevance = (
                "Shor's algorithm solves integer factorization and discrete logarithms in polynomial time, "
                "completely breaking classical public-key algorithms once a Cryptanalytically Relevant Quantum Computer (CRQC) is realized."
            )
        elif "3DES" in val or "DES" in val:
            quantum_relevance = "Classically obsolete; Grover's algorithm further reduces effective key length to trivially broken levels."
        else:
            quantum_relevance = "Classical algorithms must be systematically evaluated against Shor's and Grover's threat models."

        # 4. Banking Impact
        if is_unobservable:
            banking_impact = "Internal compliance documentation and authenticated audits are needed to close reporting gaps."
        elif severity in ("CRITICAL", "HIGH"):
            banking_impact = "Interbank payment transactions, account privacy, and regulatory standing under central bank directives are exposed."
        else:
            banking_impact = "Routine operational impact requiring scheduled cryptographic agility updates."

        # 5. Remediation & Standards
        if is_unobservable:
            remediation = "Conduct an internal credential and configuration audit to confirm algorithm parameters."
            standards_guidance = "NIST SP 800-52r2 and NIST FIPS 140-3 observability guidelines."
            migration_considerations = "Verify asset inventory and enable telemetry logging."
        elif "AES-256" in val:
            remediation = "Retain AES-256; no replacement required for quantum readiness. Ensure authenticated modes (AES-GCM) are used."
            standards_guidance = "NIST FIPS 197 and NIST SP 800-38D."
            migration_considerations = "Verify hardware cryptographic acceleration and key rotation schedules."
        elif role == "KEY_EXCHANGE" or "KEX" in rule_id:
            remediation = "Upgrade to hybrid key exchange incorporating NIST FIPS 203 (ML-KEM-768 / Kyber)."
            standards_guidance = "NIST FIPS 203 and NSA CNSA 2.0."
            migration_considerations = "Account for 1,184-byte ciphertext expansion in TLS ClientHello and MTU sizing."
        elif role == "DIGITAL_SIGNATURE" or "CERT" in rule_id or "SIG" in rule_id:
            remediation = "Transition to post-quantum digital signatures: NIST FIPS 204 (ML-DSA) or NIST FIPS 205 (SLH-DSA)."
            standards_guidance = "NIST FIPS 204, NIST FIPS 205, and NSA CNSA 2.0."
            migration_considerations = "Update PKI trust stores, HSM firmware, and X.509 certificate parsing libraries."
        else:
            remediation = request.recommendation or "Upgrade cryptographic primitives in accordance with NIST Post-Quantum standards."
            standards_guidance = "NIST FIPS 203/204/205."
            migration_considerations = "Test interoperability in staging prior to production deployment."

        data = FindingExplanationResponse(
            rule_id=rule_id,
            meaning=meaning,
            why_it_matters=why_it_matters,
            quantum_relevance=quantum_relevance,
            crypto_component=request.role or "Cryptographic Primitive",
            what_evidence_establishes=what_establishes,
            what_evidence_does_not_establish=what_not_establishes,
            banking_impact=banking_impact,
            remediation=remediation,
            migration_considerations=migration_considerations,
            standards_guidance=standards_guidance,
            advisory_disclaimer=DEFAULT_ADVISORY_DISCLAIMER,
        )

        return AIExplanationResult[FindingExplanationResponse](
            success=True,
            is_available=True,
            provider=FALLBACK_PROVIDER_NAME,
            data=data,
            error=None,
            disclaimer=DEFAULT_ADVISORY_DISCLAIMER,
        )

    @staticmethod
    def explain_banking_risk(
        request: BankingRiskExplanationRequest,
    ) -> AIExplanationResult[BankingRiskExplanationResponse]:
        """Generates a rule-based explanation for banking system risk posture and ranking."""
        system_name = request.system_name or request.system_id
        score = request.priority_score
        band = request.priority_band

        score_rationale = (
            f"Banking system '{system_name}' received a deterministic priority score of {score}/100 "
            f"(Priority Band {band}). The score reflects weighted cryptographic vulnerabilities, "
            f"network exposure ({request.exposure or 'INTERNAL'}), data sensitivity ({request.data_sensitivity or 'HIGH'}), "
            f"and data retention horizon ({request.data_lifetime or 'STANDARD'})."
        )

        contributing_factors = [
            f"Deterministic priority score: {score}/100 in Priority Band {band}.",
            f"Network exposure tier: {request.exposure or 'INTERNAL'}.",
            f"Business criticality tier: {request.criticality or 'TIER_1'}.",
            f"Identified weak links: {len(request.weak_links)} component(s) identified.",
        ]
        if request.top_findings:
            contributing_factors.extend([f"Key finding: {f}" for f in request.top_findings[:3]])

        severity_weighting = (
            "Cryptographic algorithms vulnerable to Shor's algorithm (RSA, ECC key exchange) receive higher "
            "weighting when protecting long-lived financial data due to harvest-now-decrypt-later (SNDL) exposure. "
            "Symmetric ciphers (AES-256) and unobservable evidence items are not penalized as active vulnerabilities."
        )

        queue_reason = (
            f"Queue placement in band {band} is mathematically derived from the composite priority score ({score}). "
            f"Systems with higher scores present greater SNDL exposure and must be scheduled earlier in the migration roadmap."
        )

        supporting_evidence = [
            f"Verified findings: {len(request.top_findings)} finding(s) cataloged.",
            f"Cryptographic key chain weak links: {', '.join(request.weak_links) if request.weak_links else 'None identified'}.",
        ]

        evidence_gaps = request.evidence_gaps or [
            "Internal HSM firmware versions require authenticated verification.",
            "Service-to-service internal mTLS configurations require boundary inspection.",
        ]

        data = BankingRiskExplanationResponse(
            system_id=request.system_id,
            system_name=request.system_name,
            score_rationale=score_rationale,
            contributing_factors=contributing_factors,
            severity_weighting_explanation=severity_weighting,
            upgrade_queue_position_reason=queue_reason,
            supporting_evidence=supporting_evidence,
            evidence_gaps_needed=evidence_gaps,
            advisory_disclaimer=DEFAULT_ADVISORY_DISCLAIMER,
        )

        return AIExplanationResult[BankingRiskExplanationResponse](
            success=True,
            is_available=True,
            provider=FALLBACK_PROVIDER_NAME,
            data=data,
            error=None,
            disclaimer=DEFAULT_ADVISORY_DISCLAIMER,
        )

    @staticmethod
    def advise_migration(
        request: MigrationAdvisoryRequest,
    ) -> AIExplanationResult[MigrationAdvisoryResponse]:
        """Generates a rule-based post-quantum migration advisory."""
        system_name = request.system_name or request.system_id
        score = request.baseline_priority_score
        band = request.baseline_priority_band

        justification = (
            f"System '{system_name}' currently operates with baseline priority score {score} ({band}). "
            f"Migration is necessary to eliminate harvest-now-decrypt-later vulnerability and comply with "
            f"regulatory post-quantum mandates."
        )

        target_roles = [
            "Key Encapsulation / Exchange (TLS sessions and data in transit)",
            "Digital Signatures (PKI credentials, code signing, and transaction authorization)",
        ]

        pqc_direction = (
            "Adopt NIST FIPS 203 (ML-KEM) for key exchange mechanisms and NIST FIPS 204 (ML-DSA) "
            "or NIST FIPS 205 (SLH-DSA) for digital signature validation, conforming to NSA CNSA 2.0 timelines."
        )

        operational_impact = (
            f"Migration impact is assessed as {request.migration_impact or 'MEDIUM'}. Increased public key and "
            f"ciphertext sizes (e.g. ML-KEM-768 ciphertext: 1,088 bytes) require verifying network MTU sizes, "
            f"TLS fragmentation handling, and hardware security module (HSM) memory capacity."
        )

        interop_guidance = (
            "Deploy hybrid key exchange modes (e.g., X25519 + ML-KEM-768) during the transition period. "
            "Hybrid combinations preserve classical security compliance (FIPS 140-3) while providing immediate "
            "quantum resistance against eavesdropping."
        )

        phases = [
            "Phase 1: Cryptographic Inventory & Dependency Discovery — catalog all libraries, certificates, and HSM firmware.",
            "Phase 2: Hybrid Key Exchange Pilot — enable hybrid PQC on non-critical ingress endpoints and validate latency.",
            "Phase 3: Digital Signature & PKI Upgrade — issue dual-certificate hierarchies and transition internal root CAs.",
            "Phase 4: Full PQC Enforcement & Classical Decommissioning — enforce pure FIPS 203/204 suites and retire legacy ciphers.",
        ]

        validation_steps = [
            "Validate MTU and TCP packet fragmentation under peak transaction throughput.",
            "Benchmark TLS handshake latency overhead in staging environments.",
            "Verify HSM firmware compatibility with FIPS 203 / FIPS 204 algorithms.",
            "Perform automated rollback drills to ensure high availability during migration.",
        ]

        data = MigrationAdvisoryResponse(
            system_id=request.system_id,
            system_name=request.system_name,
            migration_justification=justification,
            target_cryptographic_roles=target_roles,
            pqc_direction=pqc_direction,
            operational_impact_assessment=operational_impact,
            interoperability_and_testing=interop_guidance,
            suggested_migration_phases=phases,
            pre_deployment_validation_steps=validation_steps,
            advisory_disclaimer=DEFAULT_ADVISORY_DISCLAIMER,
        )

        return AIExplanationResult[MigrationAdvisoryResponse](
            success=True,
            is_available=True,
            provider=FALLBACK_PROVIDER_NAME,
            data=data,
            error=None,
            disclaimer=DEFAULT_ADVISORY_DISCLAIMER,
        )

    @staticmethod
    def explain_report(
        system_id: str,
    ) -> AIExplanationResult[ReportExplanationResponse]:
        """Generates a rule-based executive and technical report narrative."""
        data = ReportExplanationResponse(
            system_id=system_id,
            executive_summary={
                "overall_situation": f"Assessment for system '{system_id}' reveals cryptographic transition requirements under post-quantum standards.",
                "primary_risks": "Classical public-key exchange algorithms (RSA, ECC) are vulnerable to harvest-now-decrypt-later attacks.",
                "critical_assets": f"Core boundary interfaces and cryptographic storage endpoints associated with {system_id}.",
                "high_level_actions": "Initiate hybrid PQC key exchange pilots and inventory internal cryptographic assets.",
            },
            technical_summary={
                "cryptographic_findings": "Identified public-key mechanisms requiring transition to NIST FIPS 203 and FIPS 204 standards.",
                "evidence_distinctions": "Distinguished confirmed cryptographic telemetry from unobservable internal credentials (NOT_OBSERVABLE != VULNERABLE).",
                "algorithm_migration": "Prioritized transition paths to ML-KEM-768 for transport and ML-DSA-65 for authentication.",
                "dependencies": "Evaluated HSM firmware, TLS termination proxies, and interbank gateway integrations.",
                "sequence": "Phase 1: Hybrid KEM -> Phase 2: Dual PKI -> Phase 3: Pure PQC cutover.",
            },
            management_recommendations={
                "prioritization_rationale": "Resource allocation follows deterministic risk scores and financial data retention horizons.",
                "migration_planning": "Multi-year phased modernization aligned with national post-quantum timelines.",
                "governance_and_validation": "Continuous cryptographic posture scanning and tamper-evident audit trail verification.",
            },
            advisory_disclaimer=DEFAULT_ADVISORY_DISCLAIMER,
        )

        return AIExplanationResult[ReportExplanationResponse](
            success=True,
            is_available=True,
            provider=FALLBACK_PROVIDER_NAME,
            data=data,
            error=None,
            disclaimer=DEFAULT_ADVISORY_DISCLAIMER,
        )
