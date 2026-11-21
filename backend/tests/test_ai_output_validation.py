import pytest
from unittest.mock import AsyncMock, patch

from app.ai.schemas import (
    FindingExplanationResponse,
    BankingRiskExplanationResponse,
    MigrationAdvisoryResponse,
    FindingExplanationRequest,
)
from app.ai.validation import validate_ai_explanation
from app.ai.service import QuantumReadinessAIService
from app.ai.providers.mock import MockAIProvider


class TestAiOutputTrustValidation:
    """Task D2 test suite for deterministic AI output trust validation."""

    def test_valid_finding_explanation_passes(self):
        valid_payload = FindingExplanationResponse(
            rule_id="TLS-1.3-KEX-RSA",
            meaning="RSA key exchange was observed in the TLS handshake.",
            why_it_matters="RSA key exchange does not provide forward secrecy and is vulnerable to harvest-now-decrypt-later attacks.",
            quantum_relevance="Shor's algorithm can factor RSA integers in polynomial time, breaking RSA key exchange.",
            crypto_component="Key Exchange",
            what_evidence_establishes="The scanner observed TLS cipher suites utilizing RSA key transport.",
            what_evidence_does_not_establish="This evidence does not establish private key compromise.",
            banking_impact="Confidentiality of customer transaction data is exposed to future quantum decryption.",
            remediation="Transition to hybrid key exchange incorporating NIST FIPS 203 (ML-KEM).",
            migration_considerations="Update TLS cipher suites to support ML-KEM-768.",
            standards_guidance="Aligned with NIST FIPS 203 and NSA CNSA 2.0 timelines.",
        )
        context = {
            "evidence_status": "OBSERVED",
            "severity": "HIGH",
        }
        res = validate_ai_explanation(valid_payload, context)
        assert res.is_valid is True
        assert len(res.violations) == 0

    def test_not_observable_contradiction_rejected(self):
        bad_payload = FindingExplanationResponse(
            rule_id="CERT-INTERNAL-RSA",
            meaning="Internal certificate status could not be verified directly.",
            why_it_matters="The system is confirmed vulnerable to active quantum attacks.",
            quantum_relevance="Vulnerable to Shor's algorithm.",
            crypto_component="Digital Signature",
            what_evidence_establishes="Internal certificates were not directly observable.",
            what_evidence_does_not_establish="Evidence indicates an actively vulnerable endpoint.",
            banking_impact="Severe risk.",
            remediation="Remediate confirmed security flaw immediately.",
            migration_considerations="None.",
            standards_guidance="NIST FIPS 204.",
        )
        context = {
            "evidence_status": "NOT_OBSERVABLE",
            "severity": "MEDIUM",
        }
        res = validate_ai_explanation(bad_payload, context)
        assert res.is_valid is False
        assert any("NOT_OBSERVABLE" in v for v in res.violations)

    def test_not_observable_correct_framing_passes(self):
        good_payload = FindingExplanationResponse(
            rule_id="CERT-INTERNAL-RSA",
            meaning="Internal certificate configuration was not observable from external scanning.",
            why_it_matters="Observability gaps must be verified internally to determine posture.",
            quantum_relevance="If classical algorithms are in use internally, they will require migration.",
            crypto_component="Digital Signature",
            what_evidence_establishes="External scanner cannot access internal boundary assets.",
            what_evidence_does_not_establish="Not observable does not mean vulnerable. No compromise is established.",
            banking_impact="Internal verification required for complete regulatory audit.",
            remediation="Conduct internal credential audit.",
            migration_considerations="Align with FIPS 204.",
            standards_guidance="NIST FIPS 204 (ML-DSA).",
        )
        context = {
            "evidence_status": "NOT_OBSERVABLE",
            "severity": "MEDIUM",
        }
        res = validate_ai_explanation(good_payload, context)
        assert res.is_valid is True
        assert len(res.violations) == 0

    def test_aes256_shors_algorithm_claim_rejected(self):
        bad_payload = FindingExplanationResponse(
            rule_id="ENC-AES-256",
            meaning="AES-256 encryption observed.",
            why_it_matters="Data is encrypted at rest.",
            quantum_relevance="AES-256 is broken by Shor's algorithm and must be replaced immediately.",
            crypto_component="Data Encryption",
            what_evidence_establishes="AES-256 is configured.",
            what_evidence_does_not_establish="Nothing.",
            banking_impact="Potential breach.",
            remediation="Replace AES-256 with a post-quantum cipher.",
            migration_considerations="HSM update.",
            standards_guidance="NIST FIPS 203.",
        )
        res = validate_ai_explanation(bad_payload, {"severity": "LOW"})
        assert res.is_valid is False
        assert any("AES-256" in v for v in res.violations)

    def test_aes256_grovers_correct_explanation_passes(self):
        good_payload = FindingExplanationResponse(
            rule_id="ENC-AES-256",
            meaning="AES-256 symmetric cipher observed.",
            why_it_matters="AES-256 provides strong cryptographic protection.",
            quantum_relevance="Under Grover's algorithm, brute-force search space is halved to 128 bits of quantum security, which remains cryptographically secure.",
            crypto_component="Data Encryption",
            what_evidence_establishes="AES-256 is in use.",
            what_evidence_does_not_establish="No vulnerability exists.",
            banking_impact="Meets banking standards.",
            remediation="No replacement required; AES-256 remains approved for quantum resilience.",
            migration_considerations="Maintain current symmetric key lengths.",
            standards_guidance="NIST FIPS 197.",
        )
        res = validate_ai_explanation(good_payload, {"severity": "LOW"})
        assert res.is_valid is True
        assert len(res.violations) == 0

    def test_hallucinated_fips_standard_rejected(self):
        bad_payload = FindingExplanationResponse(
            rule_id="TLS-1.3-KEX",
            meaning="Key exchange mechanism.",
            why_it_matters="Forward secrecy.",
            quantum_relevance="Vulnerable to quantum attack.",
            crypto_component="Key Exchange",
            what_evidence_establishes="Observed TLS parameters.",
            what_evidence_does_not_establish="None.",
            banking_impact="Risk.",
            remediation="Migrate according to NIST FIPS 999 and FIPS 777 recommendations.",
            migration_considerations="None.",
            standards_guidance="Refer to FIPS 999.",
        )
        res = validate_ai_explanation(bad_payload)
        assert res.is_valid is False
        assert any("FIPS 999" in v for v in res.violations)

    def test_severity_override_attempt_rejected(self):
        override_payload = FindingExplanationResponse(
            rule_id="TLS-1.2-ECDHE",
            meaning="ECDHE key exchange.",
            why_it_matters="The scanner marked this as MEDIUM, but actual severity should be CRITICAL due to threat profile.",
            quantum_relevance="ECDHE is broken by Shor's algorithm.",
            crypto_component="Key Exchange",
            what_evidence_establishes="ECDHE curves.",
            what_evidence_does_not_establish="None.",
            banking_impact="Impact.",
            remediation="Remediate.",
            migration_considerations="None.",
            standards_guidance="NIST FIPS 203.",
        )
        context = {"severity": "MEDIUM"}
        res = validate_ai_explanation(override_payload, context)
        assert res.is_valid is False
        assert any("severity" in v for v in res.violations)

    def test_fabricated_financial_costs_rejected(self):
        cost_payload = MigrationAdvisoryResponse(
            system_id="SYS-CORE-01",
            system_name="Core Banking Gateway",
            migration_justification="PQC transition needed.",
            target_cryptographic_roles=["Key Exchange"],
            pqc_direction="ML-KEM",
            operational_impact_assessment="The estimated financial cost is $1,250,000 for HSM upgrades.",
            interoperability_and_testing="Test in staging.",
            suggested_migration_phases=["Phase 1: Inventory"],
            pre_deployment_validation_steps=["Verify ML-KEM"],
        )
        res = validate_ai_explanation(cost_payload, {"disallow_financial_fabrication": True})
        assert res.is_valid is False
        assert any("dollar figures" in v or "financial" in v for v in res.violations)

    @pytest.mark.asyncio
    async def test_service_rejects_untrustworthy_output(self):
        """End-to-end: QuantumReadinessAIService rejects AI response that fails validation."""
        service = QuantumReadinessAIService(provider=MockAIProvider())

        # Mock provider returning output claiming AES-256 is broken by Shor's
        untrusted_json = (
            '{\n'
            '  "rule_id": "TEST-RULE",\n'
            '  "meaning": "Test meaning",\n'
            '  "why_it_matters": "Test why it matters",\n'
            '  "quantum_relevance": "AES-256 is broken by Shor\'s algorithm",\n'
            '  "crypto_component": "Test component",\n'
            '  "what_evidence_establishes": "Test evidence",\n'
            '  "what_evidence_does_not_establish": "Test not establish",\n'
            '  "banking_impact": "Test impact",\n'
            '  "remediation": "Test remediation",\n'
            '  "migration_considerations": "Test considerations",\n'
            '  "standards_guidance": "NIST FIPS 203",\n'
            '  "advisory_disclaimer": "AI Advisory"\n'
            '}'
        )

        with patch.object(service._provider, "generate", new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = untrusted_json

            req = FindingExplanationRequest(
                rule_id="TEST-RULE",
                title="Test Finding",
                value="AES-256",
                role="DATA_ENCRYPTION",
                source="CONFIG",
                evidence_status="OBSERVED",
                severity="LOW",
                risk="QUANTUM",
            )
            result = await service.explain_finding(req)

            assert result.success is False
            assert "deterministic trust validation" in result.error
            assert result.data is None
