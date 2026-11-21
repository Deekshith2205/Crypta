import pytest
from unittest.mock import AsyncMock, patch

from app.ai.fallback import DeterministicExplanationService, FALLBACK_PROVIDER_NAME
from app.ai.service import QuantumReadinessAIService
from app.ai.providers.none import NoneAIProvider
from app.ai.providers.mock import MockAIProvider
from app.ai.providers.base import (
    AIProviderTimeoutError,
    AIProviderRateLimitError,
)
from app.ai.schemas import (
    FindingExplanationRequest,
    BankingRiskExplanationRequest,
    MigrationAdvisoryRequest,
    ReportExplanationRequest,
)


class TestDeterministicExplanationFallback:
    """Task D3 test suite for deterministic explanation fallback engine."""

    def test_fallback_finding_explanation_rsa(self):
        req = FindingExplanationRequest(
            rule_id="TLS-1.2-RSA-KEX",
            title="RSA Key Exchange in TLS",
            value="RSA-2048",
            role="KEY_EXCHANGE",
            source="EXTERNAL_SCAN",
            evidence_status="OBSERVED",
            severity="HIGH",
            risk="QUANTUM",
        )
        res = DeterministicExplanationService.explain_finding(req)
        assert res.success is True
        assert res.provider == FALLBACK_PROVIDER_NAME
        data = res.data
        assert data.rule_id == "TLS-1.2-RSA-KEX"
        assert "Shor's" in data.quantum_relevance
        assert "FIPS 203" in data.remediation or "ML-KEM" in data.remediation
        assert "AI Advisory" in data.advisory_disclaimer

    def test_fallback_finding_explanation_aes256_invariant(self):
        req = FindingExplanationRequest(
            rule_id="CIPHER-AES-256",
            title="AES-256-GCM Bulk Encryption",
            value="AES-256-GCM",
            role="DATA_ENCRYPTION",
            source="CONFIG",
            evidence_status="OBSERVED",
            severity="LOW",
            risk="QUANTUM",
        )
        res = DeterministicExplanationService.explain_finding(req)
        assert res.success is True
        assert res.provider == FALLBACK_PROVIDER_NAME
        data = res.data
        assert "Grover" in data.quantum_relevance
        assert "128 bits" in data.quantum_relevance
        assert "no replacement required" in data.remediation.lower() or "retain aes-256" in data.remediation.lower()

    def test_fallback_finding_explanation_not_observable_invariant(self):
        req = FindingExplanationRequest(
            rule_id="HSM-FIRMWARE-CHECK",
            title="HSM Firmware PQC Readiness",
            value="UNVERIFIED",
            role="KEY_STORAGE",
            source="CONFIG",
            evidence_status="NOT_OBSERVABLE",
            severity="MEDIUM",
            risk="QUANTUM",
        )
        res = DeterministicExplanationService.explain_finding(req)
        assert res.success is True
        data = res.data
        assert "does not establish vulnerability" in data.what_evidence_does_not_establish.lower()

    def test_fallback_banking_risk_explanation(self):
        req = BankingRiskExplanationRequest(
            system_id="SYS-CORE-001",
            system_name="Core Payments Hub",
            priority_score=85,
            priority_band="P0",
            exposure="EXTERNAL",
            criticality="TIER_1",
            top_findings=["RSA-2048 in payment gateway", "Missing PQC agility"],
            weak_links=["Gateway-TLS-KEX"],
        )
        res = DeterministicExplanationService.explain_banking_risk(req)
        assert res.success is True
        assert res.provider == FALLBACK_PROVIDER_NAME
        data = res.data
        assert data.system_id == "SYS-CORE-001"
        assert "85/100" in data.score_rationale
        assert "P0" in data.score_rationale
        assert len(data.contributing_factors) >= 4

    def test_fallback_migration_advisory(self):
        req = MigrationAdvisoryRequest(
            system_id="SYS-CORE-001",
            system_name="Core Payments Hub",
            baseline_priority_score=85,
            baseline_priority_band="P0",
            migration_impact="HIGH",
        )
        res = DeterministicExplanationService.advise_migration(req)
        assert res.success is True
        assert res.provider == FALLBACK_PROVIDER_NAME
        data = res.data
        assert "ML-KEM" in data.pqc_direction
        assert len(data.suggested_migration_phases) >= 3
        assert len(data.pre_deployment_validation_steps) >= 3

    def test_fallback_report_explanation(self):
        res = DeterministicExplanationService.explain_report("SYS-CORE-001")
        assert res.success is True
        assert res.provider == FALLBACK_PROVIDER_NAME
        data = res.data
        assert data.system_id == "SYS-CORE-001"
        assert "overall_situation" in data.executive_summary
        assert "algorithm_migration" in data.technical_summary
        assert "prioritization_rationale" in data.management_recommendations

    @pytest.mark.asyncio
    async def test_service_engages_fallback_when_provider_unconfigured(self):
        """When AI provider is none, fallback=True returns expert explanation instead of failing."""
        service = QuantumReadinessAIService(
            provider=NoneAIProvider("Unconfigured test provider"),
            enable_fallback=True,
        )
        req = FindingExplanationRequest(
            rule_id="RULE-UNCONFIG",
            title="Unconfigured Test",
            value="RSA-2048",
            role="KEY_EXCHANGE",
            source="SCAN",
            evidence_status="OBSERVED",
            severity="HIGH",
            risk="QUANTUM",
        )
        res = await service.explain_finding(req)
        assert res.success is True
        assert res.provider == FALLBACK_PROVIDER_NAME
        assert res.data.rule_id == "RULE-UNCONFIG"

    @pytest.mark.asyncio
    async def test_service_engages_fallback_on_provider_timeout(self):
        """When provider times out, fallback=True returns expert explanation."""
        provider = MockAIProvider()
        provider.generate = AsyncMock(side_effect=AIProviderTimeoutError("Mock timeout"))
        service = QuantumReadinessAIService(provider=provider, enable_fallback=True)

        req = FindingExplanationRequest(
            rule_id="RULE-TIMEOUT",
            title="Timeout Test",
            value="ECDSA-P256",
            role="DIGITAL_SIGNATURE",
            source="SCAN",
            evidence_status="OBSERVED",
            severity="MEDIUM",
            risk="QUANTUM",
        )
        res = await service.explain_finding(req)
        assert res.success is True
        assert res.provider == FALLBACK_PROVIDER_NAME
        assert "Shor's" in res.data.quantum_relevance

    @pytest.mark.asyncio
    async def test_service_engages_fallback_on_validation_failure(self):
        """When AI outputs invalid/contradictory claims, fallback engages and replaces untrusted output."""
        provider = MockAIProvider()
        # Mock response that claims AES-256 is broken by Shor's (fails trust validation)
        invalid_json = (
            '{\n'
            '  "rule_id": "RULE-VALIDATION-FAIL",\n'
            '  "meaning": "Invalid",\n'
            '  "why_it_matters": "Invalid",\n'
            '  "quantum_relevance": "AES-256 is broken by Shor\'s algorithm",\n'
            '  "crypto_component": "Data Encryption",\n'
            '  "what_evidence_establishes": "None",\n'
            '  "what_evidence_does_not_establish": "None",\n'
            '  "banking_impact": "None",\n'
            '  "remediation": "None",\n'
            '  "migration_considerations": "None",\n'
            '  "standards_guidance": "FIPS 203",\n'
            '  "advisory_disclaimer": "AI Advisory"\n'
            '}'
        )
        provider.generate = AsyncMock(return_value=invalid_json)
        service = QuantumReadinessAIService(provider=provider, enable_fallback=True)

        req = FindingExplanationRequest(
            rule_id="RULE-VALIDATION-FAIL",
            title="Validation Failure Test",
            value="AES-256",
            role="DATA_ENCRYPTION",
            source="SCAN",
            evidence_status="OBSERVED",
            severity="LOW",
            risk="QUANTUM",
        )
        res = await service.explain_finding(req)
        # Trust validation failed, so fallback took over with truthful explanation
        assert res.success is True
        assert res.provider == FALLBACK_PROVIDER_NAME
        assert "128 bits" in res.data.quantum_relevance
