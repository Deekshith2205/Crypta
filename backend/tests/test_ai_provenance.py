import pytest
from app.ai.provenance import (
    canonicalize_evidence,
    compute_evidence_hash,
    bind_provenance_metadata,
    verify_explanation_provenance,
)
from app.ai.schemas import (
    FindingExplanationRequest,
    FindingExplanationResponse,
    BankingRiskExplanationRequest,
)
from app.ai.service import QuantumReadinessAIService
from app.ai.providers.mock import MockAIProvider
from app.ai.fallback import DeterministicExplanationService
from app.ai.budget import AI_BUDGET_TRACKER


class TestAiEvidenceProvenance:
    """Task D5 test suite for evidence provenance, canonical hashing, and traceability."""

    def setup_method(self):
        AI_BUDGET_TRACKER.reset()

    def test_canonicalize_evidence_key_order_invariant(self):
        dict_a = {"z_rule": "TLS-1.3", "a_role": "KEY_EXCHANGE", "nested": {"b": 2, "a": 1}}
        dict_b = {"a_role": "KEY_EXCHANGE", "z_rule": "TLS-1.3", "nested": {"a": 1, "b": 2}}

        bytes_a = canonicalize_evidence(dict_a)
        bytes_b = canonicalize_evidence(dict_b)

        assert bytes_a == bytes_b
        assert compute_evidence_hash(dict_a) == compute_evidence_hash(dict_b)

    def test_hash_changes_on_any_input_mutation(self):
        original = {"rule_id": "TLS-RSA", "severity": "HIGH", "observed": "RSA-2048"}
        mutated = {"rule_id": "TLS-RSA", "severity": "MEDIUM", "observed": "RSA-2048"}

        hash_orig = compute_evidence_hash(original)
        hash_mut = compute_evidence_hash(mutated)

        assert len(hash_orig) == 64
        assert len(hash_mut) == 64
        assert hash_orig != hash_mut

    def test_bind_provenance_metadata_to_model(self):
        input_data = {
            "rule_id": "CERT-EXPIRED",
            "evidence_status": "OBSERVED",
            "severity": "CRITICAL",
        }
        res_model = FindingExplanationResponse(
            rule_id="CERT-EXPIRED",
            meaning="Certificate has expired.",
            why_it_matters="TLS connections will fail.",
            quantum_relevance="Classical flaw.",
            crypto_component="Digital Signature",
            what_evidence_establishes="Observed validity dates.",
            what_evidence_does_not_establish="None.",
            banking_impact="Downtime.",
            remediation="Renew certificate.",
            migration_considerations="Transition to ML-DSA.",
            standards_guidance="NIST FIPS 204.",
        )

        assert res_model.evidence_hash is None
        bind_provenance_metadata(res_model, input_data)

        assert res_model.evidence_hash == compute_evidence_hash(input_data)
        assert res_model.evidence_status == "OBSERVED"
        assert res_model.generated_at is not None
        assert res_model.provenance_verified is True

    def test_verify_provenance_passes_for_untampered_evidence(self):
        req = FindingExplanationRequest(
            rule_id="TEST-PROVENANCE",
            title="Provenance Test",
            value="RSA-4096",
            role="KEY_EXCHANGE",
            source="CONFIG",
            evidence_status="OBSERVED",
            severity="HIGH",
            risk="QUANTUM",
        )
        res = DeterministicExplanationService.explain_finding(req)
        assert res.data.evidence_hash is not None

        # Verify against authentic request
        is_valid, error = verify_explanation_provenance(res.data, req)
        assert is_valid is True
        assert error is None

    def test_verify_provenance_fails_when_evidence_tampered(self):
        req = FindingExplanationRequest(
            rule_id="TEST-TAMPER",
            title="Tamper Test",
            value="RSA-2048",
            role="KEY_EXCHANGE",
            source="CONFIG",
            evidence_status="OBSERVED",
            severity="HIGH",
            risk="QUANTUM",
        )
        res = DeterministicExplanationService.explain_finding(req)

        # Attacker tries to attach this explanation to a different finding
        tampered_req = req.model_copy(update={"value": "ECDSA-P256", "severity": "LOW"})

        is_valid, error = verify_explanation_provenance(res.data, tampered_req)
        assert is_valid is False
        assert "Provenance hash mismatch" in error

    @pytest.mark.asyncio
    async def test_service_attaches_evidence_hash_and_provenance(self):
        service = QuantumReadinessAIService(provider=MockAIProvider())
        req = FindingExplanationRequest(
            rule_id="TEST-SERVICE-PROVENANCE",
            title="Service Provenance Test",
            value="ML-KEM-768",
            role="KEY_EXCHANGE",
            source="EXTERNAL_SCAN",
            evidence_status="OBSERVED",
            severity="LOW",
            risk="QUANTUM",
        )

        result = await service.explain_finding(req)
        assert result.success is True
        assert result.evidence_hash is not None
        assert result.data.evidence_hash == result.evidence_hash
        assert result.data.evidence_status == "OBSERVED"
        assert result.data.provenance_verified is True

        # Verify provenance
        is_valid, error = verify_explanation_provenance(result.data, req.model_dump())
        assert is_valid is True
        assert error is None
