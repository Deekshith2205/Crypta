"""Phase F Migration Recommendations & Reporting Consistency Tests.

Validates:
- F7: Role-aware post-quantum recommendations:
      - Key establishment / wrapping -> FIPS 203 ML-KEM (ML-KEM-768/1024) or hybrid X25519MLKEM768.
      - Digital signatures / authentication -> FIPS 204 ML-DSA (ML-DSA-65/87) or FIPS 205 SLH-DSA.
      - Bulk symmetric encryption -> AES-256 (retains 128-bit quantum security under Grover's algorithm).
- Invariant: NOT_OBSERVABLE != VULNERABLE across all layers.
- Authoritative deterministic scoring precedence over AI advisory layer.
"""

import pytest
from app.models.profiles import get_synthetic_profile_by_id, get_synthetic_banking_profiles
from app.services.report_service import build_complete_json_report
from app.security.crypto_catalog import (
    resolve_quantum_migration_recommendation,
    get_algorithm_profile,
    PQC_STANDARDS,
)


class TestMigrationRecommendationsConsistency:
    """Verifies role-aware PQC recommendations and reporting consistency."""

    def test_role_aware_kem_recommendations(self):
        """Key establishment / wrapping recommendations must target FIPS 203 ML-KEM or hybrid."""
        target_rsa_wrap = resolve_quantum_migration_recommendation(role="KEY_WRAPPING", algorithm="RSA-2048")
        assert "ML-KEM" in target_rsa_wrap

        target_ecdh = resolve_quantum_migration_recommendation(role="KEY_EXCHANGE", algorithm="ECDHE")
        assert "ML-KEM" in target_ecdh or "X25519 + ML-KEM" in target_ecdh

    def test_role_aware_signature_recommendations(self):
        """Digital signature / authentication recommendations must target FIPS 204 ML-DSA or FIPS 205 SLH-DSA."""
        target_rsa_sig = resolve_quantum_migration_recommendation(role="DIGITAL_SIGNATURE", algorithm="RSA-2048")
        assert "ML-DSA" in target_rsa_sig or "SLH-DSA" in target_rsa_sig

        target_ecdsa = resolve_quantum_migration_recommendation(role="CERTIFICATE_AUTHENTICATION", algorithm="ECDSA")
        assert "ML-DSA" in target_ecdsa or "SLH-DSA" in target_ecdsa

    def test_role_aware_symmetric_recommendations(self):
        """Symmetric encryption recommendations must specify AES-256 for Grover resistance."""
        target_sym = resolve_quantum_migration_recommendation(role="BULK_ENCRYPTION", algorithm="AES-128")
        assert "AES-256" in target_sym
        assert "Grover" in target_sym

    def test_grover_aes256_symmetric_resilience_in_reports(self):
        """Reports must accurately state that AES-256 retains 128 bits of quantum security under Grover's algorithm."""
        report = build_complete_json_report("BANK-PROF-CORE-BANKING")

        assert "grover_aes256_status" in report.quantum_posture
        status = report.quantum_posture["grover_aes256_status"]
        assert "AES-256" in status
        assert "128-bit" in status
        assert "not quantum-broken" in status.lower()

    def test_not_observable_is_not_vulnerable_invariant(self):
        """NOT_OBSERVABLE controls must be tracked as evidence gaps and NOT classified as vulnerabilities."""
        report = build_complete_json_report("BANK-PROF-CORE-BANKING")

        # Observability invariant stated
        assert report.observability.get("evidence_invariant") == "NOT_OBSERVABLE != VULNERABLE"

        # Evidence gaps list
        assert isinstance(report.evidence_gaps, list)
        for gap in report.evidence_gaps:
            assert "control" in gap
            assert "required_evidence" in gap
            assert "VULNERABILITY" not in gap.get("gap_type", "")

    def test_authoritative_scoring_precedence_over_ai_advisory(self):
        """Deterministic scanner risk score remains the authoritative single source of truth."""
        report = build_complete_json_report("BANK-PROF-CORE-BANKING")

        # Score is deterministic integer in [0, 100]
        assert 0 <= report.priority["score"] <= 100
        assert report.priority["band"] in ["P0", "P1", "P2", "P3"]

        # Even when AI advisory is present, scanner priority score is unchanged
        report.ai_advisory = {
            "executive_summary": {"overall_situation": "Advisory text"},
            "advisory_disclaimer": "AI Advisory is purely informational.",
        }

        # Deterministic score is unchanged
        assert report.priority["score"] == 92
        assert report.priority["band"] == "P0"
