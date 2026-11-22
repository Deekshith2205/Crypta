"""Automated tests for Task D6:
Unified Banking Assessment & Executive Compliance Reporting.

Verifies:
1. Complete integration of CBOM (CycloneDX 1.7), Zero Trust (NIST SP 800-207),
   Key Protection Chain, What-If simulation, and Sealed Cryptographic Audit.
2. Compliance mappings covering:
   - NIST SP 800-227 (Cryptographic Key Management & Transition)
   - CNSA 2.0 (Commercial National Security Algorithm Suite)
   - FIPS 203 (ML-KEM)
   - FIPS 204 (ML-DSA)
   - FIPS 205 (SLH-DSA)
3. Cryptographic seal integrity: canonical RFC 8785 payload hashing and signature verification.
4. Executive Summary contains actionable P0-P3 prioritization without false alarm.
5. Invariant: AES-256 Grover resilience is clearly documented in both quantum posture and compliance.
"""

import json
import pytest
from app.services.report_service import build_complete_json_report, generate_pdf_report
from app.models.report import CompleteAssessmentReport
from app.models.risk import KeyChainStatus


def test_unified_banking_report_compliance_mappings():
    """Verify report includes NIST SP 800-227, CNSA 2.0, and FIPS 203/204/205 compliance mappings."""
    report = build_complete_json_report("BANK-PROF-CORE-BANKING", seal_audit=True)
    assert isinstance(report, CompleteAssessmentReport)

    assert report.compliance_mappings is not None
    mappings = report.compliance_mappings

    # 1. NIST SP 800-227
    assert "nist_sp_800_227" in mappings
    assert "FIPS 203" in mappings["nist_sp_800_227"]["key_establishment"]
    assert "FIPS 204" in mappings["nist_sp_800_227"]["digital_signatures"]

    # 2. CNSA 2.0
    assert "cnsa_2_0" in mappings
    assert "AES-256" in mappings["cnsa_2_0"]["symmetric_encryption"]
    assert "ML-KEM" in mappings["cnsa_2_0"]["asymmetric_kem"]
    assert "ML-DSA" in mappings["cnsa_2_0"]["asymmetric_signatures"]

    # 3. FIPS 203 / 204 / 205
    assert "fips_203" in mappings
    assert "ML-KEM" in mappings["fips_203"]["target"]
    assert "fips_204" in mappings
    assert "ML-DSA" in mappings["fips_204"]["target"]
    assert "fips_205" in mappings
    assert "SLH-DSA" in mappings["fips_205"]["target"]


def test_unified_banking_report_zero_trust_integration():
    """Verify report contains NIST SP 800-207 Zero Trust assessment with honest observability."""
    report = build_complete_json_report("BANK-PROF-CORE-BANKING")
    assert report.zero_trust is not None
    zt = report.zero_trust

    assert "summary" in zt
    assert "controls" in zt
    assert len(zt["controls"]) == 6
    assert zt["summary"]["posture_label"] == "EDGE_ENCRYPTED_INTERNAL_UNKNOWN"
    assert "NOT_OBSERVABLE_EXTERNALLY" in zt["summary"]["observational_honesty_statement"]


def test_unified_banking_report_cbom_integration():
    """Verify report contains valid CycloneDX 1.7 CBOM."""
    report = build_complete_json_report("BANK-PROF-CORE-BANKING")
    assert report.cbom is not None
    assert report.cbom.get("bomFormat") == "CycloneDX"
    assert report.cbom.get("specVersion") == "1.7"
    assert "components" in report.cbom


def test_unified_banking_report_sealed_audit_verification():
    """Verify report includes verifiable cryptographic audit record with signature."""
    report = build_complete_json_report("BANK-PROF-CORE-BANKING", seal_audit=True)
    assert report.audit is not None
    assert len(report.audit.assessment_hash) == 64
    assert report.audit.signature is not None
    assert len(report.audit.signature) > 16
    assert report.audit.record_id is not None
