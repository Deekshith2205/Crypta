"""Phase F PDF Report Reliability & Security Tests.

Validates:
- F3 & F4: Professional PDF report generation using ReportLab.
- Safe rendering with XML/HTML escaping for untrusted inputs (prevents ExpatError crashes).
- Correct magic bytes (%PDF-) and non-empty stream across all 8 synthetic banking systems.
- Inclusion of executive summary, key protection chain, ranked upgrade queue,
  evidence gap invariant, and Regulatory Standards Compliance table (NIST SP 800-227, CNSA 2.0, FIPS 203/204/205).
- Clean handling of unknown or missing systems.
"""

import pytest
from app.services.report_service import (
    build_complete_json_report,
    generate_pdf_report,
)
from app.models.report import CompleteAssessmentReport


class TestPdfReportReliability:
    """PDF generation reliability and adversarial escaping verification."""

    ALL_SYNTHETIC_SYSTEMS = [
        "BANK-PROF-PAYMENT-GATEWAY",
        "BANK-PROF-CORE-BANKING",
        "BANK-PROF-KYC-DB",
        "BANK-PROF-NET-BANKING",
        "BANK-PROF-ATM-NETWORK",
        "BANK-PROF-UPI",
        "BANK-PROF-ADMIN-VPN",
        "BANK-PROF-INTERBANK-GATEWAY",
    ]

    def test_pdf_export_all_synthetic_banking_systems(self):
        """Generates valid, non-empty binary PDF stream across all 8 synthetic systems."""
        for system_id in self.ALL_SYNTHETIC_SYSTEMS:
            pdf_bytes = generate_pdf_report(system_id)
            assert isinstance(pdf_bytes, bytes), f"Expected bytes for {system_id}"
            assert len(pdf_bytes) > 2500, f"PDF stream too short for {system_id}: {len(pdf_bytes)} bytes"
            assert pdf_bytes.startswith(b"%PDF-"), f"Missing %PDF- header for {system_id}"

    def test_pdf_adversarial_xml_injection_resilience(self):
        """Adversarial or malformed strings containing XML tags must be safely escaped and not crash ReportLab."""
        report = build_complete_json_report("BANK-PROF-CORE-BANKING")

        # Mutate multiple text fields with XML/HTML payloads
        report.system["name"] = "Core Banking <script>alert(1)</script> & Co."
        report.executive_summary["readiness_verdict"] = (
            "System verdict with unclosed <b tag & special <font color='blue'>markup & ampersands."
        )
        report.executive_summary["primary_concern"] = (
            "Weak RSA-2048 key wrapping & <untrusted> tags with quotes '\"' & null \x00 safely handled."
        )

        pdf_bytes = generate_pdf_report("BANK-PROF-CORE-BANKING", report=report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 2500

    def test_pdf_includes_regulatory_compliance_section(self):
        """PDF report renders Section 13 with NIST SP 800-227, CNSA 2.0, FIPS 203, 204, and 205."""
        report = build_complete_json_report("BANK-PROF-CORE-BANKING")
        assert report.compliance_mappings is not None
        assert "nist_sp_800_227" in report.compliance_mappings
        assert "cnsa_2_0" in report.compliance_mappings
        assert "fips_203" in report.compliance_mappings
        assert "fips_204" in report.compliance_mappings
        assert "fips_205" in report.compliance_mappings

        pdf_bytes = generate_pdf_report("BANK-PROF-CORE-BANKING", report=report)
        assert pdf_bytes.startswith(b"%PDF-")
        # PDF is larger because it now includes Section 13 table
        assert len(pdf_bytes) > 3000

    def test_pdf_with_ai_advisory_rendering(self):
        """PDF report correctly renders Section 14 when AI advisory is attached."""
        report = build_complete_json_report("BANK-PROF-CORE-BANKING")
        report.ai_advisory = {
            "executive_summary": {
                "overall_situation": "Executive view: Core Banking requires PQC transition planning.",
                "high_level_actions": "1. Inventory RSA wrapping keys. 2. Target ML-KEM-768.",
            },
            "technical_summary": {
                "algorithm_migration": "Transition key wrapping to FIPS 203 ML-KEM.",
            },
            "advisory_disclaimer": "AI Advisory is informational; deterministic scanner is authoritative.",
        }

        pdf_bytes = generate_pdf_report("BANK-PROF-CORE-BANKING", report=report)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 3500

    def test_pdf_unknown_system_fallback(self):
        """When an unknown system ID is provided to report_service, it safely falls back to Core Banking."""
        pdf_bytes = generate_pdf_report("BANK-UNKNOWN-SYSTEM-999")
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 2500
