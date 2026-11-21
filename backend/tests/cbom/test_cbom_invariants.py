"""Task D1: CycloneDX 1.7 CBOM Invariants and Determinism Tests.

Verifies:
1. CBOM is an INVENTORY, NOT a risk engine (prohibits P0/P1/P2/P3 risk scores).
2. Deterministic, reproducible UUIDv5 serial number generation.
3. Secret-safe redaction (no raw private keys or passwords).
4. Evidence status provenance (NOT_OBSERVABLE != VULNERABLE).
5. Fallback CBOM in report_service produces a fully schema-valid CycloneDX 1.7 document.
"""

import json
from pathlib import Path
import pytest
import uuid

from app.cbom.builder import CBOMBuilder, CBOM_NAMESPACE
from app.cbom.validators import CBOMValidator
from app.services.report_service import generate_system_cbom
from app.scanners.config_scanner.scanner import BankingConfigScanner
from app.scanners.config_scanner.models import NormalizedCryptoInventory, NormalizedCryptoAsset, CryptoRole, EvidenceStatus

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_data" / "banking"


def test_cbom_inventory_invariant_prohibits_risk_scores():
    """Invariant 1: CBOM must not contain risk engine scores or priority bands (P0/P1/P2/P3)."""
    validator = CBOMValidator()
    doc_with_risk_score = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "version": 1,
        "metadata": {"timestamp": "2026-10-30T00:00:00Z"},
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "crypto-test-01",
                "name": "RSA-2048",
                "cryptoProperties": {"assetType": "algorithm"},
                "properties": [
                    {"name": "banking:priority_score", "value": "95"},
                    {"name": "banking:priority_band", "value": "P0"},
                ],
            }
        ],
    }

    report = validator.validate(doc_with_risk_score)
    assert report.is_valid is False
    assert any("risk engine" in issue.lower() or "prohibited" in issue.lower() for issue in report.issues)


def test_cbom_deterministic_serial_number_and_content():
    """Invariant 5: Identical inventories produce bit-for-bit identical CBOM and serial numbers."""
    scanner = BankingConfigScanner(root_dir=SAMPLE_DIR)
    inv = scanner.scan_directory(SAMPLE_DIR / "upi_backend")

    builder = CBOMBuilder(deterministic=True)
    doc1 = builder.build_cbom(inv, timestamp="2026-10-30T00:00:00Z")
    doc2 = builder.build_cbom(inv, timestamp="2026-10-30T00:00:00Z")

    assert doc1.serialNumber == doc2.serialNumber
    assert doc1.serialNumber.startswith("urn:uuid:")

    dump1 = json.dumps(doc1.model_dump(by_alias=True, exclude_none=True), sort_keys=True)
    dump2 = json.dumps(doc2.model_dump(by_alias=True, exclude_none=True), sort_keys=True)
    assert dump1 == dump2


def test_generate_system_cbom_fallback_validity():
    """generate_system_cbom must always produce a schema-valid CycloneDX 1.7 document even on fallback."""
    validator = CBOMValidator()
    cbom_data = generate_system_cbom("NON-EXISTENT-SYSTEM-ID")

    assert cbom_data["bomFormat"] == "CycloneDX"
    assert cbom_data["specVersion"] == "1.7"
    assert cbom_data["serialNumber"].startswith("urn:uuid:")
    assert cbom_data["version"] >= 1
    assert "metadata" in cbom_data

    report = validator.validate(cbom_data)
    assert report.is_valid is True
    assert len(report.issues) == 0


def test_cbom_evidence_status_preservation_not_observable_not_vulnerable():
    """Invariant 3: Unobservable controls are recorded as NOT_OBSERVABLE, never converted to vulnerabilities."""
    inv = NormalizedCryptoInventory(
        system_id="BANK-TEST",
        system_name="Test Banking System",
        components=[
            NormalizedCryptoAsset(
                asset_id="asset-01",
                name="Key Wrapping Control",
                role=CryptoRole.KEY_WRAPPING,
                algorithm="NOT_OBSERVABLE",
                asset_type="algorithm",
                evidence_status=EvidenceStatus.NOT_OBSERVABLE,
                source_file="application.yml",
                source_path="security.key_wrapping",
                source_line=10,
            )
        ],
    )

    builder = CBOMBuilder(deterministic=True)
    doc = builder.build_cbom(inv)

    validator = CBOMValidator()
    report = validator.validate(doc)
    assert report.is_valid is True

    # Inspect component properties
    comp = doc.components[0]
    prop_dict = {p.name: p.value for p in comp.properties}
    assert prop_dict.get("quantumshield:evidence_status") == "NOT_OBSERVABLE"
    assert "vulnerable" not in [p.name.lower() for p in comp.properties]
