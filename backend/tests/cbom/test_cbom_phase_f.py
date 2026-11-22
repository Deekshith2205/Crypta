"""Phase F Cryptographic Bill of Materials (CBOM) Validation & Interoperability Tests.

Validates:
- F1: CycloneDX 1.7 CBOM generation, component model conformity, deterministic inventory.
- F2: JSON export, schema validation, stable serialization, provenance preservation,
      and adherence to Invariant 1 (CBOM is an inventory, NOT a risk engine).
"""

import json
import pytest

try:
    from cyclonedx.schema import SchemaVersion, OutputFormat
    from cyclonedx.validation import make_schemabased_validator
    CYCLONEDX_LIB_AVAILABLE = True
except ImportError:
    CYCLONEDX_LIB_AVAILABLE = False

from app.cbom.builder import CBOMBuilder
from app.cbom.models import (
    CBOMComponent,
    CBOMDependency,
    CBOMProperty,
    CryptoProperties,
    CycloneDXDocument,
    AlgorithmProperties,
)
from app.cbom.serializer import CBOMSerializer
from app.cbom.validators import CBOMValidator
from app.scanners.config_scanner.models import (
    CryptoAgility,
    EvidenceStatus,
    NormalizedCryptoAsset,
    NormalizedCryptoInventory,
)


def _create_sample_asset(
    asset_id: str = "asset-001",
    name: str = "AES-256-GCM",
    role: str = "DATA_ENCRYPTION",
    algorithm: str = "AES-256-GCM",
    evidence_status: EvidenceStatus = EvidenceStatus.OBSERVED,
    source_file: str = "application.yml",
    source_path: str = "server.ssl.ciphers",
    source_line: int = 15,
) -> NormalizedCryptoAsset:
    return NormalizedCryptoAsset(
        asset_id=asset_id,
        name=name,
        role=role,
        algorithm=algorithm,
        key_size=256,
        mode="GCM",
        curve=None,
        padding=None,
        protocol="TLS",
        protocol_version="1.3",
        asset_type="algorithm",
        source_file=source_file,
        source_path=source_path,
        source_line=source_line,
        evidence_status=evidence_status,
        crypto_agility=CryptoAgility.CONFIGURABLE,
        metadata={"execution_env": "software"},
    )


class TestCBOMPhaseFValidation:
    """Test suite for F1 & F2 CycloneDX 1.7 CBOM standards compliance."""

    def test_cbom_root_structure_cyclonedx_1_7(self):
        """CBOM document must strictly follow CycloneDX 1.7 specification root keys."""
        inventory = NormalizedCryptoInventory(
            system_id="BANK-TEST-CORE",
            system_name="Test Core Banking",
            criticality="CRITICAL",
            trust_zone="CORE_SECURE",
            components=[
                _create_sample_asset(asset_id="a1", name="AES-256-GCM", algorithm="AES-256-GCM"),
                _create_sample_asset(
                    asset_id="a2",
                    name="RSA-2048",
                    role="KEY_WRAPPING",
                    algorithm="RSA-2048",
                    evidence_status=EvidenceStatus.INFERRED,
                ),
            ],
        )

        builder = CBOMBuilder(deterministic=True)
        doc = builder.build_cbom(inventory)

        assert doc.bomFormat == "CycloneDX"
        assert doc.specVersion == "1.7"
        assert doc.serialNumber.startswith("urn:uuid:")
        assert doc.version == 1
        assert doc.metadata.timestamp is not None
        assert len(doc.components) == 2

        # Validate with CBOMValidator
        validator = CBOMValidator()
        report = validator.validate(doc)
        assert report.is_valid is True, f"Validation issues: {report.issues}"
        assert report.component_count == 2

    def test_cbom_deterministic_serialization(self):
        """Serializing the same inventory twice must produce byte-for-byte identical output."""
        inventory = NormalizedCryptoInventory(
            system_id="BANK-TEST-PAYMENT",
            system_name="Payment Gateway",
            components=[
                _create_sample_asset(asset_id="c1", name="ML-KEM-768", algorithm="ML-KEM-768", role="KEY_EXCHANGE"),
                _create_sample_asset(asset_id="c2", name="SHA-256", algorithm="SHA-256", role="HASHING"),
            ],
        )

        builder = CBOMBuilder(deterministic=True)
        serializer = CBOMSerializer(sort_keys=True, indent=2)

        doc1 = builder.build_cbom(inventory)
        json1 = serializer.to_json(doc1)

        doc2 = builder.build_cbom(inventory)
        json2 = serializer.to_json(doc2)

        assert json1 == json2, "CBOM serialization must be strictly deterministic"
        # Confirm valid JSON parse
        parsed = json.loads(json1)
        assert parsed["specVersion"] == "1.7"
        assert len(parsed["components"]) == 2

    def test_invariant_1_cbom_is_inventory_not_risk_engine(self):
        """CBOM is an INVENTORY, NOT a risk engine: rejects priority_score and P0/P1/P2/P3 risk scores."""
        validator = CBOMValidator()

        # Build a valid document first
        inventory = NormalizedCryptoInventory(
            system_id="BANK-TEST-INVARIANT",
            system_name="Test Invariant",
            components=[_create_sample_asset(asset_id="i1", name="AES-256", algorithm="AES-256")],
        )
        builder = CBOMBuilder(deterministic=True)
        doc = builder.build_cbom(inventory)

        doc_dict = doc.model_dump(by_alias=True, exclude_none=True)

        # Inject prohibited risk property into component
        doc_dict["components"][0]["properties"].append({
            "name": "banking:priority_score",
            "value": "85",
        })

        report = validator.validate(doc_dict)
        assert report.is_valid is False
        assert any("violates Invariant 1" in issue for issue in report.issues)
        assert any("banking:priority_score" in issue for issue in report.issues)

    def test_invariant_1_rejects_priority_band_property(self):
        """CBOM validator rejects P0/P1/P2/P3 priority bands in component properties."""
        validator = CBOMValidator()
        inventory = NormalizedCryptoInventory(
            system_id="BANK-TEST-BAND",
            system_name="Test Band",
            components=[_create_sample_asset(asset_id="b1", name="AES-256", algorithm="AES-256")],
        )
        builder = CBOMBuilder(deterministic=True)
        doc = builder.build_cbom(inventory)
        doc_dict = doc.model_dump(by_alias=True, exclude_none=True)

        doc_dict["components"][0]["properties"].append({
            "name": "priority_band",
            "value": "P0",
        })

        report = validator.validate(doc_dict)
        assert report.is_valid is False
        assert any("violates Invariant 1" in issue for issue in report.issues)

    def test_cbom_provenance_preservation(self):
        """Preserves source_file, source_path, source_line, and evidence_status (OBSERVED/INFERRED/NOT_OBSERVABLE)."""
        asset = _create_sample_asset(
            asset_id="prov-1",
            name="ECDHE-RSA-AES256-GCM-SHA384",
            evidence_status=EvidenceStatus.OBSERVED,
            source_file="nginx.conf",
            source_path="http.ssl_ciphers",
            source_line=42,
        )
        inventory = NormalizedCryptoInventory(
            system_id="BANK-TEST-PROV",
            system_name="Test Provenance",
            components=[asset],
        )

        builder = CBOMBuilder(deterministic=True)
        doc = builder.build_cbom(inventory)

        comp = doc.components[0]
        prop_dict = {p.name: p.value for p in comp.properties}

        assert prop_dict["quantumshield:source_file"] == "nginx.conf"
        assert prop_dict["quantumshield:config_path"] == "http.ssl_ciphers"
        assert prop_dict["quantumshield:source_line"] == "42"
        assert prop_dict["quantumshield:evidence_status"] == "OBSERVED"
        assert prop_dict["quantumshield:role"] == "DATA_ENCRYPTION"

    def test_cbom_secret_sanitization(self):
        """Guarantees raw passwords, keys, and credentials are never stored or serialized in CBOM."""
        sensitive_asset = NormalizedCryptoAsset(
            asset_id="sec-1",
            name="db_password=SuperSecretPassword123!",
            role="KEY_STORAGE",
            algorithm="AES-256",
            description="Private key pin=9876 password:secret",
            asset_type="storage",
            source_file="keystore.jks",
            source_path="db.secret",
            evidence_status=EvidenceStatus.OBSERVED,
            crypto_agility=CryptoAgility.HARDCODED,
        )

        inventory = NormalizedCryptoInventory(
            system_id="BANK-TEST-SECRET",
            system_name="Test Secret Sanitization",
            components=[sensitive_asset],
        )

        builder = CBOMBuilder(deterministic=True)
        doc = builder.build_cbom(inventory)
        serializer = CBOMSerializer()
        cbom_json = serializer.to_json(doc)

        assert "SuperSecretPassword123!" not in cbom_json
        assert "password:secret" not in cbom_json
        assert "[REDACTED_CREDENTIAL]" in cbom_json

        # Validator check
        validator = CBOMValidator()
        report = validator.validate(doc)
        assert report.is_valid is True

    def test_cbom_referential_integrity(self):
        """Dependencies must point to valid component bom-refs and reject dangling references."""
        validator = CBOMValidator()

        # Valid document with dependencies
        comp1 = CBOMComponent(
            bom_ref="crypto-bank-001-transport-tls",
            name="TLS 1.3",
            cryptoProperties=CryptoProperties(assetType="protocol"),
        )
        comp2 = CBOMComponent(
            bom_ref="crypto-bank-002-data-aes",
            name="AES-256-GCM",
            cryptoProperties=CryptoProperties(assetType="algorithm"),
        )

        dep_valid = CBOMDependency(
            ref="crypto-bank-001-transport-tls",
            dependsOn=["crypto-bank-002-data-aes"],
        )

        doc = CycloneDXDocument(
            bomFormat="CycloneDX",
            specVersion="1.7",
            serialNumber="urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            version=1,
            metadata={"timestamp": "2026-10-30T00:00:00Z"},
            components=[comp1, comp2],
            dependencies=[dep_valid],
        )

        report = validator.validate(doc)
        assert report.is_valid is True
        assert report.dependency_count == 1

        # Dangling dependency reference
        dep_invalid = CBOMDependency(
            ref="crypto-bank-001-transport-tls",
            dependsOn=["crypto-nonexistent-ref"],
        )
        doc_invalid = doc.model_copy(update={"dependencies": [dep_invalid]})
        report_invalid = validator.validate(doc_invalid)
        assert report_invalid.is_valid is False
        assert any("does not exist in components" in issue for issue in report_invalid.issues)

    def test_cbom_empty_inventory_handling(self):
        """Empty inventory produces a valid, schema-compliant CycloneDX CBOM document."""
        inventory = NormalizedCryptoInventory(
            system_id="BANK-EMPTY-SYS",
            system_name="Empty Banking System",
            components=[],
        )

        builder = CBOMBuilder(deterministic=True)
        doc = builder.build_cbom(inventory)

        assert doc.specVersion == "1.7"
        assert len(doc.components) == 0
        assert len(doc.dependencies) == 0

        validator = CBOMValidator()
        report = validator.validate(doc)
        assert report.is_valid is True
        assert report.component_count == 0

    def test_official_cyclonedx_1_7_schema_validation(self):
        """Validates that generated banking CBOMs conform strictly to the official CycloneDX 1.7 JSON Schema."""
        if not CYCLONEDX_LIB_AVAILABLE:
            pytest.skip("cyclonedx-python-lib not installed")

        from app.services.report_service import generate_system_cbom

        validator = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_7)
        systems = [
            "BANK-PROF-PAYMENT-GATEWAY",
            "BANK-PROF-CORE-BANKING",
            "BANK-PROF-KYC-DB",
            "BANK-PROF-NET-BANKING",
            "BANK-PROF-ATM-NETWORK",
        ]
        for sys_id in systems:
            cbom_dict = generate_system_cbom(sys_id)
            json_str = json.dumps(cbom_dict)
            validation_err = validator.validate_str(json_str)
            assert validation_err is None, f"CycloneDX 1.7 schema validation error for {sys_id}: {validation_err}"
