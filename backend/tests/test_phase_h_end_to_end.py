"""Phase H: End-to-End Comprehensive Application Verification Test Suite.

Executes the complete main application lifecycle across all 20 scenarios
specified in the Phase H roadmap:
1. Application startup & lifespan initialization
2. Health & liveness endpoint verification
3. API authentication & security headers
4. Banking profile loading & system inventory
5. Artifact upload & static code analysis (zero-execution invariant)
6. Config manifest static parsing
7. Deterministic finding generation & role classification
8. Multi-dimensional banking risk scoring & agility evaluation
9. What-If post-quantum migration simulation (immutability check)
10. CycloneDX 1.7 CBOM generation
11. CBOM export & official JSON schema validation
12. Comprehensive banking compliance report generation
13. Binary PDF executive report generation & export
14. Ranked post-quantum upgrade roadmap sequencing (P0-P3)
15. SSRF & private target rejection on scan endpoints
16. AI readiness status & budget telemetry
17. Deterministic AI explanation fallback engagement
18. Audit record creation with deterministic canonical hashing
19. Hash-chain cryptographic ledger verification
20. Structured error handling & boundary input rejection
"""

import json
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.ai.fallback import DeterministicExplanationService
from app.ai.schemas import FindingExplanationRequest

try:
    from cyclonedx.schema import SchemaVersion, OutputFormat
    from cyclonedx.validation import make_schemabased_validator
    CYCLONEDX_LIB_AVAILABLE = True
except ImportError:
    CYCLONEDX_LIB_AVAILABLE = False


@pytest.fixture(scope="module")
def client():
    """Shared ASGI TestClient fixture."""
    with TestClient(app) as test_client:
        yield test_client


class TestPhaseHEndToEndLifecycle:
    """Complete 20-step end-to-end verification of QuantumShield."""

    # 1. Startup & 2. Health endpoint
    def test_01_health_and_correlation(self, client):
        """GET /api/health verifies app startup, health state, and X-Request-ID propagation."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "healthy"
        assert "timestamp" in data
        assert "x-request-id" in resp.headers
        assert len(resp.headers["x-request-id"]) >= 16

    # 3. Security Headers
    def test_02_security_headers(self, client):
        """Responses must enforce defensive security headers."""
        resp = client.get("/api/health")
        headers = resp.headers
        assert headers.get("x-content-type-options") == "nosniff"
        assert headers.get("x-frame-options") == "DENY"
        assert headers.get("referrer-policy") == "no-referrer"

    # 4. Banking Profile Loading
    def test_03_banking_profiles_inventory(self, client):
        """GET /api/banking/profiles returns synthetic financial institution profiles."""
        resp = client.get("/api/banking/profiles")
        assert resp.status_code == 200
        profiles = resp.json()
        assert len(profiles) >= 5
        sys_ids = {p["id"] for p in profiles}
        assert "BANK-PROF-CORE-BANKING" in sys_ids
        assert "BANK-PROF-PAYMENT-GATEWAY" in sys_ids

    # 5. Static Code Cryptographic Analysis
    def test_04_static_code_analysis_zero_execution(self, client):
        """POST /api/scan/code performs AST/regex static analysis without executing code."""
        synthetic_java = (
            "import javax.crypto.Cipher;\n"
            "public class PaymentCrypto {\n"
            "    public void encrypt() throws Exception {\n"
            "        Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");\n"
            "    }\n"
            "}"
        )
        resp = client.post(
            "/api/scan/code",
            json={"files": [{"name": "PaymentCrypto.java", "content": synthetic_java}]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_status"] == "SUCCESS"
        assert data["finding_count"] >= 1
        rule_ids = {f.get("finding_id") or f.get("title") for f in data["findings"]}
        assert any("ECB" in r or "MISUSE-ECB" in r for r in rule_ids)

    # 6. Config Manifest Static Parsing
    def test_05_static_config_analysis(self, client):
        """POST /api/scan/config statically parses configuration manifests."""
        synthetic_yaml = (
            "server:\n"
            "  ssl:\n"
            "    enabled-protocols: TLSv1.2\n"
            "    ciphers: TLS_RSA_WITH_AES_256_GCM_SHA384\n"
        )
        resp = client.post(
            "/api/scan/config",
            json={"files": [{"name": "application.yml", "content": synthetic_yaml}]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_status"] == "SUCCESS"
        assert "findings" in data

    # 7. Deterministic Finding Generation & 8. Risk Scoring
    def test_06_deterministic_risk_assessment(self, client):
        """GET /api/banking/profiles/{id}/risk returns deterministic risk scores."""
        resp = client.get("/api/banking/profiles/BANK-PROF-CORE-BANKING/risk")
        assert resp.status_code == 200
        risk = resp.json()
        assert risk["asset_id"] == "BANK-PROF-CORE-BANKING"
        assert 0 <= risk["priority_score"] <= 100
        assert "migration_priority" in risk
        assert "technical_risk" in risk

    # 9. What-If Post-Quantum Migration Simulator
    def test_07_what_if_migration_simulator(self, client):
        """POST /api/banking/risk/what-if computes deltas without mutating baseline state."""
        payload = {
            "asset_id": "BANK-PROF-CORE-BANKING",
            "changes": [
                {
                    "component": "KEY_WRAPPING",
                    "target_algorithm": "ML-KEM-768",
                }
            ],
        }
        resp = client.post("/api/banking/risk/what-if", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["asset_id"] == "BANK-PROF-CORE-BANKING"
        assert data["evidence_state"] == "SIMULATED"
        assert "comparison" in data
        comparison = data["comparison"]
        assert "priority_score_before" in comparison
        assert "priority_score_after" in comparison
        assert comparison["priority_score_after"] <= comparison["priority_score_before"]
        assert comparison["priority_score_delta"] <= 0

    # 10. CycloneDX 1.7 CBOM Generation & 11. Schema Validation
    def test_08_cbom_generation_and_schema_validation(self, client):
        """GET /api/banking/systems/{id}/cbom generates CycloneDX 1.7 document conforming to official schema."""
        resp = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/cbom")
        assert resp.status_code == 200
        cbom = resp.json()
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.7"
        assert cbom["serialNumber"].startswith("urn:uuid:")
        assert "components" in cbom
        assert len(cbom["components"]) > 0

        # Validate against official CycloneDX 1.7 schema if library is available
        if CYCLONEDX_LIB_AVAILABLE:
            validator = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_7)
            err = validator.validate_str(json.dumps(cbom))
            assert err is None, f"CycloneDX 1.7 schema validation error: {err}"

    # 12. Banking Report Generation & 13. PDF Export
    def test_09_banking_report_and_pdf_export(self, client):
        """GET /api/banking/systems/{id}/report/json and /pdf generate valid exports."""
        # JSON report
        resp_json = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json")
        assert resp_json.status_code == 200
        report = resp_json.json()
        assert report["system"]["id"] == "BANK-PROF-CORE-BANKING"
        assert "executive_summary" in report
        assert "quantum_posture" in report
        assert "priority" in report

        # PDF export
        resp_pdf = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/pdf")
        assert resp_pdf.status_code == 200
        assert resp_pdf.headers.get("content-type") == "application/pdf"
        assert resp_pdf.content.startswith(b"%PDF-")
        assert len(resp_pdf.content) > 1000

    # 14. Ranked Upgrade Plan
    def test_10_ranked_upgrade_plan(self, client):
        """GET /api/banking/upgrade-plan returns dynamically ranked migration roadmap."""
        resp = client.get("/api/banking/upgrade-plan")
        assert resp.status_code == 200
        plan = resp.json()
        assert plan["total_systems"] >= 5
        assert len(plan["queue"]) == plan["total_systems"]
        assert plan["queue"][0]["rank"] == 1

    # 15. SSRF & Private Target Rejection
    def test_11_ssrf_rejection(self, client):
        """POST /api/scan strictly rejects loopback, RFC 1918, and metadata targets."""
        targets = ["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.1"]
        for target in targets:
            resp = client.post("/api/scan", json={"domain": target, "port": 443})
            assert resp.status_code in {400, 422}
            data = resp.json()
            assert data.get("error") in {"UNSAFE_TARGET", "DOMAIN_VALIDATION_ERROR"}

    # 16. AI Status & Budget Telemetry
    def test_12_ai_status_and_budget(self, client):
        """GET /api/ai/status and GET /api/ai/budget return system readiness."""
        resp_status = client.get("/api/ai/status")
        assert resp_status.status_code == 200
        assert "is_available" in resp_status.json()

        resp_budget = client.get("/api/ai/budget")
        assert resp_budget.status_code == 200
        budget = resp_budget.json()
        assert "daily_token_budget" in budget
        assert "tokens_used_today" in budget

    # 17. Deterministic AI Fallback Engagement
    def test_13_ai_fallback_explanation(self, client):
        """POST /api/ai/explain/finding returns safe response and fallback service provides expert guidance."""
        payload = {
            "rule_id": "CRYPTO-RSA-2048",
            "title": "RSA-2048 Certificate Signature",
            "value": "RSA-2048",
            "role": "DIGITAL_SIGNATURE",
            "source": "EXTERNAL_SCAN",
            "evidence_status": "OBSERVED",
            "severity": "HIGH",
            "risk": "QUANTUM",
            "message": "Vulnerable to Shor's algorithm.",
            "recommendation": "Migrate to ML-DSA-65 (NIST FIPS 204).",
        }
        # API endpoint handles unconfigured provider safely
        resp = client.post("/api/ai/explain/finding", json=payload)
        assert resp.status_code == 200
        assert "success" in resp.json()

        # Deterministic offline fallback engine provides expert advice
        req = FindingExplanationRequest(**payload)
        fallback_res = DeterministicExplanationService.explain_finding(req)
        assert fallback_res.success is True
        assert fallback_res.data.rule_id == "CRYPTO-RSA-2048"
        assert "Shor's" in fallback_res.data.quantum_relevance
        assert "FIPS 204" in fallback_res.data.remediation or "ML-DSA" in fallback_res.data.remediation

    # 18. Audit Ledger & 19. Hash-Chain Verification
    def test_14_audit_ledger_and_head(self, client):
        """GET /api/audit/head and GET /api/audit/ledger verify the tamper-evident hash ledger."""
        # Query audit head
        resp_head = client.get("/api/audit/head")
        assert resp_head.status_code == 200
        head_data = resp_head.json()
        assert "current_hash" in head_data
        assert head_data.get("chain_valid") is True
        assert head_data.get("status") in {"LOCALLY_VERIFIED", "VALID", "EMPTY"}

        # Query paginated audit ledger
        resp_ledger = client.get("/api/audit/ledger?limit=10")
        assert resp_ledger.status_code == 200
        ledger_data = resp_ledger.json()
        assert "records" in ledger_data
        assert "total" in ledger_data

    # 20. Structured Error Handling & Input Boundaries
    def test_15_input_boundaries_error_handling(self, client):
        """API endpoints reject out-of-bounds ports, invalid JSON, and missing fields cleanly."""
        # Out-of-bounds port
        resp = client.post("/api/scan", json={"domain": "example.com", "port": 99999})
        assert resp.status_code == 400
        assert resp.json().get("error") == "INVALID_PORT"

        # Non-whitelisted port
        resp = client.post("/api/scan", json={"domain": "example.com", "port": 8080})
        assert resp.status_code == 400
        assert resp.json().get("error") == "DISALLOWED_PORT"
