"""API tests for Task C6: Audit Ledger and Head Endpoints.

Tests:
- GET /api/audit/ledger (pagination, filtering, read-only, bounds, no secret leakage)
- GET /api/audit/head (latest record metadata, count, chain integrity status, empty handling)
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.audit_chain_service import (
    AuditChainService,
    DEFAULT_AUDIT_CHAIN_SERVICE,
    GENESIS_PREVIOUS_HASH,
)
from app.security.audit_storage import AuditLedgerStorage
from app.security.audit_key import AuditKeyManager

client = TestClient(app)


def test_get_audit_ledger_pagination_and_stability():
    """GET /api/audit/ledger must return paginated records in stable order."""
    response = client.get("/api/audit/ledger?limit=5&offset=0")
    assert response.status_code == 200
    data = response.json()

    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert "records" in data
    assert data["limit"] == 5
    assert data["offset"] == 0
    assert len(data["records"]) <= 5

    # Check structure of each record - verify no secrets/keys are leaked
    for rec in data["records"]:
        assert "record_id" in rec
        assert "assessment_id" in rec
        assert "assessment_hash" in rec
        assert "current_hash" in rec
        assert "previous_hash" in rec
        assert "timestamp" in rec
        assert "signature" in rec
        # Verify no secret signing key or raw DB paths
        assert "key" not in rec
        assert "private" not in rec
        assert "db_path" not in rec


def test_get_audit_ledger_pagination_bounds():
    """GET /api/audit/ledger must enforce valid pagination limits."""
    # Exceed max limit (500)
    resp_over = client.get("/api/audit/ledger?limit=501")
    assert resp_over.status_code == 422

    # Negative offset
    resp_neg = client.get("/api/audit/ledger?offset=-1")
    assert resp_neg.status_code == 422

    # Zero limit
    resp_zero = client.get("/api/audit/ledger?limit=0")
    assert resp_zero.status_code == 422


def test_get_audit_ledger_filter_by_system():
    """GET /api/audit/ledger?system_id=... must filter by system_id."""
    resp = client.get("/api/audit/ledger?system_id=BANK-PROF-CORE-BANKING")
    assert resp.status_code == 200
    data = resp.json()
    for rec in data["records"]:
        assert rec["assessment_id"] == "BANK-PROF-CORE-BANKING"


def test_get_audit_ledger_is_read_only():
    """GET /api/audit/ledger must not mutate the ledger count."""
    r1 = client.get("/api/audit/ledger?limit=100")
    assert r1.status_code == 200
    count1 = r1.json()["total"]

    r2 = client.get("/api/audit/ledger?limit=100")
    assert r2.status_code == 200
    count2 = r2.json()["total"]

    assert count1 == count2


def test_get_audit_head_endpoint():
    """GET /api/audit/head must return the current head of the ledger."""
    resp = client.get("/api/audit/head")
    assert resp.status_code == 200
    head = resp.json()

    assert "record_id" in head
    assert "current_hash" in head
    assert "timestamp" in head
    assert "record_count" in head
    assert "chain_valid" in head
    assert "status" in head
    assert head["status"] in ("VALID", "LOCALLY_VERIFIED", "EXTERNALLY_ANCHORED", "EMPTY")
    assert "external_anchor" in head
    assert len(head["current_hash"]) == 64


def test_get_audit_head_is_read_only():
    """GET /api/audit/head must not alter the ledger."""
    h1 = client.get("/api/audit/head").json()
    h2 = client.get("/api/audit/head").json()
    assert h1["record_id"] == h2["record_id"]
    assert h1["record_count"] == h2["record_count"]
    assert h1["current_hash"] == h2["current_hash"]


def test_get_audit_head_empty_ledger(tmp_path, monkeypatch):
    """GET /api/audit/head on an empty ledger must return EMPTY status safely."""
    empty_db = tmp_path / "empty.db"
    empty_storage = AuditLedgerStorage(data_dir=tmp_path, db_filename="empty.db")
    empty_svc = AuditChainService(storage=empty_storage)

    monkeypatch.setattr("app.api.routes.DEFAULT_AUDIT_CHAIN_SERVICE", empty_svc)

    resp = client.get("/api/audit/head")
    assert resp.status_code == 200
    head = resp.json()
    assert head["record_count"] == 0
    assert head["record_id"] is None
    assert head["current_hash"] == GENESIS_PREVIOUS_HASH
    assert head["status"] == "EMPTY"
    assert head["chain_valid"] is True
