"""Tests for Task C4: Controlled Audit Record Creation & Idempotency."""

import pytest
from starlette.testclient import TestClient
from app.main import app
from app.services.audit_chain_service import (
    AuditChainService,
    DEFAULT_AUDIT_CHAIN_SERVICE,
)
from app.security.audit_storage import AuditLedgerStorage
from app.security.audit_key import AuditKeyManager
from app.services.report_service import build_complete_json_report


def test_get_requests_do_not_create_audit_records(tmp_path, monkeypatch):
    """GET endpoints must be read-only and never append records to the audit ledger."""
    test_storage = AuditLedgerStorage(data_dir=tmp_path)
    test_key_mgr = AuditKeyManager(data_dir=tmp_path)
    test_svc = AuditChainService(storage=test_storage, key_manager=test_key_mgr)

    monkeypatch.setattr("app.services.audit_chain_service.DEFAULT_AUDIT_CHAIN_SERVICE", test_svc)
    monkeypatch.setattr("app.services.report_service.DEFAULT_AUDIT_CHAIN_SERVICE", test_svc)

    initial_count = test_storage.get_record_count()

    client = TestClient(app)

    # Issue multiple GET requests to report endpoints
    r1 = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json")
    assert r1.status_code == 200

    r2 = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json")
    assert r2.status_code == 200

    r3 = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/pdf")
    assert r3.status_code == 200

    # Ledger count must remain completely unchanged
    assert test_storage.get_record_count() == initial_count


def test_repeated_build_complete_json_report_does_not_mutate_ledger(tmp_path):
    """Calling build_complete_json_report in read mode must not create records."""
    test_storage = AuditLedgerStorage(data_dir=tmp_path)
    test_key_mgr = AuditKeyManager(data_dir=tmp_path)
    test_svc = AuditChainService(storage=test_storage, key_manager=test_key_mgr)

    # Calling directly without seal_audit=True
    rep1 = build_complete_json_report("BANK-PROF-CORE-BANKING", seal_audit=False, audit_service=test_svc)
    rep2 = build_complete_json_report("BANK-PROF-CORE-BANKING", seal_audit=False, audit_service=test_svc)

    assert rep1.report_metadata["report_id"]
    assert test_storage.get_record_count() == 0


def test_idempotent_finalization_prevents_duplicate_records(tmp_path):
    """Finalizing identical assessment data consecutively must return the existing record without appending."""
    test_storage = AuditLedgerStorage(data_dir=tmp_path)
    test_key_mgr = AuditKeyManager(data_dir=tmp_path)
    test_svc = AuditChainService(storage=test_storage, key_manager=test_key_mgr)

    assessment = {"system_id": "BANK-01", "score": 90, "findings": ["F1"]}

    # First finalization
    rec1 = test_svc.create_audit_record(assessment, assessment_id="BANK-01", store=True)
    assert test_storage.get_record_count() == 1

    # Retry with identical assessment data
    rec2 = test_svc.create_audit_record(assessment, assessment_id="BANK-01", store=True)
    assert test_storage.get_record_count() == 1
    assert rec1.record_id == rec2.record_id
    assert rec1.current_hash == rec2.current_hash


def test_new_assessment_content_appends_new_record(tmp_path):
    """When assessment content changes, a new record must be appended."""
    test_storage = AuditLedgerStorage(data_dir=tmp_path)
    test_key_mgr = AuditKeyManager(data_dir=tmp_path)
    test_svc = AuditChainService(storage=test_storage, key_manager=test_key_mgr)

    rec1 = test_svc.create_audit_record({"score": 90}, assessment_id="BANK-01", store=True)
    rec2 = test_svc.create_audit_record({"score": 40}, assessment_id="BANK-01", store=True)

    assert test_storage.get_record_count() == 2
    assert rec1.record_id != rec2.record_id
    assert rec2.previous_hash == rec1.current_hash


def test_failed_assessments_do_not_create_records(tmp_path):
    """Invalid or failed requests must never produce audit records."""
    test_storage = AuditLedgerStorage(data_dir=tmp_path)
    initial_count = test_storage.get_record_count()

    client = TestClient(app)
    # Target validation failure (empty domain)
    res = client.post("/api/scan", json={"domain": ""})
    assert res.status_code == 400

    # Disallowed port
    res2 = client.post("/api/scan", json={"domain": "example.com", "port": 22})
    assert res2.status_code == 400

    assert test_storage.get_record_count() == initial_count
