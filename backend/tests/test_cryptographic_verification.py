"""Tests for Task C5: Cryptographic Audit Verification Outcomes.

Verifies all explicit verification outcomes:
- VALID
- INVALID_SIGNATURE
- PAYLOAD_HASH_MISMATCH
- CHAIN_BROKEN
- RECORD_NOT_IN_LEDGER
- LEDGER_CORRUPTED
- VERIFICATION_ERROR
"""

import pytest
from app.models.audit_chain import AuditRecord, AuditVerificationResult, AuditVerificationStatus
from app.security.audit_key import AuditKeyManager
from app.security.audit_storage import AuditLedgerStorage
from app.services.audit_chain_service import (
    AuditChainService,
    canonicalize_json,
    compute_sha256,
    GENESIS_PREVIOUS_HASH,
)


@pytest.fixture
def test_setup(tmp_path):
    key_dir = tmp_path / "keys"
    km = AuditKeyManager(data_dir=key_dir)
    data_dir = tmp_path / "data"
    storage = AuditLedgerStorage(data_dir=data_dir, db_filename="test_audit.db")
    svc = AuditChainService(storage=storage, key_manager=km)
    return svc, storage, km


def test_verification_outcome_valid(test_setup):
    """A valid, signed, and stored audit record must return status VALID."""
    svc, storage, km = test_setup
    payload = {"system_id": "SYS-TEST", "score": 95, "criticality": "HIGH"}
    record = svc.create_audit_record(payload, assessment_id="SYS-TEST", store=True)

    result = svc.verify_audit_record(record, assessment_data=payload)
    assert result.valid is True
    assert result.status == AuditVerificationStatus.VALID.value
    assert result.status == "VALID"
    assert result.error is None
    assert result.record_id == record.record_id


def test_verification_outcome_payload_hash_mismatch(test_setup):
    """Altering payload after creation must return PAYLOAD_HASH_MISMATCH."""
    svc, storage, km = test_setup
    payload = {"system_id": "SYS-TEST", "score": 95}
    record = svc.create_audit_record(payload, assessment_id="SYS-TEST", store=True)

    tampered_payload = {"system_id": "SYS-TEST", "score": 20}
    result = svc.verify_audit_record(record, assessment_data=tampered_payload)

    assert result.valid is False
    assert result.status == AuditVerificationStatus.PAYLOAD_HASH_MISMATCH.value
    assert "tampering detected" in result.error.lower()


def test_verification_outcome_invalid_signature(test_setup, tmp_path):
    """Forged, modified, or foreign-key signature must return INVALID_SIGNATURE."""
    svc, storage, km = test_setup
    payload = {"system_id": "SYS-TEST", "score": 95}
    record = svc.create_audit_record(payload, assessment_id="SYS-TEST", store=True)

    # Corrupt the signature
    forged_record = record.model_copy(update={"signature": "bad" * 21 + "a"})
    result = svc.verify_audit_record(forged_record, assessment_data=payload)

    assert result.valid is False
    assert result.status == AuditVerificationStatus.INVALID_SIGNATURE.value
    assert "signature" in result.error.lower()

    # Signed with an unauthorized key
    attacker_km = AuditKeyManager(data_dir=tmp_path / "attacker")
    sig_mat = f"{record.record_id}:{record.assessment_id}:{record.assessment_hash}:{record.previous_hash}:{record.current_hash}:{record.timestamp}".encode("utf-8")
    unauthorized_sig = attacker_km.sign(sig_mat)
    unauthorized_record = record.model_copy(update={"signature": unauthorized_sig})

    result_unauth = svc.verify_audit_record(unauthorized_record, assessment_data=payload)
    assert result_unauth.valid is False
    assert result_unauth.status == AuditVerificationStatus.INVALID_SIGNATURE.value


def test_verification_outcome_chain_broken(test_setup):
    """Modifying previous_hash or current_hash must return CHAIN_BROKEN."""
    svc, storage, km = test_setup
    payload = {"system_id": "SYS-TEST", "score": 95}
    record = svc.create_audit_record(payload, assessment_id="SYS-TEST", store=True)

    # Break current_hash
    tampered_current = record.model_copy(update={"current_hash": "f" * 64})
    result = svc.verify_audit_record(tampered_current, assessment_data=payload)
    assert result.valid is False
    assert result.status == AuditVerificationStatus.CHAIN_BROKEN.value

    # Break chain sequence in verify_audit_chain
    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-TEST-2", store=True)
    broken_r2 = r2.model_copy(update={"previous_hash": "e" * 64})
    chain_result = svc.verify_audit_chain([record, broken_r2])
    assert chain_result.valid is False
    assert chain_result.status == AuditVerificationStatus.CHAIN_BROKEN.value


def test_verification_outcome_record_not_in_ledger(test_setup):
    """Valid signature and valid payload but absent from ledger must return RECORD_NOT_IN_LEDGER."""
    svc, storage, km = test_setup
    payload = {"system_id": "SYS-UNRECORDED", "score": 80}
    # Create record WITHOUT storing it in the ledger
    unrecorded = svc.create_audit_record(payload, assessment_id="SYS-UNRECORDED", store=False)

    result = svc.verify_audit_record(unrecorded, assessment_data=payload, check_ledger=True)
    assert result.valid is False
    assert result.status == AuditVerificationStatus.RECORD_NOT_IN_LEDGER.value
    assert result.status == "RECORD_NOT_IN_LEDGER"
    assert "Valid signature, but record is not present in the verified audit ledger." in result.error


def test_verification_outcome_ledger_corrupted(test_setup):
    """Tampering with record directly inside SQLite storage must return LEDGER_CORRUPTED."""
    svc, storage, km = test_setup
    payload = {"system_id": "SYS-TEST", "score": 95}
    record = svc.create_audit_record(payload, assessment_id="SYS-TEST", store=True)

    # Corrupt the record directly inside SQLite
    with storage._get_connection() as conn:
        conn.execute("UPDATE audit_records SET current_hash = ? WHERE record_id = ?", ("d" * 64, record.record_id))

    result = svc.verify_audit_record(record, assessment_data=payload, check_ledger=True)
    assert result.valid is False
    assert result.status == AuditVerificationStatus.LEDGER_CORRUPTED.value


def test_verification_outcome_verification_error(test_setup):
    """Malformed record missing mandatory fields must return VERIFICATION_ERROR."""
    svc, storage, km = test_setup
    payload = {"system_id": "SYS-TEST", "score": 95}
    record = svc.create_audit_record(payload, assessment_id="SYS-TEST", store=True)

    malformed = record.model_copy(update={"record_id": "", "current_hash": ""})
    result = svc.verify_audit_record(malformed)
    assert result.valid is False
    assert result.status == AuditVerificationStatus.VERIFICATION_ERROR.value


def test_verify_ledger_method(test_setup):
    """verify_ledger() must verify entire chain from genesis to head."""
    svc, storage, km = test_setup
    r1 = svc.create_audit_record({"step": 1}, assessment_id="SYS-1", store=True)
    r2 = svc.create_audit_record({"step": 2}, assessment_id="SYS-2", store=True)
    r3 = svc.create_audit_record({"step": 3}, assessment_id="SYS-3", store=True)

    res = svc.verify_ledger()
    assert res.valid is True
    assert res.status in (AuditVerificationStatus.VALID.value, AuditVerificationStatus.LOCALLY_VERIFIED.value)
    assert res.records_checked == 3
