"""Mandatory Adversarial Tests for Independently Protected External Checkpoints (C-Remediation 1).

Covers all 10 required attack scenarios:
1. Append records and create a trusted external checkpoint.
2. Delete newest SQLite records while leaving external checkpoint unchanged (Suffix Truncation).
3. Modify internal SQLite checkpoints together with the ledger (Bypass of Internal-Only Checkpoints).
4. Replace the database with an older database copy (Ledger Rollback).
5. Replace the database with a rewritten valid-looking chain (Ledger Divergence / Fork).
6. Delete the internal checkpoint table (Resilience to internal table deletion).
7. Delete or corrupt the external checkpoint (Invalid external anchor).
8. Attempt to replay an older external checkpoint (Replay protection).
9. Restart the application and verify trusted checkpoint validation persists.
10. Verify that unavailable external verification never produces a misleading fully verified result.
"""

import shutil
import sqlite3
import pytest
from app.models.audit_chain import AuditRecord, AuditVerificationStatus
from app.security.audit_key import AuditKeyManager
from app.security.audit_storage import AuditLedgerStorage
from app.security.external_checkpoint import (
    InMemoryExternalCheckpointProvider,
    TrustedCheckpoint,
    CheckpointError,
)
from app.services.audit_chain_service import AuditChainService


@pytest.fixture
def independent_checkpoint_env(tmp_path):
    key_dir = tmp_path / "keys"
    data_dir = tmp_path / "data"
    km = AuditKeyManager(data_dir=key_dir)
    storage = AuditLedgerStorage(data_dir=data_dir, db_filename="audit_ledger.db")
    external_provider = InMemoryExternalCheckpointProvider()
    svc = AuditChainService(storage=storage, key_manager=km, checkpoint_provider=external_provider)
    return svc, storage, km, external_provider, data_dir, tmp_path


def test_scenario_1_append_and_create_external_checkpoint(independent_checkpoint_env):
    """Scenario 1: Append records and create a trusted external checkpoint."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-2", store=True)

    chk = svc.create_external_checkpoint()
    assert chk is not None
    assert chk.record_count == 2
    assert chk.head_hash == r2.current_hash
    assert chk.sequence_number == 1
    assert ext_provider.verify_signature(chk) is True

    # Ledger verification should succeed with EXTERNALLY_ANCHORED
    res = svc.verify_ledger()
    assert res.valid is True
    assert res.status == AuditVerificationStatus.EXTERNALLY_ANCHORED.value
    assert res.details.get("external_anchor") == "VERIFIED"


def test_scenario_2_suffix_truncation_detection(independent_checkpoint_env):
    """Scenario 2: Delete newest SQLite records while external checkpoint remains unchanged."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-2", store=True)
    r3 = svc.create_audit_record({"scan": 3}, assessment_id="SYS-3", store=True)

    # Anchor at 3 records
    chk = svc.create_external_checkpoint()
    assert chk.record_count == 3

    # Attacker deletes newest record (r3) from SQLite
    with storage._get_connection() as conn:
        conn.execute("DELETE FROM audit_records WHERE record_id = ?", (r3.record_id,))

    # Must detect suffix truncation against the independent anchor
    res = svc.verify_ledger()
    assert res.valid is False
    assert res.status == AuditVerificationStatus.LEDGER_SUFFIX_TRUNCATION_DETECTED.value
    assert "suffix truncation detected" in res.error.lower()


def test_scenario_3_internal_checkpoints_forged_with_ledger(independent_checkpoint_env):
    """Scenario 3: Attacker modifies internal SQLite checkpoints together with the ledger."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-2", store=True)
    r3 = svc.create_audit_record({"scan": 3}, assessment_id="SYS-3", store=True)

    # External anchor created at 3 records
    ext_chk = svc.create_external_checkpoint()
    # Internal checkpoint also created at 3 records
    internal_chk = storage.create_checkpoint()

    # Attacker rewrites internal SQLite checkpoints table AND deletes record 3
    with storage._get_connection() as conn:
        conn.execute("DELETE FROM audit_records WHERE record_id = ?", (r3.record_id,))
        # Attacker updates internal SQLite checkpoint to falsely claim head is record 2
        conn.execute("UPDATE audit_checkpoints SET head_hash = ?, record_count = 2", (r2.current_hash,))

    # Internal checkpoint now looks "valid" for 2 records, but external anchor detects truncation!
    res = svc.verify_ledger()
    assert res.valid is False
    assert res.status == AuditVerificationStatus.LEDGER_SUFFIX_TRUNCATION_DETECTED.value
    assert "suffix truncation detected" in res.error.lower()


def test_scenario_4_database_rollback_to_older_copy(independent_checkpoint_env):
    """Scenario 4: Attacker replaces the database with an older database snapshot."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    db_path = data_dir / "audit_ledger.db"

    # State 1: 2 records
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-2", store=True)
    storage.close()

    # Backup older snapshot
    backup_db = tmp_path / "older_snapshot.db"
    shutil.copyfile(db_path, backup_db)

    # State 2: Reopen and add records 3 and 4, then anchor externally
    storage_reopened = AuditLedgerStorage(data_dir=data_dir, db_filename="audit_ledger.db")
    svc_reopened = AuditChainService(storage=storage_reopened, key_manager=km, checkpoint_provider=ext_provider)
    r3 = svc_reopened.create_audit_record({"scan": 3}, assessment_id="SYS-3", store=True)
    r4 = svc_reopened.create_audit_record({"scan": 4}, assessment_id="SYS-4", store=True)
    svc_reopened.create_external_checkpoint()
    storage_reopened.close()

    # Attacker rolls back: overwrites audit_ledger.db with the older 2-record snapshot
    shutil.copyfile(backup_db, db_path)

    # Reconnect and verify
    storage_restored = AuditLedgerStorage(data_dir=data_dir, db_filename="audit_ledger.db")
    svc_restored = AuditChainService(storage=storage_restored, key_manager=km, checkpoint_provider=ext_provider)

    res = svc_restored.verify_ledger()
    assert res.valid is False
    assert res.status == AuditVerificationStatus.LEDGER_SUFFIX_TRUNCATION_DETECTED.value


def test_scenario_5_database_rewritten_chain_fork(independent_checkpoint_env):
    """Scenario 5: Attacker replaces the database with a rewritten, valid-looking alternate chain."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-2", store=True)

    # External anchor at r2
    ext_chk = svc.create_external_checkpoint()
    assert ext_chk.record_count == 2
    assert ext_chk.head_hash == r2.current_hash

    # Attacker wipes records and creates a fake valid chain with identical count (2 records)
    with storage._get_connection() as conn:
        conn.execute("DELETE FROM audit_records;")

    # Re-insert 2 altered records
    fake_r1 = svc.create_audit_record({"scan": "tampered_1"}, assessment_id="SYS-1", store=True)
    fake_r2 = svc.create_audit_record({"scan": "tampered_2"}, assessment_id="SYS-2", store=True)

    # Record count matches (2 == 2), internal chain is valid, but head hash diverges from anchor
    res = svc.verify_ledger()
    assert res.valid is False
    assert res.status == AuditVerificationStatus.LEDGER_ROLLBACK_DETECTED.value
    assert "chain divergence detected" in res.error.lower()


def test_scenario_6_internal_checkpoint_table_deletion(independent_checkpoint_env):
    """Scenario 6: Attacker drops the internal SQLite checkpoint table completely."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    svc.create_external_checkpoint()

    # Attacker drops audit_checkpoints table from SQLite
    with storage._get_connection() as conn:
        conn.execute("DROP TABLE audit_checkpoints;")

    # External checkpoint still validates the ledger safely
    res = svc.verify_ledger()
    assert res.valid is True
    assert res.status == AuditVerificationStatus.EXTERNALLY_ANCHORED.value


def test_scenario_7_corrupt_external_checkpoint_detected(independent_checkpoint_env):
    """Scenario 7: Attacker corrupts or tampers with the external checkpoint signature."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    chk = svc.create_external_checkpoint()

    # Corrupt the signature of the checkpoint in the external provider
    chk_corrupted = chk.model_copy(update={"signature": "bad" * 21 + "a"})
    ext_provider._checkpoints[-1] = chk_corrupted

    res = svc.verify_ledger()
    assert res.valid is False
    assert res.status == AuditVerificationStatus.EXTERNAL_ANCHOR_INVALID.value


def test_scenario_8_replay_older_checkpoint_rejected(independent_checkpoint_env):
    """Scenario 8: Attempting to replay an older checkpoint is rejected by sequence/count checks."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    chk1 = svc.create_external_checkpoint()

    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-2", store=True)
    chk2 = svc.create_external_checkpoint()
    assert chk2.sequence_number > chk1.sequence_number

    # Attempt to replay chk1 (older sequence number and lower count)
    with pytest.raises(CheckpointError) as exc:
        ext_provider.save_checkpoint(chk1)
    assert "replay detected" in str(exc.value).lower()


def test_scenario_9_restart_persistence_with_trusted_checkpoint(independent_checkpoint_env):
    """Scenario 9: Application restarts and independently verified checkpointing remains operational."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)
    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-2", store=True)
    svc.create_external_checkpoint()
    storage.close()

    # Simulate full restart
    restarted_storage = AuditLedgerStorage(data_dir=data_dir, db_filename="audit_ledger.db")
    restarted_km = AuditKeyManager(data_dir=tmp_path / "keys")
    restarted_svc = AuditChainService(
        storage=restarted_storage,
        key_manager=restarted_km,
        checkpoint_provider=ext_provider,
    )

    res = restarted_svc.verify_ledger()
    assert res.valid is True
    assert res.status == AuditVerificationStatus.EXTERNALLY_ANCHORED.value
    assert res.records_checked == 2


def test_scenario_10_unavailable_external_anchor_never_misleads(independent_checkpoint_env):
    """Scenario 10: Unavailable external verification never produces a misleading fully verified result."""
    svc, storage, km, ext_provider, data_dir, tmp_path = independent_checkpoint_env
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1", store=True)

    # Disable external provider to simulate network partition / external outage
    ext_provider.set_operational(False)

    # When require_external=True is requested, must NOT claim fully verified; returns error
    res_required = svc.verify_ledger(require_external=True)
    assert res_required.valid is False
    assert res_required.status == AuditVerificationStatus.EXTERNAL_ANCHOR_UNAVAILABLE.value
    assert "unavailable" in res_required.error.lower()

    # When unrequired, it reports LOCALLY_VERIFIED only, never claiming EXTERNALLY_ANCHORED
    res_unrequired = svc.verify_ledger(require_external=False)
    assert res_unrequired.valid is True
    assert res_unrequired.status == AuditVerificationStatus.LOCALLY_VERIFIED.value
    assert "UNAVAILABLE" in res_unrequired.details.get("external_anchor", "")
