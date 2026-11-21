"""Tests for Task C2: Persistent SQLite Audit Storage."""

import concurrent.futures
import sqlite3
import pytest
from pathlib import Path
from app.models.audit_chain import AuditRecord
from app.security.audit_storage import AuditLedgerStorage, AuditStorageError


def make_sample_record(record_id: str, prev_hash: str, assessment_id: str = "SYS-1") -> AuditRecord:
    return AuditRecord(
        record_id=record_id,
        assessment_id=assessment_id,
        assessment_hash="a" * 64,
        previous_hash=prev_hash,
        current_hash="c" * 64,
        signature="s" * 64,
        timestamp="2026-11-21T10:00:00Z",
        schema_version="1.0.0",
        canonical_payload='{"test":true}',
    )


def test_initial_database_creation(tmp_path):
    """Database file and schema must be initialized automatically."""
    storage = AuditLedgerStorage(data_dir=tmp_path)
    db_file = tmp_path / "audit_ledger.db"

    assert db_file.exists()
    assert storage.get_record_count() == 0
    assert storage.get_latest_hash() == "0" * 64


def test_record_persistence_and_reload(tmp_path):
    """Records written to storage must persist across instances (application restart)."""
    storage1 = AuditLedgerStorage(data_dir=tmp_path)
    r1 = make_sample_record("rec-001", "0" * 64)
    storage1.append_record(r1)

    assert storage1.get_record_count() == 1
    fetched = storage1.get_record_by_id("rec-001")
    assert fetched is not None
    assert fetched.record_id == "rec-001"
    assert fetched.signature == "s" * 64

    # Simulate restart by creating new storage instance on same directory
    storage2 = AuditLedgerStorage(data_dir=tmp_path)
    assert storage2.get_record_count() == 1
    reloaded = storage2.get_record_by_id("rec-001")
    assert reloaded is not None
    assert reloaded.record_id == "rec-001"
    assert reloaded.current_hash == "c" * 64


def test_multiple_sequential_writes(tmp_path):
    """Sequential records must be stored in order and queryable."""
    storage = AuditLedgerStorage(data_dir=tmp_path)

    r1 = AuditRecord(
        record_id="rec-01",
        assessment_id="SYS-1",
        assessment_hash="a" * 64,
        previous_hash="0" * 64,
        current_hash="1" * 64,
        signature="sig1",
        timestamp="2026-11-21T10:01:00Z",
    )
    r2 = AuditRecord(
        record_id="rec-02",
        assessment_id="SYS-2",
        assessment_hash="b" * 64,
        previous_hash="1" * 64,
        current_hash="2" * 64,
        signature="sig2",
        timestamp="2026-11-21T10:02:00Z",
    )

    storage.append_record(r1)
    storage.append_record(r2)

    assert storage.get_record_count() == 2
    assert storage.get_latest_hash() == "2" * 64

    records = storage.get_records(limit=10, offset=0)
    assert len(records) == 2
    assert records[0].record_id == "rec-01"
    assert records[1].record_id == "rec-02"


def test_duplicate_record_id_rejected(tmp_path):
    """Appending a record with an existing record_id must raise AuditStorageError."""
    storage = AuditLedgerStorage(data_dir=tmp_path)
    r1 = make_sample_record("rec-dup", "0" * 64)
    storage.append_record(r1)

    r2 = make_sample_record("rec-dup", "0" * 64)
    with pytest.raises(AuditStorageError):
        storage.append_record(r2)


def test_concurrent_write_safety(tmp_path):
    """Concurrent writes must all succeed safely without database locks or corruptions."""
    storage = AuditLedgerStorage(data_dir=tmp_path)

    def write_worker(idx: int):
        rec = AuditRecord(
            record_id=f"rec-conc-{idx:03d}",
            assessment_id=f"SYS-{idx}",
            assessment_hash="h" * 64,
            previous_hash="p" * 64,
            current_hash=f"{idx:064d}",
            signature=f"sig-{idx}",
            timestamp="2026-11-21T10:00:00Z",
        )
        storage.append_record(rec)
        return idx

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(write_worker, range(20)))

    assert len(results) == 20
    assert storage.get_record_count() == 20
