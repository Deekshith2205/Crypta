"""Tests for Task C1: Secure Audit Signing Key Management."""

import os
import stat
import tempfile
import pytest
from pathlib import Path
from app.security.audit_key import AuditKeyManager, AuditKeyError


def test_key_generation_and_persistence(tmp_path):
    """When no key is configured, generate and persist a 256-bit key."""
    mgr1 = AuditKeyManager(data_dir=tmp_path)
    key1 = mgr1.get_key()

    assert isinstance(key1, bytes)
    assert len(key1) >= 32

    key_file = tmp_path / "audit_signing.key"
    assert key_file.exists()

    # Restart behavior: second manager instance reloads identical key
    mgr2 = AuditKeyManager(data_dir=tmp_path)
    key2 = mgr2.get_key()

    assert key1 == key2


def test_env_provided_key(tmp_path, monkeypatch):
    """QS_AUDIT_SIGNING_KEY environment variable takes precedence."""
    env_secret = "a" * 64  # 64 hex characters (32 bytes)
    monkeypatch.setenv("QS_AUDIT_SIGNING_KEY", env_secret)

    mgr = AuditKeyManager(data_dir=tmp_path)
    key = mgr.get_key()

    assert key == bytes.fromhex(env_secret)
    # File should not be created if env key is used
    key_file = tmp_path / "audit_signing.key"
    assert not key_file.exists()


def test_invalid_short_env_key(tmp_path, monkeypatch):
    """Short or weak keys (< 32 bytes) must raise AuditKeyError."""
    monkeypatch.setenv("QS_AUDIT_SIGNING_KEY", "too_short_key")
    mgr = AuditKeyManager(data_dir=tmp_path)

    with pytest.raises(AuditKeyError) as exc_info:
        mgr.get_key()
    assert "at least 32 bytes" in str(exc_info.value).lower()


def test_corrupted_key_file_raises_error(tmp_path):
    """A corrupted key file must raise AuditKeyError and NEVER be silently overwritten."""
    key_file = tmp_path / "audit_signing.key"
    key_file.write_text("corrupted_short")

    mgr = AuditKeyManager(data_dir=tmp_path)
    with pytest.raises(AuditKeyError) as exc_info:
        mgr.get_key()
    assert "corrupted" in str(exc_info.value).lower()

    # Verify file was not overwritten
    assert key_file.read_text() == "corrupted_short"


def test_signing_and_constant_time_verification(tmp_path):
    """HMAC-SHA256 signatures must be deterministic and verifiable."""
    mgr = AuditKeyManager(data_dir=tmp_path)
    message = b"canonical-assessment-payload-hash-12345"

    sig1 = mgr.sign(message)
    sig2 = mgr.sign(message)

    assert isinstance(sig1, str)
    assert len(sig1) == 64  # SHA-256 hex digest length
    assert sig1 == sig2

    # Verification passes for identical message
    assert mgr.verify(message, sig1) is True

    # Verification fails for modified message
    assert mgr.verify(b"tampered-message", sig1) is False

    # Verification fails for invalid signature format or altered signature
    altered_sig = ("0" if sig1[0] != "0" else "1") + sig1[1:]
    assert mgr.verify(message, altered_sig) is False


def test_key_never_exposed_in_repr_or_str(tmp_path):
    """AuditKeyManager string representation must not leak key bytes or hex."""
    mgr = AuditKeyManager(data_dir=tmp_path)
    key_hex = mgr.get_key().hex()

    str_rep = str(mgr)
    repr_rep = repr(mgr)

    assert key_hex not in str_rep
    assert key_hex not in repr_rep
    assert "REDACTED" in str_rep or "AuditKeyManager" in str_rep


def test_key_rotation_and_archiving(tmp_path):
    """rotate_key archives the old key and writes the new key."""
    mgr = AuditKeyManager(data_dir=tmp_path)
    old_key = mgr.get_key()

    new_key = mgr.rotate_key()
    assert new_key != old_key
    assert len(new_key) >= 32

    # Check archive
    archive_file = tmp_path / "audit_signing.key.prev"
    assert archive_file.exists()
    assert bytes.fromhex(archive_file.read_text().strip()) == old_key

    # Current key is updated
    key_file = tmp_path / "audit_signing.key"
    assert bytes.fromhex(key_file.read_text().strip()) == new_key


def test_missing_key_refuses_silent_regeneration_when_ledger_exists(tmp_path):
    """If audit_records exist in ledger DB but key file is missing, refuse silent regeneration."""
    import sqlite3
    db_file = tmp_path / "audit_ledger.db"
    conn = sqlite3.connect(str(db_file))
    with conn:
        conn.execute("""
            CREATE TABLE audit_records (
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT UNIQUE NOT NULL
            );
        """)
        conn.execute("INSERT INTO audit_records (record_id) VALUES ('existing-rec-01');")
    conn.close()

    mgr = AuditKeyManager(data_dir=tmp_path)
    with pytest.raises(AuditKeyError) as exc_info:
        mgr.get_key()
    assert "refusing to silently generate" in str(exc_info.value).lower()
