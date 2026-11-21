"""Adversarial and Edge-Case Tests for External Audit Checkpoints (Task 1 Remediation).

Verifies fail-closed semantics, signature verification, replay rejection,
hash divergence / rollback detection, record truncation detection,
read-only GET endpoints, and persistence across service restarts.
"""

import os
import shutil
import tempfile
import uuid
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.models.audit_chain import AuditVerificationStatus
from app.security.audit_key import AuditKeyManager
from app.security.audit_storage import AuditLedgerStorage
from app.security.external_checkpoint import (
    BaseCheckpointProvider,
    CheckpointError,
    InMemoryExternalCheckpointProvider,
    SignedExternalHttpCheckpointProvider,
    TrustedCheckpoint,
)
from app.services.audit_chain_service import AuditChainService


client = TestClient(app)


class TestAuditCheckpointAdversarial:
    """Comprehensive adversarial test suite for Phase C audit checkpointing."""

    def test_unconfigured_provider_fails_closed_when_mandatory(self, monkeypatch):
        """When QS_REQUIRE_EXTERNAL_CHECKPOINT=true and provider is unconfigured,

        audit record creation must fail closed (raise CheckpointError).
        """
        monkeypatch.setenv("QS_REQUIRE_EXTERNAL_CHECKPOINT", "true")
        unconfigured_provider = SignedExternalHttpCheckpointProvider(endpoint_url="")
        assert not unconfigured_provider.is_configured()

        service = AuditChainService(checkpoint_provider=unconfigured_provider)
        assert service.is_external_checkpoint_mandatory

        with pytest.raises(CheckpointError, match="Mandatory external audit checkpointing failed"):
            service.create_audit_record(
                assessment_data={"system": "test-bank", "score": 85},
                assessment_id="TEST-FAIL-CLOSED",
                store=True,
            )

    def test_unconfigured_provider_verify_ledger_fails_closed_when_required(self):
        """When verify_ledger(require_external=True) is called with an unconfigured provider,

        it must return valid=False with EXTERNAL_ANCHOR_UNAVAILABLE.
        """
        unconfigured_provider = SignedExternalHttpCheckpointProvider(endpoint_url="")
        service = AuditChainService(checkpoint_provider=unconfigured_provider)

        # Create one local record with optional anchoring disabled
        service.create_audit_record(
            assessment_data={"system": "test-bank"},
            assessment_id="TEST-SYS-1",
            store=True,
            auto_checkpoint=False,
        )

        res = service.verify_ledger(require_external=True)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.EXTERNAL_ANCHOR_UNAVAILABLE.value
        assert "unconfigured" in res.error.lower()

    def test_provider_timeout_verify_ledger_fails_closed_when_required(self):
        """When provider times out during verification and require_external=True,

        verify_ledger must fail closed.
        """
        mock_provider = MagicMock(spec=BaseCheckpointProvider)
        mock_provider.is_configured.return_value = True
        mock_provider.get_latest_checkpoint.side_effect = CheckpointError("Connection timed out after 5.0s")

        service = AuditChainService(checkpoint_provider=mock_provider)
        service.create_audit_record(
            assessment_data={"system": "test-bank"},
            assessment_id="TEST-TIMEOUT",
            store=True,
            auto_checkpoint=False,
        )

        res = service.verify_ledger(require_external=True)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.EXTERNAL_ANCHOR_UNAVAILABLE.value
        assert "timed out" in res.error.lower()

    def test_provider_http_500_verify_ledger_fails_closed_when_required(self):
        """When provider returns HTTP 500 and require_external=True,

        verify_ledger must fail closed.
        """
        mock_provider = MagicMock(spec=BaseCheckpointProvider)
        mock_provider.is_configured.return_value = True
        mock_provider.get_latest_checkpoint.side_effect = CheckpointError(
            "Remote external checkpoint query failed with HTTP 500: Internal Server Error"
        )

        service = AuditChainService(checkpoint_provider=mock_provider)
        service.create_audit_record(
            assessment_data={"system": "test-bank"},
            assessment_id="TEST-HTTP-500",
            store=True,
            auto_checkpoint=False,
        )

        res = service.verify_ledger(require_external=True)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.EXTERNAL_ANCHOR_UNAVAILABLE.value
        assert "HTTP 500" in res.error

    def test_invalid_checkpoint_signature_rejected_by_http_provider(self):
        """SignedExternalHttpCheckpointProvider must reject responses whose HMAC signature

        does not match the checkpoint payload.
        """
        key = b"super-secret-checkpoint-key-32b!"
        provider = SignedExternalHttpCheckpointProvider(
            endpoint_url="http://fake-anchor.local",
            signing_key=key,
        )

        tampered_checkpoint = TrustedCheckpoint(
            checkpoint_id=str(uuid.uuid4()),
            sequence_number=1,
            head_hash="a" * 64,
            record_count=1,
            timestamp="2026-11-21T00:00:00Z",
            signature="deadbeef" * 8,  # Invalid HMAC signature
            provider_type="HTTP_REMOTE",
        )

        # Provider verify_signature must return False
        assert provider.verify_signature(tampered_checkpoint) is False

    def test_invalid_checkpoint_signature_detected_in_verify_ledger(self):
        """When the external checkpoint has a forged or invalid signature,

        verify_ledger must return EXTERNAL_ANCHOR_INVALID.
        """
        provider = InMemoryExternalCheckpointProvider(signing_key=b"legit-secret-key-32b-padding!!")
        service = AuditChainService(checkpoint_provider=provider)

        service.create_audit_record(
            assessment_data={"system": "core-banking", "account": "1234"},
            assessment_id="SYS-SIG-TEST",
            store=True,
            auto_checkpoint=True,
        )

        # Corrupt the signature on the stored checkpoint
        assert len(provider._checkpoints) > 0
        legit_chk = provider._checkpoints[-1]
        corrupted_chk = legit_chk.model_copy(update={"signature": "badf00d" * 8})
        provider._checkpoints[-1] = corrupted_chk

        res = service.verify_ledger(require_external=True)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.EXTERNAL_ANCHOR_INVALID.value
        assert "signature verification failed" in res.error.lower()

    def test_checkpoint_replay_attack_rejected(self):
        """Replay attack: submitting an older or identical sequence number must be rejected."""
        provider = InMemoryExternalCheckpointProvider(signing_key=b"replay-test-key-32b-padding!!")

        chk1 = TrustedCheckpoint(
            checkpoint_id=str(uuid.uuid4()),
            sequence_number=1,
            head_hash="1" * 64,
            record_count=1,
            timestamp="2026-11-21T00:00:00Z",
            provider_type="IN_MEMORY",
        )
        provider.save_checkpoint(chk1)

        # Attempt to save checkpoint with same sequence_number=1 (replay)
        chk_replay = TrustedCheckpoint(
            checkpoint_id=str(uuid.uuid4()),
            sequence_number=1,
            head_hash="2" * 64,
            record_count=2,
            timestamp="2026-11-21T00:01:00Z",
            provider_type="IN_MEMORY",
        )
        with pytest.raises(CheckpointError, match="Replay detected"):
            provider.save_checkpoint(chk_replay)

    def test_checkpoint_head_hash_divergence_detected(self):
        """Chain divergence / rollback: when the external checkpoint anchors a hash

        different from what is present at that position in the ledger,
        verify_ledger must report LEDGER_ROLLBACK_DETECTED.
        """
        provider = InMemoryExternalCheckpointProvider(signing_key=b"hash-mismatch-key-32b-padding!")
        service = AuditChainService(checkpoint_provider=provider)

        rec = service.create_audit_record(
            assessment_data={"system": "core-banking", "balance": 1000},
            assessment_id="SYS-DIVERGENCE",
            store=True,
            auto_checkpoint=True,
        )

        # Tamper with the anchored checkpoint head hash to simulate divergence
        divergent_hash = "f" * 64
        divergent_sig = provider.compute_signature(2, divergent_hash, 1, "2026-11-21T00:00:00Z")
        divergent_chk = TrustedCheckpoint(
            checkpoint_id=str(uuid.uuid4()),
            sequence_number=2,  # valid higher sequence
            head_hash=divergent_hash,
            record_count=1,
            timestamp="2026-11-21T00:00:00Z",
            signature=divergent_sig,
            provider_type="IN_MEMORY",
        )
        provider.save_checkpoint(divergent_chk)

        res = service.verify_ledger(require_external=True)
        assert res.valid is False
        assert res.status == AuditVerificationStatus.LEDGER_ROLLBACK_DETECTED.value
        assert "chain divergence detected" in res.error.lower()

    def test_checkpoint_suffix_truncation_detected(self):
        """Suffix truncation: when records are truncated from the database,

        the record count is less than the external checkpoint record count,
        causing LEDGER_SUFFIX_TRUNCATION_DETECTED.
        """
        temp_dir = tempfile.mkdtemp()
        try:
            storage = AuditLedgerStorage(data_dir=Path(temp_dir), db_filename="trunc_test.db")
            provider = InMemoryExternalCheckpointProvider(signing_key=b"truncation-test-key-32b-pad!!")
            service = AuditChainService(storage=storage, checkpoint_provider=provider)

            # Add two records
            service.create_audit_record(
                assessment_data={"item": 1},
                assessment_id="SYS-TRUNC-1",
                store=True,
                auto_checkpoint=True,
            )
            service.create_audit_record(
                assessment_data={"item": 2},
                assessment_id="SYS-TRUNC-2",
                store=True,
                auto_checkpoint=True,
            )

            # Checkpoint anchors 2 records
            latest_chk = provider.get_latest_checkpoint()
            assert latest_chk is not None
            assert latest_chk.record_count == 2

            # Now tamper directly with the database to delete the second record
            with storage._get_connection() as conn:
                conn.execute("DELETE FROM audit_records WHERE sequence_number = 2")
                conn.commit()

            # verify_ledger must detect that stored records (1) < external anchor count (2)
            res = service.verify_ledger(require_external=True)
            assert res.valid is False
            assert res.status == AuditVerificationStatus.LEDGER_SUFFIX_TRUNCATION_DETECTED.value
            assert "suffix truncation detected" in res.error.lower()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_audit_get_endpoints_are_strictly_read_only(self):
        """GET /api/audit/ledger and GET /api/audit/head must never mutate the ledger state."""
        # Initial head check
        res_head_init = client.get("/api/audit/head")
        assert res_head_init.status_code == 200
        head_data_init = res_head_init.json()

        res_ledger_init = client.get("/api/audit/ledger?limit=100")
        assert res_ledger_init.status_code == 200
        ledger_data_init = res_ledger_init.json()
        initial_total = ledger_data_init["total"]

        # Call GET endpoints multiple times
        for _ in range(5):
            h_res = client.get("/api/audit/head")
            assert h_res.status_code == 200
            l_res = client.get("/api/audit/ledger?limit=100")
            assert l_res.status_code == 200

        # Verify state is unchanged
        res_head_after = client.get("/api/audit/head")
        assert res_head_after.status_code == 200
        assert res_head_after.json() == head_data_init

        res_ledger_after = client.get("/api/audit/ledger?limit=100")
        assert res_ledger_after.status_code == 200
        assert res_ledger_after.json()["total"] == initial_total
        assert len(res_ledger_after.json()["records"]) == len(ledger_data_init["records"])

    def test_checkpoint_persistence_across_service_restart(self, monkeypatch):
        """External checkpoint and SQLite ledger verify cleanly across service restarts."""
        temp_dir = tempfile.mkdtemp()
        monkeypatch.setenv("QS_AUDIT_SIGNING_KEY", "persistence-audit-key-32b-padding!!")
        try:
            key_mgr = AuditKeyManager(data_dir=Path(temp_dir))
            provider = InMemoryExternalCheckpointProvider(signing_key=b"pers-checkpoint-key-32b-pad!!")

            # First service lifecycle
            storage1 = AuditLedgerStorage(data_dir=Path(temp_dir), db_filename="pers_test.db")
            svc1 = AuditChainService(storage=storage1, key_manager=key_mgr, checkpoint_provider=provider)
            svc1.create_audit_record(
                assessment_data={"system": "pers-sys", "data": "initial"},
                assessment_id="SYS-PERS-1",
                store=True,
                auto_checkpoint=True,
            )
            v1 = svc1.verify_ledger(require_external=True)
            assert v1.valid is True
            assert v1.status == AuditVerificationStatus.EXTERNALLY_ANCHORED.value

            # Second service lifecycle: new instances connected to same db and checkpoint provider
            storage2 = AuditLedgerStorage(data_dir=Path(temp_dir), db_filename="pers_test.db")
            svc2 = AuditChainService(storage=storage2, key_manager=key_mgr, checkpoint_provider=provider)
            v2 = svc2.verify_ledger(require_external=True)
            assert v2.valid is True
            assert v2.status == AuditVerificationStatus.EXTERNALLY_ANCHORED.value
            assert v2.records_checked == 1
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
