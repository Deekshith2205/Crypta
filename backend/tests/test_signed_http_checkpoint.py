"""Tests for SignedExternalHttpCheckpointProvider with a real local HTTP server (Task C10).

Verifies all 12 required scenarios:
1. Successful checkpoint submission.
2. Correct HMAC signature generation.
3. Invalid signature rejection.
4. HTTP 400 response.
5. HTTP 401/403 response.
6. HTTP 500 response.
7. Connection timeout.
8. Connection refused.
9. Malformed response.
10. Duplicate checkpoint submission.
11. Sequence mismatch.
12. Provider unavailable during mandatory anchoring.

And verifies that the HTTP provider is genuinely invoked by the production audit lifecycle.
"""

import hashlib
import hmac
import http.server
import json
import os
import socket
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
import pytest

from app.models.audit_chain import AuditRecord, AuditVerificationStatus
from app.security.audit_key import AuditKeyManager
from app.security.audit_storage import AuditLedgerStorage
from app.security.external_checkpoint import (
    SignedExternalHttpCheckpointProvider,
    TrustedCheckpoint,
    CheckpointError,
)
from app.services.audit_chain_service import AuditChainService


class MockCheckpointHttpHandler(http.server.BaseHTTPRequestHandler):
    """Local HTTP handler simulating a remote append-only audit vault."""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress standard logging to keep test output clean
        pass

    @property
    def server_state(self) -> Dict[str, Any]:
        return self.server.state  # type: ignore

    def do_POST(self) -> None:
        state = self.server_state
        mode = state.get("mode", "normal")

        # Always drain incoming request body on Windows so TCP socket doesn't abort
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""

        if mode == "delay":
            time.sleep(state.get("delay_seconds", 2.0))

        if mode == "status_400":
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Bad Request")
            return

        if mode == "status_401":
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        if mode == "status_403":
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return

        if mode == "status_500":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
            return

        if self.path == "/checkpoints":
            sig = self.headers.get("X-Checkpoint-Signature", "")

            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_response(400)
                self.end_headers()
                return

            # Check for sequence mismatch or duplicate replay
            checkpoints: List[Dict[str, Any]] = state["checkpoints"]
            if checkpoints:
                last = checkpoints[-1]
                if data["sequence_number"] <= last["sequence_number"]:
                    self.send_response(409)
                    self.end_headers()
                    self.wfile.write(b"Conflict: sequence mismatch or duplicate")
                    return

            state["received_signatures"].append(sig)
            state["received_payloads"].append(data)
            checkpoints.append(data)

            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "CREATED", "checkpoint_id": data.get("checkpoint_id")}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:
        state = self.server_state
        mode = state.get("mode", "normal")

        if mode == "delay":
            time.sleep(state.get("delay_seconds", 2.0))

        if mode == "malformed":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{broken_json: true,,")
            return

        if mode == "status_500":
            self.send_response(500)
            self.end_headers()
            return

        if self.path == "/checkpoints/latest":
            checkpoints = state["checkpoints"]
            if not checkpoints:
                self.send_response(404)
                self.end_headers()
                return

            latest = dict(checkpoints[-1])
            if mode == "corrupt_sig":
                latest["signature"] = "deadbeef" * 8

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(latest).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def http_checkpoint_server():
    """Spins up a lightweight local HTTP server on a random free port for checkpoint testing."""
    server = http.server.HTTPServer(("127.0.0.1", 0), MockCheckpointHttpHandler)
    server.state = {  # type: ignore
        "checkpoints": [],
        "received_signatures": [],
        "received_payloads": [],
        "mode": "normal",
        "delay_seconds": 0.0,
    }
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}"
    secret_key = b"test-external-vault-secret-key-32b"

    yield server, url, secret_key

    server.shutdown()
    server.server_close()


# ============================================================================
# C10 Tests: Scenarios 1 to 12
# ============================================================================

def test_http_1_successful_checkpoint_submission(http_checkpoint_server):
    """1. Successful checkpoint submission over real HTTP."""
    server, url, key = http_checkpoint_server
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)
    assert provider.is_configured() is True
    assert provider.get_status() == "OPERATIONAL"

    chk = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=1,
        head_hash="a" * 64,
        record_count=5,
        timestamp="2026-11-21T12:00:00Z",
    )
    result = provider.save_checkpoint(chk)
    assert result is True

    # Retrieve and verify
    latest = provider.get_latest_checkpoint()
    assert latest is not None
    assert latest.checkpoint_id == chk.checkpoint_id
    assert latest.sequence_number == 1
    assert latest.head_hash == "a" * 64
    assert latest.record_count == 5


def test_http_2_correct_hmac_signature_generation(http_checkpoint_server):
    """2. Correct HMAC signature generation verified by remote recipient."""
    server, url, key = http_checkpoint_server
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)

    ts = "2026-11-21T12:00:00Z"
    chk = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=1,
        head_hash="b" * 64,
        record_count=10,
        timestamp=ts,
    )
    provider.save_checkpoint(chk)

    # Calculate expected signature independently
    expected_material = f"1:{'b'*64}:10:{ts}".encode("utf-8")
    expected_sig = hmac.new(key, expected_material, hashlib.sha256).hexdigest()

    # Verify server received this exact signature
    assert len(server.state["received_signatures"]) == 1  # type: ignore
    assert server.state["received_signatures"][0] == expected_sig  # type: ignore


def test_http_3_invalid_signature_rejection(http_checkpoint_server):
    """3. Invalid signature rejection when retrieving checkpoint from remote vault."""
    server, url, key = http_checkpoint_server
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)

    chk = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=1,
        head_hash="c" * 64,
        record_count=3,
        timestamp="2026-11-21T12:00:00Z",
    )
    provider.save_checkpoint(chk)

    # Server now returns corrupted signature on GET
    server.state["mode"] = "corrupt_sig"  # type: ignore
    with pytest.raises(CheckpointError) as exc:
        provider.get_latest_checkpoint()
    assert "signature verification failed" in str(exc.value).lower()


def test_http_4_http_400_response(http_checkpoint_server):
    """4. HTTP 400 Bad Request error handled safely."""
    server, url, key = http_checkpoint_server
    server.state["mode"] = "status_400"  # type: ignore
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)

    chk = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=1,
        head_hash="d" * 64,
        record_count=1,
        timestamp="2026-11-21T12:00:00Z",
    )
    with pytest.raises(CheckpointError) as exc:
        provider.save_checkpoint(chk)
    assert "400" in str(exc.value)


def test_http_5_http_401_403_response(http_checkpoint_server):
    """5. HTTP 401 Unauthorized / 403 Forbidden responses handled safely."""
    server, url, key = http_checkpoint_server
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)

    chk = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=1,
        head_hash="e" * 64,
        record_count=1,
        timestamp="2026-11-21T12:00:00Z",
    )

    # 401
    server.state["mode"] = "status_401"  # type: ignore
    with pytest.raises(CheckpointError) as exc401:
        provider.save_checkpoint(chk)
    assert "401" in str(exc401.value)

    # 403
    server.state["mode"] = "status_403"  # type: ignore
    with pytest.raises(CheckpointError) as exc403:
        provider.save_checkpoint(chk)
    assert "403" in str(exc403.value)


def test_http_6_http_500_response(http_checkpoint_server):
    """6. HTTP 500 Internal Server Error handled safely."""
    server, url, key = http_checkpoint_server
    server.state["mode"] = "status_500"  # type: ignore
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)

    chk = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=1,
        head_hash="f" * 64,
        record_count=1,
        timestamp="2026-11-21T12:00:00Z",
    )
    with pytest.raises(CheckpointError) as exc:
        provider.save_checkpoint(chk)
    assert "500" in str(exc.value)


def test_http_7_connection_timeout(http_checkpoint_server):
    """7. Connection timeout handled safely."""
    server, url, key = http_checkpoint_server
    server.state["mode"] = "delay"  # type: ignore
    server.state["delay_seconds"] = 1.0  # type: ignore

    # Provider with tight 0.1s timeout
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=0.1)

    chk = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=1,
        head_hash="0" * 64,
        record_count=1,
        timestamp="2026-11-21T12:00:00Z",
    )
    with pytest.raises(CheckpointError) as exc:
        provider.save_checkpoint(chk)
    assert "failed" in str(exc.value).lower()


def test_http_8_connection_refused():
    """8. Connection refused handled safely (unbound port)."""
    # Pick a port that is guaranteed closed
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    closed_port = sock.getsockname()[1]
    sock.close()

    provider = SignedExternalHttpCheckpointProvider(
        endpoint_url=f"http://127.0.0.1:{closed_port}",
        signing_key=b"test-key-32-bytes-long-for-hmac-sha256",
        timeout_seconds=0.5,
    )
    chk = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=1,
        head_hash="1" * 64,
        record_count=1,
        timestamp="2026-11-21T12:00:00Z",
    )
    with pytest.raises(CheckpointError) as exc:
        provider.save_checkpoint(chk)
    assert "failed" in str(exc.value).lower()


def test_http_9_malformed_response(http_checkpoint_server):
    """9. Malformed non-JSON response from server on query."""
    server, url, key = http_checkpoint_server
    server.state["mode"] = "malformed"  # type: ignore
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)

    with pytest.raises(CheckpointError) as exc:
        provider.get_latest_checkpoint()
    assert "unable to reach" in str(exc.value).lower() or "malformed" in str(exc.value).lower()


def test_http_10_duplicate_checkpoint_submission(http_checkpoint_server, tmp_path):
    """10. Duplicate checkpoint submission prevented via audit service idempotency."""
    server, url, key = http_checkpoint_server
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)
    storage = AuditLedgerStorage(data_dir=tmp_path / "data", db_filename="audit_ledger.db")
    km = AuditKeyManager(data_dir=tmp_path / "keys")
    svc = AuditChainService(storage=storage, key_manager=km, checkpoint_provider=provider)

    r1 = svc.create_audit_record({"test": 1}, assessment_id="SYS-1", store=True)

    # First explicit checkpoint creation: sends HTTP POST
    chk1 = svc.create_external_checkpoint()
    assert chk1 is not None
    assert len(server.state["received_payloads"]) == 1  # type: ignore

    # Second explicit checkpoint creation for unchanged ledger: idempotent, does not resend
    chk2 = svc.create_external_checkpoint()
    assert chk2 is not None
    assert chk2.checkpoint_id == chk1.checkpoint_id
    assert len(server.state["received_payloads"]) == 1  # type: ignore (no duplicate post!)


def test_http_11_sequence_mismatch(http_checkpoint_server):
    """11. Sequence mismatch or replay attempt rejected."""
    server, url, key = http_checkpoint_server
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)

    chk1 = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=5,
        head_hash="5" * 64,
        record_count=5,
        timestamp="2026-11-21T12:00:00Z",
    )
    provider.save_checkpoint(chk1)

    # Attempt to submit an older sequence number (sequence 4 <= 5) -> server returns 409 Conflict
    chk_old = TrustedCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        sequence_number=4,
        head_hash="4" * 64,
        record_count=4,
        timestamp="2026-11-21T12:00:00Z",
    )
    with pytest.raises(CheckpointError) as exc:
        provider.save_checkpoint(chk_old)
    assert "409" in str(exc.value) or "failed" in str(exc.value)


def test_http_12_provider_unavailable_during_mandatory_anchoring(http_checkpoint_server, tmp_path, monkeypatch):
    """12. When QS_REQUIRE_EXTERNAL_CHECKPOINT=True and provider is unavailable, fail safely."""
    monkeypatch.setenv("QS_REQUIRE_EXTERNAL_CHECKPOINT", "true")
    server, url, key = http_checkpoint_server
    # Server returns 500
    server.state["mode"] = "status_500"  # type: ignore

    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)
    storage = AuditLedgerStorage(data_dir=tmp_path / "data", db_filename="audit_ledger.db")
    km = AuditKeyManager(data_dir=tmp_path / "keys")
    svc = AuditChainService(storage=storage, key_manager=km, checkpoint_provider=provider)

    assert svc.is_external_checkpoint_mandatory is True

    # Storing a record with mandatory external checkpointing enabled must fail safely
    with pytest.raises(CheckpointError) as exc:
        svc.create_audit_record({"scan": "mandatory"}, assessment_id="SYS-FAIL", store=True)
    assert "mandatory" in str(exc.value).lower()

    # Ledger verification must report EXTERNAL_ANCHOR_UNAVAILABLE and valid=False
    res = svc.verify_ledger()
    assert res.valid is False
    assert res.status == AuditVerificationStatus.EXTERNAL_ANCHOR_UNAVAILABLE.value


# ============================================================================
# Production Audit Lifecycle Verification
# ============================================================================

def test_http_provider_invoked_by_production_audit_lifecycle(http_checkpoint_server, tmp_path):
    """Verifies that the SignedExternalHttpCheckpointProvider is genuinely invoked
    during report sealing in the production audit lifecycle.
    """
    server, url, key = http_checkpoint_server
    provider = SignedExternalHttpCheckpointProvider(endpoint_url=url, signing_key=key, timeout_seconds=3.0)
    storage = AuditLedgerStorage(data_dir=tmp_path / "data", db_filename="audit_ledger.db")
    km = AuditKeyManager(data_dir=tmp_path / "keys")
    svc = AuditChainService(storage=storage, key_manager=km, checkpoint_provider=provider)

    from app.services.report_service import build_complete_json_report

    # Seal report using our HTTP-anchored service
    report = build_complete_json_report("CORE-BANKING-01", seal_audit=True, audit_service=svc)

    assert report.audit is not None
    # Verify the local HTTP test server actually received the checkpoint via HTTP POST
    assert len(server.state["received_payloads"]) == 1  # type: ignore
    received_chk = server.state["received_payloads"][0]  # type: ignore

    assert received_chk["record_count"] == 1
    assert received_chk["head_hash"] == report.audit.current_hash
    assert received_chk["sequence_number"] == 1

    # Full ledger verification must return EXTERNALLY_ANCHORED
    verify_res = svc.verify_ledger()
    assert verify_res.valid is True
    assert verify_res.status == AuditVerificationStatus.EXTERNALLY_ANCHORED.value
    assert verify_res.details.get("external_anchor") == "VERIFIED"
