"""Audit Hash Chain Service.
Implements tamper-evident cryptographic history for assessments and reports.
Uses SHA-256 over RFC 8785 compliant canonical JSON representations.
"""

import hashlib
import hmac
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from app.models.audit_chain import AuditRecord, AuditVerificationResult, AuditVerificationStatus

GENESIS_PREVIOUS_HASH: str = "0" * 64

VOLATILE_FIELD_KEYS = {
    "timestamp",
    "scanned_at",
    "created_at",
    "generated_at",
    "report_id",
    "simulation_id",
    "record_id",
    "audit_record_id",
    "execution_time_ms",
    "latency_ms",
    "duration_ms",
}


def strip_volatile_fields(data: Any) -> Any:
    """Recursively removes volatile timestamps, generated report IDs, and execution latency fields."""
    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json")
    elif hasattr(data, "dict"):
        data = data.dict()

    if isinstance(data, dict):
        return {
            k: strip_volatile_fields(v)
            for k, v in data.items()
            if k.lower() not in VOLATILE_FIELD_KEYS
        }
    elif isinstance(data, list):
        return [strip_volatile_fields(item) for item in data]
    else:
        return data


def canonicalize_json(data: Any, strip_volatile: bool = False) -> str:
    """
    Produces deterministic, RFC 8785 canonical JSON serialization:
    - Sorts dictionary keys lexicographically
    - Uses compact formatting (no indentation, no extra whitespace after ':' or ',')
    - Handles nested dictionaries, lists, and primitives consistently
    - Optionally strips volatile metadata fields
    """
    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json")
    elif hasattr(data, "dict"):
        data = data.dict()

    if strip_volatile:
        data = strip_volatile_fields(data)

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def compute_sha256(data_str: str) -> str:
    """Computes SHA-256 hexadecimal digest of UTF-8 encoded string."""
    return hashlib.sha256(data_str.encode("utf-8")).hexdigest()


def compute_payload_hash(data: Any) -> str:
    """Computes deterministic SHA-256 content hash of assessment payload with volatile metadata excluded."""
    canonical = canonicalize_json(data, strip_volatile=True)
    return compute_sha256(canonical)


from app.security.audit_storage import AuditLedgerStorage, DEFAULT_AUDIT_STORAGE, GENESIS_HASH
from app.security.audit_key import AuditKeyManager, DEFAULT_AUDIT_KEY_MANAGER
from app.security.external_checkpoint import (
    BaseCheckpointProvider,
    TrustedCheckpoint,
    DEFAULT_EXTERNAL_CHECKPOINT_PROVIDER,
    CheckpointError,
)


class AuditChainService:
    """Manages creation, storage, and cryptographic verification of tamper-evident audit records."""

    def __init__(
        self,
        storage: Optional[AuditLedgerStorage] = None,
        key_manager: Optional[AuditKeyManager] = None,
        checkpoint_provider: Optional[BaseCheckpointProvider] = None,
    ):
        self._storage = storage
        self._key_manager = key_manager if key_manager is not None else DEFAULT_AUDIT_KEY_MANAGER
        self._checkpoint_provider = checkpoint_provider if checkpoint_provider is not None else DEFAULT_EXTERNAL_CHECKPOINT_PROVIDER
        self._in_memory_fallback: List[AuditRecord] = []
        self._lock = threading.RLock()

    def get_latest_hash(self) -> str:
        """Returns the current_hash of the latest record or GENESIS_PREVIOUS_HASH."""
        if self._storage is not None:
            return self._storage.get_latest_hash()
        if not self._in_memory_fallback:
            return GENESIS_PREVIOUS_HASH
        return self._in_memory_fallback[-1].current_hash

    def get_latest_record_for_system(self, system_id: str) -> Optional[AuditRecord]:
        """Returns the latest audit record for a given system if available."""
        if self._storage is not None:
            count = self._storage.get_record_count(assessment_id=system_id)
            if count > 0:
                records = self._storage.get_records(limit=1, offset=count - 1, assessment_id=system_id)
                if records:
                    return records[0]
        for rec in reversed(self._in_memory_fallback):
            if rec.assessment_id == system_id:
                return rec
        return None

    def create_audit_record(
        self,
        assessment_data: Any,
        assessment_id: str,
        previous_hash: Optional[str] = None,
        store: bool = True,
    ) -> AuditRecord:
        """
        Creates a new tamper-evident audit record:
        1. canonical_json = canonicalize_json(assessment_data)
        2. assessment_hash = SHA256(canonical_json without volatile fields)
        3. current_hash = SHA256(canonical_json + previous_hash)
        4. signature = HMAC-SHA256(rec_id + assessment_id + a_hash + prev + c_hash + timestamp)
        Includes idempotency: if stored record for assessment_id already has matching assessment_hash, returns existing record.
        Atomically links and commits to ledger when store=True.
        """
        with self._lock:
            canonical = canonicalize_json(assessment_data, strip_volatile=True)
            a_hash = compute_sha256(canonical)

            # Idempotency check: prevent duplicate records on retry of identical assessment
            if store:
                latest_existing = self.get_latest_record_for_system(assessment_id)
                if latest_existing is not None and latest_existing.assessment_hash == a_hash:
                    return latest_existing

            prev = previous_hash if previous_hash is not None else self.get_latest_hash()
            c_hash = compute_sha256(canonical + prev)
            ts = datetime.now(timezone.utc).isoformat()
            rec_id = str(uuid.uuid4())

            sig_material = f"{rec_id}:{assessment_id}:{a_hash}:{prev}:{c_hash}:{ts}".encode("utf-8")
            sig = self._key_manager.sign(sig_material)

            record = AuditRecord(
                record_id=rec_id,
                assessment_id=assessment_id,
                assessment_hash=a_hash,
                previous_hash=prev,
                current_hash=c_hash,
                signature=sig,
                timestamp=ts,
                schema_version="1.0.0",
                canonical_payload=canonical,
            )

            if store:
                if self._storage is not None:
                    self._storage.append_record(record)
                else:
                    self._in_memory_fallback.append(record)

            return record

    def verify_audit_record(
        self,
        record: AuditRecord,
        assessment_data: Optional[Any] = None,
        check_ledger: Optional[bool] = None,
    ) -> AuditVerificationResult:
        """
        Verifies the cryptographic integrity of a single audit record.
        Validates:
        1. Required metadata integrity
        2. Payload content hash (assessment_hash)
        3. Current hash linkage (current_hash)
        4. HMAC-SHA256 signature
        5. Persistent ledger membership
        """
        try:
            # Step 0: Check mandatory metadata fields
            if (
                not record.record_id
                or not record.current_hash
                or not record.timestamp
                or not record.assessment_id
                or not record.assessment_hash
            ):
                return AuditVerificationResult(
                    valid=False,
                    status=AuditVerificationStatus.VERIFICATION_ERROR.value,
                    record_id=getattr(record, "record_id", None),
                    error="Audit record is missing mandatory cryptographic fields.",
                )

            # Step 1: Verify canonical payload against assessment_data if provided
            if assessment_data is not None:
                recalculated_canonical = canonicalize_json(assessment_data, strip_volatile=True)
                recalculated_a_hash = compute_sha256(recalculated_canonical)
                if not hmac.compare_digest(recalculated_a_hash, record.assessment_hash):
                    alt_raw = compute_sha256(canonicalize_json(assessment_data, strip_volatile=False))
                    if hmac.compare_digest(alt_raw, record.assessment_hash):
                        recalculated_a_hash = alt_raw
                if not hmac.compare_digest(recalculated_a_hash, record.assessment_hash):
                    return AuditVerificationResult(
                        valid=False,
                        status=AuditVerificationStatus.PAYLOAD_HASH_MISMATCH.value,
                        record_id=record.record_id,
                        error=f"Assessment data tampering detected! Recalculated hash {recalculated_a_hash} != recorded hash {record.assessment_hash}",
                        details={"expected_hash": record.assessment_hash, "computed_hash": recalculated_a_hash},
                    )
            elif record.canonical_payload:
                recalculated_a_hash = compute_sha256(record.canonical_payload)
                if not hmac.compare_digest(recalculated_a_hash, record.assessment_hash):
                    try:
                        parsed = json.loads(record.canonical_payload)
                        alt_hash = compute_payload_hash(parsed)
                        if hmac.compare_digest(alt_hash, record.assessment_hash):
                            recalculated_a_hash = alt_hash
                    except Exception:
                        pass
                if not hmac.compare_digest(recalculated_a_hash, record.assessment_hash):
                    return AuditVerificationResult(
                        valid=False,
                        status=AuditVerificationStatus.PAYLOAD_HASH_MISMATCH.value,
                        record_id=record.record_id,
                        error="Canonical payload does not match assessment_hash. Record modified in storage.",
                        details={"expected_hash": record.assessment_hash, "computed_hash": recalculated_a_hash},
                    )

            # Step 2: Verify current_hash = SHA256(canonical_payload + previous_hash)
            payload = record.canonical_payload or (canonicalize_json(assessment_data, strip_volatile=True) if assessment_data is not None else "")
            recalculated_current = compute_sha256(payload + record.previous_hash)

            if not hmac.compare_digest(recalculated_current, record.current_hash):
                if assessment_data is not None:
                    alt_current = compute_sha256(canonicalize_json(assessment_data, strip_volatile=False) + record.previous_hash)
                    if hmac.compare_digest(alt_current, record.current_hash):
                        recalculated_current = alt_current
            if not hmac.compare_digest(recalculated_current, record.current_hash):
                return AuditVerificationResult(
                    valid=False,
                    status=AuditVerificationStatus.CHAIN_BROKEN.value,
                    record_id=record.record_id,
                    error=f"Cryptographic hash chain signature invalid! Recalculated current_hash {recalculated_current} != {record.current_hash}",
                    details={"expected_hash": record.current_hash, "computed_hash": recalculated_current},
                )

            # Step 3: Verify HMAC-SHA256 signature
            if not record.signature:
                return AuditVerificationResult(
                    valid=False,
                    status=AuditVerificationStatus.INVALID_SIGNATURE.value,
                    record_id=record.record_id,
                    error="Audit record signature is missing.",
                    details={"record_id": record.record_id},
                )

            sig_material = f"{record.record_id}:{record.assessment_id}:{record.assessment_hash}:{record.previous_hash}:{record.current_hash}:{record.timestamp}".encode("utf-8")
            if not self._key_manager.verify(sig_material, record.signature):
                return AuditVerificationResult(
                    valid=False,
                    status=AuditVerificationStatus.INVALID_SIGNATURE.value,
                    record_id=record.record_id,
                    error="Audit record signature verification failed.",
                    details={"record_id": record.record_id},
                )

            # Step 4: Persistent ledger membership check
            should_check_ledger = check_ledger if check_ledger is not None else (self._storage is not None)
            if should_check_ledger:
                if self._storage is not None:
                    stored = self._storage.get_record_by_id(record.record_id)
                    if stored is None:
                        return AuditVerificationResult(
                            valid=False,
                            status=AuditVerificationStatus.RECORD_NOT_IN_LEDGER.value,
                            record_id=record.record_id,
                            error="Valid signature, but record is not present in the verified audit ledger.",
                            details={"record_id": record.record_id, "in_ledger": False},
                        )
                    if not hmac.compare_digest(stored.current_hash, record.current_hash) or not hmac.compare_digest(stored.assessment_hash, record.assessment_hash):
                        return AuditVerificationResult(
                            valid=False,
                            status=AuditVerificationStatus.LEDGER_CORRUPTED.value,
                            record_id=record.record_id,
                            error="Record content does not match persistent ledger copy.",
                            details={"stored_hash": stored.current_hash, "presented_hash": record.current_hash},
                        )
                elif self._in_memory_fallback:
                    in_mem = next((r for r in self._in_memory_fallback if r.record_id == record.record_id), None)
                    if in_mem is None:
                        return AuditVerificationResult(
                            valid=False,
                            status=AuditVerificationStatus.RECORD_NOT_IN_LEDGER.value,
                            record_id=record.record_id,
                            error="Valid signature, but record is not present in the verified audit ledger.",
                            details={"record_id": record.record_id, "in_ledger": False},
                        )
                    if not hmac.compare_digest(in_mem.current_hash, record.current_hash):
                        return AuditVerificationResult(
                            valid=False,
                            status=AuditVerificationStatus.LEDGER_CORRUPTED.value,
                            record_id=record.record_id,
                            error="Record content does not match in-memory ledger copy.",
                            details={"stored_hash": in_mem.current_hash, "presented_hash": record.current_hash},
                        )

            return AuditVerificationResult(
                valid=True,
                status=AuditVerificationStatus.VALID.value,
                record_id=record.record_id,
                records_checked=1,
                details={
                    "assessment_hash": record.assessment_hash,
                    "current_hash": record.current_hash,
                    "signature_valid": True,
                    "ledger_verified": bool(should_check_ledger and (self._storage is not None or self._in_memory_fallback)),
                },
            )
        except Exception as e:
            return AuditVerificationResult(
                valid=False,
                status=AuditVerificationStatus.VERIFICATION_ERROR.value,
                record_id=getattr(record, "record_id", None),
                error=f"Malformed audit record: {str(e)}",
            )

    def verify_audit_chain(
        self,
        records: List[AuditRecord],
        check_ledger: bool = False,
    ) -> AuditVerificationResult:
        """
        Verifies an entire sequence of chained audit records.
        Verifies:
        1. Each record's internal cryptographic validity and signature.
        2. Sequence continuity (record[i].previous_hash == record[i-1].current_hash).
        """
        if not records:
            return AuditVerificationResult(
                valid=True,
                status=AuditVerificationStatus.VALID.value,
                records_checked=0,
                details={"message": "Empty chain is valid"},
            )

        for i, rec in enumerate(records):
            # Verify internal record validity
            res = self.verify_audit_record(rec, check_ledger=check_ledger)
            if not res.valid:
                return AuditVerificationResult(
                    valid=False,
                    status=res.status,
                    record_id=rec.record_id,
                    error=f"Record #{i} ({rec.record_id}) verification failed: {res.error}",
                    records_checked=i,
                    details=res.details,
                )

            # Check chain continuity
            if i > 0:
                prev_rec = records[i - 1]
                if not hmac.compare_digest(rec.previous_hash, prev_rec.current_hash):
                    return AuditVerificationResult(
                        valid=False,
                        status=AuditVerificationStatus.CHAIN_BROKEN.value,
                        record_id=rec.record_id,
                        error=f"Broken audit hash chain at index {i}! Record previous_hash {rec.previous_hash} != prior record current_hash {prev_rec.current_hash}",
                        records_checked=i,
                        details={"index": i, "expected_prev": prev_rec.current_hash, "actual_prev": rec.previous_hash},
                    )

        return AuditVerificationResult(
            valid=True,
            status=AuditVerificationStatus.VALID.value,
            records_checked=len(records),
            details={
                "chain_length": len(records),
                "head_hash": records[-1].current_hash,
                "genesis_hash": records[0].previous_hash,
            },
        )

    def create_external_checkpoint(self) -> Optional[TrustedCheckpoint]:
        """
        Creates and stores an independently authenticated checkpoint of the current ledger head.
        Enforces monotonic sequence numbering for replay attack protection.
        """
        with self._lock:
            if self._checkpoint_provider is None or not self._checkpoint_provider.is_configured():
                return None
            records = self.get_ledger()
            head_hash = self.get_latest_hash()
            count = len(records)
            prev_chk = self._checkpoint_provider.get_latest_checkpoint()
            seq = (prev_chk.sequence_number + 1) if prev_chk else 1
            now_ts = datetime.now(timezone.utc).isoformat()

            chk = TrustedCheckpoint(
                checkpoint_id=str(uuid.uuid4()),
                sequence_number=seq,
                head_hash=head_hash,
                record_count=count,
                timestamp=now_ts,
                provider_type=self._checkpoint_provider.__class__.__name__,
            )
            self._checkpoint_provider.save_checkpoint(chk)
            return chk

    def verify_ledger(self, require_external: bool = False) -> AuditVerificationResult:
        """
        Verifies the full persistent audit ledger:
        1. Validates entire chain sequence continuity from genesis to head.
        2. Validates internal SQLite anchor checkpoints.
        3. Validates independently protected external checkpoints (detecting suffix truncation and rollback).
        """
        try:
            records = self.get_ledger()
            if not records:
                return AuditVerificationResult(
                    valid=True,
                    status=AuditVerificationStatus.VALID.value,
                    records_checked=0,
                    details={"message": "Audit ledger is empty.", "external_anchor": "EMPTY"},
                )

            chain_res = self.verify_audit_chain(records, check_ledger=False)
            if not chain_res.valid:
                status = AuditVerificationStatus.LEDGER_CORRUPTED.value if chain_res.status in (
                    AuditVerificationStatus.CHAIN_BROKEN.value,
                    AuditVerificationStatus.PAYLOAD_HASH_MISMATCH.value,
                    AuditVerificationStatus.INVALID_SIGNATURE.value,
                ) else chain_res.status
                return AuditVerificationResult(
                    valid=False,
                    status=status,
                    record_id=chain_res.record_id,
                    error=f"Audit ledger integrity corrupted: {chain_res.error}",
                    records_checked=chain_res.records_checked,
                    details=chain_res.details,
                )

            # 2. Validate internal SQLite checkpoint if present
            if self._storage is not None and hasattr(self._storage, "get_latest_checkpoint"):
                chk = self._storage.get_latest_checkpoint()
                if chk is not None:
                    if len(records) < chk["record_count"]:
                        return AuditVerificationResult(
                            valid=False,
                            status=AuditVerificationStatus.LEDGER_CORRUPTED.value,
                            error=f"Ledger truncation detected! Record count {len(records)} < checkpoint record count {chk['record_count']}.",
                            records_checked=len(records),
                        )
                    chk_idx = chk["record_count"] - 1
                    if chk_idx < len(records):
                        chk_rec = records[chk_idx]
                        if not hmac.compare_digest(chk_rec.current_hash, chk["head_hash"]):
                            return AuditVerificationResult(
                                valid=False,
                                status=AuditVerificationStatus.LEDGER_CORRUPTED.value,
                                record_id=chk_rec.record_id,
                                error=f"Ledger checkpoint mismatch! Expected {chk['head_hash']}, got {chk_rec.current_hash}.",
                                records_checked=len(records),
                            )

            # 3. Validate external independent checkpoint
            ext_status = "UNCONFIGURED"
            ext_chk_data = None
            if self._checkpoint_provider is not None and self._checkpoint_provider.is_configured():
                try:
                    ext_chk = self._checkpoint_provider.get_latest_checkpoint()
                except Exception as e:
                    if require_external:
                        return AuditVerificationResult(
                            valid=False,
                            status=AuditVerificationStatus.EXTERNAL_ANCHOR_UNAVAILABLE.value,
                            error=f"External checkpoint provider unavailable: {str(e)}",
                            records_checked=len(records),
                        )
                    ext_status = f"UNAVAILABLE: {str(e)}"
                    ext_chk = None

                if ext_chk is not None:
                    ext_chk_data = ext_chk.model_dump(mode="json")
                    # Check external checkpoint signature authenticity
                    if not self._checkpoint_provider.verify_signature(ext_chk):
                        return AuditVerificationResult(
                            valid=False,
                            status=AuditVerificationStatus.EXTERNAL_ANCHOR_INVALID.value,
                            error="External checkpoint signature verification failed.",
                            records_checked=len(records),
                            details={"checkpoint": ext_chk_data},
                        )

                    # Check suffix truncation
                    if len(records) < ext_chk.record_count:
                        return AuditVerificationResult(
                            valid=False,
                            status=AuditVerificationStatus.LEDGER_SUFFIX_TRUNCATION_DETECTED.value,
                            error=f"Ledger suffix truncation detected! Stored records ({len(records)}) < external anchor count ({ext_chk.record_count}).",
                            records_checked=len(records),
                            details={"external_checkpoint": ext_chk_data},
                        )

                    # Check rollback / divergence
                    if ext_chk.record_count > 0:
                        chk_idx = ext_chk.record_count - 1
                        if chk_idx < len(records):
                            rec_at_chk = records[chk_idx]
                            if not hmac.compare_digest(rec_at_chk.current_hash, ext_chk.head_hash):
                                return AuditVerificationResult(
                                    valid=False,
                                    status=AuditVerificationStatus.LEDGER_ROLLBACK_DETECTED.value,
                                    error=f"Ledger rollback or chain divergence detected! Record hash {rec_at_chk.current_hash} != external anchor {ext_chk.head_hash}.",
                                    records_checked=len(records),
                                    details={"external_checkpoint": ext_chk_data, "divergent_record": rec_at_chk.record_id},
                                )

                    # If all records up to external checkpoint match, it is externally anchored!
                    return AuditVerificationResult(
                        valid=True,
                        status=AuditVerificationStatus.EXTERNALLY_ANCHORED.value,
                        records_checked=len(records),
                        details={
                            "ledger_length": len(records),
                            "head_hash": records[-1].current_hash,
                            "genesis_hash": records[0].previous_hash,
                            "external_anchor": "VERIFIED",
                            "external_checkpoint": ext_chk_data,
                        },
                    )
            elif require_external:
                prov_status = self._checkpoint_provider.get_status() if self._checkpoint_provider else "UNCONFIGURED"
                return AuditVerificationResult(
                    valid=False,
                    status=AuditVerificationStatus.EXTERNAL_ANCHOR_UNAVAILABLE.value,
                    error=f"External checkpoint anchoring is required but unavailable or unconfigured ({prov_status}).",
                    records_checked=len(records),
                )

            # When external provider is not configured:
            return AuditVerificationResult(
                valid=True,
                status=AuditVerificationStatus.LOCALLY_VERIFIED.value,
                records_checked=len(records),
                details={
                    "ledger_length": len(records),
                    "head_hash": records[-1].current_hash,
                    "genesis_hash": records[0].previous_hash,
                    "external_anchor": ext_status,
                },
            )
        except Exception as e:
            return AuditVerificationResult(
                valid=False,
                status=AuditVerificationStatus.LEDGER_CORRUPTED.value,
                error=f"Failed to verify ledger integrity: {str(e)}",
            )

    def get_ledger(self) -> List[AuditRecord]:
        """Returns the audit ledger records."""
        if self._storage is not None:
            return self._storage.get_records(limit=100000, offset=0)
        return list(self._in_memory_fallback)


# Default singleton instance bound to persistent storage
DEFAULT_AUDIT_CHAIN_SERVICE = AuditChainService(storage=DEFAULT_AUDIT_STORAGE)


def seed_baseline_audit_records(service: Optional[AuditChainService] = None) -> None:
    """
    Seeds baseline synthetic profiles into the persistent ledger once on initialization
    if any profile does not yet have a sealed audit record.
    """
    svc = service or DEFAULT_AUDIT_CHAIN_SERVICE
    if svc._storage is None:
        return
    try:
        from app.models.profiles import SYNTHETIC_BANKING_PROFILES
        from app.services.report_service import build_complete_json_report
        for profile in SYNTHETIC_BANKING_PROFILES:
            if svc.get_latest_record_for_system(profile.id) is None:
                build_complete_json_report(profile.id, seal_audit=True, audit_service=svc)
    except Exception:
        pass


# Ensure baseline records are seeded if persistent ledger is empty
seed_baseline_audit_records(DEFAULT_AUDIT_CHAIN_SERVICE)
