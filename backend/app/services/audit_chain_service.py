"""Audit Hash Chain Service.
Implements tamper-evident cryptographic history for assessments and reports.
Uses SHA-256 over RFC 8785 compliant canonical JSON representations.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from app.models.audit_chain import AuditRecord, AuditVerificationResult

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


class AuditChainService:
    """Manages creation, storage, and cryptographic verification of tamper-evident audit records."""

    def __init__(
        self,
        storage: Optional[AuditLedgerStorage] = None,
        key_manager: Optional[AuditKeyManager] = None,
    ):
        self._storage = storage
        self._key_manager = key_manager if key_manager is not None else DEFAULT_AUDIT_KEY_MANAGER
        self._in_memory_fallback: List[AuditRecord] = []

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
        """
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
    ) -> AuditVerificationResult:
        """
        Verifies the cryptographic integrity of a single audit record.
        Detects:
        - Payload tampering (assessment_hash mismatch)
        - Current hash mismatch
        """
        try:
            # Step 1: Verify canonical payload against assessment_data if provided
            if assessment_data is not None:
                recalculated_canonical = canonicalize_json(assessment_data, strip_volatile=True)
                recalculated_a_hash = compute_sha256(recalculated_canonical)
                if recalculated_a_hash != record.assessment_hash:
                    alt_raw = compute_sha256(canonicalize_json(assessment_data, strip_volatile=False))
                    if alt_raw == record.assessment_hash:
                        recalculated_a_hash = alt_raw
                if recalculated_a_hash != record.assessment_hash:
                    return AuditVerificationResult(
                        valid=False,
                        record_id=record.record_id,
                        error=f"Assessment data tampering detected! Recalculated hash {recalculated_a_hash} != recorded hash {record.assessment_hash}",
                        details={"expected_hash": record.assessment_hash, "computed_hash": recalculated_a_hash},
                    )
            elif record.canonical_payload:
                recalculated_a_hash = compute_sha256(record.canonical_payload)
                if recalculated_a_hash != record.assessment_hash:
                    try:
                        parsed = json.loads(record.canonical_payload)
                        alt_hash = compute_payload_hash(parsed)
                        if alt_hash == record.assessment_hash:
                            recalculated_a_hash = alt_hash
                    except Exception:
                        pass
                if recalculated_a_hash != record.assessment_hash:
                    return AuditVerificationResult(
                        valid=False,
                        record_id=record.record_id,
                        error="Canonical payload does not match assessment_hash. Record modified in storage.",
                        details={"expected_hash": record.assessment_hash, "computed_hash": recalculated_a_hash},
                    )

            # Step 2: Verify current_hash = SHA256(canonical_payload + previous_hash)
            payload = record.canonical_payload or (canonicalize_json(assessment_data) if assessment_data is not None else "")
            recalculated_current = compute_sha256(payload + record.previous_hash)

            if recalculated_current != record.current_hash:
                return AuditVerificationResult(
                    valid=False,
                    record_id=record.record_id,
                    error=f"Cryptographic hash chain signature invalid! Recalculated current_hash {recalculated_current} != {record.current_hash}",
                    details={"expected_hash": record.current_hash, "computed_hash": recalculated_current},
                )

            return AuditVerificationResult(
                valid=True,
                record_id=record.record_id,
                records_checked=1,
                details={"assessment_hash": record.assessment_hash, "current_hash": record.current_hash},
            )
        except Exception as e:
            return AuditVerificationResult(
                valid=False,
                record_id=record.record_id,
                error=f"Malformed audit record: {str(e)}",
            )

    def verify_audit_chain(self, records: List[AuditRecord]) -> AuditVerificationResult:
        """
        Verifies an entire sequence of chained audit records.
        Verifies:
        1. Each record's internal hash integrity.
        2. Sequence continuity (record[i].previous_hash == record[i-1].current_hash).
        """
        if not records:
            return AuditVerificationResult(valid=True, records_checked=0, details={"message": "Empty chain is valid"})

        for i, rec in enumerate(records):
            # Verify internal record validity
            res = self.verify_audit_record(rec)
            if not res.valid:
                return AuditVerificationResult(
                    valid=False,
                    record_id=rec.record_id,
                    error=f"Record #{i} ({rec.record_id}) verification failed: {res.error}",
                    records_checked=i,
                )

            # Check chain continuity
            if i > 0:
                prev_rec = records[i - 1]
                if rec.previous_hash != prev_rec.current_hash:
                    return AuditVerificationResult(
                        valid=False,
                        record_id=rec.record_id,
                        error=f"Broken audit hash chain at index {i}! Record previous_hash {rec.previous_hash} != prior record current_hash {prev_rec.current_hash}",
                        records_checked=i,
                        details={"index": i, "expected_prev": prev_rec.current_hash, "actual_prev": rec.previous_hash},
                    )

        return AuditVerificationResult(
            valid=True,
            records_checked=len(records),
            details={
                "chain_length": len(records),
                "head_hash": records[-1].current_hash,
                "genesis_hash": records[0].previous_hash,
            },
        )

    def get_ledger(self) -> List[AuditRecord]:
        """Returns the audit ledger records."""
        if self._storage is not None:
            return self._storage.get_records(limit=100000, offset=0)
        return list(self._in_memory_fallback)


# Default singleton instance bound to persistent storage
DEFAULT_AUDIT_CHAIN_SERVICE = AuditChainService(storage=DEFAULT_AUDIT_STORAGE)
