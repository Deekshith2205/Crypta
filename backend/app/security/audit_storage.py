"""Persistent SQLite Audit Storage (Task C2).
Provides ACID-compliant, thread-safe, persistent ledger storage for audit hash chains.
"""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from app.models.audit_chain import AuditRecord
from app.security.audit_key import get_default_data_dir

GENESIS_HASH: str = "0" * 64


class AuditStorageError(Exception):
    """Raised when an audit storage operation fails or violates ledger integrity."""
    pass


class AuditLedgerStorage:
    """
    SQLite-backed storage manager for the audit ledger.
    - Thread-safe using SQLite connection and threading.Lock.
    - Preserves records across process restarts.
    - Enforces unique record_ids and indexed queries.
    - Records checkpoints for ledger truncation detection.
    """

    DB_FILENAME = "audit_ledger.db"

    def __init__(self, data_dir: Optional[Path] = None, db_filename: Optional[str] = None):
        self._data_dir = Path(data_dir).resolve() if data_dir else get_default_data_dir()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_dir / (db_filename or self.DB_FILENAME)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
                timeout=30.0,
            )
            self._conn.row_factory = sqlite3.Row
            # Enable WAL mode and foreign keys
            with self._conn:
                self._conn.execute("PRAGMA journal_mode = WAL;")
                self._conn.execute("PRAGMA foreign_keys = ON;")
        return self._conn

    def _init_db(self) -> None:
        """Initializes tables and indexes safely."""
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_records (
                        sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                        record_id TEXT UNIQUE NOT NULL,
                        assessment_id TEXT NOT NULL,
                        assessment_hash TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        current_hash TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        schema_version TEXT NOT NULL,
                        canonical_payload TEXT
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_record_id ON audit_records(record_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_assessment_id ON audit_records(assessment_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_records(timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_current_hash ON audit_records(current_hash);")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_checkpoints (
                        checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        head_hash TEXT NOT NULL,
                        record_count INTEGER NOT NULL,
                        timestamp TEXT NOT NULL
                    );
                """)

    def append_record(self, record: AuditRecord) -> AuditRecord:
        """Appends a new audit record atomically within a database transaction."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO audit_records (
                            record_id,
                            assessment_id,
                            assessment_hash,
                            previous_hash,
                            current_hash,
                            signature,
                            timestamp,
                            schema_version,
                            canonical_payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            record.record_id,
                            record.assessment_id,
                            record.assessment_hash,
                            record.previous_hash,
                            record.current_hash,
                            record.signature,
                            record.timestamp,
                            record.schema_version,
                            record.canonical_payload,
                        ),
                    )
                return record
            except sqlite3.IntegrityError as e:
                raise AuditStorageError(f"Audit record with id '{record.record_id}' already exists: {e}") from e
            except sqlite3.Error as e:
                raise AuditStorageError(f"Database error writing audit record: {e}") from e

    def get_record_by_id(self, record_id: str) -> Optional[AuditRecord]:
        """Queries a record by record_id."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT * FROM audit_records WHERE record_id = ? LIMIT 1;",
                (record_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_record(row)

    def get_latest_record(self) -> Optional[AuditRecord]:
        """Queries the latest record by sequence_number."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT * FROM audit_records ORDER BY sequence_number DESC LIMIT 1;"
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_record(row)

    def get_latest_hash(self) -> str:
        """Returns the current_hash of the latest record or GENESIS_HASH."""
        latest = self.get_latest_record()
        return latest.current_hash if latest else GENESIS_HASH

    def get_records(
        self,
        limit: int = 50,
        offset: int = 0,
        assessment_id: Optional[str] = None,
    ) -> List[AuditRecord]:
        """Queries a slice of audit records in ascending sequence order."""
        with self._lock:
            conn = self._get_connection()
            if assessment_id:
                cursor = conn.execute(
                    """
                    SELECT * FROM audit_records
                    WHERE assessment_id = ?
                    ORDER BY sequence_number ASC
                    LIMIT ? OFFSET ?;
                    """,
                    (assessment_id, limit, offset),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM audit_records
                    ORDER BY sequence_number ASC
                    LIMIT ? OFFSET ?;
                    """,
                    (limit, offset),
                )
            return [self._row_to_record(row) for row in cursor.fetchall()]

    def get_record_count(self, assessment_id: Optional[str] = None) -> int:
        """Returns total records in the ledger."""
        with self._lock:
            conn = self._get_connection()
            if assessment_id:
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM audit_records WHERE assessment_id = ?;",
                    (assessment_id,),
                )
            else:
                cursor = conn.execute("SELECT COUNT(*) FROM audit_records;")
            return cursor.fetchone()[0]

    def create_checkpoint(self) -> Dict[str, Any]:
        """Creates an anchor checkpoint of the current ledger head."""
        with self._lock:
            conn = self._get_connection()
            count = self.get_record_count()
            head_hash = self.get_latest_hash()
            now_ts = datetime.now(timezone.utc).isoformat()
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO audit_checkpoints (head_hash, record_count, timestamp)
                    VALUES (?, ?, ?);
                    """,
                    (head_hash, count, now_ts),
                )
                chk_id = cursor.lastrowid
            return {
                "checkpoint_id": chk_id,
                "head_hash": head_hash,
                "record_count": count,
                "timestamp": now_ts,
            }

    def get_latest_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Retrieves the most recent anchor checkpoint."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT * FROM audit_checkpoints ORDER BY checkpoint_id DESC LIMIT 1;"
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "checkpoint_id": row["checkpoint_id"],
                "head_hash": row["head_hash"],
                "record_count": row["record_count"],
                "timestamp": row["timestamp"],
            }

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> AuditRecord:
        return AuditRecord(
            record_id=row["record_id"],
            assessment_id=row["assessment_id"],
            assessment_hash=row["assessment_hash"],
            previous_hash=row["previous_hash"],
            current_hash=row["current_hash"],
            signature=row["signature"] if "signature" in row.keys() else "",
            timestamp=row["timestamp"],
            schema_version=row["schema_version"],
            canonical_payload=row["canonical_payload"],
        )

    def close(self) -> None:
        """Closes the underlying database connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


# Singleton instance
DEFAULT_AUDIT_STORAGE = AuditLedgerStorage()
