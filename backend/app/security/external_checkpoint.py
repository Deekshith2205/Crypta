"""Independently Protected External Audit Checkpoints.
Provides an independent trust boundary for ledger anchoring to detect
suffix-truncation, database rollback, rewriting, and deletion attacks.
"""

import hashlib
import hmac
import json
import logging
import os
import threading
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("quantumshield.audit.checkpoint")


class TrustedCheckpoint(BaseModel):
    """
    Cryptographically authenticated checkpoint anchored outside the SQLite database.
    """
    checkpoint_id: str = Field(..., description="Unique checkpoint identifier (UUID)")
    sequence_number: int = Field(..., ge=1, description="Monotonically increasing sequence number for replay protection")
    head_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hash of the ledger head record")
    record_count: int = Field(..., ge=0, description="Total ledger record count anchored by this checkpoint")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of checkpoint generation")
    signature: str = Field(default="", description="HMAC-SHA256 signature calculated over checkpoint material")
    provider_type: str = Field(default="INDEPENDENT", description="Identifier of the anchoring provider")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Supplementary provenance metadata")


class CheckpointError(Exception):
    """Raised when external checkpoint operations fail or violate security invariants."""
    pass


class BaseCheckpointProvider(ABC):
    """Abstract interface for external, independently protected checkpoint providers."""

    def __init__(self, signing_key: Optional[bytes] = None):
        self._signing_key = signing_key or self._resolve_signing_key()

    def _resolve_signing_key(self) -> bytes:
        """Resolves the checkpoint signing key from QS_EXTERNAL_CHECKPOINT_KEY or fallback."""
        key_env = os.environ.get("QS_EXTERNAL_CHECKPOINT_KEY")
        if key_env:
            clean = key_env.strip()
            if len(clean) == 64:
                try:
                    return bytes.fromhex(clean)
                except ValueError:
                    pass
            return clean.encode("utf-8")
        # Fallback to secondary derived secret if not provided
        return b"qs-independent-anchor-checkpoint-key-secret-32b"

    def compute_signature(self, sequence_number: int, head_hash: str, record_count: int, timestamp: str) -> str:
        """Calculates deterministic HMAC-SHA256 signature over checkpoint fields."""
        material = f"{sequence_number}:{head_hash}:{record_count}:{timestamp}".encode("utf-8")
        return hmac.new(self._signing_key, material, hashlib.sha256).hexdigest()

    def verify_signature(self, checkpoint: TrustedCheckpoint) -> bool:
        """Constant-time verification of checkpoint signature."""
        if not checkpoint.signature:
            return False
        expected = self.compute_signature(
            checkpoint.sequence_number,
            checkpoint.head_hash,
            checkpoint.record_count,
            checkpoint.timestamp,
        )
        return hmac.compare_digest(expected, checkpoint.signature)

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the provider is operational and configured."""
        pass

    @abstractmethod
    def is_independent_boundary(self) -> bool:
        """Returns True if the provider represents an independent trust boundary (not local DB)."""
        pass

    @abstractmethod
    def get_status(self) -> str:
        """Returns provider operational status: 'OPERATIONAL', 'UNCONFIGURED', or 'UNAVAILABLE'."""
        pass

    @abstractmethod
    def save_checkpoint(self, checkpoint: TrustedCheckpoint) -> bool:
        """Persists a new authenticated checkpoint to the independent destination."""
        pass

    @abstractmethod
    def get_latest_checkpoint(self) -> Optional[TrustedCheckpoint]:
        """Retrieves the latest verified checkpoint from the independent destination."""
        pass


class InMemoryExternalCheckpointProvider(BaseCheckpointProvider):
    """
    In-memory independent checkpoint provider for deterministic testing.
    Simulates a remote append-only service with replay prevention and signature checks.
    """

    def __init__(self, signing_key: Optional[bytes] = None, operational: bool = True):
        super().__init__(signing_key=signing_key)
        self._checkpoints: List[TrustedCheckpoint] = []
        self._lock = threading.RLock()
        self._operational = operational

    def is_configured(self) -> bool:
        return True

    def is_independent_boundary(self) -> bool:
        return True

    def get_status(self) -> str:
        return "OPERATIONAL" if self._operational else "UNAVAILABLE"

    def set_operational(self, operational: bool) -> None:
        self._operational = operational

    def save_checkpoint(self, checkpoint: TrustedCheckpoint) -> bool:
        if not self._operational:
            raise CheckpointError("External checkpoint service is currently unavailable.")

        with self._lock:
            # Replay protection: sequence number and record count must be strictly monotonic
            if self._checkpoints:
                latest = self._checkpoints[-1]
                if checkpoint.sequence_number <= latest.sequence_number:
                    raise CheckpointError(
                        f"Replay detected: sequence {checkpoint.sequence_number} <= previous {latest.sequence_number}"
                    )
                if checkpoint.record_count < latest.record_count:
                    raise CheckpointError(
                        f"Rollback detected: record count {checkpoint.record_count} < previous {latest.record_count}"
                    )

            # Ensure valid signature before storing
            if not checkpoint.signature:
                checkpoint.signature = self.compute_signature(
                    checkpoint.sequence_number,
                    checkpoint.head_hash,
                    checkpoint.record_count,
                    checkpoint.timestamp,
                )
            elif not self.verify_signature(checkpoint):
                raise CheckpointError("Checkpoint signature verification failed.")

            self._checkpoints.append(checkpoint.model_copy())
            return True

    def get_latest_checkpoint(self) -> Optional[TrustedCheckpoint]:
        if not self._operational:
            raise CheckpointError("External checkpoint service is currently unavailable.")
        with self._lock:
            if not self._checkpoints:
                return None
            return self._checkpoints[-1].model_copy()

    def get_all_checkpoints(self) -> List[TrustedCheckpoint]:
        with self._lock:
            return [c.model_copy() for c in self._checkpoints]

    def clear(self) -> None:
        with self._lock:
            self._checkpoints.clear()


class SignedExternalHttpCheckpointProvider(BaseCheckpointProvider):
    """
    Real HTTP integration for external audit anchoring.
    Communicates with a remote append-only log or SIEM webhook configured via environment variables:
    - QS_EXTERNAL_CHECKPOINT_URL: Target endpoint URL
    - QS_EXTERNAL_CHECKPOINT_KEY: Authentication and HMAC secret
    """

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        signing_key: Optional[bytes] = None,
        timeout_seconds: float = 5.0,
    ):
        super().__init__(signing_key=signing_key)
        raw_url = endpoint_url if endpoint_url is not None else os.environ.get("QS_EXTERNAL_CHECKPOINT_URL", "")
        self._endpoint_url = raw_url.strip().rstrip("/") if raw_url else ""
        self._timeout = timeout_seconds

    def is_configured(self) -> bool:
        return bool(self._endpoint_url and self._endpoint_url.startswith(("http://", "https://")))

    def is_independent_boundary(self) -> bool:
        return True

    def get_status(self) -> str:
        return "OPERATIONAL" if self.is_configured() else "UNCONFIGURED"

    def save_checkpoint(self, checkpoint: TrustedCheckpoint) -> bool:
        if not self.is_configured():
            logger.warning("External checkpoint provider called but QS_EXTERNAL_CHECKPOINT_URL is not configured.")
            return False

        if not checkpoint.signature:
            checkpoint.signature = self.compute_signature(
                checkpoint.sequence_number,
                checkpoint.head_hash,
                checkpoint.record_count,
                checkpoint.timestamp,
            )

        payload = checkpoint.model_dump(mode="json")
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self._endpoint_url}/checkpoints",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Checkpoint-Signature": checkpoint.signature,
                "User-Agent": "QuantumShield-Audit-Anchor/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return 200 <= resp.status < 300
        except urllib.error.HTTPError as e:
            logger.error("HTTP error posting external audit checkpoint to %s: HTTP %s", self._endpoint_url, e.code)
            raise CheckpointError(f"External checkpoint storage failed with HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            logger.error("Network error reaching external audit checkpoint at %s: %s", self._endpoint_url, e.reason)
            raise CheckpointError(f"External checkpoint storage failed (network error): {e.reason}") from e
        except Exception as e:
            logger.error("Failed to post external audit checkpoint to %s: %s", self._endpoint_url, e)
            raise CheckpointError(f"External checkpoint storage failed: {e}") from e

    def get_latest_checkpoint(self) -> Optional[TrustedCheckpoint]:
        if not self.is_configured():
            return None

        req = urllib.request.Request(
            f"{self._endpoint_url}/checkpoints/latest",
            headers={"Accept": "application/json", "User-Agent": "QuantumShield-Audit-Anchor/1.0"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status == 404:
                    return None
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8"))
                if not isinstance(data, dict):
                    raise CheckpointError("Malformed response: expected JSON object from remote host.")
                checkpoint = TrustedCheckpoint(**data)
                if not self.verify_signature(checkpoint):
                    raise CheckpointError("External checkpoint signature verification failed from remote host.")
                return checkpoint
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise CheckpointError(f"Remote external checkpoint query failed with HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise CheckpointError(f"Unable to reach external checkpoint anchor (network error): {e.reason}") from e
        except Exception as e:
            if isinstance(e, CheckpointError):
                raise
            raise CheckpointError(f"Unable to reach external checkpoint anchor: {e}") from e


# Global default external provider (defaults to SignedExternalHttpCheckpointProvider)
DEFAULT_EXTERNAL_CHECKPOINT_PROVIDER = SignedExternalHttpCheckpointProvider()
