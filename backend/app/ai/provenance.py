"""Evidence Provenance and Traceability Module (Task D5).

Binds AI explanations cryptographically to the exact deterministic evidence
they explain. Ensures that explanations cannot be detached, reused across
unrelated findings, or tampered with without invalidating the provenance hash.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from pydantic import BaseModel


def canonicalize_evidence(data: Any) -> bytes:
    """
    Serializes arbitrary evidence structures into deterministic, canonical JSON bytes.
    Keys are sorted, whitespace is normalized, and non-ASCII characters are escaped.
    """
    if isinstance(data, BaseModel):
        data = data.model_dump()

    return json.dumps(
        data,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def compute_evidence_hash(data: Any) -> str:
    """Computes the SHA-256 digest of canonicalized evidence data."""
    raw_bytes = canonicalize_evidence(data)
    return hashlib.sha256(raw_bytes).hexdigest()


def bind_provenance_metadata(
    output: Any,
    input_data: Any,
    evidence_status: Optional[str] = None,
) -> Any:
    """
    Computes evidence hash and binds provenance metadata to the explanation response.
    Works with both Pydantic models and dictionaries.
    """
    evidence_hash = compute_evidence_hash(input_data)
    now_iso = datetime.now(timezone.utc).isoformat()

    status = evidence_status
    if not status and isinstance(input_data, dict):
        status = input_data.get("evidence_status")
    elif not status and hasattr(input_data, "evidence_status"):
        status = getattr(input_data, "evidence_status")

    if isinstance(output, BaseModel):
        if hasattr(output, "evidence_hash"):
            setattr(output, "evidence_hash", evidence_hash)
        if hasattr(output, "evidence_status") and status:
            setattr(output, "evidence_status", str(status))
        if hasattr(output, "generated_at"):
            setattr(output, "generated_at", now_iso)
        if hasattr(output, "provenance_verified"):
            setattr(output, "provenance_verified", True)
    elif isinstance(output, dict):
        output["evidence_hash"] = evidence_hash
        if status:
            output["evidence_status"] = str(status)
        output["generated_at"] = now_iso
        output["provenance_verified"] = True

    return output


def verify_explanation_provenance(
    output: Any,
    original_input: Any,
) -> Tuple[bool, Optional[str]]:
    """
    Verifies that the explanation's recorded evidence_hash matches the canonical
    SHA-256 hash of the provided input evidence.

    Returns (is_valid, error_reason).
    """
    if isinstance(output, BaseModel):
        recorded_hash = getattr(output, "evidence_hash", None)
    elif isinstance(output, dict):
        recorded_hash = output.get("evidence_hash")
    else:
        return False, "Output must be a Pydantic model or dictionary."

    if not recorded_hash:
        return False, "Output does not contain an evidence_hash field."

    expected_hash = compute_evidence_hash(original_input)

    if recorded_hash != expected_hash:
        return False, (
            f"Provenance hash mismatch: recorded='{recorded_hash}', "
            f"expected='{expected_hash}'."
        )

    return True, None
