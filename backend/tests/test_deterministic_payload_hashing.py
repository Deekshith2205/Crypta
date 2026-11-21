"""Tests for Task C3: Deterministic Assessment Payload Hashing."""

import pytest
from app.services.audit_chain_service import (
    canonicalize_json,
    compute_payload_hash,
    strip_volatile_fields,
    VOLATILE_FIELD_KEYS,
)


def test_identical_payloads_produce_identical_hashes():
    """Identical data structures produce identical hashes."""
    p1 = {"system_id": "BANK-01", "score": 85, "quantum_risk": "HIGH", "findings": ["F1", "F2"]}
    p2 = {"system_id": "BANK-01", "score": 85, "quantum_risk": "HIGH", "findings": ["F1", "F2"]}

    h1 = compute_payload_hash(p1)
    h2 = compute_payload_hash(p2)

    assert len(h1) == 64
    assert h1 == h2


def test_dictionary_key_order_invariance():
    """Key ordering at any level of nesting does not alter the canonical hash."""
    p1 = {
        "z_layer": {"nested_b": 2, "nested_a": 1},
        "a_system": "SYS-1",
        "m_findings": [{"id": "1", "sev": "HIGH"}, {"id": "2", "sev": "LOW"}],
    }
    p2 = {
        "a_system": "SYS-1",
        "m_findings": [{"sev": "HIGH", "id": "1"}, {"sev": "LOW", "id": "2"}],
        "z_layer": {"nested_a": 1, "nested_b": 2},
    }

    assert compute_payload_hash(p1) == compute_payload_hash(p2)


def test_volatile_metadata_exclusion():
    """Volatile timestamps and generated run/record IDs are excluded from content hash."""
    base_assessment = {
        "system_id": "BANK-CORE-01",
        "risk_score": 92,
        "priority": "P0",
        "findings": [{"id": "RSA-2048", "severity": "CRITICAL"}],
    }

    # Two runs with different execution timestamps, report IDs, and latency counters
    run1 = dict(base_assessment)
    run1["timestamp"] = "2026-11-21T10:00:00.123456Z"
    run1["report_id"] = "REP-AAAA-1111"
    run1["execution_time_ms"] = 142.5

    run2 = dict(base_assessment)
    run2["timestamp"] = "2026-11-21T12:34:56.789012Z"
    run2["report_id"] = "REP-BBBB-2222"
    run2["execution_time_ms"] = 289.1

    h1 = compute_payload_hash(run1)
    h2 = compute_payload_hash(run2)

    # Hashes must be identical because only volatile metadata differed
    assert h1 == h2


def test_meaningful_assessment_change_alters_hash():
    """Changes to security findings, scores, or targets must alter the hash."""
    base = {
        "system_id": "BANK-CORE-01",
        "risk_score": 92,
        "priority": "P0",
    }
    tampered_score = dict(base, risk_score=50)
    tampered_prio = dict(base, priority="P2")
    tampered_system = dict(base, system_id="BANK-CORE-02")

    base_hash = compute_payload_hash(base)
    assert compute_payload_hash(tampered_score) != base_hash
    assert compute_payload_hash(tampered_prio) != base_hash
    assert compute_payload_hash(tampered_system) != base_hash


def test_unicode_and_special_character_stability():
    """Unicode strings and symbols serialize deterministically."""
    payload = {
        "name": "Crédit Agricole & Münchener Rück 🛡️⚛️",
        "desc": "Zürich / 東京 / São Paulo — Quantum-Safe KEM (ML-KEM-768)",
        "special": "Tab\tNewline\nQuote\"Slash/Backslash\\",
    }
    h1 = compute_payload_hash(payload)
    h2 = compute_payload_hash(payload)

    assert h1 == h2
    assert len(h1) == 64


def test_null_and_numeric_values_consistency():
    """Null, boolean, integer, and float representations are consistent."""
    payload = {
        "nullable": None,
        "is_active": True,
        "is_quantum_safe": False,
        "int_val": 42,
        "float_val": 3.14159,
        "zero": 0,
    }
    h = compute_payload_hash(payload)
    assert isinstance(h, str)
    assert len(h) == 64
