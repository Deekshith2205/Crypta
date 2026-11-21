"""Regression tests for Task A4: Safe Finding Deduplication.
Verifies that duplicate findings are removed, but distinct findings sharing
an algorithm or rule ID are safely preserved if they have different roles,
source files, line numbers, or sources.
"""

import pytest
from types import SimpleNamespace
from app.models.findings import NormalizedFinding
from app.services.finding_normalizer import (
    collect_unified_findings,
    normalize_crypto_misuse_finding,
    normalize_config_finding,
)


def test_exact_duplicates_are_deduplicated():
    """
    Task A4: Exact duplicate findings (same rule_id, value, role, source, file, and line)
    must be deduplicated to a single finding.
    """
    f1 = SimpleNamespace(
        rule_id="MISUSE-AES-ECB",
        title="Insecure ECB Mode",
        matched_value="AES-128-ECB",
        role="DATA_ENCRYPTION",
        risk="CLASSICAL_SECURITY",
        file="services/payment.py",
        line=42,
        severity="HIGH",
    )
    f2 = SimpleNamespace(
        rule_id="MISUSE-AES-ECB",
        title="Insecure ECB Mode",
        matched_value="AES-128-ECB",
        role="DATA_ENCRYPTION",
        risk="CLASSICAL_SECURITY",
        file="services/payment.py",
        line=42,
        severity="HIGH",
    )

    unified = collect_unified_findings(
        system_id="BANK-TEST-01",
        crypto_misuse_findings=[f1, f2],
    )
    assert len(unified) == 1, f"Expected 1 finding after exact deduplication, got {len(unified)}"


def test_same_rule_and_value_different_roles_preserved():
    """
    Task A4: Findings sharing the same rule_id and value but with different
    cryptographic roles (e.g. BULK_ENCRYPTION vs KEY_WRAPPING) must NOT be collapsed.
    """
    c1 = SimpleNamespace(
        rule_id="CFG-AES-256",
        title="AES-256 Storage Encryption",
        parsed_value="AES-256",
        role="BULK_ENCRYPTION",
        evidence_status="OBSERVED",
        severity="INFORMATIONAL",
        source_file="config/database.yaml",
        source_line=10,
    )
    c2 = SimpleNamespace(
        rule_id="CFG-AES-256",
        title="AES-256 Key Wrapping",
        parsed_value="AES-256",
        role="KEY_WRAPPING",
        evidence_status="OBSERVED",
        severity="INFORMATIONAL",
        source_file="config/database.yaml",
        source_line=15,
    )

    unified = collect_unified_findings(
        system_id="BANK-TEST-02",
        config_findings=[c1, c2],
    )
    assert len(unified) == 2, (
        f"Findings with different roles were incorrectly collapsed: got {len(unified)} finding(s)"
    )
    roles = {f.role for f in unified}
    assert "BULK_ENCRYPTION" in roles
    assert "KEY_WRAPPING" in roles


def test_same_rule_and_value_different_files_preserved():
    """
    Task A4: Findings in different source files must NOT be collapsed, even if they share
    the exact same rule_id and value.
    """
    f1 = SimpleNamespace(
        rule_id="MISUSE-STATIC-IV",
        title="Static IV Detected",
        matched_value="STATIC_IV_BYTES",
        role="DATA_ENCRYPTION",
        risk="CLASSICAL_SECURITY",
        file="services/auth_service.py",
        line=30,
        severity="HIGH",
    )
    f2 = SimpleNamespace(
        rule_id="MISUSE-STATIC-IV",
        title="Static IV Detected",
        matched_value="STATIC_IV_BYTES",
        role="DATA_ENCRYPTION",
        risk="CLASSICAL_SECURITY",
        file="services/transaction_service.py",
        line=30,
        severity="HIGH",
    )

    unified = collect_unified_findings(
        system_id="BANK-TEST-03",
        crypto_misuse_findings=[f1, f2],
    )
    assert len(unified) == 2, (
        f"Findings across different files were incorrectly collapsed: got {len(unified)} finding(s)"
    )
    files = {f.source_file for f in unified}
    assert "services/auth_service.py" in files
    assert "services/transaction_service.py" in files


def test_same_file_different_lines_preserved():
    """
    Task A4: Findings in the same source file at distinct line numbers
    must NOT be collapsed into one.
    """
    f1 = SimpleNamespace(
        rule_id="MISUSE-MD5-HASH",
        title="MD5 Weak Hash",
        matched_value="MD5",
        role="HASH_FUNCTION",
        risk="CLASSICAL_SECURITY",
        file="utils/crypto_helper.py",
        line=15,
        severity="HIGH",
    )
    f2 = SimpleNamespace(
        rule_id="MISUSE-MD5-HASH",
        title="MD5 Weak Hash",
        matched_value="MD5",
        role="HASH_FUNCTION",
        risk="CLASSICAL_SECURITY",
        file="utils/crypto_helper.py",
        line=85,
        severity="HIGH",
    )

    unified = collect_unified_findings(
        system_id="BANK-TEST-04",
        crypto_misuse_findings=[f1, f2],
    )
    assert len(unified) == 2, (
        f"Findings on distinct lines were incorrectly collapsed: got {len(unified)} finding(s)"
    )
    lines = {f.source_line for f in unified}
    assert 15 in lines
    assert 85 in lines


def test_different_sources_with_same_value_preserved():
    """
    Task A4: Observations from different sources (e.g. Configuration vs Code Misuse)
    must remain separate evidence items.
    """
    cfg = SimpleNamespace(
        rule_id="CFG-DES-CIPHER",
        title="DES Cipher Configured",
        parsed_value="DES",
        role="DATA_ENCRYPTION",
        evidence_status="OBSERVED",
        severity="CRITICAL",
        source_file="config/cipher.conf",
        source_line=5,
    )
    misuse = SimpleNamespace(
        rule_id="MISUSE-DES-CIPHER",
        title="DES Cipher Instantiated",
        matched_value="DES",
        role="DATA_ENCRYPTION",
        risk="CLASSICAL_SECURITY",
        file="core/crypto.py",
        line=40,
        severity="CRITICAL",
    )

    unified = collect_unified_findings(
        system_id="BANK-TEST-05",
        config_findings=[cfg],
        crypto_misuse_findings=[misuse],
    )
    assert len(unified) == 2, (
        f"Cross-source findings were incorrectly collapsed: got {len(unified)} finding(s)"
    )
    sources = {f.source for f in unified}
    assert "CONFIGURATION_FILE" in sources
    assert "CODE_ANALYSIS" in sources
