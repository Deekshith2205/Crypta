"""Comprehensive hardening regression test suite for Crypto-Misuse Scanner (Task D2).
Validates:
1. Strict non-execution invariant across Python, Java, JavaScript/TypeScript, and PHP.
2. AES-256 Grover quantum security invariant across all language detectors.
3. Strict separation of Classical, Quantum, Implementation, and Secret Exposure risk categories.
4. Implementation flaws on AES-256 (ECB mode, static IV, nonce reuse) are never classified as QUANTUM_SECURITY.
5. Large file and binary file rejection safety.
"""

import os
import tempfile
import pytest
from pathlib import Path

from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner
from app.scanners.crypto_misuse.models import (
    RiskCategory,
    FindingSeverity,
    CryptoRole,
    EvidenceStatus,
)


@pytest.fixture
def scanner():
    return CryptoMisuseScanner()


def test_non_execution_invariant_all_languages(scanner, tmp_path):
    """Ensure scanner strictly parses without executing code for all supported languages."""
    canary_file = tmp_path / "CANARY_EXECUTED.txt"
    assert not canary_file.exists()

    # Python payload attempting file creation
    py_code = f"""
import os
os.system("touch {canary_file.as_posix()}")
cipher = "AES-256"
"""
    scanner.scan_source(py_code, "python", "exploit.py")
    assert not canary_file.exists(), "Python code was executed during scan!"

    # Java payload attempting execution
    java_code = f"""
public class Exploit {{
    public static void main(String[] args) throws Exception {{
        Runtime.getRuntime().exec("touch {canary_file.as_posix()}");
    }}
}}
"""
    scanner.scan_source(java_code, "java", "Exploit.java")
    assert not canary_file.exists(), "Java code was executed during scan!"

    # JavaScript payload attempting execution
    js_code = f"""
const cp = require('child_process');
cp.execSync('touch {canary_file.as_posix()}');
"""
    scanner.scan_source(js_code, "javascript", "exploit.js")
    assert not canary_file.exists(), "JavaScript code was executed during scan!"

    # PHP payload attempting execution
    php_code = f"""<?php
shell_exec("touch {canary_file.as_posix()}");
"""
    scanner.scan_source(php_code, "php", "exploit.php")
    assert not canary_file.exists(), "PHP code was executed during scan!"


def test_aes_256_grover_invariant_across_all_languages(scanner):
    """
    Validate AES-256 non-broken Grover invariant across all misuse detectors.
    Grover's search offers quadratic speedup, meaning AES-256 retains ~128 bits
    of effective quantum security (exceeding NIST 112-bit post-quantum threshold).
    Therefore, AES-256 bulk encryption MUST NEVER be flagged as QUANTUM_SECURITY.
    """
    # 1. Python AES-256
    py_code = """
from Crypto.Cipher import AES
key = os.urandom(32)
cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
"""
    py_res = scanner.scan_source(py_code, "python", "aes256.py")
    for f in py_res.findings:
        assert f.risk != RiskCategory.QUANTUM_SECURITY.value, f"Python AES-256 flagged as quantum risk: {f}"

    # 2. Java AES-256
    java_code = """
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKeySpec keySpec = new SecretKeySpec(keyBytes256, "AES");
"""
    java_res = scanner.scan_source(java_code, "java", "Aes256.java")
    for f in java_res.findings:
        assert f.risk != RiskCategory.QUANTUM_SECURITY.value, f"Java AES-256 flagged as quantum risk: {f}"

    # 3. JavaScript AES-256
    js_code = """
const cipher = crypto.createCipheriv('aes-256-gcm', key32, iv12);
"""
    js_res = scanner.scan_source(js_code, "javascript", "aes256.js")
    for f in js_res.findings:
        assert f.risk != RiskCategory.QUANTUM_SECURITY.value, f"JS AES-256 flagged as quantum risk: {f}"

    # 4. PHP AES-256
    php_code = """<?php
$ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv12);
"""
    php_res = scanner.scan_source(php_code, "php", "aes256.php")
    for f in php_res.findings:
        assert f.risk != RiskCategory.QUANTUM_SECURITY.value, f"PHP AES-256 flagged as quantum risk: {f}"


def test_aes_misuse_is_never_quantum_risk(scanner):
    """
    When AES-256 is misused (e.g., ECB mode, static IV, nonce reuse, hardcoded key),
    the finding MUST reflect the actual vulnerability category (CLASSICAL_SECURITY,
    IMPLEMENTATION_SECURITY, SECRET_EXPOSURE) and NEVER QUANTUM_SECURITY.
    """
    # A. AES with ECB mode -> CLASSICAL_SECURITY
    ecb_code = """
cipher = AES.new(key, AES.MODE_ECB)
"""
    res = scanner.scan_source(ecb_code, "python", "test_ecb.py")
    ecb_findings = [f for f in res.findings if f.rule_id == "MISUSE-ECB-MODE"]
    assert len(ecb_findings) == 1
    assert ecb_findings[0].risk == RiskCategory.CLASSICAL_SECURITY.value
    assert ecb_findings[0].risk != RiskCategory.QUANTUM_SECURITY.value

    # B. AES with static IV -> IMPLEMENTATION_SECURITY
    iv_code = """
cipher = AES.new(key, AES.MODE_CBC, iv=b"0000000000000000")
"""
    res = scanner.scan_source(iv_code, "python", "test_iv.py")
    iv_findings = [f for f in res.findings if f.rule_id == "MISUSE-STATIC-IV"]
    assert len(iv_findings) == 1
    assert iv_findings[0].risk == RiskCategory.IMPLEMENTATION_SECURITY.value
    assert iv_findings[0].risk != RiskCategory.QUANTUM_SECURITY.value

    # C. Hardcoded AES key -> SECRET_EXPOSURE
    key_code = """
aes_key = "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c"
"""
    res = scanner.scan_source(key_code, "python", "test_key.py")
    key_findings = [f for f in res.findings if f.rule_id == "MISUSE-HARDCODED-KEY"]
    assert len(key_findings) == 1
    assert key_findings[0].risk == RiskCategory.SECRET_EXPOSURE.value
    assert key_findings[0].risk != RiskCategory.QUANTUM_SECURITY.value


def test_quantum_vulnerabilities_correctly_classified(scanner):
    """
    Verify that asymmetric key exchange and public-key algorithms vulnerable
    to Shor's algorithm ARE classified under QUANTUM_SECURITY.
    """
    # Static RSA Key Exchange
    rsa_kex = 'cipher_suite = "TLS_RSA_WITH_AES_256_GCM_SHA384"'
    res_rsa = scanner.scan_source(rsa_kex, "python", "kex_sample.py")
    rsa_findings = [f for f in res_rsa.findings if f.rule_id == "MISUSE-HARDCODED-RSA-KEX"]
    assert len(rsa_findings) == 1
    assert rsa_findings[0].risk == RiskCategory.QUANTUM_SECURITY.value
    assert rsa_findings[0].role == CryptoRole.KEY_ESTABLISHMENT.value

    # ECDH Key Exchange
    ecdh_code = """
kex = "ECDHE"
curve = ec.SECP256R1()
"""
    res_ecdh = scanner.scan_source(ecdh_code, "python", "ecdh_sample.py")
    ecdh_findings = [f for f in res_ecdh.findings if f.rule_id == "MISUSE-HARDCODED-ECDH-KEX"]
    assert len(ecdh_findings) >= 1
    for f in ecdh_findings:
        assert f.risk == RiskCategory.QUANTUM_SECURITY.value
        assert f.role == CryptoRole.KEY_ESTABLISHMENT.value


def test_scanner_file_safety_limits(scanner, tmp_path):
    """Test scanner limits: binary files skipped, oversized files rejected, non-existent files handled."""
    # 1. Non-existent file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        scanner.scan_file(tmp_path / "does_not_exist.py")

    # 2. Binary file is skipped safely
    bin_file = tmp_path / "binary_sample.py"
    bin_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\x00\x00" * 100)
    res_bin = scanner.scan_file(bin_file)
    assert res_bin.files_scanned == 0
    assert len(res_bin.findings) == 0

    # 3. Oversized file exceeds max_file_size_bytes -> skipped safely
    small_scanner = CryptoMisuseScanner(max_file_size_bytes=100)
    large_file = tmp_path / "large_file.py"
    large_file.write_text("x = 1\n" * 100, encoding="utf-8")
    res_large = small_scanner.scan_file(large_file)
    assert res_large.files_scanned == 0
    assert len(res_large.findings) == 0
