# Dependency Security & Vulnerability Audit Report

**Platform:** QuantumShield — Banking Quantum Readiness & Remediation Engine
**Branch:** `janya`
**Task:** Task B8 (Phase B: Security Hardening — Backend Lockfile & Reproducibility)
**Date:** November 2026
**Status:** Completed & Verified (Verdict: PASS)

---

## 1. Executive Summary

As part of Phase B (Security Hardening, Task B8), a comprehensive software supply chain, dependency security, and reproducibility audit was conducted across both the Python backend and React/TypeScript frontend.

To resolve the independent security audit's PARTIAL finding regarding loose semantic ranges, an exact, cryptographically hashed backend lockfile (`backend/requirements.lock`) was introduced alongside `backend/requirements.in`.

### Audit & Verification Verdict:
- **`backend/requirements.lock`:** 0 known vulnerabilities found across all direct and transitive dependencies via `pip-audit`.
- **`frontend/package-lock.json`:** 0 known vulnerabilities found across all production and development dependencies via `npm audit`.
- **Reproducible Installation:** Verified from scratch in a fresh temporary virtual environment (`$env:TEMP/qs_test_venv_b8`) using `pip install --require-hashes -r backend/requirements.lock`.
- **Clean Environment Test Suite:** All 495 backend unit, integration, and security tests passed in the isolated environment.

---

## 2. Python Dependency Declarations & Exact Lockfile Architecture

### 2.1 File Structure
1. **`backend/requirements.in`**: Source of direct runtime and test dependency requirements with bounded semantic version ranges.
2. **`backend/requirements.lock`**: Fully resolved, deterministic dependency tree pinning exact versions and multiple SHA-256 integrity hashes for all wheels and source distributions.
3. **`backend/requirements.txt`**: Backward-compatible specification documenting both loose and reproducible installation modes.

### 2.2 Direct Dependency Declarations (`backend/requirements.in`)

| Package | Bounded Range | Locked Version | Role / Justification |
| :--- | :--- | :--- | :--- |
| `fastapi` | `>=0.110.0,<0.136.0` | `0.135.4` | Core ASGI web framework and routing |
| `uvicorn[standard]` | `>=0.28.0,<1.0.0` | `0.54.0` | Production ASGI web server with standard event loop/parsers |
| `pydantic` | `>=2.6.0,<3.0.0` | `2.14.4` | Data modeling, validation, and schema generation (v2 API) |
| `cryptography` | `>=42.0.0,<51.0.0` | `50.0.2` | Cryptographic primitives, X.509 certificate parsing |
| `pytest` | `>=8.0.0,<10.0.0` | `9.2.0` | Test runner and test execution framework |
| `pytest-asyncio` | `>=0.23.0,<2.0.0` | `1.5.0` | Asyncio fixtures and coroutine testing |
| `httpx` | `>=0.27.0,<1.0.0` | `0.28.1` | HTTP client for ASGI integration tests and REST AI provider calls |
| `dnspython` | `>=2.8.0,<3.0.0` | `2.9.2` | DNS resolver for SSRF target IP inspection |
| `PyYAML` | `>=6.0.0,<7.0.0` | `6.0.4` | Hardened YAML configuration parsing |
| `certifi` | `>=2024.2.2` | `2026.11.20` | Authoritative Mozilla CA certificate bundle |
| `reportlab` | `>=4.1.0,<5.0.0` | `4.5.1` | PDF executive report generator (`app.services.report_service`) |
| `cyclonedx-python-lib` | `>=9.0.0,<12.0.0` | `11.12.0` | Official CycloneDX 1.7 schema validation (`app.cbom`) |
| `redis` | `>=5.0.0,<9.0.0` | `8.1.0` | Distributed atomic rate limiting & shared budget enforcement (`app.ai.budget`) |

*Note on `reportlab`, `cyclonedx-python-lib`, and `redis`:* During verification and CI hardening, `reportlab` was verified for PDF report generation, `cyclonedx-python-lib` for official CycloneDX 1.7 schema validation, and `redis` for shared atomic AI budget tracking. All were formally added to `requirements.in` and `requirements.txt` with bounded constraints and pinned with SHA-256 integrity hashes in `requirements.lock`.

### 2.3 Lockfile Generation
- **Target Python Version:** Python 3.13.1
- **Tooling:** `pip-tools` (v7.7.0) / `pip-compile`
- **Exact Compilation Command:**
  ```powershell
  python -m piptools compile backend/requirements.in --generate-hashes -o backend/requirements.lock
  ```

---

## 3. Clean-Room Installation & Functional Verification

### 3.1 Clean Virtual Environment Verification Process
To prove reproducibility beyond the developer's local environment, an isolated temporary virtual environment was provisioned:

```powershell
$tempVenv = Join-Path $env:TEMP "qs_test_venv_b8"
python -m venv $tempVenv
$tempPython = Join-Path $tempVenv "Scripts\python.exe"

# Install strictly from the lockfile with mandatory hash checking
& $tempPython -m pip install --require-hashes -r backend/requirements.lock
```

### 3.2 Verification Results
- **Installation Status:** Succeeded with exit code 0.
- **Integrity Validation:** Every downloaded package was verified against its SHA-256 hash.
- **Import Verification:**
  ```text
  $ & $tempPython -c "import app.main; print('Import success:', app.main.app.title)"
  Import success: QuantumShield API
  ```
- **Test Suite Execution in Clean Venv:**
  ```text
  $ & $tempPython -m pytest -q backend/tests
  ............................................................... [100%]
  495 passed, 2 warnings in 15.81s
  ```

---

## 4. Vulnerability & Supply Chain Security Audit

### 4.1 Python Backend Audit (`backend/requirements.lock`)
- **Scanner:** `pip-audit` v2.10.1
- **Command:** `python -m pip_audit -r backend/requirements.lock`
- **Database:** PyPI Advisory Database & Open Source Vulnerabilities (OSV)
- **Result:**
  ```text
  No known vulnerabilities found
  ```
- **Vulnerabilities Found:** 0

### 4.2 Node.js Frontend Audit (`frontend/package.json` & `package-lock.json`)
- **Scanner:** `npm audit`
- **Command:** `npm.cmd --prefix frontend audit`
- **Database:** npm / GitHub Security Advisory Database
- **Result:**
  ```text
  found 0 vulnerabilities
  ```
- **Vulnerabilities Found:** 0

---

## 5. Limitations & Platform Considerations

1. **Python ABI & Binary Wheel Compatibility:**
   `backend/requirements.lock` includes SHA-256 hashes for source distributions (`sdist`) and standard pre-compiled platform wheels for C-extension packages (`cryptography`, `cffi`, `watchfiles`, `pillow`, `reportlab`). The lockfile is targeted at **Python 3.13**. Environments using other major Python versions (e.g. 3.11 or 3.12) should recompile using `pip-compile` on that specific version.
2. **Deterministic Installation Command:**
   Production pipelines and CI/CD runners must always invoke `pip install --require-hashes -r backend/requirements.lock` rather than `pip install -r backend/requirements.txt` to guarantee deterministic builds.

---

## 6. Files Changed in Task B8

- `backend/requirements.in` (NEW): Direct dependency constraints for `pip-compile`.
- `backend/requirements.lock` (NEW): Exact locked package versions and multi-distribution SHA-256 hashes.
- `backend/requirements.txt` (MODIFIED): Documented lockfile usage and added `reportlab>=4.1.0,<5.0.0`.
- `README.md` (MODIFIED): Added reproducible installation and lockfile maintenance instructions.
- `docs/audit-reports/DEPENDENCY_SECURITY_AUDIT.md` (MODIFIED): Comprehensive lockfile and verification documentation.
- `docs/audit-reports/PHASE_B_AUDIT_REPORT.md` (MODIFIED): Updated Task B8 status from PARTIAL to PASS.
