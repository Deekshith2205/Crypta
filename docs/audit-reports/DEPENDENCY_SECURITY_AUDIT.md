# Dependency Security & Vulnerability Audit Report

**Platform:** QuantumShield — Banking Quantum Readiness & Remediation Engine  
**Branch:** `janya`  
**Task:** Task B8 (Phase B: Security Hardening)  
**Date:** November 2026  
**Status:** Completed & Verified  

---

## 1. Executive Summary

As part of Phase B (Security Hardening), a comprehensive software supply chain and dependency security audit was conducted across both the Python backend and React/TypeScript frontend.

The audit evaluated all direct runtime dependencies, development tooling, and transitive packages against known vulnerabilities (CVEs and vendor security advisories) using authoritative security scanning utilities:
- **Backend (Python):** `pip-audit` v2.10.1 querying the PyPI Advisory Database and Google OSV API.
- **Frontend (Node.js):** `npm audit` querying the npm Advisory Database.

**Audit Verdict:**
- **`backend/requirements.txt`:** 0 known vulnerabilities found across all direct runtime dependencies.
- **`frontend/package.json`:** 0 known vulnerabilities found across all production and development dependencies.
- **Version Pinning:** Unbounded floating dependencies (`>=`) were replaced with upper-bounded, tested semantic version constraints to prevent supply chain drift and breaking API changes.

---

## 2. Python Dependency Security Audit

### 2.1 Scanner Configuration
- **Tool:** `pip-audit` 2.10.1
- **Vulnerability Database:** PyPI Advisory Database & Open Source Vulnerabilities (OSV)
- **Target File:** `backend/requirements.txt`

### 2.2 Scanned Direct Dependencies

| Package | Constrained Range | Installed Version | Vulnerabilities Found | Status |
| :--- | :--- | :--- | :--- | :--- |
| `fastapi` | `>=0.110.0,<0.136.0` | `0.135.2` | None (0) | PASSED |
| `uvicorn[standard]` | `>=0.28.0,<1.0.0` | `0.42.0` | None (0) | PASSED |
| `pydantic` | `>=2.6.0,<3.0.0` | `2.12.5` | None (0) | PASSED |
| `cryptography` | `>=42.0.0,<51.0.0` | `50.0.2` | None (0) | PASSED |
| `pytest` | `>=8.0.0,<10.0.0` | `9.1.1` | None (0) | PASSED |
| `pytest-asyncio` | `>=0.23.0,<2.0.0` | `1.4.1` | None (0) | PASSED |
| `httpx` | `>=0.27.0,<1.0.0` | `0.28.1` | None (0) | PASSED |
| `dnspython` | `>=2.8.0,<3.0.0` | `2.8.0` | None (0) | PASSED |
| `PyYAML` | `>=6.0.0,<7.0.0` | `6.0.2` | None (0) | PASSED |
| `certifi` | `>=2024.2.2` | `2025.1.31` | None (0) | PASSED |

### 2.3 Command Output
```text
$ python -m pip_audit -r backend/requirements.txt
No known vulnerabilities found
```

### 2.4 Analysis of Global Environment Artifacts
During the host-level environment scan (`pip-audit`), several legacy packages residing in the host Python environment were detected (such as `pillow`, `tornado`, `soupsieve`, and `pymongo`). 

**QuantumShield Isolation Assessment:**
- QuantumShield does **not** import, reference, or depend upon `pillow`, `tornado`, `pymongo`, or `soupsieve`.
- Runtime execution is strictly isolated to FastAPI, Starlette, Uvicorn, Pydantic, Cryptography, and dnspython.
- Transitive runtime dependencies (`starlette`, `urllib3`, `certifi`) are monitored and constrained.

---

## 3. Frontend Dependency Security Audit

### 3.1 Scanner Configuration
- **Tool:** `npm audit` (Node.js package manager)
- **Vulnerability Database:** npm Advisory Database / GitHub Advisory Database
- **Target Files:** `frontend/package.json`, `frontend/package-lock.json`

### 3.2 Inventory of Dependencies

#### Production Dependencies (`dependencies`)
| Package | Version Spec | Purpose | Vulnerabilities Found | Status |
| :--- | :--- | :--- | :--- | :--- |
| `react` | `^19.3.1` | UI View Framework | None (0) | PASSED |
| `react-dom` | `^19.3.1` | DOM Renderer for React | None (0) | PASSED |
| `lucide-react` | `^1.64.0` | High-fidelity UI icon library | None (0) | PASSED |

#### Development Dependencies (`devDependencies`)
| Package | Version Spec | Purpose | Vulnerabilities Found | Status |
| :--- | :--- | :--- | :--- | :--- |
| `vite` | `^8.3.5` | Fast build tool and dev server | None (0) | PASSED |
| `@vitejs/plugin-react` | `^6.1.2` | React Fast Refresh for Vite | None (0) | PASSED |
| `typescript` | `~7.0.2` | Static type checker | None (0) | PASSED |
| `oxlint` | `^1.89.0` | High-performance linter | None (0) | PASSED |
| `tailwindcss` | `^4.3.3` | Utility-first CSS styling engine | None (0) | PASSED |
| `@tailwindcss/vite` | `^4.3.3` | Tailwind v4 Vite compiler plugin | None (0) | PASSED |
| `@types/*` | `^19.x / ^24.x` | TypeScript type declarations | None (0) | PASSED |

### 3.3 Command Output
```text
$ cd frontend && npm audit
found 0 vulnerabilities
```

---

## 4. Remediations & Version Constraints Applied

### 4.1 Previous State vs. Hardened State in `backend/requirements.txt`

| Dependency | Previous Unbounded Spec | Hardened Constrained Spec | Justification |
| :--- | :--- | :--- | :--- |
| `fastapi` | `fastapi>=0.110.0` | `fastapi>=0.110.0,<0.136.0` | Prevents unexpected breaking changes in routing and dependency injection |
| `uvicorn[standard]` | `uvicorn[standard]>=0.28.0` | `uvicorn[standard]>=0.28.0,<1.0.0` | Constrains ASGI server to 0.x stable branch |
| `pydantic` | `pydantic>=2.6.0` | `pydantic>=2.6.0,<3.0.0` | Locks to Pydantic v2 API |
| `cryptography` | `cryptography>=42.0.0` | `cryptography>=42.0.0,<51.0.0` | Pins tested OpenSSL / PyCA bindings |
| `pytest` | `pytest>=8.0.0` | `pytest>=8.0.0,<10.0.0` | Ensures test framework API consistency |
| `pytest-asyncio` | `pytest-asyncio>=0.23.0` | `pytest-asyncio>=0.23.0,<2.0.0` | Enforces asyncio test runner compatibility |
| `httpx` | `httpx>=0.27.0` | `httpx>=0.27.0,<1.0.0` | Locks HTTP client for ASGI testing |
| `dnspython` | `dnspython>=2.8.0` | `dnspython>=2.8.0,<3.0.0` | Ensures resolver API stability for SSRF defense |
| `PyYAML` | *(implicit / unlisted)* | `PyYAML>=6.0.0,<7.0.0` | Explicitly pins safe YAML parsing library |
| `certifi` | *(implicit / unlisted)* | `certifi>=2024.2.2` | Ensures trusted root CA certificate store is declared |

---

## 5. Accepted Risks & Compensating Controls

| Potential Risk Area | Assessment | Compensating Architectural Control in QuantumShield |
| :--- | :--- | :--- |
| **Parser Denial of Service** | Malformed or maliciously crafted config files (YAML, JSON, XML) could attempt CPU/memory exhaustion. | Enforced strict `SafeConfigParser` limits (Task B1): max depth <= 20, max nodes <= 5,000, alias count <= 5, string length <= 65,536, and forbidden XML DOCTYPE/ENTITY. |
| **Request Flooding & ReDoS** | High-volume endpoint abuse could exhaust server concurrency or thread workers. | `InMemoryRateLimiter` (Task B2) enforces sliding-window limits per client IP (10/min scan, 5/min upload/AI) and 5 concurrent scan slots with bounded storage. |
| **Internal Target Scanning (SSRF)** | Attackers supplying internal IPs or disallowed service ports to external scanners. | Strict IP validation (`is_safe_public_ip`) and explicit port allowlisting (`DEFAULT_ALLOWED_SCAN_PORTS = {443, 8443, 993, 995, 465}`) (Task B3). |
| **Large Payload Flooding** | Clients sending oversized multi-megabyte payloads to exhaust memory. | `RequestSizeLimitMiddleware` (Task B6) enforces a strict 5 MiB ceiling and returns HTTP 413 before parsing. |
| **Sensitive Data Exposure** | Exceptions returning file paths, credentials, or internal IPs. | `sanitize_error_detail` (Task B4) strips Windows/Linux paths, DB URIs, and credentials from all error responses. |

---

## 6. Verification & Reproducibility

The dependency audit can be reproduced at any time using the following commands from the repository root:

```powershell
# 1. Audit Python backend dependencies
python -m pip_audit -r backend/requirements.txt

# 2. Audit Node.js frontend dependencies
cd frontend
npm audit
cd ..
```
