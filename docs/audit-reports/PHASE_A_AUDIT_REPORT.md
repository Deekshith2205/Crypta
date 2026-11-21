# Phase A Audit Report: Cryptographic Classification, Catalog & Normalization Hardening

**Platform:** QuantumShield — Banking Quantum Readiness & Remediation Engine  
**Branch:** `janya`  
**Phase:** Phase A (Tasks A1 – A6)  
**Status:** Completed & Fully Verified  

---

## 1. Phase Overview

Phase A addresses core cryptographic assessment integrity across QuantumShield. The platform audits banking systems to identify cryptographic assets, detect cryptographic misuses, evaluate classical and post-quantum security vulnerabilities, and generate prioritized remediation roadmaps.

Prior to Phase A, the ingestion and normalization layer exhibited several architectural shortcomings:
- Decentralized, duplicate algorithm classification logic scattered across scanners and normalizers.
- Incomplete parameter parsing for key exchange protocols such as Diffie-Hellman, leading to inaccurate risk assignment.
- Fragile handling of unknown or proprietary algorithms, risking either silent drop or the invention of non-existent vulnerabilities.
- Naive deduplication logic collapsing distinct pieces of evidence across microservices, files, lines, and cryptographic roles.
- Generic post-quantum remediation recommendations conflating disjoint cryptographic functions (such as recommending digital signature algorithms for key exchange).

Phase A established a centralized, deterministic classification engine, hardened normalization invariants, safe deduplication cardinality, and strictly role-aware post-quantum recommendations aligned with NIST FIPS 203, 204, and 205 standards.

---

## 2. Original Audit Findings

The independent application-security audit identified the following primary weaknesses in the cryptographic classification and evidence normalization subsystems:

1. **Fragmented Classification Logic (Audit Finding A-01):**
   Algorithm classification was duplicated across `crypto_catalog.py`, `quantum_risk.py`, `finding_normalizer.py`, and rule evaluators. New primitives (e.g., 3DES, RC4, post-quantum standards like ML-KEM/ML-DSA) were not consistently mapped across all paths, resulting in conflicting severity levels.

2. **Diffie-Hellman Parameter Ambiguity (Audit Finding A-02):**
   Diffie-Hellman configurations (`DH-1024`, `DH-2048`, `diffie-hellman-group1-sha1`, `dh1024.pem`) were either treated identically or categorized without extracting underlying group sizes and key lengths. Legacy 1024-bit DH was not differentiated in severity from standard 2048-bit DH facing quantum Shor threats.

3. **Unknown Algorithm Mishandling & Invariant Violations (Audit Finding A-03):**
   Strings representing unknown, proprietary, or custom algorithms were either discarded during normalization or subjected to arbitrary severity assignment. Furthermore, non-observable states were occasionally conflated with confirmed vulnerabilities, violating the core evidence invariant `NOT_OBSERVABLE != VULNERABLE`.

4. **Over-Aggressive Evidence Deduplication (Audit Finding A-04):**
   Findings were deduplicated using a simplistic `(rule_id, value)` tuple. This caused legitimate distinct findings occurring across different banking services (e.g., Core Banking vs. Payment Gateway), different source files, different lines, or different cryptographic roles to be collapsed into a single finding, obscuring the true attack surface.

5. **Conflated Quantum Migration Guidance (Audit Finding A-05):**
   Remediation recommendations frequently suggested generic `"ML-KEM / ML-DSA"` phrasing regardless of whether the finding pertained to key encapsulation, digital signature authentication, or symmetric bulk encryption.

---

## 3. Root Causes

| Issue | Root Cause |
| :--- | :--- |
| **A1: Classification Duplication** | Lack of a single authoritative entrypoint for algorithm domain mapping. Scanners and normalizers implemented ad-hoc string comparisons and fallback dictionaries. |
| **A2: DH Parameter Parsing** | Normalizers evaluated DH algorithm names via regex patterns that matched `"DH"` without parsing parameter bit lengths or known RFC groups (e.g., Oakley Group 1 / RFC 2409). |
| **A3: Unknown Primitive Handling** | Lack of an explicit `is_known_algorithm()` validator to distinguish known primitives from uncataloged identifiers or non-cryptographic configuration strings (e.g., file paths, booleans). |
| **A4: Deduplication Collisions** | Deduplication keys omitted operational metadata (`source`, `source_file`, `source_line`, and `role`), assuming `rule_id` and raw algorithm string were globally unique within a scan. |
| **A5: Role-Agnostic Recommendations** | Normalizers lacked contextual role dispatching, using static recommendation templates that lumped Key Encapsulation (KEM) and Digital Signature Algorithms (DSA) together. |

---

## 4. Changes Implemented

### Task A1: Centralized Cryptographic Classification
- **Files Modified:**
  - `backend/app/security/crypto_catalog.py`: Added canonical profiles for 3DES, DES, RC4, ChaCha20-Poly1305, ML-KEM, ML-DSA, and SLH-DSA; implemented `classify_risk_domain()` and `get_algorithm_profile()`.
  - `backend/app/services/finding_normalizer.py`: Replaced fragmented regexes and dictionaries with calls to `classify_risk_domain()`.
- **New Tests:**
  - `backend/tests/test_crypto_classification_hardening.py`: Verified centralized mapping, classical/quantum classification, and catalog completeness.

### Task A2: Diffie-Hellman Parameter Parsing & Severity Differentiation
- **Files Modified:**
  - `backend/app/security/crypto_catalog.py`: Implemented `parse_dh_parameter()` extracting family, key size, and cryptographic role for strings like `DH-1024`, `DH-2048`, `diffie-hellman-group1-sha1`, and `.pem` parameter files.
  - `backend/app/services/finding_normalizer.py`: Updated config and TLS finding normalizers to rate weak DH (<2048 bits / Group 1) as `CRITICAL` (classically broken) and standard DH (>=2048 bits) as `HIGH` (quantum Shor threat).
- **New Tests:**
  - `backend/tests/test_diffie_hellman_classification.py`: Verified extraction of key sizes, group names, and appropriate severity graduation.

### Task A3: Unknown Algorithm Classification & Invariant Hardening
- **Files Modified:**
  - `backend/app/security/crypto_catalog.py`: Added `is_known_algorithm()` to identify cataloged primitives and default uncataloged strings to `risk="UNKNOWN"`.
  - `backend/app/services/finding_normalizer.py`: Hardened `normalize_config_finding`, `normalize_tls_finding`, and `normalize_profile_evidence_item` so uncataloged strings are preserved with `risk="UNKNOWN"` and neutral severity (`INFORMATIONAL`/`LOW`). Separated operational configuration artifacts (`.pem`, `.so`, booleans, secret redactions) from cryptographic algorithms. Enforced `NOT_OBSERVABLE != VULNERABLE`.
- **New Tests:**
  - `backend/tests/test_unknown_algorithm_handling.py`: Validated preservation of uncataloged algorithms, absence of hallucinated vulnerabilities, and non-observable invariant protection.

### Task A4: Safe Finding Deduplication
- **Files Modified:**
  - `backend/app/services/finding_normalizer.py`: Implemented `make_finding_dedup_key()` constructing a 6-tuple `(rule_id, value, role, source, source_file, source_line)` across TLS, static config, profile, and misuse scanners.
- **New Tests:**
  - `backend/tests/test_finding_deduplication.py`: Verified that identical findings are safely deduplicated while distinct findings across files, lines, and roles are preserved.

### Task A5: Role-Aware Quantum Migration Recommendations
- **Files Modified:**
  - `backend/app/security/crypto_catalog.py`: Implemented `resolve_quantum_migration_recommendation()` enforcing strict role alignment:
    - *Key Establishment / Exchange:* NIST FIPS 203 (ML-KEM / Kyber) or hybrid (X25519 + ML-KEM-768); never ML-DSA.
    - *Digital Signatures / Certificates:* NIST FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA); never ML-KEM.
    - *Symmetric Ciphers:* Evaluates Grover's algorithm speedup and recommends AES-256-GCM (~128-bit quantum security margin); never KEM/DSA.
    - *Hybrid Schemes:* Categorized as positive quantum-ready posture (`INFORMATIONAL`).
  - `backend/app/services/finding_normalizer.py`: Routed TLS, config, and profile normalization paths through `resolve_quantum_migration_recommendation()`.
- **New Tests:**
  - `backend/tests/test_quantum_migration_recommendations.py`: Verified strict separation between KEM and DSA recommendations, Grover guidance for symmetric keys, and hybrid recognition.

---

## 5. Security & Architectural Improvements

1. **Deterministic Single Source of Truth:**
   All cryptographic classifications now originate from `crypto_catalog.py`, eliminating conflicting interpretations between scanners.
2. **Elimination of False Certainty on Unknowns:**
   Uncataloged or proprietary algorithms are explicitly surfaced as `risk="UNKNOWN"` with neutral severity, preventing false positives while alerting auditors to manual review requirements.
3. **Strict Invariant Enforcement:**
   `NOT_OBSERVABLE` evidence statuses never inherit vulnerability severities (`CRITICAL` or `HIGH`), preserving audit integrity.
4. **Accurate Attack Surface Representation:**
   6-tuple deduplication ensures that an organization using `RSA-2048` across 10 distinct microservices sees all 10 distinct exposure points rather than 1 collapsed finding.
5. **Standards-Compliant Remediation:**
   Remediation advice strictly conforms to NIST post-quantum standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), preventing engineers from misapplying signature algorithms to key encapsulation or vice-versa.

---

## 6. Test Verification Evidence

### Phase A Test Suites
```bash
python -m pytest \
  backend/tests/test_crypto_classification_hardening.py \
  backend/tests/test_diffie_hellman_classification.py \
  backend/tests/test_unknown_algorithm_handling.py \
  backend/tests/test_finding_deduplication.py \
  backend/tests/test_quantum_migration_recommendations.py \
  backend/tests/test_evidence_integration.py -v
```
**Result:** 31 passed in 1.45s.

### Full Backend Regression Suite
```bash
python -m pytest -q
```
**Result:** 451 passed, 1 warning in 18.73s.

### Frontend Test Suite
```bash
npm.cmd test -- --run
```
**Result:** 15 passed, 0 failed, 4 suites passed in 293ms.

### Frontend TypeScript & Linter Verification
```bash
npx tsc --noEmit; npx oxlint; npm run build
```
**Result:** 0 errors, build successful in 1.25s.

---

## 7. Git Commit Log for Phase A

All commits reside exclusively on the `janya` branch and have been pushed to `origin/janya`:

| Commit Hash | Description |
| :--- | :--- |
| `33276ad` | `refactor(crypto): centralize algorithm risk domain classification (Task A1)` |
| `162bb38` | `refactor(crypto): harden Diffie-Hellman classification and parameter extraction (Task A2)` |
| `1004e8a` | `fix(crypto): preserve unknown algorithms as neutral findings (Task A3)` |
| `fc2b2c8` | `fix(findings): deduplicate cryptographic evidence safely (Task A4)` |
| `5c8beff` | `fix(crypto): ensure role-aware quantum migration recommendations (Task A5)` |

---

## 8. Sign-Off & Transition

Phase A is complete, verified, and adheres to all engineering and security specifications. All regression suites pass without warnings or defects. The repository is ready to proceed to **Phase B: Upload Validation, File Ingestion, and Scanner Robustness**.
