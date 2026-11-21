"""Cryptographic Catalog and Post-Quantum Knowledge Base.
Defines risk classifications, quantum threat vectors (Shor vs Grover),
and NIST Post-Quantum Cryptography (PQC) standards mappings.
"""

import re
from typing import Dict, Any, Optional
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    INFO = "INFORMATIONAL"


class QuantumThreatVector(str, Enum):
    SHOR = "Shor's Algorithm (Polynomial Speedup)"
    GROVER = "Grover's Algorithm (Quadratic Speedup)"
    SNDL = "Store Now, Decrypt Later (SNDL)"
    CLASSICAL_BROKEN = "Classically Broken & Quantum Insecure"
    RESISTANT = "Quantum Resistant (Adequate Margin)"
    POST_QUANTUM = "Post-Quantum Cryptographic Primitive"


# NIST PQC Standards Reference Catalog
PQC_STANDARDS = {
    "ML_KEM": {
        "standard": "NIST FIPS 203 (ML-KEM / Kyber)",
        "description": "Module-Lattice-Based Key-Encapsulation Mechanism for general encryption and key exchange.",
        "levels": ["ML-KEM-512 (Category 1)", "ML-KEM-768 (Category 3)", "ML-KEM-1024 (Category 5)"],
        "hybrid_target": "X25519 + ML-KEM-768 hybrid key exchange (RFC 9870 / draft-ietf-tls-hybrid-design)",
    },
    "ML_DSA": {
        "standard": "NIST FIPS 204 (ML-DSA / Dilithium)",
        "description": "Module-Lattice-Based Digital Signature Standard for identity authentication and certificates.",
        "levels": ["ML-DSA-44 (Category 2)", "ML-DSA-65 (Category 3)", "ML-DSA-87 (Category 5)"],
        "hybrid_target": "Dual-signature or composite X.509 certificates (ECDSA + ML-DSA)",
    },
    "SLH_DSA": {
        "standard": "NIST FIPS 205 (SLH-DSA / SPHINCS+)",
        "description": "Stateless Hash-Based Digital Signature Standard, stateless alternative avoiding lattice assumptions.",
        "levels": ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f"],
        "target_use": "Long-lived root CAs and firmware signing where lattice security is conservative.",
    },
    "AES_256": {
        "standard": "NIST SP 800-131A Rev 2 / CNSA 2.0",
        "description": "256-bit symmetric encryption providing ~128 bits of security against Grover's algorithm.",
    },
    "SHA_384": {
        "standard": "NIST FIPS 180-4 / CNSA 2.0",
        "description": "SHA-384 or SHA-512 provides robust collision resistance under quantum collision search algorithms.",
    }
}


# Catalog of algorithm profiles with quantum assessment metadata
ALGORITHM_CATALOG: Dict[str, Dict[str, Any]] = {
    # Asymmetric Public Key & Signatures (Shor's Algorithm)
    "RSA": {
        "family": "RSA",
        "category": "public_key",
        "threat_vector": QuantumThreatVector.SHOR.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "RSA relies on the computational difficulty of factoring large composite integers. "
            "Shor's algorithm solves prime factorization in polynomial time O((log N)^3) on a "
            "cryptanalytically relevant quantum computer (CRQC), breaking all standard RSA key sizes."
        ),
        "target_standard": PQC_STANDARDS["ML_DSA"]["standard"],
    },
    "ECC": {
        "family": "ECC",
        "category": "public_key",
        "threat_vector": QuantumThreatVector.SHOR.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "Elliptic Curve Cryptography relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP). "
            "Shor's algorithm solves ECDLP in polynomial time. Standard curves (P-256, P-384, P-521) require "
            "fewer logical qubits to break than 2048-bit RSA, rendering them completely vulnerable to CRQCs."
        ),
        "target_standard": PQC_STANDARDS["ML_DSA"]["standard"],
    },
    "EdDSA": {
        "family": "EdDSA",
        "category": "public_key",
        "threat_vector": QuantumThreatVector.SHOR.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "Edwards-curve Digital Signature Algorithm (Ed25519/Ed448) is vulnerable to Shor's algorithm "
            "for elliptic curve discrete logarithms, and will be broken by a CRQC."
        ),
        "target_standard": PQC_STANDARDS["ML_DSA"]["standard"],
    },
    "Diffie-Hellman": {
        "family": "Diffie-Hellman",
        "category": "key_exchange",
        "threat_vector": QuantumThreatVector.SNDL.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "Classical Diffie-Hellman (DHE/DH) key establishment is broken by Shor's algorithm. "
            "Under 'Store Now, Decrypt Later' (SNDL), recorded ciphertexts can be decrypted retroactively."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    },
    "DH-1024": {
        "family": "Diffie-Hellman",
        "category": "key_exchange",
        "key_size": 1024,
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "1024-bit Diffie-Hellman is classically broken (vulnerable to Logjam attacks and precomputation) "
            "and disallowed by NIST SP 800-131A Rev 2. It is also completely broken by Shor's algorithm on a CRQC."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    },
    "DH-2048": {
        "family": "Diffie-Hellman",
        "category": "key_exchange",
        "key_size": 2048,
        "threat_vector": QuantumThreatVector.SNDL.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "2048-bit Diffie-Hellman provides ~112 bits of classical security, but is vulnerable to Shor's algorithm "
            "and 'Store Now, Decrypt Later' (SNDL) attacks by quantum adversaries."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    },
    "diffie-hellman-group1-sha1": {
        "family": "Diffie-Hellman",
        "category": "key_exchange",
        "key_size": 1024,
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "diffie-hellman-group1-sha1 uses a 1024-bit MODP group (Oakley Group 2) and deprecated SHA-1, "
            "rendering it vulnerable to Logjam precomputations, hash collisions, and Shor's algorithm."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    },
    "diffie-hellman-group14-sha256": {
        "family": "Diffie-Hellman",
        "category": "key_exchange",
        "key_size": 2048,
        "threat_vector": QuantumThreatVector.SNDL.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "diffie-hellman-group14-sha256 uses 2048-bit MODP group with SHA-256. Classically acceptable, "
            "but vulnerable to quantum SNDL attacks."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    },
    "ECDHE": {
        "family": "ECC",
        "category": "key_exchange",
        "threat_vector": QuantumThreatVector.SNDL.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "Ephemeral Elliptic Curve Diffie-Hellman (X25519, P-256) establishes forward-secret session keys "
            "against classical adversaries, but an adversary capturing encrypted sessions today can decrypt them "
            "later using Shor's algorithm on a quantum computer (SNDL attack)."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    },

    # Symmetric Ciphers (Grover's Algorithm)
    "AES-128": {
        "family": "AES",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.GROVER.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "Grover's algorithm provides a quadratic speedup for unstructured brute-force key search, "
            "reducing the effective security of 128-bit symmetric keys to ~64 bits. While not polynomial, "
            "a 64-bit security margin provides inadequate defense against well-resourced quantum adversaries."
        ),
        "target_standard": PQC_STANDARDS["AES_256"]["standard"],
    },
    "AES-256": {
        "family": "AES",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "AES-256 provides 256 bits of classical security. Under Grover's quantum attack, effective "
            "brute-force resistance remains ~128 bits, which exceeds current post-quantum security requirements."
        ),
        "target_standard": "Compliant (NIST CNSA 2.0 approved)",
    },
    "ChaCha20": {
        "family": "ChaCha",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "ChaCha20 uses a 256-bit key. Under Grover's quantum search, effective security remains "
            "~128 bits, providing solid post-quantum symmetric confidentiality."
        ),
        "target_standard": "Compliant (Quantum Resistant)",
    },

    # Hashes & MACs
    "SHA-256": {
        "family": "SHA-2",
        "category": "hash",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "SHA-256 provides 128-bit collision resistance classically. Quantum collision search (BHT algorithm) "
            "theoretically reduces collision search to ~2^85 operations, though quantum memory constraints make "
            "this attack extremely challenging. Suitable for standard security; transition to SHA-384 recommended for CNSA 2.0."
        ),
        "target_standard": PQC_STANDARDS["SHA_384"]["standard"],
    },
    "SHA-384": {
        "family": "SHA-2",
        "category": "hash",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "SHA-384 provides 192 bits of collision resistance classically and ~128 bits under quantum collision attacks, "
            "meeting the requirements of NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)."
        ),
        "target_standard": "Compliant (NIST CNSA 2.0 approved)",
    },
    "SHA-512": {
        "family": "SHA-2",
        "category": "hash",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "SHA-512 provides 256 bits of classical collision resistance and ~170 bits under quantum collision attacks, "
            "delivering extensive post-quantum safety margins."
        ),
        "target_standard": "Compliant (Post-Quantum Secure)",
    },
    "SHA-1": {
        "family": "SHA-1",
        "category": "hash",
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "SHA-1 is broken classically (collision attacks demonstrated since 2017) and offers zero quantum resilience."
        ),
        "target_standard": PQC_STANDARDS["SHA_384"]["standard"],
    },
    "MD5": {
        "family": "MD5",
        "category": "hash",
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "MD5 is severely compromised classically and must not be used in any security context."
        ),
        "target_standard": PQC_STANDARDS["SHA_384"]["standard"],
    },
    "3DES": {
        "family": "3DES",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "Triple-DES (3DES) is deprecated by NIST (SP 800-131A Rev 2) and disallowed after 2023 "
            "due to Sweet32 64-bit block collision attacks and inadequate key strength."
        ),
        "target_standard": PQC_STANDARDS["AES_256"]["standard"],
    },
    "DES": {
        "family": "DES",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "Single DES uses a 56-bit key trivially breakable by classical exhaustive search."
        ),
        "target_standard": PQC_STANDARDS["AES_256"]["standard"],
    },
    "RC4": {
        "family": "RC4",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "RC4 stream cipher suffers from severe statistical biases (RFC 7465 prohibits its use in TLS)."
        ),
        "target_standard": PQC_STANDARDS["AES_256"]["standard"],
    },
    "ML-KEM": {
        "family": "ML-KEM",
        "category": "key_exchange",
        "threat_vector": QuantumThreatVector.POST_QUANTUM.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "NIST FIPS 203 standardized post-quantum module-lattice key encapsulation mechanism."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["standard"],
    },
    "ML-DSA": {
        "family": "ML-DSA",
        "category": "public_key",
        "threat_vector": QuantumThreatVector.POST_QUANTUM.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "NIST FIPS 204 standardized post-quantum module-lattice digital signature standard."
        ),
        "target_standard": PQC_STANDARDS["ML_DSA"]["standard"],
    },
    "SLH-DSA": {
        "family": "SLH-DSA",
        "category": "public_key",
        "threat_vector": QuantumThreatVector.POST_QUANTUM.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "NIST FIPS 205 standardized stateless hash-based digital signature standard."
        ),
        "target_standard": PQC_STANDARDS["SLH_DSA"]["standard"],
    },
}


def parse_dh_parameter(val_or_name: Optional[str]) -> Optional[Dict[str, Any]]:
    """Identifies and parses Diffie-Hellman parameters, groups, and key exchange algorithms.
    Accurately extracts canonical family ('Diffie-Hellman'), key size, role ('Key Establishment'),
    weakness classification, severity (CRITICAL vs HIGH), and NIST ML-KEM migration recommendations.
    """
    if not val_or_name or not isinstance(val_or_name, str):
        return None
    clean = val_or_name.strip()
    clean_u = clean.upper()

    # Fast validation: is this a Diffie-Hellman indicator?
    is_dh = False
    if any(k in clean_u for k in ("DIFFIE", "DHE", "FFDHE", "DHPARAM", "DH_PARAM", "SSL_DHPARAM")):
        is_dh = True
    elif "DH" in clean_u and not any(k in clean_u for k in ("ECDH", "CHACHA")):
        # Look for DH followed or preceded by numbers, or word boundary / file extension
        if re.search(r"(?i)(?:\b|_|-|/)dh(?:\b|_|-|\d|\.pem)", clean):
            is_dh = True

    if not is_dh:
        return None

    # Key size extraction
    key_size = None
    if "GROUP14" in clean_u:
        key_size = 2048
    elif "GROUP15" in clean_u:
        key_size = 3072
    elif "GROUP16" in clean_u:
        key_size = 4096
    elif "GROUP1" in clean_u or "GROUP2" in clean_u:
        key_size = 1024
    elif "1024" in clean_u:
        key_size = 1024
    elif "2048" in clean_u:
        key_size = 2048
    elif "3072" in clean_u:
        key_size = 3072
    elif "4096" in clean_u:
        key_size = 4096
    elif "768" in clean_u:
        key_size = 768
    else:
        m = re.search(r"(?i)(?:dh|ffdhe)?[-_]?(\d{3,4})", clean)
        if m:
            try:
                key_size = int(m.group(1))
            except ValueError:
                key_size = None

    # Weakness determination: key_size < 2048 or SHA-1 usage
    is_weak = False
    if key_size is not None and key_size < 2048:
        is_weak = True
    if "SHA1" in clean_u or "SHA-1" in clean_u:
        is_weak = True

    # Canonical name
    if "GROUP1-SHA1" in clean_u or "GROUP1_SHA1" in clean_u:
        canonical_name = "diffie-hellman-group1-sha1"
    elif "GROUP14-SHA256" in clean_u or "GROUP14_SHA256" in clean_u:
        canonical_name = "diffie-hellman-group14-sha256"
    elif "FFDHE" in clean_u and key_size:
        canonical_name = f"FFDHE-{key_size}"
    elif key_size:
        canonical_name = f"DH-{key_size}"
    else:
        canonical_name = "Diffie-Hellman"

    severity = "CRITICAL" if is_weak else "HIGH"
    threat_vector = (
        QuantumThreatVector.CLASSICAL_BROKEN.value
        if is_weak
        else QuantumThreatVector.SNDL.value
    )

    rec = "Upgrade to X25519 + ML-KEM-768 hybrid key exchange (NIST FIPS 203) and decommission finite-field Diffie-Hellman."

    return {
        "family": "Diffie-Hellman",
        "role": "Key Establishment",
        "canonical_name": canonical_name,
        "key_size": key_size,
        "is_weak": is_weak,
        "severity": severity,
        "threat_vector": threat_vector,
        "recommendation": rec,
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    }


def get_algorithm_profile(algo_name: Optional[str]) -> Optional[Dict[str, Any]]:
    """Retrieves the cryptographic profile and quantum threat assessment for a primitive.
    Matches exact catalog keys or canonical algorithm identifiers.
    """
    if not algo_name or not isinstance(algo_name, str):
        return None
    clean = algo_name.strip().upper()
    if not clean:
        return None

    # 1. Exact catalog key match (case-insensitive)
    for key, profile in ALGORITHM_CATALOG.items():
        if clean == key.upper():
            return profile

    # 2. Canonical substring pattern matches
    # Diffie-Hellman variants and parameters
    dh_info = parse_dh_parameter(clean)
    if dh_info:
        canon = dh_info["canonical_name"]
        if canon in ALGORITHM_CATALOG:
            return ALGORITHM_CATALOG[canon]
        return {
            "family": dh_info["family"],
            "category": "key_exchange",
            "key_size": dh_info["key_size"],
            "threat_vector": dh_info["threat_vector"],
            "shor_vulnerable": True,
            "grover_vulnerable": False,
            "vulnerability_explanation": (
                f"{dh_info['canonical_name']} key establishment is vulnerable to Shor's algorithm and SNDL."
                if not dh_info["is_weak"]
                else f"{dh_info['canonical_name']} is classically broken (inadequate key size / Logjam) and vulnerable to Shor's algorithm."
            ),
            "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
        }

    # Classically broken primitives
    if any(k in clean for k in ["3DES", "TRIPLE-DES", "DES-EDE"]):
        return ALGORITHM_CATALOG.get("3DES")
    if "RC4" in clean:
        return ALGORITHM_CATALOG.get("RC4")
    if "MD5" in clean:
        return ALGORITHM_CATALOG.get("MD5")
    if "SHA-1" in clean or "SHA1" in clean:
        return ALGORITHM_CATALOG.get("SHA-1")
    if "DES" in clean and not any(k in clean for k in ["ED25519", "ED448", "EDDSA", "ECDSA", "ML-DSA", "SLH-DSA"]):
        return ALGORITHM_CATALOG.get("DES")

    # Post-quantum primitives
    if any(k in clean for k in ["ML-KEM", "KYBER"]):
        return ALGORITHM_CATALOG.get("ML-KEM")
    if any(k in clean for k in ["ML-DSA", "DILITHIUM"]):
        return ALGORITHM_CATALOG.get("ML-DSA")
    if any(k in clean for k in ["SLH-DSA", "SPHINCS"]):
        return ALGORITHM_CATALOG.get("SLH-DSA")

    # Quantum-resistant symmetric ciphers & hashes
    if any(k in clean for k in ["AES-256", "AES256"]):
        return ALGORITHM_CATALOG.get("AES-256")
    if any(k in clean for k in ["CHACHA20", "CHACHA"]):
        return ALGORITHM_CATALOG.get("ChaCha20")
    if any(k in clean for k in ["SHA-512", "SHA512"]):
        return ALGORITHM_CATALOG.get("SHA-512")
    if any(k in clean for k in ["SHA-384", "SHA384"]):
        return ALGORITHM_CATALOG.get("SHA-384")
    if any(k in clean for k in ["SHA-256", "SHA256"]):
        return ALGORITHM_CATALOG.get("SHA-256")

    # Grover-vulnerable symmetric ciphers
    if any(k in clean for k in ["AES-128", "AES128", "AES-192", "AES192"]):
        return ALGORITHM_CATALOG.get("AES-128")

    # Shor-vulnerable asymmetric public-key and key-exchange algorithms
    if "RSA" in clean:
        return ALGORITHM_CATALOG.get("RSA")
    if "ECDHE" in clean or "X25519" in clean:
        return ALGORITHM_CATALOG.get("ECDHE")
    if any(k in clean for k in ["ECDSA", "ECC", "SECP", "PRIME256"]):
        return ALGORITHM_CATALOG.get("ECC")
    if any(k in clean for k in ["ED25519", "ED448", "EDDSA"]):
        return ALGORITHM_CATALOG.get("EdDSA")
    if any(k in clean for k in ["DIFFIE", "DHE"]) or ("DH" in clean and "ECDH" not in clean):
        return ALGORITHM_CATALOG.get("Diffie-Hellman")

    return None


def classify_risk_domain(
    algorithm: Optional[str] = None,
    threat_vector: Optional[str] = None,
    title: Optional[str] = None,
    category: Optional[str] = None,
    default: str = "CLASSICAL",
) -> str:
    """Deterministically classifies finding risk domain into 'QUANTUM' or 'CLASSICAL'.

    Evaluation order:
    1. Explicit threat vector mapping (e.g. SHOR, GROVER, SNDL, RESISTANT, POST_QUANTUM -> QUANTUM;
       CLASSICAL_BROKEN -> CLASSICAL).
    2. Central knowledge base lookup via get_algorithm_profile(algorithm).
    3. Structural text pattern matching across title, category, and algorithm.
    4. Safe fallback to default.
    """
    # 1. Threat vector mapping
    if threat_vector:
        tv = str(threat_vector).upper()
        # Must check CLASSICAL_BROKEN before checking for "QUANTUM" because
        # CLASSICAL_BROKEN's description is "Classically Broken & Quantum Insecure".
        if (
            "CLASSICAL_BROKEN" in tv
            or "CLASSICALLY BROKEN" in tv
            or tv == QuantumThreatVector.CLASSICAL_BROKEN.value.upper()
        ):
            return "CLASSICAL"
        if any(
            q in tv
            for q in [
                "SHOR",
                "GROVER",
                "SNDL",
                "RESISTANT",
                "POST_QUANTUM",
                "POST-QUANTUM",
                "QUANTUM",
            ]
        ):
            return "QUANTUM"

    # 2. Central knowledge base lookup
    if algorithm:
        profile = get_algorithm_profile(algorithm)
        if profile and "threat_vector" in profile:
            vec = profile["threat_vector"]
            if vec == QuantumThreatVector.CLASSICAL_BROKEN.value:
                return "CLASSICAL"
            if vec in (
                QuantumThreatVector.SHOR.value,
                QuantumThreatVector.GROVER.value,
                QuantumThreatVector.SNDL.value,
                QuantumThreatVector.RESISTANT.value,
                QuantumThreatVector.POST_QUANTUM.value,
            ):
                return "QUANTUM"

    # 3. Contextual text pattern matching
    combined = f"{algorithm or ''} {title or ''} {category or ''}".upper()

    # Broken classical cryptography / implementation flaws
    if any(
        c in combined
        for c in [
            "3DES",
            "DES",
            "MD5",
            "SHA-1",
            "SHA1",
            "RC4",
            "RC2",
            "BLOWFISH",
            "ECB",
            "NO_SALT",
            "STATIC_IV",
            "WEAK_RANDOM",
            "TLS 1.0",
            "TLS 1.1",
            "TLS1.0",
            "TLS1.1",
            "EXPIRED",
            "CLASSICAL_BROKEN",
            "CLASSICAL_SECURITY",
        ]
    ):
        return "CLASSICAL"

    # Quantum threat / PQC indicators
    if any(
        q in combined
        for q in [
            "SHOR",
            "GROVER",
            "SNDL",
            "PQC",
            "QUANTUM",
            "ML-KEM",
            "ML-DSA",
            "SLH-DSA",
            "KYBER",
            "DILITHIUM",
            "SPHINCS",
            "RSA",
            "ECDH",
            "ECDSA",
            "DIFFIE",
            "X25519",
            "AES-128",
            "AES128",
            "AES-256",
            "AES256",
            "CHACHA20",
        ]
    ):
        return "QUANTUM"

    return default

