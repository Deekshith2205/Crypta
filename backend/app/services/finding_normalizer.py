"""Unified Finding Normalization Pipeline.
Integrates findings across TLS Scanner, Crypto Misuse Scanner, Configuration Scanner,
and Banking Profile declarations into a standardized NormalizedFinding collection.
Enforces strict evidence semantics: NOT_OBSERVABLE != VULNERABLE.
"""

from typing import List, Dict, Any, Optional
from app.models.findings import NormalizedFinding
from app.models.banking import BankingAsset, EvidenceItem
from app.security.crypto_catalog import classify_risk_domain, parse_dh_parameter, is_known_algorithm


def is_empty_or_placeholder(val: Any) -> bool:
    """Returns True if the value is missing, empty, or unobservable placeholder."""
    if val is None:
        return True
    s = str(val).strip().upper()
    return s in ("", "NONE", "N/A", "UNKNOWN", "NOT OBSERVABLE", "NOT_OBSERVABLE", "UNSPECIFIED", "NULL")


def is_file_or_path(val: Any) -> bool:
    """Returns True if the value represents a file path or library name."""
    s = str(val).strip()
    if "/" in s or "\\" in s:
        return True
    return any(s.lower().endswith(ext) for ext in [".crt", ".pem", ".key", ".cer", ".so", ".dll", ".dylib", ".conf", ".yaml", ".yml", ".json"])



def sanitize_secret_value(val: str) -> str:
    """Strictly redacts private keys and secret material from finding values."""
    val_u = str(val).upper()
    if "BEGIN" in val_u and "PRIVATE KEY" in val_u:
        return "[REDACTED_PRIVATE_KEY_MATERIAL]"
    if "AKIA" in str(val):
        return "[REDACTED_API_KEY]"
    return str(val)


def normalize_tls_finding(finding: Any, system_id: Optional[str] = None) -> NormalizedFinding:
    """Normalizes a raw TLS finding into a NormalizedFinding."""
    fid = getattr(finding, "id", getattr(finding, "rule_id", "TLS-FINDING"))
    title = getattr(finding, "title", "TLS Observation")
    role = getattr(finding, "role", getattr(finding, "category", "Perimeter Cryptography"))
    val = sanitize_secret_value(str(getattr(finding, "value", getattr(finding, "algorithm", "N/A"))))
    src = getattr(finding, "source", "EXTERNAL_SCAN")
    sev = str(getattr(finding, "risk_level", getattr(finding, "severity", "MEDIUM"))).upper()
    ev = getattr(finding, "evidence", getattr(finding, "observability", getattr(finding, "evidence_status", "OBSERVED")))

    # Determine risk category (Quantum vs Classical vs Unknown)
    threat = getattr(finding, "quantum_threat", getattr(finding, "quantum_threat_vector", None))
    cat = getattr(finding, "category", None)

    is_empty = is_empty_or_placeholder(val)

    if is_empty or str(ev).upper() == "NOT_OBSERVABLE":
        ev = "NOT_OBSERVABLE"
        sev = "INFORMATIONAL"
        risk = "UNKNOWN"
        msg = getattr(finding, "security_impact", getattr(finding, "reason", getattr(finding, "message", f"{title}: Parameter is not observable.")))
        rec = getattr(finding, "recommendation", "Directly inspect TLS server configuration.")
    elif not is_known_algorithm(val) and not threat:
        # Task A3: Unknown TLS cipher or parameter without recognized threat vector
        risk = "UNKNOWN"
        sev = "INFORMATIONAL" if sev in ("HIGH", "CRITICAL") else sev
        msg = getattr(finding, "security_impact", getattr(finding, "reason", getattr(finding, "message", f"{title}: Negotiated unknown or unrecognized cipher suite ({val}).")))
        raw_rec = getattr(finding, "recommendation", None)
        if raw_rec and not any(pqc in raw_rec.upper() for pqc in ["POST-QUANTUM", "PQC", "ML-KEM", "ML-DSA"]):
            rec = raw_rec
        else:
            rec = "Inspect TLS cipher configuration and verify cipher suite security properties."
    else:
        default_risk = "QUANTUM" if getattr(finding, "is_quantum_vulnerable", True) else "CLASSICAL"
        risk = classify_risk_domain(
            algorithm=val,
            threat_vector=str(threat) if threat else None,
            title=title,
            category=str(cat) if cat else None,
            default=default_risk,
        )
        msg = getattr(finding, "security_impact", getattr(finding, "reason", getattr(finding, "message", title)))
        rec = getattr(finding, "recommendation", "Upgrade to post-quantum cryptographic standards.")

    # Invariant: If evidence is NOT_OBSERVABLE, severity must not be CRITICAL/HIGH vulnerability
    if str(ev).upper() == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"

    return NormalizedFinding(
        rule_id=str(fid),
        title=title,
        value=val,
        role=str(role),
        source=str(src) if src else "EXTERNAL_SCAN",
        source_file=getattr(finding, "source_file", None),
        source_line=getattr(finding, "source_line", getattr(finding, "line", None)),
        evidence_status=str(ev).upper(),
        severity=str(sev).upper(),
        risk=risk,
        message=str(msg),
        recommendation=str(rec),
        system_id=system_id,
        asset_id=system_id,
        layer="EDGE",
        metadata={"category": getattr(finding, "category", None)},
    )


def normalize_crypto_misuse_finding(finding: Any, system_id: Optional[str] = None) -> NormalizedFinding:
    """Normalizes a MisuseFinding into a NormalizedFinding."""
    fid = getattr(finding, "rule_id", "MISUSE-GENERIC")
    title = getattr(finding, "title", "Crypto Misuse Observation")
    val = sanitize_secret_value(str(getattr(finding, "matched_value", getattr(finding, "value", "N/A"))))
    role = str(getattr(finding, "role", "CODE_IMPLEMENTATION"))
    src = "CODE_ANALYSIS"
    ev = str(getattr(finding, "evidence_status", "OBSERVED")).upper()
    sev = str(getattr(finding, "severity", "HIGH")).upper()
    
    raw_risk = str(getattr(finding, "risk", "")).upper()
    if "QUANTUM" in raw_risk or any(q in str(fid).upper() for q in ["RSA-KEX", "ECDH-KEX", "QUANTUM"]):
        risk = "QUANTUM"
    elif raw_risk in ("CLASSICAL_SECURITY", "IMPLEMENTATION_SECURITY", "SECRET_EXPOSURE", "CRYPTO_AGILITY", "CLASSICAL"):
        risk = "CLASSICAL"
    else:
        threat = getattr(finding, "quantum_threat_vector", None)
        risk = classify_risk_domain(
            algorithm=val,
            threat_vector=str(threat) if threat else None,
            title=title,
            category=role,
            default="CLASSICAL",
        )

    msg = getattr(finding, "description", getattr(finding, "message", title))
    rec = getattr(finding, "recommendation", "Follow cryptographic implementation best practices.")
    file_path = getattr(finding, "file", getattr(finding, "source_file", None))
    line_no = getattr(finding, "line", getattr(finding, "line_number", getattr(finding, "source_line", None)))

    # Invariant: If evidence is NOT_OBSERVABLE, severity must not be CRITICAL/HIGH
    if ev == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"

    return NormalizedFinding(
        rule_id=str(fid),
        title=title,
        value=val,
        role=role,
        source=src,
        source_file=str(file_path) if file_path else None,
        source_line=int(line_no) if line_no is not None else None,
        evidence_status=ev,
        severity=sev,
        risk=risk,
        message=str(msg),
        recommendation=str(rec),
        system_id=system_id,
        asset_id=system_id,
        layer="SERVICE_TO_SERVICE",
        metadata={
            "language": getattr(finding, "language", None),
            "confidence": getattr(finding, "confidence", None),
            **(getattr(finding, "metadata", {}) or {}),
            "scanner_risk_category": raw_risk,
        },
    )


def normalize_config_finding(finding: Any, system_id: Optional[str] = None) -> NormalizedFinding:
    """Normalizes a ConfigObservation or ConfigFinding into a NormalizedFinding."""
    fid = getattr(finding, "rule_id", f"CFG-{getattr(finding, 'path', getattr(finding, 'asset_name', 'OBSERVATION'))}")
    title = getattr(finding, "title", getattr(finding, "asset_name", getattr(finding, "path", "Configuration Observation")))
    raw_val = getattr(finding, "parsed_value", getattr(finding, "raw_value", getattr(finding, "value", None)))
    val = sanitize_secret_value(str(raw_val if raw_val is not None else "N/A"))
    role_raw = getattr(finding, "role", "CONFIGURATION")
    role = role_raw.value if hasattr(role_raw, "value") else str(role_raw)
    src = "CONFIGURATION_FILE"
    ev_raw = getattr(finding, "evidence_status", "OBSERVED")
    ev = ev_raw.value if hasattr(ev_raw, "value") else str(ev_raw)
    sev = str(getattr(finding, "severity", "MEDIUM")).upper()

    threat = getattr(finding, "quantum_threat", getattr(finding, "quantum_threat_vector", None))
    cat = getattr(finding, "category", None) or str(fid)
    file_path = getattr(finding, "source_file", getattr(finding, "file", getattr(finding, "file_path", None)))
    line_no = getattr(finding, "source_line", getattr(finding, "line", None))

    is_empty = is_empty_or_placeholder(raw_val) or is_empty_or_placeholder(val)
    algo_candidate = getattr(finding, "algorithm", None) or val
    is_operational_val = (
        isinstance(raw_val, bool)
        or (isinstance(raw_val, (int, float)) and not getattr(finding, "algorithm", None))
        or is_file_or_path(val)
        or "REDACTED" in str(val).upper()
    )

    if is_empty or ev.upper() == "NOT_OBSERVABLE":
        ev = "NOT_OBSERVABLE"
        sev = "INFORMATIONAL"
        risk = "UNKNOWN"
        msg = getattr(finding, "description", getattr(finding, "message", f"{title}: Parameter value is missing or not observable."))
        rec = getattr(finding, "recommendation", "Inspect configuration directly or configure missing parameter.")
    else:
        # Check for Diffie-Hellman parameter or algorithm
        dh_info = parse_dh_parameter(algo_candidate) or parse_dh_parameter(val) or parse_dh_parameter(title)
        if not dh_info and any(k in str(val).upper() or k in str(title).upper() for k in ("DIFFIE-HELLMAN", "DHPARAM", "DH-1024", "DH-2048", "DH1024")):
            dh_info = parse_dh_parameter(f"{title} {val}")

        if dh_info:
            role = "Key Establishment"
            sev = dh_info["severity"]
            risk = "CLASSICAL" if dh_info["is_weak"] else "QUANTUM"
            rec = dh_info["recommendation"]
            msg = (
                f"Diffie-Hellman key exchange ({dh_info['canonical_name']}) configured with "
                f"{dh_info['key_size'] or 'unspecified'}-bit parameters. "
                f"{'Insecure key size vulnerable to Logjam and discrete log precomputation; ' if dh_info['is_weak'] else ''}"
                f"vulnerable to Shor's algorithm and Store Now, Decrypt Later (SNDL)."
            )
        elif role in ("SYSTEM_METADATA", "KEY_STORAGE", "KEY_ROTATION", "CERTIFICATE_VALIDATION") or is_operational_val:
            risk = "CLASSICAL"
            sev = "INFORMATIONAL" if (sev in ("HIGH", "CRITICAL", "MEDIUM") and role in ("SYSTEM_METADATA", "KEY_ROTATION")) else sev
            msg = getattr(finding, "description", getattr(finding, "message", f"{title}: {val}"))
            rec = getattr(finding, "recommendation", "Maintain system configuration and key management policies.")
        elif not is_known_algorithm(algo_candidate):
            # Task A3: Unknown / unrecognized algorithm
            risk = "UNKNOWN"
            sev = "INFORMATIONAL" if sev in ("HIGH", "CRITICAL", "MEDIUM") else sev
            msg = getattr(
                finding,
                "description",
                getattr(
                    finding,
                    "message",
                    f"{title} specifies unknown or unrecognized cryptographic primitive ({val}). Cryptographic security properties cannot be determined automatically.",
                ),
            )
            if "unknown" not in msg.lower() and "unrecognized" not in msg.lower():
                msg = f"{title} specifies unknown or unrecognized cryptographic primitive ({val}). {msg}"
            raw_rec = getattr(finding, "recommendation", None)
            if raw_rec and not any(pqc in raw_rec.upper() for pqc in ["ML-KEM", "ML-DSA", "AES-256", "KYBER", "DILITHIUM"]):
                rec = raw_rec
            else:
                rec = "Review proprietary or unknown algorithm specifications against organizational cryptographic policies."
        else:
            risk = classify_risk_domain(
                algorithm=str(algo_candidate),
                threat_vector=str(threat) if threat else None,
                title=title,
                category=str(cat),
                default="CLASSICAL",
            )
            msg = getattr(finding, "description", getattr(finding, "message", f"{title}: {val}"))
            rec = getattr(finding, "recommendation", "Review and align configuration with banking standards.")

    # Invariant: If not observable, not vulnerable
    if ev.upper() == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"

    return NormalizedFinding(
        rule_id=str(fid),
        title=title,
        value=val,
        role=role,
        source=src,
        source_file=str(file_path) if file_path else None,
        source_line=int(line_no) if line_no is not None else None,
        evidence_status=ev.upper(),
        severity=sev,
        risk=risk,
        message=str(msg),
        recommendation=str(rec),
        system_id=system_id,
        asset_id=system_id,
        layer=getattr(finding, "layer", "CONFIGURATION"),
        metadata={
            "crypto_agility": getattr(finding, "crypto_agility", None),
            **(getattr(finding, "metadata", {}) or {}),
        },
    )


def normalize_profile_evidence_item(item: EvidenceItem, system_id: Optional[str] = None) -> NormalizedFinding:
    """Normalizes an explicit Banking Profile EvidenceItem into a NormalizedFinding."""
    val_upper = item.value.upper()
    role = item.control
    src = item.source.value if hasattr(item.source, "value") else str(item.source)
    obs = item.observability.value if hasattr(item.observability, "value") else str(item.observability)
    layer = item.layer.value if (item.layer and hasattr(item.layer, "value")) else str(item.layer or "EDGE")

    ev_status = "DECLARED" if src == "OPERATOR_DECLARED" else ("OBSERVED" if src == "CONFIGURATION_FILE" else obs)

    if is_empty_or_placeholder(item.value) or obs == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"
        risk = "UNKNOWN"
        msg = item.description or f"{item.control}: Parameter value is missing or not observable."
        rec = "Inspect configuration directly or configure missing parameter."
    else:
        # Determine risk dimension
        dh_info = parse_dh_parameter(item.value) or parse_dh_parameter(item.control)
        if dh_info:
            role = "Key Establishment"
            sev = dh_info["severity"]
            risk = "CLASSICAL" if dh_info["is_weak"] else "QUANTUM"
            rec = dh_info["recommendation"]
            msg = (
                f"{item.control} operates with Diffie-Hellman key exchange ({dh_info['canonical_name']}) "
                f"using {dh_info['key_size'] or 'unspecified'}-bit parameters. "
                f"{'Insecure key size vulnerable to Logjam attack; ' if dh_info['is_weak'] else ''}"
                f"vulnerable to Shor's algorithm and Store Now, Decrypt Later (SNDL)."
            )
        elif not is_known_algorithm(item.value) and not any(k in val_upper for k in ["TLS", "HTTPS", "SSH", "MFA", "HSM", "KMS", "KEY", "TOKEN", "SMARTCARD", "PROTOCOL"]):
            risk = "UNKNOWN"
            sev = "INFORMATIONAL"
            msg = item.description or f"{item.control}: Unknown or unrecognized cryptographic primitive ({item.value})."
            rec = "Verify algorithm specifications and evaluate cryptographic security margin."
        else:
            risk = classify_risk_domain(algorithm=item.value, title=item.control, default="CLASSICAL")
            if risk == "QUANTUM":
                if any(pqc in val_upper for pqc in ["ML-KEM", "ML-DSA", "X25519MLKEM", "AES-256", "CHACHA20", "SHA-384", "SHA-512"]):
                    sev = "INFORMATIONAL"
                    msg = f"{item.control} verified using quantum-resilient primitive ({item.value})."
                    rec = "Maintain periodic audit and certificate lifecycle."
                elif any(g in val_upper for g in ["AES-128", "AES128"]):
                    sev = "HIGH"
                    msg = f"{item.control} operates with 128-bit symmetric key ({item.value}) vulnerable to Grover's algorithm quadratic search."
                    rec = "Upgrade symmetric encryption keys to AES-256-GCM."
                else:
                    sev = "HIGH" if ("RSA-2048" in val_upper or "ECDH" in val_upper) else "MEDIUM"
                    msg = f"{item.control} operates with classical asymmetric algorithm ({item.value}) vulnerable to Shor's algorithm."
                    rec = "Transition to NIST Post-Quantum Cryptographic Standards (ML-KEM / ML-DSA)."
            elif any(c in val_upper for c in ["3DES", "DES", "MD5", "SHA-1", "TLSV1.0", "TLSV1.1"]):
                sev = "CRITICAL" if "3DES" in val_upper else "HIGH"
                msg = f"{item.control} configured with deprecated classical cryptographic primitive ({item.value})."
                rec = "Replace deprecated primitive with AES-256-GCM and SHA-256/384."
            else:
                sev = "LOW"
                msg = item.description or f"{item.control}: {item.value}"
                rec = "Maintain standard operational monitoring."

    # Invariant: If not observable, not vulnerable
    if obs == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"
        risk = "UNKNOWN"

    return NormalizedFinding(
        rule_id=f"PROF-EV-{item.id}",
        title=f"{item.control}: {item.value}",
        value=item.value,
        role=role,
        source=src,
        source_file=getattr(item, "file_path", None),
        source_line=None,
        evidence_status=ev_status,
        severity=sev,
        risk=risk,
        message=msg,
        recommendation=rec,
        system_id=system_id,
        asset_id=system_id,
        layer=layer,
        metadata={"original_description": item.description, "confidence": item.confidence},
    )


def collect_unified_findings(
    system_id: str,
    tls_findings: Optional[List[Any]] = None,
    crypto_misuse_findings: Optional[List[Any]] = None,
    config_findings: Optional[List[Any]] = None,
    banking_profile: Optional[BankingAsset] = None,
) -> List[NormalizedFinding]:
    """
    Integrates findings across all 4 sources into a deduplicated, normalized collection.
    """
    unified: List[NormalizedFinding] = []
    seen_keys = set()

    # 1. TLS Findings
    if tls_findings:
        for f in tls_findings:
            norm = normalize_tls_finding(f, system_id=system_id)
            dedup_key = (norm.rule_id, norm.value)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unified.append(norm)

    # 2. Crypto Misuse Findings
    if crypto_misuse_findings:
        for f in crypto_misuse_findings:
            norm = normalize_crypto_misuse_finding(f, system_id=system_id)
            dedup_key = (norm.rule_id, norm.value)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unified.append(norm)

    # 3. Config Findings
    if config_findings:
        for f in config_findings:
            norm = normalize_config_finding(f, system_id=system_id)
            dedup_key = (norm.rule_id, norm.value)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unified.append(norm)

    # 4. Banking Profile Declarations
    if banking_profile and banking_profile.evidence_items:
        for item in banking_profile.evidence_items:
            norm = normalize_profile_evidence_item(item, system_id=system_id)
            dedup_key = (norm.rule_id, norm.value)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unified.append(norm)

    return unified
