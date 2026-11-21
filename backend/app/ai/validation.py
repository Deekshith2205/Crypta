"""Deterministic AI Output Trust Validation (Task D2).

Ensures that AI-generated explanations:
1. Never contradict deterministic evidence status (NOT_OBSERVABLE != VULNERABLE).
2. Never claim AES-256 is broken by Shor's algorithm or quantum-broken.
3. Only cite valid NIST / PQC standards (FIPS 203, 204, 205, CNSA 2.0).
4. Never contradict or attempt to override deterministic severity, risk scores, or rankings.
5. Never invent fabricated financial dollar costs.

Deterministic code is the sole authority; AI output violating these rules is rejected.
"""

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

VALID_FIPS_NUMBERS = {
    140,  # FIPS 140-2 / 140-3 Security Requirements for Cryptographic Modules
    180,  # FIPS 180-4 Secure Hash Standard (SHA)
    186,  # FIPS 186-5 Digital Signature Standard (DSS)
    197,  # FIPS 197 Advanced Encryption Standard (AES)
    198,  # FIPS 198-1 Keyed-Hash Message Authentication Code (HMAC)
    202,  # FIPS 202 SHA-3 Standard
    203,  # FIPS 203 ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
    204,  # FIPS 204 ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
    205,  # FIPS 205 SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
}

FIPS_PATTERN = re.compile(r"\b(?:NIST\s+)?FIPS\s+(\d+)\b", re.IGNORECASE)

# Patterns claiming AES-256 is quantum-broken
AES256_QUANTUM_BROKEN_PATTERNS = [
    re.compile(r"(?i)\baes[- ]?256\s+(?:is\s+)?(?:broken|vulnerable|compromised)\s+(?:by|to)\s+shor'?s"),
    re.compile(r"(?i)\bshor'?s\s+algorithm\s+(?:breaks|compromises)\s+aes[- ]?256"),
    re.compile(r"(?i)\baes[- ]?256\s+(?:is\s+)?quantum[- ]broken"),
    re.compile(r"(?i)\baes[- ]?256\s+is\s+no\s+longer\s+secure\s+against\s+quantum"),
    re.compile(r"(?i)\breplace\s+aes[- ]?256\s+with\s+(?:a\s+)?post[- ]quantum"),
]

# Patterns asserting confirmed vulnerability for NOT_OBSERVABLE evidence
NOT_OBSERVABLE_CONTRADICTION_PATTERNS = [
    re.compile(r"(?i)\b(?:confirmed|proven|verified|actively)\s+vulnerable\b"),
    re.compile(r"(?i)\bconfirmed\s+(?:security\s+)?flaw\b"),
    re.compile(r"(?i)\bdefinitely\s+(?:compromised|insecure)\b"),
    re.compile(r"(?i)\bis\s+(?:proven\s+to\s+be\s+)?exploitable\b"),
    re.compile(r"(?i)\bhas\s+been\s+compromised\b"),
]

# Patterns claiming severity override
SEVERITY_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)\b(?:actual|real|correct)\s+severity\s+(?:is|should\s+be)\s+([A-Z]+)\b"),
    re.compile(r"(?i)\bchange\s+severity\s+to\s+([A-Z]+)\b"),
    re.compile(r"(?i)\bmark\s+(?:this\s+as\s+)?([A-Z]+)\s+severity\b"),
]

# Patterns for fabricated financial costs
FABRICATED_COST_PATTERN = re.compile(
    r"\$\s*\d{1,3}(?:,\d{3})*(?:\.\d+)?\s*(?:million|billion|thousand|k|m)?\b",
    re.IGNORECASE,
)


class OutputValidationResult(BaseModel):
    """Result of deterministic trust validation on an AI output."""
    is_valid: bool = Field(..., description="Whether the AI explanation conforms to trust rules")
    violations: List[str] = Field(default_factory=list, description="List of fatal policy violations")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings")


def extract_all_text_content(obj: Any) -> str:
    """Recursively collects all text strings from a model or dictionary."""
    if isinstance(obj, BaseModel):
        obj = obj.model_dump()

    text_parts: List[str] = []

    def _collect(val: Any):
        if isinstance(val, str):
            text_parts.append(val)
        elif isinstance(val, dict):
            for v in val.values():
                _collect(v)
        elif isinstance(val, list):
            for v in val:
                _collect(v)

    _collect(obj)
    return " ".join(text_parts)


def validate_ai_explanation(
    output: Any,
    deterministic_context: Optional[Dict[str, Any]] = None,
) -> OutputValidationResult:
    """
    Validates AI explanation output against deterministic truth invariants.
    Returns OutputValidationResult(is_valid=True/False, violations=[...], warnings=[...]).
    """
    violations: List[str] = []
    warnings: List[str] = []
    context = deterministic_context or {}

    full_text = extract_all_text_content(output)

    # 1. Evidence Status Alignment (NOT_OBSERVABLE != VULNERABLE)
    evidence_status = str(context.get("evidence_status", "")).upper()
    if evidence_status == "NOT_OBSERVABLE":
        for pat in NOT_OBSERVABLE_CONTRADICTION_PATTERNS:
            match = pat.search(full_text)
            if match:
                violations.append(
                    f"Evidence status is NOT_OBSERVABLE, but AI explanation asserted "
                    f"confirmed vulnerability: '{match.group(0)}'."
                )
                break

    # 2. Cryptographic Accuracy: AES-256 Quantum Invariant
    for pat in AES256_QUANTUM_BROKEN_PATTERNS:
        match = pat.search(full_text)
        if match:
            violations.append(
                f"AI explanation erroneously claimed AES-256 is quantum-broken: '{match.group(0)}'. "
                f"AES-256 retains 128 bits of security against Grover's algorithm and is not broken by Shor's."
            )
            break

    # 3. Standards Integrity: FIPS Standard Numbers
    fips_matches = FIPS_PATTERN.findall(full_text)
    for num_str in fips_matches:
        try:
            num = int(num_str)
            if num not in VALID_FIPS_NUMBERS:
                violations.append(
                    f"AI explanation cited non-existent or unapproved FIPS standard: FIPS {num}."
                )
        except ValueError:
            pass

    # 4. Severity and Score Integrity: No AI Overrides
    expected_severity = str(context.get("severity", "")).upper()
    if expected_severity:
        for pat in SEVERITY_OVERRIDE_PATTERNS:
            match = pat.search(full_text)
            if match:
                overridden_sev = match.group(1).upper()
                if overridden_sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "INFO"}:
                    if overridden_sev != expected_severity:
                        violations.append(
                            f"AI explanation attempted to change severity to {overridden_sev} "
                            f"(deterministic engine established {expected_severity})."
                        )
                        break

    # 5. Financial Cost Fabrications
    # If the context is a migration advisory, verify no speculative dollar estimates
    if context.get("disallow_financial_fabrication", True):
        # Check specific advisory fields if present
        cost_matches = FABRICATED_COST_PATTERN.findall(full_text)
        if cost_matches:
            # Check if text is presenting specific dollar figures as factual migration costs
            if any(re.search(r"(?i)\bcost\b|\bbudget\b|\bexpense\b|\bprice\b", full_text) for _ in [1]):
                violations.append(
                    f"AI explanation contains speculative dollar figures: {cost_matches[:3]}. "
                    f"AI must not invent financial cost estimates."
                )

    return OutputValidationResult(
        is_valid=len(violations) == 0,
        violations=violations,
        warnings=warnings,
    )
