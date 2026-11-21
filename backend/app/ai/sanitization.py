"""Input sanitization, privacy protection, and prompt injection defense.

Guards the AI intelligence layer against:
1. Data leakage: redacts private keys, secrets, tokens, PANs, account numbers.
2. Prompt injection: detects and neutralizes instruction override phrases.
3. Unbounded inputs: truncates inputs to prevent resource exhaustion.
"""

import re
from typing import Any, Dict, List, Optional

# Secret and privacy redactor patterns
REDACTION_PATTERNS = [
    # PEM Private Keys
    (
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
            re.IGNORECASE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # JWT and Bearer Tokens
    (
        re.compile(
            r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\b"
        ),
        "Bearer [REDACTED_JWT_TOKEN]",
    ),
    # Passwords / API keys in key-value format
    (
        re.compile(
            r"(?i)(password|secret|api_key|token|access_key|auth_token)\s*[:=]\s*['\"]?[^\s,'\"\n]{3,}['\"]?",
        ),
        r"\1: [REDACTED_SECRET]",
    ),
    # Credit Card Numbers (13 to 19 digits)
    (
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "[REDACTED_CARD_NUMBER]",
    ),
    # Common bank account / IFSC / Indian Aadhaar format
    (
        re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"),
        "[REDACTED_IDENTIFIER]",
    ),
]

# Prompt injection patterns designed to hijack instructions
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|system)\s+instructions\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:an?\s+unrestricted|DAN|a\s+different)\b"),
    re.compile(r"(?i)\boverride\s+(?:system\s+)?(?:prompt|safety|instructions)\b"),
    re.compile(r"(?i)\bchange\s+(?:finding\s+)?severity\s+to\b"),
    re.compile(r"(?i)\bchange\s+(?:risk\s+)?score\s+to\b"),
    re.compile(r"(?i)\bmark\s+(?:as\s+)?(?:not\s+vulnerable|clean|safe|zero\s+risk)\b"),
    re.compile(r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>"),
    re.compile(r"(?i)javascript:\s*"),
]


def sanitize_text(text: Optional[str], max_length: int = 4000) -> str:
    """
    Sanitizes untrusted text by:
    1. Redacting private keys, tokens, and financial identifiers.
    2. Neutralizing prompt injection attempts.
    3. Stripping control characters.
    4. Truncating to bounded length.
    """
    if not text:
        return ""

    content = str(text)

    # 1. Strip null bytes and non-printable control characters (except newline, tab)
    content = "".join(
        ch for ch in content if ch == "\n" or ch == "\t" or (ord(ch) >= 32 and ord(ch) != 127)
    )

    # 2. Redact sensitive secrets and privacy data
    for pattern, replacement in REDACTION_PATTERNS:
        content = pattern.sub(replacement, content)

    # 3. Neutralize prompt injection phrases
    for pattern in PROMPT_INJECTION_PATTERNS:
        content = pattern.sub("[FILTERED_INPUT]", content)

    # 4. Truncate bounded length
    if len(content) > max_length:
        content = content[:max_length] + " ... [TRUNCATED]"

    return content


def _sanitize_value(value: Any, max_field_length: int) -> Any:
    """Recursively sanitizes strings inside dictionaries and nested lists."""
    if isinstance(value, str):
        return sanitize_text(value, max_length=max_field_length)

    if isinstance(value, dict):
        return {
            key: _sanitize_value(item, max_field_length)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _sanitize_value(item, max_field_length)
            for item in value
        ]

    return value


def sanitize_dict_fields(
    data: Dict[str, Any],
    max_field_length: int = 4000,
) -> Dict[str, Any]:
    """Recursively sanitizes all string fields, including arbitrarily nested lists."""
    return _sanitize_value(data, max_field_length)