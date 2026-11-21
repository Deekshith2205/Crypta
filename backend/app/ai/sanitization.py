"""Input sanitization, privacy protection, and prompt injection defense.

Guards the AI intelligence layer against:
1. Data leakage: redacts private keys, secrets, tokens, PANs, account numbers, and high-entropy API keys.
2. Prompt injection: neutralizes English, multilingual, and Unicode-obfuscated instruction override attempts.
3. Delimiter breakout: strips and neutralizes XML/markdown delimiter hijacking tags.
4. Unbounded inputs: truncates inputs to prevent resource exhaustion.
"""

import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, List, Optional

# Known secret patterns
KNOWN_API_KEY_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),          # OpenAI / generic secret
    re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"),           # Google API key
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                # AWS access key ID
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),      # GitHub PAT (ghp_, gho_, etc.)
    re.compile(r"\bxox[baprs]-[-A-Za-z0-9]{10,}\b"),   # Slack tokens
]

# Privacy and secret redaction patterns
REDACTION_PATTERNS = [
    # Known API Keys (must precede generic digit/token rules)
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bxox[baprs]-[-A-Za-z0-9]{10,}\b"), "[REDACTED_API_KEY]"),

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
        re.compile(r"(?<![A-Za-z0-9_-])(?:\d[ -]*?){13,19}(?![A-Za-z0-9_-])"),
        "[REDACTED_CARD_NUMBER]",
    ),
    # Common bank account / IFSC / Indian Aadhaar format
    (
        re.compile(r"(?<![A-Za-z0-9_-])\d{4}[ -]?\d{4}[ -]?\d{4}(?![A-Za-z0-9_-])"),
        "[REDACTED_IDENTIFIER]",
    ),
]

# Delimiter breakout patterns that attempt to escape prompt framing
DELIMITER_BREAKOUT_PATTERNS = [
    re.compile(r"</?untrusted_evidence[^>]*>", re.IGNORECASE),
    re.compile(r"</?evidence[^>]*>", re.IGNORECASE),
    re.compile(r"</?finding[^>]*>", re.IGNORECASE),
    re.compile(r"</?system[^>]*>", re.IGNORECASE),
    re.compile(r"</?prompt[^>]*>", re.IGNORECASE),
    re.compile(r"</?instructions[^>]*>", re.IGNORECASE),
    re.compile(r"```+\s*(?:system|assistant|admin|user|prompt)[^\n]*", re.IGNORECASE),
    re.compile(r"\[\s*(?:system|prompt|instruction|system\s+prompt)\s*\]", re.IGNORECASE),
    re.compile(r"<!--\s*#?\s*(?:system|override|prompt|admin)[\s\S]*?-->", re.IGNORECASE),
]

# Multilingual and multi-variant prompt injection patterns
PROMPT_INJECTION_PATTERNS = [
    # English
    re.compile(r"(?i)\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:(?:previous|prior|above|system|preceding)\s+)?(?:instructions|directions|prompts|rules|commands)\b"),
    re.compile(r"(?i)\bdisregard\s+all\s+previous\s+directions\b"),
    re.compile(r"(?i)\b(?:reveal|repeat|output|show|print)\s+(?:all\s+)?(?:the\s+(?:above\s+|system\s+)?|your\s+|system\s+)?(?:prompt|instructions|config|configuration|rules)(?:\s+verbatim)?\b"),
    re.compile(r"(?i)\b(?:you\s+are\s+now|act\s+as)\s+(?:in\s+developer\s+mode|an?\s+unrestricted|DAN|a\s+different|an\s+evil|acting\s+as)\b"),
    re.compile(r"(?i)\bdeveloper\s+mode\b"),
    re.compile(r"(?i)\bsystem\s+prompt\s+override\b"),
    re.compile(r"(?i)\boverride\s+(?:all\s+)?(?:system\s+)?(?:prompt|safety|instructions|rules)\b"),
    re.compile(r"(?i)\bchange\s+(?:finding\s+)?severity\s+to\b"),
    re.compile(r"(?i)\bchange\s+(?:risk\s+)?score\s+to\b"),
    re.compile(r"(?i)\bmark\s+(?:all\s+findings\s+as\s+|this\s+as\s+|as\s+)?(?:not\s+vulnerable|clean|safe|zero\s+risk)\b"),
    re.compile(r"(?i)\bpretend\s+(?:you\s+are|to\s+be)\b"),
    re.compile(r"(?i)\bsystem\s+directive\s*:\s*"),
    re.compile(r"(?i)\bnew\s+instruction\s*:\s*"),

    # French
    re.compile(r"(?i)\b(?:ignore[zr]?|oublie[zr]?)\s+(?:toutes\s+les\s+|les\s+)?(?:instructions|directives|commandes)(?:\s+pr[eé]c[eé]dentes)?\b"),

    # Spanish
    re.compile(r"(?i)\b(?:ignora|olvida)\s+(?:todas\s+las\s+|las\s+)?(?:instrucciones|directivas|comandos)(?:\s+(?:anteriores|previas))?\b"),

    # German
    re.compile(r"(?i)\b(?:ignoriere|vergiss)\s+(?:alle\s+)?(?:vorherigen\s+|bisherigen\s+)?(?:anweisungen|befehle)\b"),

    # Chinese (Simplified & Traditional)
    re.compile(r"(?:忽略|无视)(?:先前(?:的)?|之前(?:的)?|所有)?(?:的)?(?:指令|提示|指示)"),

    # Russian
    re.compile(r"(?i)\b(?:игнорируй(?:те)?|забудь(?:те)?)\s+(?:все\s+)?(?:предыдущие\s+)?(?:инструкции|команды)\b"),

    # Code / Script injection
    re.compile(r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>"),
    re.compile(r"(?i)javascript:\s*"),
]

# Patterns for legitimate cryptographic digests that must NEVER be redacted
LEGITIMATE_HASH_PATTERNS = [
    re.compile(r"^[0-9a-fA-F]{64}$"),                                     # SHA-256
    re.compile(r"^[0-9a-fA-F]{40}$"),                                     # SHA-1
    re.compile(r"^[0-9a-fA-F]{32}$"),                                     # MD5
    re.compile(r"^([0-9a-fA-F]{2}:){15,31}[0-9a-fA-F]{2}$"),             # Hex fingerprint (colon-delimited)
    re.compile(r"^sha(?:256|384|512):[0-9a-fA-F]{64,128}$", re.I),       # Prefixed hash
]


def is_legitimate_crypto_identifier(token: str) -> bool:
    """Returns True if the token matches standard cryptographic digests or fingerprints."""
    cleaned = token.strip().strip(",;\"'()[]{}")
    return any(p.match(cleaned) for p in LEGITIMATE_HASH_PATTERNS)


def shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def redact_high_entropy_secrets(text: str) -> str:
    """
    Detects and redacts high-entropy secret tokens while strictly preserving
    legitimate cryptographic hashes (SHA-256, fingerprints).
    """
    lines = text.splitlines(keepends=True)
    out_lines = []

    for line in lines:
        words = line.split(" ")
        redacted_words = []

        for word in words:
            clean_word = word.strip(".,;:\"'()[]{}<>\r\n\t")
            if not clean_word:
                redacted_words.append(word)
                continue

            # 1. Check known API key patterns first
            is_known_key = any(p.search(clean_word) for p in KNOWN_API_KEY_PATTERNS)
            if is_known_key:
                redacted_words.append(word.replace(clean_word, "[REDACTED_API_KEY]"))
                continue

            # 2. Check if this is a legitimate cryptographic digest (MUST PRESERVE)
            if is_legitimate_crypto_identifier(clean_word):
                redacted_words.append(word)
                continue

            # 3. Shannon entropy check for unlabeled high-entropy secrets (e.g. 24-80 chars, entropy > 4.3)
            if 24 <= len(clean_word) <= 80:
                # Check character diversity: must contain mixed alphanumeric characters
                has_upper = any(c.isupper() for c in clean_word)
                has_lower = any(c.islower() for c in clean_word)
                has_digit = any(c.isdigit() for c in clean_word)

                if (has_upper + has_lower + has_digit) >= 2:
                    # If pure hex, it could be a raw key or hash. If exactly 32/40/64/128 hex chars, preserve.
                    is_pure_hex = all(c in "0123456789abcdefABCDEF" for c in clean_word)
                    if is_pure_hex and len(clean_word) in (32, 40, 64, 128):
                        redacted_words.append(word)
                        continue

                    entropy = shannon_entropy(clean_word)
                    if entropy > 4.3:
                        redacted_words.append(word.replace(clean_word, "[REDACTED_HIGH_ENTROPY_TOKEN]"))
                        continue

            redacted_words.append(word)

        out_lines.append(" ".join(redacted_words))

    return "".join(out_lines)


def sanitize_text(text: Optional[str], max_length: int = 4000) -> str:
    """
    Sanitizes untrusted text by:
    1. Applying Unicode NFKC normalization (defeats homoglyph and composite char injection).
    2. Stripping control characters.
    3. Neutralizing delimiter breakout tags.
    4. Neutralizing multilingual prompt injection phrases.
    5. Redacting sensitive secrets, keys, and privacy identifiers.
    6. Redacting high-entropy unlabeled API tokens while preserving legitimate hashes.
    7. Truncating to bounded length.
    """
    if not text:
        return ""

    # 1. Unicode normalization (NFKC normalizes homoglyphs, fullwidth letters, compatibility chars)
    normalized = unicodedata.normalize("NFKC", str(text))

    # 2. Strip null bytes and non-printable control characters (except newline, tab)
    content = "".join(
        ch for ch in normalized if ch == "\n" or ch == "\t" or (ord(ch) >= 32 and ord(ch) != 127)
    )

    # 3. Neutralize delimiter breakout tags
    for pattern in DELIMITER_BREAKOUT_PATTERNS:
        content = pattern.sub("[ESCAPED_DELIMITER]", content)

    # 4. Neutralize multilingual prompt injection phrases
    for pattern in PROMPT_INJECTION_PATTERNS:
        content = pattern.sub("[FILTERED_INPUT]", content)

    # 5. Redact known sensitive secrets and privacy data
    for pattern, replacement in REDACTION_PATTERNS:
        content = pattern.sub(replacement, content)

    # 6. Redact known API key formats and high-entropy secret tokens (while preserving legitimate hashes)
    content = redact_high_entropy_secrets(content)

    # 7. Truncate to bounded length
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


def contains_prompt_injection(text: Optional[str]) -> bool:
    """Returns True if the text matches any prompt injection patterns after NFKC normalization."""
    if not text:
        return False
    normalized = unicodedata.normalize("NFKC", str(text))
    return any(p.search(normalized) for p in PROMPT_INJECTION_PATTERNS)


def redact_sensitive_patterns(text: Optional[str]) -> str:
    """Redacts known sensitive secrets and patterns."""
    if not text:
        return ""
    content = text
    for pattern, replacement in REDACTION_PATTERNS:
        content = pattern.sub(replacement, content)
    return redact_high_entropy_secrets(content)


# Alias for explicit request payload sanitization
sanitize_request_payload = sanitize_dict_fields