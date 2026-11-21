"""Audit Signing Key Management (Task C1).
Provides cryptographically secure, persistent, unexposed signing keys using HMAC-SHA256.
"""

import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Optional


class AuditKeyError(Exception):
    """Raised when the audit signing key is missing, invalid, or corrupted."""
    pass


def get_default_data_dir() -> Path:
    """Returns the configured data directory from QS_DATA_DIR or default ./data."""
    raw = os.environ.get("QS_DATA_DIR")
    if raw:
        path = Path(raw).resolve()
    else:
        # Resolve to <repo_root>/data
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        path = (repo_root / "data").resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


class AuditKeyManager:
    """
    Manages the cryptographic signing key for assessment audit trails.
    - Uses HMAC-SHA256.
    - Prioritizes QS_AUDIT_SIGNING_KEY from environment.
    - If absent, generates and persists a 256-bit key in data_dir / 'audit_signing.key'.
    - Never overwrites existing keys silently.
    - Redacts key representation in logs and string conversions.
    """

    KEY_FILENAME = "audit_signing.key"
    MIN_KEY_BYTES = 32

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        env_var: str = "QS_AUDIT_SIGNING_KEY",
    ):
        self._data_dir = Path(data_dir).resolve() if data_dir else None
        self._env_var = env_var
        self._cached_key: Optional[bytes] = None

    @property
    def data_dir(self) -> Path:
        if self._data_dir is None:
            self._data_dir = get_default_data_dir()
        else:
            self._data_dir.mkdir(parents=True, exist_ok=True)
        return self._data_dir

    def get_key(self) -> bytes:
        """Retrieves and validates the 256-bit signing key."""
        if self._cached_key is not None:
            return self._cached_key

        # Check environment variable first
        env_key = os.environ.get(self._env_var)
        if env_key:
            env_key_clean = env_key.strip()
            # If 64-char hex, decode
            if len(env_key_clean) == 64:
                try:
                    key_bytes = bytes.fromhex(env_key_clean)
                except ValueError:
                    key_bytes = env_key_clean.encode("utf-8")
            else:
                key_bytes = env_key_clean.encode("utf-8")

            if len(key_bytes) < self.MIN_KEY_BYTES:
                raise AuditKeyError(
                    f"Signing key provided via {self._env_var} must be at least 32 bytes (256 bits). "
                    f"Provided length: {len(key_bytes)} bytes."
                )
            self._cached_key = key_bytes
            return self._cached_key

        # Check persisted file
        key_file = self.data_dir / self.KEY_FILENAME
        if key_file.exists():
            try:
                content = key_file.read_text(encoding="utf-8").strip()
            except Exception as e:
                raise AuditKeyError(f"Failed to read existing audit signing key file: {e}") from e

            if len(content) == 64:
                try:
                    key_bytes = bytes.fromhex(content)
                except ValueError:
                    key_bytes = content.encode("utf-8")
            else:
                key_bytes = content.encode("utf-8")

            if len(key_bytes) < self.MIN_KEY_BYTES:
                raise AuditKeyError(
                    f"Existing audit signing key file ({key_file}) is corrupted or too short "
                    f"({len(key_bytes)} bytes < {self.MIN_KEY_BYTES} bytes required). "
                    "Refusing to silently replace or overwrite."
                )

            self._cached_key = key_bytes
            return self._cached_key

        # Generate a new cryptographically secure random key
        new_key = secrets.token_bytes(self.MIN_KEY_BYTES)
        try:
            key_file.write_text(new_key.hex(), encoding="utf-8")
            # Restrict file permissions if supported (POSIX 0600)
            try:
                os.chmod(key_file, 0o600)
            except (AttributeError, OSError):
                pass
        except Exception as e:
            raise AuditKeyError(f"Failed to persist generated audit signing key to {key_file}: {e}") from e

        self._cached_key = new_key
        return self._cached_key

    def sign(self, message: bytes) -> str:
        """Computes HMAC-SHA256 signature over binary message returning lowercase hex digest."""
        key = self.get_key()
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def verify(self, message: bytes, signature_hex: str) -> bool:
        """Constant-time verification of HMAC-SHA256 signature."""
        try:
            expected = self.sign(message)
            return hmac.compare_digest(expected, signature_hex)
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"<AuditKeyManager data_dir='{self.data_dir}' [KEY REDACTED]>"

    def __str__(self) -> str:
        return "<AuditKeyManager [KEY REDACTED]>"


# Singleton instance
DEFAULT_AUDIT_KEY_MANAGER = AuditKeyManager()
