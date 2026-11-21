"""Centralized Configuration and Environment Management for QuantumShield.

Provides:
- Strongly typed, validated configuration models.
- Safe defaults for local development.
- Production environment validation and fail-safe checks.
- Credential protection: sensitive fields use repr=False to prevent accidental leakage in logs.
"""

import os
from typing import List, Optional, Set
from pydantic import BaseModel, Field, ConfigDict


DEFAULT_ALLOWED_ORIGINS: List[str] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

DEFAULT_ALLOWED_SCAN_PORTS: Set[int] = {443, 8443, 993, 995, 465}
DEFAULT_MAX_REQUEST_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MiB


class ServerConfig(BaseModel):
    """Server and network interface configuration."""
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000, ge=1, le=65535)
    environment: str = Field(default="development")
    allowed_origins: List[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_ORIGINS))
    max_request_size_bytes: int = Field(default=DEFAULT_MAX_REQUEST_SIZE_BYTES, ge=1024)
    api_key: Optional[str] = Field(default=None, repr=False)

    model_config = ConfigDict(populate_by_name=True)


class SecurityConfig(BaseModel):
    """Network scanning and edge proxy security configuration."""
    allowed_scan_ports: Set[int] = Field(default_factory=lambda: set(DEFAULT_ALLOWED_SCAN_PORTS))
    trusted_proxy_count: int = Field(default=0, ge=0)
    data_dir: Optional[str] = Field(default=None)

    model_config = ConfigDict(populate_by_name=True)


class RateLimitConfig(BaseModel):
    """Rate limiter thresholds and sliding-window intervals."""
    scan_limit: int = Field(default=10, ge=1)
    scan_window: float = Field(default=60.0, ge=1.0)
    upload_limit: int = Field(default=5, ge=1)
    upload_window: float = Field(default=60.0, ge=1.0)
    ai_limit: int = Field(default=5, ge=1)
    ai_window: float = Field(default=60.0, ge=1.0)

    model_config = ConfigDict(populate_by_name=True)


class AuditConfig(BaseModel):
    """Cryptographic audit ledger and external checkpoint configuration."""
    require_external_checkpoint: bool = Field(default=False)
    external_checkpoint_url: Optional[str] = Field(default=None)
    external_checkpoint_key: Optional[str] = Field(default=None, repr=False)
    audit_signing_key: Optional[str] = Field(default=None, repr=False)

    model_config = ConfigDict(populate_by_name=True)


class AppConfig(BaseModel):
    """Root application configuration aggregating all subsystems."""
    server: ServerConfig = Field(default_factory=ServerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    model_config = ConfigDict(populate_by_name=True)

    @property
    def is_production(self) -> bool:
        """Returns True if running in a production environment."""
        return self.server.environment.strip().lower() in ("production", "prod")

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Constructs AppConfig from environment variables."""
        # 1. Server settings
        host = os.environ.get("HOST", "0.0.0.0")
        try:
            port = int(os.environ.get("PORT", "8000"))
        except ValueError:
            port = 8000
        environment = os.environ.get("ENVIRONMENT", "development").strip().lower()

        raw_origins = os.environ.get("QS_ALLOWED_ORIGINS", os.environ.get("CORS_ALLOWED_ORIGINS", "")).strip()
        if raw_origins:
            origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
        else:
            origins = list(DEFAULT_ALLOWED_ORIGINS)

        raw_size = os.environ.get("QS_MAX_REQUEST_SIZE_BYTES", os.environ.get("MAX_REQUEST_SIZE_BYTES", "")).strip()
        try:
            max_size = int(raw_size) if raw_size else DEFAULT_MAX_REQUEST_SIZE_BYTES
        except ValueError:
            max_size = DEFAULT_MAX_REQUEST_SIZE_BYTES

        api_key = (os.environ.get("QS_API_KEY", os.environ.get("API_KEY", "")) or "").strip() or None

        server = ServerConfig(
            host=host,
            port=port,
            environment=environment,
            allowed_origins=origins,
            max_request_size_bytes=max_size,
            api_key=api_key,
        )

        # 2. Security settings
        raw_ports = os.environ.get("QS_ALLOWED_SCAN_PORTS", os.environ.get("ALLOWED_SCAN_PORTS", "")).strip()
        if raw_ports:
            try:
                ports = {int(p.strip()) for p in raw_ports.split(",") if p.strip()}
            except ValueError:
                ports = set(DEFAULT_ALLOWED_SCAN_PORTS)
        else:
            ports = set(DEFAULT_ALLOWED_SCAN_PORTS)

        raw_proxy = os.environ.get("QS_TRUSTED_PROXY_COUNT", os.environ.get("TRUSTED_PROXY_COUNT", "0")).strip()
        try:
            proxy_count = int(raw_proxy)
        except ValueError:
            proxy_count = 0

        data_dir = os.environ.get("QS_DATA_DIR")

        security = SecurityConfig(
            allowed_scan_ports=ports,
            trusted_proxy_count=proxy_count,
            data_dir=data_dir,
        )

        # 3. Rate limit settings
        rate_limit = RateLimitConfig(
            scan_limit=int(os.environ.get("QS_RATE_LIMIT_SCAN", "10")),
            scan_window=float(os.environ.get("QS_RATE_LIMIT_SCAN_WINDOW", "60.0")),
            upload_limit=int(os.environ.get("QS_RATE_LIMIT_UPLOAD", "5")),
            upload_window=float(os.environ.get("QS_RATE_LIMIT_UPLOAD_WINDOW", "60.0")),
            ai_limit=int(os.environ.get("QS_RATE_LIMIT_AI", "5")),
            ai_window=float(os.environ.get("QS_RATE_LIMIT_AI_WINDOW", "60.0")),
        )

        # 4. Audit settings
        req_ext = os.environ.get("QS_REQUIRE_EXTERNAL_CHECKPOINT", "").strip().lower() in ("true", "1", "yes")
        ext_url = os.environ.get("QS_EXTERNAL_CHECKPOINT_URL", "").strip() or None
        ext_key = os.environ.get("QS_EXTERNAL_CHECKPOINT_KEY", "").strip() or None
        audit_key = os.environ.get("QS_AUDIT_SIGNING_KEY", os.environ.get("AUDIT_CHAIN_KEY", "")).strip() or None

        audit = AuditConfig(
            require_external_checkpoint=req_ext,
            external_checkpoint_url=ext_url,
            external_checkpoint_key=ext_key,
            audit_signing_key=audit_key,
        )

        return cls(
            server=server,
            security=security,
            rate_limit=rate_limit,
            audit=audit,
        )

    def validate_startup(self) -> List[str]:
        """Validates configuration at application startup and returns warnings or issues."""
        warnings: List[str] = []

        if self.is_production:
            if "*" in self.server.allowed_origins:
                warnings.append("PRODUCTION WARNING: Wildcard CORS origin '*' is permitted.")
            if not self.server.api_key:
                warnings.append("PRODUCTION NOTICE: No API key (QS_API_KEY) configured. Endpoints are unauthenticated.")
            if self.audit.require_external_checkpoint and not self.audit.external_checkpoint_url:
                warnings.append("PRODUCTION CONFIG ERROR: QS_REQUIRE_EXTERNAL_CHECKPOINT is True but QS_EXTERNAL_CHECKPOINT_URL is missing.")

        return warnings


def get_app_config() -> AppConfig:
    """Returns application configuration instance."""
    return AppConfig.from_env()
