"""QuantumShield - Quantum Readiness / Post-Quantum Cryptography Assessment Platform.
Main FastAPI application entry point.
"""

from contextlib import asynccontextmanager
import logging
import os
from typing import List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.config import get_app_config, DEFAULT_ALLOWED_ORIGINS
from app.security.error_handler import register_exception_handlers
from app.security.middleware import (
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    ApiKeyAuthMiddleware,
)
from app.security.correlation import (
    RequestCorrelationIdMiddleware,
    CorrelationIdLogFilter,
)

# Configure structured logging with request correlation filter
_log_handler = logging.StreamHandler()
_log_handler.addFilter(CorrelationIdLogFilter())
_log_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] [req:%(request_id)s] %(name)s: %(message)s")
)
_root_logger = logging.getLogger()
_root_logger.handlers = [_log_handler]
_root_logger.setLevel(logging.INFO)

logger = logging.getLogger("quantumshield")


def get_cors_origins(env_origins: Optional[str] = None) -> List[str]:
    """Retrieves allowed CORS origins from environment or defaults to safe local origins."""
    raw = env_origins if env_origins is not None else os.environ.get(
        "QS_ALLOWED_ORIGINS", os.environ.get("CORS_ALLOWED_ORIGINS", "")
    )
    if not raw:
        return list(DEFAULT_ALLOWED_ORIGINS)
    parsed = [orig.strip() for orig in raw.split(",") if orig.strip()]
    return parsed if parsed else list(DEFAULT_ALLOWED_ORIGINS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for startup checks and graceful shutdown."""
    config = get_app_config()
    logger.info("QuantumShield API v1.0.0 initializing in '%s' mode.", config.server.environment)
    warnings = config.validate_startup()
    for w in warnings:
        logger.warning("Startup configuration audit: %s", w)
    yield
    logger.info("QuantumShield API shutting down gracefully.")


app = FastAPI(
    title="QuantumShield API",
    description="Banking Security Audit & Zero-Trust Readiness Platform with Quantum-Safe Cryptographic Assessment",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure hardened CORS: explicit origins and no wildcard credentials
_cors_origins = get_cors_origins()
_has_wildcard = "*" in _cors_origins
_allow_credentials = not _has_wildcard

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# Middleware stack
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(ApiKeyAuthMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestCorrelationIdMiddleware)

# Register API routes
app.include_router(api_router, prefix="/api")

# Register security exception handlers to prevent sensitive data leakage
register_exception_handlers(app)


@app.get("/")
def root():
    return {
        "platform": "QuantumShield",
        "tagline": "Know your cryptographic exposure before quantum computers do.",
        "api_docs": "/docs",
        "health_check": "/api/health",
        "scan_endpoint": "POST /api/scan",
        "audit_endpoint": "POST /api/audit",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
