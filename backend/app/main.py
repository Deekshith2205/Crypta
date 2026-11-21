"""QuantumShield - Quantum Readiness / Post-Quantum Cryptography Assessment Platform.
Main FastAPI application entry point.
"""

import logging
import os
from typing import List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.security.error_handler import register_exception_handlers
from app.security.middleware import RequestSizeLimitMiddleware, SecurityHeadersMiddleware

# Configure clean logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("quantumshield")

DEFAULT_ALLOWED_ORIGINS: List[str] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


def get_cors_origins(env_origins: Optional[str] = None) -> List[str]:
    """Retrieves allowed CORS origins from environment or defaults to safe local origins."""
    raw = env_origins if env_origins is not None else os.environ.get(
        "QS_ALLOWED_ORIGINS", os.environ.get("CORS_ALLOWED_ORIGINS", "")
    )
    if not raw:
        return list(DEFAULT_ALLOWED_ORIGINS)
    parsed = [orig.strip() for orig in raw.split(",") if orig.strip()]
    return parsed if parsed else list(DEFAULT_ALLOWED_ORIGINS)


app = FastAPI(
    title="QuantumShield API",
    description="Banking Security Audit & Zero-Trust Readiness Platform with Quantum-Safe Cryptographic Assessment",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
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

# Enforce 5 MiB request body limits and attach baseline security headers
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

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

