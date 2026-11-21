"""Security-focused error handling and sensitive exception leakage prevention.

Ensures that internal system details (file paths, database URIs, credentials,
stack traces, and internal network addresses) are never exposed to external clients.
"""

import logging
import re
from typing import Any
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("quantumshield.error_handler")

GENERIC_500_MESSAGE = "An internal error occurred while processing the request. Please try again later."

# Compiled regex patterns for redaction
_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[^ \t\n\r\"';]+", re.IGNORECASE)
_UNIX_PATH_RE = re.compile(r"(?:/(?:etc|var|usr|home|root|tmp|bin|sbin|opt|app|proc|sys)|(?:\.\./)+)[^ \t\n\r\"';]+", re.IGNORECASE)
_DATABASE_URI_RE = re.compile(r"(?:postgres(?:ql)?|mysql|sqlite|mongodb|redis|amqp|couchdb)://[^\s\"'>]+", re.IGNORECASE)
_CREDENTIAL_RE = re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|bearer|access_key)\s*[:=]\s*['\"]?[^\s\"'>]+", re.IGNORECASE)
_STACK_TRACE_RE = re.compile(r"Traceback \(most recent call last\):[\s\S]*", re.IGNORECASE)
_PRIVATE_IP_RE = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b")


def sanitize_error_detail(detail: Any) -> str:
    """Sanitizes an error detail string, redacting sensitive system details.

    Redacts:
    - Windows and Unix absolute/relative file paths
    - Database connection strings and URIs
    - Credentials, tokens, secrets, and API keys
    - Stack traces
    - Private and loopback IP addresses
    """
    if detail is None:
        return ""
    text = str(detail)

    # Redact credentials and tokens first
    text = _CREDENTIAL_RE.sub("[REDACTED_SECRET]", text)

    # Redact database URIs
    text = _DATABASE_URI_RE.sub("[REDACTED_URI]", text)

    # Redact filesystem paths
    text = _WINDOWS_PATH_RE.sub("[REDACTED_PATH]", text)
    text = _UNIX_PATH_RE.sub("[REDACTED_PATH]", text)

    # Redact stack traces
    text = _STACK_TRACE_RE.sub("[REDACTED_STACK_TRACE]", text)

    # Redact private and metadata IP addresses
    text = _PRIVATE_IP_RE.sub("[REDACTED_IP]", text)

    return text


def create_safe_error_response(
    status_code: int,
    error_code: str,
    detail: str,
    target_domain: str = None,
) -> JSONResponse:
    """Creates a JSON error response with sanitized details and safe generic 500 messages."""
    if status_code >= 500:
        safe_detail = GENERIC_500_MESSAGE
    else:
        safe_detail = sanitize_error_detail(detail)

    content = {
        "error": error_code,
        "detail": safe_detail,
    }
    if target_domain is not None:
        content["target_domain"] = target_domain

    return JSONResponse(status_code=status_code, content=content)


def register_exception_handlers(app: FastAPI) -> None:
    """Registers global exception handlers on the FastAPI application."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code >= 500:
            logger.error(
                "HTTP %d error on %s %s: %s",
                exc.status_code,
                request.method,
                request.url.path,
                exc.detail,
                exc_info=True,
            )
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "error": "HTTP_INTERNAL_ERROR",
                    "detail": GENERIC_500_MESSAGE,
                },
            )

        logger.warning(
            "HTTP %d error on %s %s: %s",
            exc.status_code,
            request.method,
            request.url.path,
            exc.detail,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTP_ERROR",
                "detail": sanitize_error_detail(str(exc.detail)),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.error(
            "Unhandled exception on %s %s: %s",
            request.method,
            request.url.path,
            exc,
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "detail": GENERIC_500_MESSAGE,
            },
        )
