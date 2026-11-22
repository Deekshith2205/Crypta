"""Request correlation ID tracking and structured logging filter for QuantumShield.

Provides:
- ASGI middleware for X-Request-ID propagation and generation.
- Thread-safe ContextVar storage for the active request ID.
- Python logging Filter injecting request_id into log records.
- Credential scrubbing for logged event dictionaries.
"""

from contextvars import ContextVar
import logging
import re
from typing import Any, Dict, Optional
import uuid
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Scope, Receive, Send

REQUEST_ID_CTX_VAR: ContextVar[str] = ContextVar("request_id", default="-")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_SENSITIVE_KEY_RE = re.compile(r"(?i)(password|secret|key|token|auth|credential)")


def get_current_request_id() -> str:
    """Returns the current request correlation ID or '-' if outside a request context."""
    return REQUEST_ID_CTX_VAR.get()


class CorrelationIdLogFilter(logging.Filter):
    """Logging filter that injects the active request correlation ID into log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_current_request_id()
        return True


class RequestCorrelationIdMiddleware:
    """Attaches or propagates an X-Request-ID correlation header across the HTTP request lifecycle."""

    HEADER_NAME = "x-request-id"

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(raw=scope.get("headers", []))
        incoming_id = headers.get(self.HEADER_NAME) or headers.get("x-correlation-id")

        if incoming_id and _SAFE_ID_RE.match(incoming_id.strip()):
            request_id = incoming_id.strip()
        else:
            request_id = uuid.uuid4().hex

        token = REQUEST_ID_CTX_VAR.set(request_id)

        # Store in scope for FastAPI access
        scope.setdefault("state", {})
        scope["state"]["request_id"] = request_id

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                raw_headers = list(message.get("headers", []))
                raw_headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = raw_headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            REQUEST_ID_CTX_VAR.reset(token)


def sanitize_log_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redacts values for keys resembling passwords, secrets, or credentials."""
    sanitized: Dict[str, Any] = {}
    for k, v in data.items():
        if _SENSITIVE_KEY_RE.search(str(k)):
            sanitized[k] = "[REDACTED_CREDENTIAL]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_log_dict(v)
        else:
            sanitized[k] = v
    return sanitized
