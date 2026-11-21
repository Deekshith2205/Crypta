"""Security middleware for QuantumShield.

Provides:
- RequestSizeLimitMiddleware: Enforces 5 MiB upper bound on request bodies (HTTP 413).
- SecurityHeadersMiddleware: Attaches standard security headers and endpoint-specific cache controls.
"""

import os
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Scope, Receive, Send

DEFAULT_MAX_REQUEST_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MiB (5,242,880 bytes)


def get_max_request_size() -> int:
    """Returns the maximum allowed request body size in bytes from environment or defaults to 5 MiB."""
    env_val = os.environ.get("QS_MAX_REQUEST_SIZE_BYTES", os.environ.get("MAX_REQUEST_SIZE_BYTES", "")).strip()
    if env_val:
        try:
            val = int(env_val)
            if val > 0:
                return val
        except ValueError:
            pass
    return DEFAULT_MAX_REQUEST_SIZE_BYTES


class PayloadTooLargeException(Exception):
    """Raised when streaming request body exceeds configured limit."""
    pass


class RequestSizeLimitMiddleware:
    """Rejects incoming HTTP requests with bodies exceeding the configured size limit with HTTP 413."""

    def __init__(self, app: ASGIApp, max_size_bytes: int = None):
        self.app = app
        self.max_size_bytes = max_size_bytes or get_max_request_size()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(raw=scope.get("headers", []))
        content_length_str = headers.get("content-length")

        path = scope.get("path", "")

        if content_length_str is not None:
            try:
                content_length = int(content_length_str)
                if content_length > self.max_size_bytes:
                    await self._send_payload_too_large(send, path)
                    return
            except ValueError:
                pass

        bytes_received = 0

        async def limited_receive():
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                bytes_received += len(body)
                if bytes_received > self.max_size_bytes:
                    raise PayloadTooLargeException()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except PayloadTooLargeException:
            await self._send_payload_too_large(send, path)

    async def _send_payload_too_large(self, send: Send, path: str = "") -> None:
        if path.startswith("/api/scan/"):
            error_code = "UPLOAD_TOO_LARGE"
            detail = "The combined upload must be at most 5 MiB."
        else:
            error_code = "PAYLOAD_TOO_LARGE"
            detail = f"Request body exceeds maximum allowed size of 5 MiB ({self.max_size_bytes} bytes)."

        body = (
            f'{{"error":"{error_code}","detail":"{detail}"}}'
        ).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })


class SecurityHeadersMiddleware:
    """Attaches standard security headers to all responses and strict Cache-Control to sensitive endpoints."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        is_sensitive = any(path.startswith(prefix) for prefix in [
            "/api/scan", "/api/audit", "/api/banking", "/api/ai"
        ])

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                raw_headers = list(message.get("headers", []))
                # Add baseline security headers
                raw_headers.append((b"x-content-type-options", b"nosniff"))
                raw_headers.append((b"x-frame-options", b"DENY"))
                raw_headers.append((b"referrer-policy", b"no-referrer"))
                raw_headers.append((b"permissions-policy", b"geolocation=(), camera=(), microphone=()"))
                if is_sensitive:
                    raw_headers.append((b"cache-control", b"no-store, no-cache, must-revalidate"))
                    raw_headers.append((b"pragma", b"no-cache"))
                message["headers"] = raw_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)
