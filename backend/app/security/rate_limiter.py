"""Scanner Rate Limiting, Trusted Proxy Handling, and Concurrency Management.

Provides:
- In-memory per-client IP sliding window rate limiting with bounded storage.
- Strict, thread-safe memory management and idle client pruning.
- Explicit trusted reverse proxy count configuration (TRUSTED_PROXY_COUNT).
- Default to ignoring untrusted X-Forwarded-For headers.
- Separate rate limiters for live scans, expensive upload scans, and AI intelligence endpoints.
- Asynchronous scan concurrency bounding (default 5 concurrent scans).
"""

import asyncio
import os
import threading
import time
import math
from typing import Dict, List, Tuple, Optional, Any


TRUSTED_PROXY_COUNT = int(os.environ.get("QS_TRUSTED_PROXY_COUNT", os.environ.get("TRUSTED_PROXY_COUNT", "0")))


def get_client_ip(request: Any, trusted_proxy_count: Optional[int] = None) -> str:
    """Extracts client IP safely.

    If trusted_proxy_count is 0 (or unset by default), X-Forwarded-For is ignored completely,
    preventing clients from bypassing rate limiting or spoofing identities.
    If trusted_proxy_count > 0, extracts the IP at position [-trusted_proxy_count] from X-Forwarded-For.
    """
    proxy_count = trusted_proxy_count if trusted_proxy_count is not None else TRUSTED_PROXY_COUNT

    direct_ip = getattr(getattr(request, "client", None), "host", "127.0.0.1") or "127.0.0.1"

    if proxy_count <= 0:
        return direct_ip

    headers = getattr(request, "headers", {})
    xff = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
    if not xff:
        return direct_ip

    parts = [p.strip() for p in xff.split(",") if p.strip()]
    if not parts:
        return direct_ip

    if len(parts) >= proxy_count:
        candidate = parts[-proxy_count]
        # Basic sanity check on extracted IP
        if candidate and "/" not in candidate and "\\" not in candidate:
            return candidate

    return direct_ip


class InMemoryRateLimiter:
    """Thread-safe sliding-window per-client rate limiter with bounded storage."""

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: float = 60.0,
        max_clients: int = 10_000,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._history: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def prune_expired(self, now: Optional[float] = None) -> None:
        """Removes expired timestamps and idle client keys from history."""
        curr_time = now if now is not None else time.time()
        cutoff = curr_time - self.window_seconds

        with self._lock:
            expired_clients = []
            for client_ip, timestamps in self._history.items():
                valid = [t for t in timestamps if t > cutoff]
                if not valid:
                    expired_clients.append(client_ip)
                else:
                    self._history[client_ip] = valid

            for client_ip in expired_clients:
                del self._history[client_ip]

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        """Checks whether client IP is allowed.
        Returns: (True, 0) or (False, retry_after)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            # Memory protection: If capacity reached and client is new, prune expired clients
            if len(self._history) >= self.max_clients and client_ip not in self._history:
                expired_clients = [
                    cip for cip, ts in self._history.items()
                    if not any(t > cutoff for t in ts)
                ]
                for cip in expired_clients:
                    del self._history[cip]

                # If still at capacity, evict oldest client by earliest timestamp (LRU eviction)
                if len(self._history) >= self.max_clients:
                    oldest_client = min(
                        self._history.keys(),
                        key=lambda k: self._history[k][0] if self._history[k] else 0.0
                    )
                    del self._history[oldest_client]

            timestamps = self._history.get(client_ip, [])
            valid_timestamps = [t for t in timestamps if t > cutoff]

            if len(valid_timestamps) >= self.max_requests:
                oldest = valid_timestamps[0]
                retry_after = max(1, math.ceil(self.window_seconds - (now - oldest)))
                self._history[client_ip] = valid_timestamps
                return False, retry_after

            valid_timestamps.append(now)
            self._history[client_ip] = valid_timestamps
            return True, 0

    def reset(self):
        """Clears all recorded rate limit history."""
        with self._lock:
            self._history.clear()


# Default instances
DEFAULT_RATE_LIMITER = InMemoryRateLimiter(
    max_requests=int(os.environ.get("QS_RATE_LIMIT_SCAN", "10")),
    window_seconds=float(os.environ.get("QS_RATE_LIMIT_SCAN_WINDOW", "60.0")),
    max_clients=10_000,
)

UPLOAD_SCAN_RATE_LIMITER = InMemoryRateLimiter(
    max_requests=int(os.environ.get("QS_RATE_LIMIT_UPLOAD", "5")),
    window_seconds=float(os.environ.get("QS_RATE_LIMIT_UPLOAD_WINDOW", "60.0")),
    max_clients=10_000,
)

AI_RATE_LIMITER = InMemoryRateLimiter(
    max_requests=int(os.environ.get("QS_RATE_LIMIT_AI", "5")),
    window_seconds=float(os.environ.get("QS_RATE_LIMIT_AI_WINDOW", "60.0")),
    max_clients=10_000,
)

MAX_CONCURRENT_SCANS = 5
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


def reset_all_limiters():
    """Clears all global rate limiters."""
    DEFAULT_RATE_LIMITER.reset()
    UPLOAD_SCAN_RATE_LIMITER.reset()
    AI_RATE_LIMITER.reset()
