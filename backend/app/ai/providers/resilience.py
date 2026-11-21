"""HTTP resilience and retry helper for AI providers.
Handles transient gateway errors, rate limit backoffs, and network disconnects.
"""

import asyncio
from datetime import datetime, timezone
import email.utils
import logging
from typing import Awaitable, Callable, Optional, Set
import httpx

from app.ai.providers.base import (
    AIProviderError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
)

logger = logging.getLogger("quantumshield.ai.resilience")

TRANSIENT_STATUS_CODES: Set[int] = {502, 503, 504}
FAIL_FAST_STATUS_CODES: Set[int] = {400, 401, 403, 404}


def parse_retry_after(header_val: Optional[str]) -> Optional[float]:
    """Parses Retry-After header as either seconds or HTTP date."""
    if not header_val:
        return None
    try:
        val = float(header_val.strip())
        return max(0.0, val)
    except ValueError:
        pass
    try:
        target_time = email.utils.parsedate_to_datetime(header_val.strip())
        now = datetime.now(timezone.utc)
        diff = (target_time - now).total_seconds()
        return max(0.0, diff)
    except Exception:
        return None


async def execute_http_with_resilience(
    http_call: Callable[[], Awaitable[httpx.Response]],
    provider_name: str,
    max_retries: int = 2,
    initial_backoff: float = 0.5,
    max_backoff: float = 3.0,
) -> httpx.Response:
    """Executes an HTTP request with exponential backoff on transient errors.

    - Retries on transient codes (502, 503, 504, and 429 when Retry-After <= 5.0)
    - Retries on network connection drops (ConnectError, ReadError, RemoteProtocolError)
    - Fails fast on client errors (400, 401, 403, 404)
    - Raises AIProviderTimeoutError on timeout
    - Re-raises structured AIProviderError subclasses
    """
    attempt = 0
    while True:
        try:
            response = await http_call()

            # Success
            if response.status_code == 200:
                return response

            # Fail-fast on 4xx client errors (do not retry)
            if response.status_code in FAIL_FAST_STATUS_CODES:
                logger.warning(
                    "%s API returned client error HTTP %d (failing fast).",
                    provider_name,
                    response.status_code,
                )
                if response.status_code in (401, 403):
                    raise AIProviderUnavailableError(
                        f"{provider_name} API authentication failed (HTTP {response.status_code})."
                    )
                raise AIProviderError(
                    f"{provider_name} API request failed with HTTP {response.status_code}."
                )

            # Rate limit handling (429)
            if response.status_code == 429:
                retry_after_hdr = response.headers.get("Retry-After")
                retry_after = parse_retry_after(retry_after_hdr)

                if retry_after is not None and retry_after <= 5.0 and attempt < max_retries:
                    logger.info(
                        "%s rate limited (HTTP 429). Retrying after %.2fs (attempt %d/%d).",
                        provider_name,
                        retry_after,
                        attempt + 1,
                        max_retries,
                    )
                    await asyncio.sleep(retry_after)
                    attempt += 1
                    continue
                else:
                    logger.warning(
                        "%s quota or rate limit exceeded (HTTP 429, Retry-After: %s).",
                        provider_name,
                        retry_after_hdr,
                    )
                    raise AIProviderRateLimitError(
                        f"{provider_name} quota or rate limit exceeded."
                    )

            # Transient gateway / server errors (502, 503, 504)
            if response.status_code in TRANSIENT_STATUS_CODES:
                if attempt < max_retries:
                    backoff = min(initial_backoff * (2 ** attempt), max_backoff)
                    logger.info(
                        "%s transient error HTTP %d. Retrying in %.2fs (attempt %d/%d).",
                        provider_name,
                        response.status_code,
                        backoff,
                        attempt + 1,
                        max_retries,
                    )
                    await asyncio.sleep(backoff)
                    attempt += 1
                    continue
                else:
                    logger.error(
                        "%s transient error HTTP %d persisted after %d retries.",
                        provider_name,
                        response.status_code,
                        max_retries,
                    )
                    raise AIProviderError(
                        f"{provider_name} service temporarily unavailable (HTTP {response.status_code})."
                    )

            # Any other unexpected non-200 status code
            logger.error(
                "%s API returned unexpected HTTP status %d.",
                provider_name,
                response.status_code,
            )
            raise AIProviderError(
                f"{provider_name} API request failed with HTTP {response.status_code}."
            )

        except httpx.TimeoutException as exc:
            logger.warning("%s API call timed out.", provider_name)
            raise AIProviderTimeoutError(
                f"{provider_name} API call timed out."
            ) from exc

        except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as exc:
            if attempt < max_retries:
                backoff = min(initial_backoff * (2 ** attempt), max_backoff)
                logger.info(
                    "%s network error (%s). Retrying in %.2fs (attempt %d/%d).",
                    provider_name,
                    type(exc).__name__,
                    backoff,
                    attempt + 1,
                    max_retries,
                )
                await asyncio.sleep(backoff)
                attempt += 1
                continue
            else:
                logger.error(
                    "%s network error (%s) persisted after %d retries.",
                    provider_name,
                    type(exc).__name__,
                    max_retries,
                )
                raise AIProviderError(
                    f"{provider_name} network error: {type(exc).__name__}"
                ) from exc

        except (AIProviderError, AIProviderUnavailableError, AIProviderRateLimitError, AIProviderTimeoutError):
            raise

        except Exception as exc:
            logger.error(
                "Unexpected error communicating with %s: %s",
                provider_name,
                type(exc).__name__,
            )
            raise AIProviderError(
                f"Unexpected error communicating with {provider_name} API."
            ) from exc
