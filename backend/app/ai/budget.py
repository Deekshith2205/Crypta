"""AI Usage Rate Limits and Daily Cost Protection (Tasks D4 & Remediation).

Provides thread-safe and shared Redis-backed tracking of AI token and cost consumption
to prevent runaway cloud API expenses and denial-of-service exhaustion across single
or multi-worker deployments.
"""

import logging
import os
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Set, Tuple

try:
    import redis
except ImportError:
    redis = None

logger = logging.getLogger("quantumshield.ai.budget")


class AIBudgetError(Exception):
    """Base exception for AI budget errors."""
    pass


class AIBudgetExceededError(AIBudgetError):
    """Raised when the daily token or cost budget for AI intelligence is exhausted."""
    pass


class BaseBudgetStorage(ABC):
    """Abstract interface for daily AI token and cost budget storage."""

    @abstractmethod
    def get_usage(self, date_str: str) -> Tuple[int, float]:
        """Returns (tokens_used, cost_usd) for the specified UTC date."""
        pass

    @abstractmethod
    def can_consume(
        self,
        date_str: str,
        estimated_tokens: int,
        daily_token_budget: int,
        daily_cost_budget_usd: float,
        request_id: Optional[str] = None,
    ) -> bool:
        """Checks if requested consumption is within today's remaining limits."""
        pass

    @abstractmethod
    def record_usage(
        self,
        date_str: str,
        tokens: int,
        cost_usd: float,
        daily_token_budget: int,
        daily_cost_budget_usd: float,
        request_id: Optional[str] = None,
    ) -> Tuple[int, float]:
        """
        Atomically records usage and returns (new_tokens_used, new_cost_used_usd).
        Prevents double charging on retry if request_id is supplied.
        """
        pass

    @abstractmethod
    def reset(self, date_str: Optional[str] = None) -> None:
        """Clears usage metrics for the given date, or all dates if None."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Returns True if the storage backend is operational."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Releases underlying connections and resources."""
        pass


class InMemoryBudgetStorage(BaseBudgetStorage):
    """Thread-safe, process-local budget storage."""

    def __init__(self):
        self._lock = threading.RLock()
        self._usage: Dict[str, Dict[str, Any]] = {}

    def _get_entry(self, date_str: str) -> Dict[str, Any]:
        if date_str not in self._usage:
            self._usage[date_str] = {
                "tokens": 0,
                "cost_usd": 0.0,
                "request_ids": set(),
            }
        return self._usage[date_str]

    def get_usage(self, date_str: str) -> Tuple[int, float]:
        with self._lock:
            entry = self._get_entry(date_str)
            return entry["tokens"], entry["cost_usd"]

    def can_consume(
        self,
        date_str: str,
        estimated_tokens: int,
        daily_token_budget: int,
        daily_cost_budget_usd: float,
        request_id: Optional[str] = None,
    ) -> bool:
        with self._lock:
            entry = self._get_entry(date_str)
            if request_id and request_id in entry["request_ids"]:
                return True
            if entry["tokens"] + estimated_tokens > daily_token_budget:
                return False
            if entry["cost_usd"] >= daily_cost_budget_usd:
                return False
            return True

    def record_usage(
        self,
        date_str: str,
        tokens: int,
        cost_usd: float,
        daily_token_budget: int,
        daily_cost_budget_usd: float,
        request_id: Optional[str] = None,
    ) -> Tuple[int, float]:
        with self._lock:
            entry = self._get_entry(date_str)
            if request_id and request_id in entry["request_ids"]:
                logger.info("Idempotent retry detected for request %s; skipping duplicate charge.", request_id)
                return entry["tokens"], entry["cost_usd"]

            entry["tokens"] += tokens
            entry["cost_usd"] += cost_usd
            if request_id:
                entry["request_ids"].add(request_id)
            return entry["tokens"], entry["cost_usd"]

    def reset(self, date_str: Optional[str] = None) -> None:
        with self._lock:
            if date_str:
                self._usage.pop(date_str, None)
            else:
                self._usage.clear()

    def is_healthy(self) -> bool:
        return True

    def close(self) -> None:
        pass


LUA_RECORD_USAGE_SCRIPT = """
local tokens_key = KEYS[1]
local cost_key = KEYS[2]
local reqs_key = KEYS[3]

local inc_tokens = tonumber(ARGV[1]) or 0
local inc_cost_micros = tonumber(ARGV[2]) or 0
local req_id = ARGV[3]
local ttl = tonumber(ARGV[4]) or 172800

if req_id and req_id ~= "" then
    local is_dup = redis.call("SISMEMBER", reqs_key, req_id)
    if is_dup == 1 then
        local cur_tok = tonumber(redis.call("GET", tokens_key) or "0")
        local cur_cst = tonumber(redis.call("GET", cost_key) or "0")
        return {1, cur_tok, cur_cst, "DUPLICATE_IDEMPOTENT"}
    end
end

local new_tok = redis.call("INCRBY", tokens_key, inc_tokens)
local new_cst = redis.call("INCRBY", cost_key, inc_cost_micros)

if req_id and req_id ~= "" then
    redis.call("SADD", reqs_key, req_id)
    redis.call("EXPIRE", reqs_key, ttl)
end

redis.call("EXPIRE", tokens_key, ttl)
redis.call("EXPIRE", cost_key, ttl)

return {1, new_tok, new_cst, "OK"}
"""


class RedisBudgetStorage(BaseBudgetStorage):
    """
    Shared distributed budget storage backed by Redis.
    Uses atomic Lua scripts to prevent race conditions across concurrent workers.
    """

    DEFAULT_TTL_SECONDS = 172800  # 48 hours for UTC rollover & historical status

    def __init__(
        self,
        redis_url: Optional[str] = None,
        redis_client: Optional[Any] = None,
        timeout_seconds: float = 2.0,
        fail_closed: bool = False,
        key_prefix: str = "qs:ai:budget",
    ):
        self._timeout = timeout_seconds
        self._fail_closed = fail_closed
        self._key_prefix = key_prefix

        if redis_client is not None:
            self._redis = redis_client
        else:
            if redis is None:
                raise RuntimeError("The 'redis' package is required for RedisBudgetStorage.")
            url = redis_url or os.environ.get("QS_REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
            self._redis = redis.Redis.from_url(
                url,
                socket_timeout=self._timeout,
                socket_connect_timeout=self._timeout,
                decode_responses=True,
            )

    def _get_keys(self, date_str: str) -> Tuple[str, str, str]:
        tokens_key = f"{self._key_prefix}:{date_str}:tokens"
        cost_key = f"{self._key_prefix}:{date_str}:cost_micros"
        reqs_key = f"{self._key_prefix}:{date_str}:reqs"
        return tokens_key, cost_key, reqs_key

    def get_usage(self, date_str: str) -> Tuple[int, float]:
        tok_key, cst_key, _ = self._get_keys(date_str)
        try:
            pipe = self._redis.pipeline()
            pipe.get(tok_key)
            pipe.get(cst_key)
            res = pipe.execute()
            tokens = int(res[0]) if res[0] is not None else 0
            cost_micros = int(res[1]) if res[1] is not None else 0
            return tokens, cost_micros / 1_000_000.0
        except Exception as e:
            if self._fail_closed:
                raise AIBudgetExceededError(f"Shared AI budget enforcement required but Redis error occurred: {e}") from e
            logger.warning("Redis get_usage failed: %s", e)
            return 0, 0.0

    def can_consume(
        self,
        date_str: str,
        estimated_tokens: int,
        daily_token_budget: int,
        daily_cost_budget_usd: float,
        request_id: Optional[str] = None,
    ) -> bool:
        tok_key, cst_key, reqs_key = self._get_keys(date_str)
        try:
            if request_id and self._redis.sismember(reqs_key, request_id):
                return True
            tokens_used, cost_used_usd = self.get_usage(date_str)
            if tokens_used + estimated_tokens > daily_token_budget:
                return False
            if cost_used_usd >= daily_cost_budget_usd:
                return False
            return True
        except Exception as e:
            if self._fail_closed:
                logger.error("Shared budget check failed with Redis error: %s (failing closed)", e)
                return False
            logger.warning("Redis can_consume failed: %s (failing open in dev)", e)
            return True

    def record_usage(
        self,
        date_str: str,
        tokens: int,
        cost_usd: float,
        daily_token_budget: int,
        daily_cost_budget_usd: float,
        request_id: Optional[str] = None,
    ) -> Tuple[int, float]:
        tok_key, cst_key, reqs_key = self._get_keys(date_str)
        cost_micros = int(round(cost_usd * 1_000_000))
        req_id_str = request_id or ""

        try:
            res = self._redis.eval(
                LUA_RECORD_USAGE_SCRIPT,
                3,
                tok_key,
                cst_key,
                reqs_key,
                tokens,
                cost_micros,
                req_id_str,
                self.DEFAULT_TTL_SECONDS,
            )

            status = int(res[0])
            new_tokens = int(res[1])
            new_cost_micros = int(res[2])
            msg = str(res[3]) if len(res) > 3 else "UNKNOWN"
            new_cost_usd = new_cost_micros / 1_000_000.0

            if status == 1 and msg == "DUPLICATE_IDEMPOTENT":
                logger.info("Idempotent retry detected for request %s; skipping duplicate charge.", request_id)

            return new_tokens, new_cost_usd

        except Exception as e:
            if self._fail_closed:
                raise AIBudgetExceededError(f"Shared AI budget enforcement required but Redis error occurred: {e}") from e
            logger.warning("Redis record_usage failed: %s", e)
            return tokens, cost_usd

    def reset(self, date_str: Optional[str] = None) -> None:
        try:
            if date_str:
                tok_key, cst_key, reqs_key = self._get_keys(date_str)
                self._redis.delete(tok_key, cst_key, reqs_key)
            else:
                pattern = f"{self._key_prefix}:*"
                keys = self._redis.keys(pattern)
                if keys:
                    self._redis.delete(*keys)
        except Exception as e:
            logger.warning("Redis reset failed: %s", e)

    def is_healthy(self) -> bool:
        try:
            return bool(self._redis.ping())
        except Exception as e:
            logger.warning("Redis health check failed: %s", e)
            return False

    def close(self) -> None:
        try:
            self._redis.close()
        except Exception:
            pass


class AIBudgetTracker:
    """Thread-safe, optionally distributed tracker for daily AI token and cost consumption."""

    def __init__(
        self,
        daily_token_budget: Optional[int] = None,
        daily_cost_budget_usd: Optional[float] = None,
        cost_per_1k_tokens: Optional[float] = None,
        storage: Optional[BaseBudgetStorage] = None,
        require_shared: Optional[bool] = None,
    ):
        self._lock = threading.RLock()

        # Defaults from environment or baseline values
        self._daily_token_budget = daily_token_budget or int(
            os.environ.get("QS_AI_DAILY_TOKEN_BUDGET", "100000")
        )
        self._daily_cost_budget_usd = daily_cost_budget_usd or float(
            os.environ.get("QS_AI_DAILY_COST_BUDGET_USD", "5.00")
        )
        self._cost_per_1k_tokens = cost_per_1k_tokens or float(
            os.environ.get("QS_AI_ESTIMATED_COST_PER_1K_TOKENS", "0.002")
        )

        self._default_token_budget = self._daily_token_budget
        self._default_cost_budget_usd = self._daily_cost_budget_usd

        req_env = os.environ.get("QS_REQUIRE_SHARED_BUDGET", "").strip().lower()
        self._require_shared = (
            require_shared if require_shared is not None
            else req_env in ("1", "true", "yes", "required", "mandatory")
        )
        self._shared_failed = False
        self._current_date = self._get_current_utc_date()

        if storage is not None:
            self._storage = storage
            self._storage_mode = "redis" if isinstance(storage, RedisBudgetStorage) else "memory"
        else:
            redis_url = os.environ.get("QS_REDIS_URL", os.environ.get("REDIS_URL", "")).strip()
            if redis_url or self._require_shared:
                try:
                    self._storage = RedisBudgetStorage(
                        redis_url=redis_url or "redis://localhost:6379/0",
                        fail_closed=self._require_shared,
                    )
                    if not self._storage.is_healthy():
                        if self._require_shared:
                            self._shared_failed = True
                            logger.error("Required shared Redis budget storage is unreachable.")
                        else:
                            logger.warning("Configured Redis budget storage is unreachable. Falling back to in-memory mode.")
                            self._storage = InMemoryBudgetStorage()
                            self._storage_mode = "memory"
                    else:
                        self._storage_mode = "redis"
                except Exception as e:
                    if self._require_shared:
                        self._shared_failed = True
                        logger.error("Failed to initialize required shared Redis budget: %s", e)
                    else:
                        logger.warning("Failed to initialize Redis budget: %s. Falling back to in-memory mode.", e)
                        self._storage = InMemoryBudgetStorage()
                        self._storage_mode = "memory"
            else:
                self._storage = InMemoryBudgetStorage()
                self._storage_mode = "memory"

    @property
    def _tokens_used_today(self) -> int:
        if self._shared_failed:
            return 0
        tokens, _ = self._storage.get_usage(self._current_date)
        return tokens

    @_tokens_used_today.setter
    def _tokens_used_today(self, value: int) -> None:
        pass

    @property
    def _cost_used_today_usd(self) -> float:
        if self._shared_failed:
            return 0.0
        _, cost = self._storage.get_usage(self._current_date)
        return cost

    @_cost_used_today_usd.setter
    def _cost_used_today_usd(self, value: float) -> None:
        pass

    @staticmethod
    def _get_current_utc_date() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    @staticmethod
    def _get_next_utc_midnight_iso() -> str:
        now = datetime.now(timezone.utc)
        tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return tomorrow.isoformat()

    def _rollover_if_new_day(self) -> None:
        """Resets counters if UTC date has changed."""
        today = self._get_current_utc_date()
        if today != self._current_date:
            self._storage.reset(today)
            self._current_date = today

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Approximates token count (~4 characters per token)."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def can_consume(self, estimated_tokens: int = 1, request_id: Optional[str] = None) -> bool:
        """Checks whether the requested token consumption is within today's budget."""
        with self._lock:
            if self._shared_failed:
                return False
            self._rollover_if_new_day()
            return self._storage.can_consume(
                self._current_date,
                estimated_tokens,
                self._daily_token_budget,
                self._daily_cost_budget_usd,
                request_id=request_id,
            )

    def record_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        exact_cost_usd: Optional[float] = None,
        request_id: Optional[str] = None,
    ) -> Tuple[int, float]:
        """
        Records consumed tokens and updates daily cost.
        Returns (tokens_used_today, cost_used_today_usd).
        """
        total_tokens = max(0, input_tokens) + max(0, output_tokens)
        cost = exact_cost_usd if exact_cost_usd is not None else (
            (total_tokens / 1000.0) * self._cost_per_1k_tokens
        )

        with self._lock:
            if self._shared_failed:
                raise AIBudgetExceededError("Shared AI budget enforcement required but Redis is unavailable.")
            self._rollover_if_new_day()
            return self._storage.record_usage(
                self._current_date,
                total_tokens,
                cost,
                self._daily_token_budget,
                self._daily_cost_budget_usd,
                request_id=request_id,
            )

    def get_status(self) -> Dict[str, Any]:
        """Returns the current daily budget and consumption status."""
        with self._lock:
            self._rollover_if_new_day()
            if self._shared_failed:
                return {
                    "date": self._current_date,
                    "daily_token_budget": self._daily_token_budget,
                    "tokens_used_today": 0,
                    "tokens_remaining": 0,
                    "daily_cost_budget_usd": round(self._daily_cost_budget_usd, 4),
                    "cost_used_today_usd": 0.0,
                    "cost_remaining_usd": 0.0,
                    "is_budget_exceeded": True,
                    "resets_at": self._get_next_utc_midnight_iso(),
                    "storage_mode": getattr(self, "_storage_mode", "memory"),
                    "error": "Shared Redis budget storage is unreachable.",
                }

            tokens_used = self._tokens_used_today
            cost_used = self._cost_used_today_usd
            remaining_tokens = max(0, self._daily_token_budget - tokens_used)
            remaining_cost = max(0.0, self._daily_cost_budget_usd - cost_used)
            is_exceeded = (
                tokens_used >= self._daily_token_budget
                or cost_used >= self._daily_cost_budget_usd
            )

            return {
                "date": self._current_date,
                "daily_token_budget": self._daily_token_budget,
                "tokens_used_today": tokens_used,
                "tokens_remaining": remaining_tokens,
                "daily_cost_budget_usd": round(self._daily_cost_budget_usd, 4),
                "cost_used_today_usd": round(cost_used, 6),
                "cost_remaining_usd": round(remaining_cost, 4),
                "is_budget_exceeded": is_exceeded,
                "resets_at": self._get_next_utc_midnight_iso(),
                "storage_mode": getattr(self, "_storage_mode", "memory"),
            }

    def set_limits(
        self,
        token_budget: Optional[int] = None,
        cost_budget_usd: Optional[float] = None,
    ) -> None:
        """Overrides budget limits for testing or dynamic configuration."""
        with self._lock:
            if token_budget is not None:
                self._daily_token_budget = token_budget
            if cost_budget_usd is not None:
                self._daily_cost_budget_usd = cost_budget_usd

    def reset(self) -> None:
        """Clears all consumption metrics and restores default limits for testing."""
        with self._lock:
            self._current_date = self._get_current_utc_date()
            self._storage.reset(self._current_date)
            self._daily_token_budget = self._default_token_budget
            self._daily_cost_budget_usd = self._default_cost_budget_usd
            self._shared_failed = False

    def close(self) -> None:
        """Closes storage connection pool."""
        with self._lock:
            self._storage.close()


# Global singleton instance
AI_BUDGET_TRACKER = AIBudgetTracker()
