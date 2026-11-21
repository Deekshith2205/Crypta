"""AI Usage Rate Limits and Daily Cost Protection (Task D4).

Provides thread-safe, persistent-day tracking of AI token and cost consumption
to prevent runaway cloud API expenses and denial-of-service exhaustion.
"""

import os
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple


class AIBudgetExceededError(Exception):
    """Raised when the daily token or cost budget for AI intelligence is exhausted."""
    pass


class AIBudgetTracker:
    """Thread-safe tracker for daily AI token and cost consumption."""

    def __init__(
        self,
        daily_token_budget: Optional[int] = None,
        daily_cost_budget_usd: Optional[float] = None,
        cost_per_1k_tokens: Optional[float] = None,
    ):
        self._lock = threading.Lock()

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

        self._current_date = self._get_current_utc_date()
        self._tokens_used_today = 0
        self._cost_used_today_usd = 0.0

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
            self._current_date = today
            self._tokens_used_today = 0
            self._cost_used_today_usd = 0.0

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Approximates token count (~4 characters per token)."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def can_consume(self, estimated_tokens: int = 1) -> bool:
        """Checks whether the requested token consumption is within today's budget."""
        with self._lock:
            self._rollover_if_new_day()
            if self._tokens_used_today + estimated_tokens > self._daily_token_budget:
                return False
            if self._cost_used_today_usd >= self._daily_cost_budget_usd:
                return False
            return True

    def record_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        exact_cost_usd: Optional[float] = None,
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
            self._rollover_if_new_day()
            self._tokens_used_today += total_tokens
            self._cost_used_today_usd += cost
            return self._tokens_used_today, self._cost_used_today_usd

    def get_status(self) -> Dict[str, Any]:
        """Returns the current daily budget and consumption status."""
        with self._lock:
            self._rollover_if_new_day()
            remaining_tokens = max(0, self._daily_token_budget - self._tokens_used_today)
            remaining_cost = max(0.0, self._daily_cost_budget_usd - self._cost_used_today_usd)
            is_exceeded = (
                self._tokens_used_today >= self._daily_token_budget
                or self._cost_used_today_usd >= self._daily_cost_budget_usd
            )

            return {
                "date": self._current_date,
                "daily_token_budget": self._daily_token_budget,
                "tokens_used_today": self._tokens_used_today,
                "tokens_remaining": remaining_tokens,
                "daily_cost_budget_usd": round(self._daily_cost_budget_usd, 4),
                "cost_used_today_usd": round(self._cost_used_today_usd, 6),
                "cost_remaining_usd": round(remaining_cost, 4),
                "is_budget_exceeded": is_exceeded,
                "resets_at": self._get_next_utc_midnight_iso(),
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
        """Clears all consumption metrics for testing."""
        with self._lock:
            self._current_date = self._get_current_utc_date()
            self._tokens_used_today = 0
            self._cost_used_today_usd = 0.0


# Global singleton instance
AI_BUDGET_TRACKER = AIBudgetTracker()
