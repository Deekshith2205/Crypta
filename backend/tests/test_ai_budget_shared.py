"""Multi-Instance Shared AI Budget Tests (Task 2 Remediation).

Verifies shared distributed budget enforcement across multiple instances/workers,
atomic updates, UTC rollover, safe concurrency, Redis outage handling,
duplicate charge prevention on retries, and clean shutdown.
"""

import concurrent.futures
import threading
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock
import pytest

from app.ai.budget import (
    AIBudgetError,
    AIBudgetExceededError,
    AIBudgetTracker,
    BaseBudgetStorage,
    InMemoryBudgetStorage,
    RedisBudgetStorage,
)


class MockRedisClient:
    """In-memory mock implementing the subset of Redis commands needed for RedisBudgetStorage."""

    def __init__(self):
        self._lock = threading.RLock()
        self._data: Dict[str, str] = {}
        self._sets: Dict[str, set] = {}
        self._is_connected = True

    def ping(self) -> bool:
        if not self._is_connected:
            raise ConnectionError("Connection refused by mock Redis")
        return True

    def pipeline(self):
        return MockPipeline(self)

    def sismember(self, key: str, member: str) -> bool:
        with self._lock:
            if not self._is_connected:
                raise ConnectionError("Mock Redis disconnected")
            return member in self._sets.get(key, set())

    def eval(self, script: str, numkeys: int, *args: Any) -> List[Any]:
        with self._lock:
            if not self._is_connected:
                raise ConnectionError("Mock Redis disconnected")

            tokens_key = args[0]
            cost_key = args[1]
            reqs_key = args[2]

            inc_tokens = int(args[3])
            inc_cost_micros = int(args[4])
            req_id = str(args[5]) if len(args) > 5 else ""

            # Check duplicate
            if req_id and req_id != "":
                if req_id in self._sets.get(reqs_key, set()):
                    cur_tok = int(self._data.get(tokens_key, "0"))
                    cur_cst = int(self._data.get(cost_key, "0"))
                    return [1, cur_tok, cur_cst, "DUPLICATE_IDEMPOTENT"]

            cur_tok = int(self._data.get(tokens_key, "0"))
            cur_cst = int(self._data.get(cost_key, "0"))

            new_tok = cur_tok + inc_tokens
            new_cst = cur_cst + inc_cost_micros

            self._data[tokens_key] = str(new_tok)
            self._data[cost_key] = str(new_cst)

            if req_id and req_id != "":
                if reqs_key not in self._sets:
                    self._sets[reqs_key] = set()
                self._sets[reqs_key].add(req_id)

            return [1, new_tok, new_cst, "OK"]

    def delete(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._data.pop(k, None)
                self._sets.pop(k, None)

    def keys(self, pattern: str) -> List[str]:
        with self._lock:
            return list(self._data.keys()) + list(self._sets.keys())

    def close(self) -> None:
        pass


class MockPipeline:
    """Mock Redis pipeline for batched GETs."""

    def __init__(self, client: MockRedisClient):
        self._client = client
        self._commands = []

    def get(self, key: str):
        self._commands.append(("get", key))
        return self

    def execute(self) -> List[Any]:
        results = []
        with self._client._lock:
            if not self._client._is_connected:
                raise ConnectionError("Mock Redis pipeline failed: disconnected")
            for cmd, key in self._commands:
                if cmd == "get":
                    results.append(self._client._data.get(key, None))
        return results


class TestAiBudgetShared:
    """Test suite for shared AI budget storage across instances."""

    def test_two_instances_share_in_memory_backend(self):
        """Two AIBudgetTracker instances sharing the same storage see unified usage."""
        shared_storage = InMemoryBudgetStorage()
        tracker1 = AIBudgetTracker(daily_token_budget=1000, storage=shared_storage)
        tracker2 = AIBudgetTracker(daily_token_budget=1000, storage=shared_storage)

        # Tracker 1 records 600 tokens
        tracker1.record_usage(input_tokens=300, output_tokens=300)

        # Tracker 2 must observe remaining 400 tokens
        status2 = tracker2.get_status()
        assert status2["tokens_used_today"] == 600
        assert status2["tokens_remaining"] == 400

        # Tracker 2 can consume 350 tokens
        assert tracker2.can_consume(350) is True

        # Tracker 2 cannot consume 450 tokens
        assert tracker2.can_consume(450) is False

    def test_two_instances_share_redis_backend_and_enforce_budget(self):
        """Two instances sharing RedisBudgetStorage enforce shared budget limits."""
        mock_redis = MockRedisClient()
        shared_storage = RedisBudgetStorage(redis_client=mock_redis)

        worker1 = AIBudgetTracker(daily_token_budget=1000, daily_cost_budget_usd=1.0, storage=shared_storage)
        worker2 = AIBudgetTracker(daily_token_budget=1000, daily_cost_budget_usd=1.0, storage=shared_storage)

        # Worker 1 consumes 700 tokens
        worker1.record_usage(input_tokens=400, output_tokens=300)

        # Worker 2 tries to consume 350 tokens (700 + 350 = 1050 > 1000 limit) -> rejected!
        assert worker2.can_consume(350) is False

        # Worker 2 can consume 250 tokens (700 + 250 = 950 <= 1000) -> allowed!
        assert worker2.can_consume(250) is True

    def test_idempotent_retry_prevents_duplicate_charge(self):
        """When request_id is reused on retry, usage is not double charged."""
        mock_redis = MockRedisClient()
        storage = RedisBudgetStorage(redis_client=mock_redis)
        tracker = AIBudgetTracker(daily_token_budget=5000, storage=storage)

        req_id = "ai-req-uuid-998877"

        # First attempt: charges 200 tokens
        tok1, cost1 = tracker.record_usage(input_tokens=100, output_tokens=100, request_id=req_id)
        assert tok1 == 200

        # Second attempt (retry of identical request): must not increment
        tok2, cost2 = tracker.record_usage(input_tokens=100, output_tokens=100, request_id=req_id)
        assert tok2 == 200
        assert cost2 == cost1

        status = tracker.get_status()
        assert status["tokens_used_today"] == 200

    def test_concurrent_consumption_across_threads_is_atomic(self):
        """Concurrent calls across threads atomically increment without loss."""
        mock_redis = MockRedisClient()
        storage = RedisBudgetStorage(redis_client=mock_redis)
        tracker = AIBudgetTracker(daily_token_budget=100_000, storage=storage)

        num_threads = 10
        increments_per_thread = 20
        tokens_per_call = 10

        def worker(thread_idx: int):
            for i in range(increments_per_thread):
                tracker.record_usage(
                    input_tokens=tokens_per_call,
                    output_tokens=0,
                    request_id=f"thread-{thread_idx}-req-{i}",
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, t) for t in range(num_threads)]
            for f in futures:
                f.result()

        expected_tokens = num_threads * increments_per_thread * tokens_per_call
        status = tracker.get_status()
        assert status["tokens_used_today"] == expected_tokens

    def test_redis_outage_fails_closed_when_require_shared_is_true(self, monkeypatch):
        """When QS_REQUIRE_SHARED_BUDGET=true and Redis is unavailable,

        the tracker must fail closed: can_consume=False, record_usage raises error.
        """
        monkeypatch.setenv("QS_REQUIRE_SHARED_BUDGET", "true")
        monkeypatch.setenv("QS_REDIS_URL", "redis://127.0.0.1:63799/0")  # unreachable port

        tracker = AIBudgetTracker(daily_token_budget=1000)
        assert tracker._shared_failed is True
        assert tracker.can_consume(1) is False

        with pytest.raises(AIBudgetExceededError, match="Shared AI budget enforcement required"):
            tracker.record_usage(input_tokens=10, output_tokens=10)

        status = tracker.get_status()
        assert status["is_budget_exceeded"] is True

    def test_redis_outage_falls_back_to_memory_when_require_shared_is_false(self, monkeypatch):
        """When QS_REQUIRE_SHARED_BUDGET=false (dev mode) and Redis is unreachable,

        the tracker falls back to in-memory mode with a logged warning.
        """
        monkeypatch.setenv("QS_REQUIRE_SHARED_BUDGET", "false")
        monkeypatch.setenv("QS_REDIS_URL", "redis://127.0.0.1:63799/0")  # unreachable port

        tracker = AIBudgetTracker(daily_token_budget=1000)
        assert tracker._shared_failed is False
        assert tracker._storage_mode == "memory"
        assert tracker.can_consume(100) is True

        tokens, cost = tracker.record_usage(input_tokens=50, output_tokens=50)
        assert tokens == 100
        assert tracker.get_status()["tokens_used_today"] == 100

    def test_utc_rollover_resets_counters_for_new_day(self):
        """Changing the tracker date triggers rollover and resets counters for the new day."""
        mock_redis = MockRedisClient()
        storage = RedisBudgetStorage(redis_client=mock_redis)
        tracker = AIBudgetTracker(daily_token_budget=500, storage=storage)

        tracker.record_usage(input_tokens=250, output_tokens=250)
        assert tracker.can_consume(1) is False

        # Simulate date rollover to a new day
        tracker._current_date = "2020-01-01"
        assert tracker.can_consume(100) is True

        status = tracker.get_status()
        assert status["tokens_used_today"] == 0
        assert status["tokens_remaining"] == 500

    def test_resource_cleanup_on_close(self):
        """Closing the budget tracker cleanly releases storage resources."""
        mock_redis = MockRedisClient()
        storage = RedisBudgetStorage(redis_client=mock_redis)
        tracker = AIBudgetTracker(storage=storage)
        tracker.close()  # Must not raise
