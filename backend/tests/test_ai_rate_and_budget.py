import pytest
from unittest.mock import patch, AsyncMock
from starlette.testclient import TestClient

from app.main import app
from app.ai.budget import AIBudgetTracker, AI_BUDGET_TRACKER
from app.security.rate_limiter import AI_RATE_LIMITER
from app.ai.service import QuantumReadinessAIService
from app.ai.providers.mock import MockAIProvider
from app.ai.schemas import FindingExplanationRequest

client = TestClient(app)


class TestAiRateAndBudget:
    """Task D4 test suite for AI rate limits, budget tracking, and cost protection."""

    def setup_method(self):
        AI_RATE_LIMITER.reset()
        AI_BUDGET_TRACKER.reset()

    def test_budget_tracker_records_consumption(self):
        tracker = AIBudgetTracker(daily_token_budget=1000, daily_cost_budget_usd=1.0)
        assert tracker.can_consume(100) is True

        tokens, cost = tracker.record_usage(input_tokens=100, output_tokens=150)
        assert tokens == 250
        assert cost > 0

        status = tracker.get_status()
        assert status["tokens_used_today"] == 250
        assert status["tokens_remaining"] == 750
        assert status["is_budget_exceeded"] is False

    def test_budget_tracker_blocks_when_token_limit_exceeded(self):
        tracker = AIBudgetTracker(daily_token_budget=500, daily_cost_budget_usd=10.0)
        tracker.record_usage(input_tokens=300, output_tokens=200)

        # Exact capacity reached
        assert tracker.can_consume(1) is False
        status = tracker.get_status()
        assert status["is_budget_exceeded"] is True
        assert status["tokens_remaining"] == 0

    def test_budget_tracker_blocks_when_cost_limit_exceeded(self):
        tracker = AIBudgetTracker(daily_token_budget=100_000, daily_cost_budget_usd=0.01)
        # Record usage with high explicit cost
        tracker.record_usage(input_tokens=100, output_tokens=100, exact_cost_usd=0.015)

        assert tracker.can_consume(10) is False
        status = tracker.get_status()
        assert status["is_budget_exceeded"] is True

    def test_budget_tracker_rollover_on_date_change(self):
        tracker = AIBudgetTracker(daily_token_budget=500)
        tracker.record_usage(input_tokens=400, output_tokens=100)
        assert tracker.can_consume(1) is False

        # Simulate date rollover to yesterday
        tracker._current_date = "2020-01-01"
        assert tracker.can_consume(100) is True
        status = tracker.get_status()
        assert status["tokens_used_today"] == 0
        assert status["tokens_remaining"] == 500

    def test_ai_budget_endpoint_returns_metrics(self):
        AI_BUDGET_TRACKER.set_limits(token_budget=50_000, cost_budget_usd=2.50)
        res = client.get("/api/ai/budget")
        assert res.status_code == 200
        data = res.json()
        assert data["daily_token_budget"] == 50_000
        assert data["daily_cost_budget_usd"] == 2.50
        assert "tokens_remaining" in data
        assert "resets_at" in data

    def test_ai_rate_limiter_blocks_burst_on_budget_endpoint(self):
        # AI_RATE_LIMITER allows 5 requests per 60s
        for _ in range(5):
            res = client.get("/api/ai/budget")
            assert res.status_code == 200

        # 6th request should be blocked with 429
        res = client.get("/api/ai/budget")
        assert res.status_code == 429
        assert "Retry-After" in res.headers
        assert res.json()["error"] == "RATE_LIMIT_EXCEEDED"

    def test_ai_rate_limiter_enforced_on_json_report_with_ai(self):
        # 5 requests should pass
        for _ in range(5):
            res = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json?include_ai=true")
            assert res.status_code == 200

        # 6th request with include_ai=true must be rejected with 429
        res = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json?include_ai=true")
        assert res.status_code == 429
        assert res.json()["error"] == "RATE_LIMIT_EXCEEDED"

    def test_standard_json_report_without_ai_not_blocked_by_ai_rate_limiter(self):
        # Exhaust AI rate limiter
        for _ in range(5):
            client.get("/api/ai/budget")
        assert client.get("/api/ai/budget").status_code == 429

        # Standard report without AI does not use AI rate limiter and must still succeed
        res = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json")
        assert res.status_code == 200
        assert "audit" in res.json()

    def test_ai_rate_limiter_enforced_on_pdf_report_with_ai(self):
        # 5 requests should pass
        for _ in range(5):
            res = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/pdf?include_ai=true")
            assert res.status_code == 200

        # 6th request with include_ai=true must be rejected with 429
        res = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/pdf?include_ai=true")
        assert res.status_code == 429
        assert res.json()["error"] == "RATE_LIMIT_EXCEEDED"

    @pytest.mark.asyncio
    async def test_service_blocks_provider_call_when_budget_exhausted(self):
        AI_BUDGET_TRACKER.set_limits(token_budget=10)
        AI_BUDGET_TRACKER.record_usage(input_tokens=10, output_tokens=0)

        provider = MockAIProvider()
        provider.generate = AsyncMock()
        service = QuantumReadinessAIService(provider=provider, enable_fallback=False)

        req = FindingExplanationRequest(
            rule_id="TEST-BUDGET-EXHAUSTED",
            title="Budget Test",
            value="RSA-2048",
            role="KEY_EXCHANGE",
            source="SCAN",
            evidence_status="OBSERVED",
            severity="HIGH",
            risk="QUANTUM",
        )
        res = await service.explain_finding(req)
        assert res.success is False
        assert "budget exceeded" in res.error.lower()
        provider.generate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_service_falls_back_when_budget_exhausted_and_fallback_enabled(self):
        AI_BUDGET_TRACKER.set_limits(token_budget=10)
        AI_BUDGET_TRACKER.record_usage(input_tokens=10, output_tokens=0)

        provider = MockAIProvider()
        provider.generate = AsyncMock()
        service = QuantumReadinessAIService(provider=provider, enable_fallback=True)

        req = FindingExplanationRequest(
            rule_id="TEST-BUDGET-FALLBACK",
            title="Budget Fallback Test",
            value="RSA-2048",
            role="KEY_EXCHANGE",
            source="SCAN",
            evidence_status="OBSERVED",
            severity="HIGH",
            risk="QUANTUM",
        )
        res = await service.explain_finding(req)
        # Transparently fell back to deterministic fallback
        assert res.success is True
        assert res.provider == "DETERMINISTIC_FALLBACK"
        provider.generate.assert_not_awaited()
