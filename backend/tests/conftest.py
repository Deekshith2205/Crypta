"""Global pytest fixtures for QuantumShield backend test suite."""

import pytest
from app.security.rate_limiter import reset_all_limiters


@pytest.fixture(autouse=True)
def reset_rate_limiters_between_tests():
    """Ensure rate limiters start clean for each test function."""
    reset_all_limiters()
    yield
    reset_all_limiters()
