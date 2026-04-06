"""
Shared test fixtures for UHC test suite.
"""

import pytest

# Default Mersenne prime: 2^61 - 1
MERSENNE_61 = (1 << 61) - 1


@pytest.fixture
def prime():
    """Default prime for testing: 2^61 - 1."""
    return MERSENNE_61


@pytest.fixture
def base(prime):
    """A fixed base for deterministic testing."""
    return 131  # small prime, easy to reason about
