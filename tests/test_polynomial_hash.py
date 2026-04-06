"""
Tests for uhc.core.polynomial_hash

Every test is traceable to a specific definition, lemma, or theorem
in the compressed-domain hashing framework.
"""

import pytest

# Will fail until implementation exists — that's TDD.
from uhc.core.polynomial_hash import (
    PolynomialHash,
    mersenne_mod,
    mersenne_mul,
    phi,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

P61 = (1 << 61) - 1  # Mersenne prime 2^61 - 1


# ---------------------------------------------------------------------------
# Mersenne arithmetic tests (Lemma 14)
# ---------------------------------------------------------------------------

class TestMersenneArithmetic:
    """Tests for modular arithmetic with p = 2^61 - 1."""

    def test_mersenne_mod_zero(self):
        """0 mod p = 0."""
        assert mersenne_mod(0) == 0

    def test_mersenne_mod_small(self):
        """Small values are unchanged."""
        assert mersenne_mod(42) == 42

    def test_mersenne_mod_p(self):
        """p mod p = 0."""
        assert mersenne_mod(P61) == 0

    def test_mersenne_mod_p_plus_one(self):
        """(p + 1) mod p = 1."""
        assert mersenne_mod(P61 + 1) == 1

    def test_mersenne_mod_2p(self):
        """2p mod p = 0."""
        assert mersenne_mod(2 * P61) == 0

    def test_mersenne_mod_large(self):
        """Large value reduces correctly."""
        val = (1 << 120) + 17
        assert mersenne_mod(val) == val % P61

    def test_mersenne_mul_commutative(self):
        """a * b = b * a (mod p)."""
        a, b = 123456789, 987654321
        assert mersenne_mul(a, b) == mersenne_mul(b, a)

    def test_mersenne_mul_identity(self):
        """a * 1 = a (mod p)."""
        a = 999999999
        assert mersenne_mul(a, 1) == mersenne_mod(a)

    def test_mersenne_mul_zero(self):
        """a * 0 = 0 (mod p)."""
        assert mersenne_mul(123456, 0) == 0

    def test_mersenne_mul_correctness(self):
        """Multiply matches Python's native modular arithmetic."""
        a, b = 2**60 - 3, 2**60 + 7
        assert mersenne_mul(a, b) == (a * b) % P61


# ---------------------------------------------------------------------------
# Definition 2: Polynomial hash function
# ---------------------------------------------------------------------------

class TestHashDefinition:
    """Tests for H(s) = Σ (s_i + 1) · x^(n-1-i) (mod p)."""

    def test_empty_string_hashes_to_zero(self):
        """Definition 2: H(ε) = 0."""
        h = PolynomialHash(prime=P61, base=131)
        assert h.hash(b"") == 0

    def test_single_byte(self):
        """H((c)) = c + 1 (mod p)."""
        h = PolynomialHash(prime=P61, base=131)
        assert h.hash(b"\x00") == 1       # 0 + 1
        assert h.hash(b"\x01") == 2       # 1 + 1
        assert h.hash(b"\xff") == 256     # 255 + 1

    def test_two_bytes_manual(self):
        """H((a, b)) = (a+1)·x + (b+1) (mod p)."""
        x = 131
        h = PolynomialHash(prime=P61, base=x)
        a, b = 3, 7
        expected = ((a + 1) * x + (b + 1)) % P61
        assert h.hash(bytes([a, b])) == expected

    def test_three_bytes_manual(self):
        """H((a,b,c)) = (a+1)·x² + (b+1)·x + (c+1) (mod p)."""
        x = 131
        h = PolynomialHash(prime=P61, base=x)
        a, b, c = 10, 20, 30
        expected = ((a + 1) * x * x + (b + 1) * x + (c + 1)) % P61
        assert h.hash(bytes([a, b, c])) == expected


# ---------------------------------------------------------------------------
# Lemma 1: Nonzero coefficients
# ---------------------------------------------------------------------------

class TestLemma1:
    """The +1 offset ensures no byte maps to zero in Z/pZ."""

    def test_null_byte_nonzero(self):
        """H((0)) ≠ 0 — the zero-padding fix."""
        h = PolynomialHash(prime=P61, base=131)
        assert h.hash(b"\x00") != 0
        assert h.hash(b"\x00") == 1

    def test_all_null_strings_distinct(self):
        """Strings of different lengths composed of null bytes hash differently."""
        h = PolynomialHash(prime=P61, base=131)
        hashes = [h.hash(b"\x00" * n) for n in range(1, 10)]
        assert len(set(hashes)) == 9  # all distinct


# ---------------------------------------------------------------------------
# Lemma 2: Distinctness of single-byte hashes
# ---------------------------------------------------------------------------

class TestLemma2:
    """For distinct bytes a ≠ b, H((a)) ≠ H((b))."""

    def test_all_single_bytes_distinct(self):
        h = PolynomialHash(prime=P61, base=131)
        hashes = [h.hash(bytes([b])) for b in range(256)]
        assert len(set(hashes)) == 256


# ---------------------------------------------------------------------------
# Theorem 1: Concatenation composability
# ---------------------------------------------------------------------------

class TestTheorem1:
    """H(A ‖ B) = H(A) · x^|B| + H(B) (mod p)."""

    def test_concat_two_strings(self):
        h = PolynomialHash(prime=P61, base=131)
        A = b"Hello"
        B = b"World"
        h_ab = h.hash(A + B)
        h_a = h.hash(A)
        h_b = h.hash(B)
        x_pow_b = h.power(len(B))
        expected = (h_a * x_pow_b + h_b) % P61
        assert h_ab == expected

    def test_concat_empty_left(self):
        """H(ε ‖ B) = H(B)."""
        h = PolynomialHash(prime=P61, base=131)
        B = b"test"
        assert h.hash(b"" + B) == h.hash(B)

    def test_concat_empty_right(self):
        """H(A ‖ ε) = H(A)."""
        h = PolynomialHash(prime=P61, base=131)
        A = b"test"
        h_a = h.hash(A)
        x_pow_0 = h.power(0)  # x^0 = 1
        assert (h_a * x_pow_0 + 0) % P61 == h_a

    def test_concat_associativity(self):
        """H(A ‖ B ‖ C) is consistent regardless of grouping."""
        h = PolynomialHash(prime=P61, base=131)
        A, B, C = b"aa", b"bb", b"cc"
        assert h.hash(A + B + C) == h.hash(A + B + C)
        # Verify via Theorem 1 applied twice:
        h_ab = (h.hash(A) * h.power(len(B)) + h.hash(B)) % P61
        h_abc = (h_ab * h.power(len(C)) + h.hash(C)) % P61
        assert h.hash(A + B + C) == h_abc

    def test_concat_random_data(self):
        """Theorem 1 holds for random byte sequences."""
        import os
        h = PolynomialHash(prime=P61, base=131)
        for _ in range(20):
            A = os.urandom(50)
            B = os.urandom(50)
            h_ab = h.hash(A + B)
            expected = (h.hash(A) * h.power(len(B)) + h.hash(B)) % P61
            assert h_ab == expected


# ---------------------------------------------------------------------------
# Definition 3 + Theorem 3: Geometric accumulator Φ
# ---------------------------------------------------------------------------

class TestPhi:
    """Φ(q, α) = Σ_{i=0}^{q-1} α^i computed by repeated doubling."""

    def test_phi_zero(self):
        """Φ(0, α) = 0."""
        assert phi(0, 5, P61) == 0

    def test_phi_one(self):
        """Φ(1, α) = 1."""
        assert phi(1, 5, P61) == 1

    def test_phi_two(self):
        """Φ(2, α) = 1 + α."""
        alpha = 5
        assert phi(2, alpha, P61) == (1 + alpha) % P61

    def test_phi_three(self):
        """Φ(3, α) = 1 + α + α²."""
        alpha = 5
        expected = (1 + alpha + alpha * alpha) % P61
        assert phi(3, alpha, P61) == expected

    def test_phi_matches_naive(self):
        """Doubling recurrence matches direct summation for small q."""
        alpha = 7
        for q in range(20):
            naive = sum(pow(alpha, i, P61) for i in range(q)) % P61
            assert phi(q, alpha, P61) == naive, f"Failed at q={q}"

    def test_phi_large_q(self):
        """Φ works for large q without overflow or timeout."""
        alpha = 131
        q = 1_000_000
        # Just verify it completes and returns a value in [0, p)
        result = phi(q, alpha, P61)
        assert 0 <= result < P61

    def test_phi_degeneracy_alpha_one(self):
        """Lemma 3: Φ(q, 1) = q (mod p) for all q."""
        for q in [0, 1, 2, 5, 10, 100, 999]:
            assert phi(q, 1, P61) == q % P61

    def test_phi_power_of_two_q(self):
        """Φ(2^k, α) — pure even-case recursion."""
        alpha = 13
        for k in range(1, 15):
            q = 1 << k
            naive = sum(pow(alpha, i, P61) for i in range(q)) % P61
            assert phi(q, alpha, P61) == naive


# ---------------------------------------------------------------------------
# Corollary 3: Closed-form equivalence
# ---------------------------------------------------------------------------

class TestCorollary3:
    """When α ≢ 1, Φ(q,α) = (α^q - 1) / (α - 1)."""

    def test_closed_form_matches_doubling(self):
        alpha = 7
        for q in [1, 2, 3, 5, 10, 50, 100]:
            doubling = phi(q, alpha, P61)
            # Closed form: (α^q - 1) · (α - 1)^(-1) mod p
            alpha_q = pow(alpha, q, P61)
            numerator = (alpha_q - 1) % P61
            denominator_inv = pow(alpha - 1, P61 - 2, P61)  # Fermat inverse
            closed = (numerator * denominator_inv) % P61
            assert doubling == closed, f"Failed at q={q}"


# ---------------------------------------------------------------------------
# Theorem 2: Geometric repetition hash
# ---------------------------------------------------------------------------

class TestTheorem2:
    """H(S^q) = H(S) · Φ(q, x^d) (mod p)."""

    def test_repeat_single_byte(self):
        """b"A" repeated q times."""
        h = PolynomialHash(prime=P61, base=131)
        S = b"A"
        for q in [1, 2, 3, 5, 10, 50]:
            direct = h.hash(S * q)
            h_s = h.hash(S)
            x_d = h.power(len(S))
            algebraic = (h_s * phi(q, x_d, P61)) % P61
            assert direct == algebraic, f"Failed at q={q}"

    def test_repeat_multi_byte_pattern(self):
        """b"abc" repeated q times."""
        h = PolynomialHash(prime=P61, base=131)
        S = b"abc"
        for q in [1, 2, 3, 7, 20]:
            direct = h.hash(S * q)
            h_s = h.hash(S)
            x_d = h.power(len(S))
            algebraic = (h_s * phi(q, x_d, P61)) % P61
            assert direct == algebraic, f"Failed at q={q}"

    def test_repeat_zero(self):
        """S^0 = ε, H(ε) = 0."""
        h = PolynomialHash(prime=P61, base=131)
        h_s = h.hash(b"abc")
        x_d = h.power(3)
        algebraic = (h_s * phi(0, x_d, P61)) % P61
        assert algebraic == 0


# ---------------------------------------------------------------------------
# Theorem 5: Overlapping back-reference hash
# ---------------------------------------------------------------------------

class TestTheorem5:
    """H(W) = H(P) · Φ(q, x^d) · x^r + H(P[0..r-1])."""

    def test_exact_repetition_no_remainder(self):
        """l is exact multiple of d: r = 0."""
        h = PolynomialHash(prime=P61, base=131)
        P = b"abc"  # d = 3
        l = 12       # q = 4, r = 0
        d = len(P)
        q, r = divmod(l, d)

        # Direct: hash the fully expanded string
        W = P * q
        direct = h.hash(W)

        # Algebraic
        h_p = h.hash(P)
        x_d = h.power(d)
        x_r = h.power(r)  # x^0 = 1
        algebraic = (h_p * phi(q, x_d, P61) % P61 * x_r + h.hash(b"")) % P61
        assert direct == algebraic

    def test_repetition_with_remainder(self):
        """l is not a multiple of d: r > 0."""
        h = PolynomialHash(prime=P61, base=131)
        P = b"abcd"  # d = 4
        l = 11        # q = 2, r = 3
        d = len(P)
        q, r = divmod(l, d)
        assert q == 2 and r == 3

        # Direct
        W = (P * q) + P[:r]  # "abcdabcdabc"
        direct = h.hash(W)

        # Algebraic (Theorem 5)
        h_p = h.hash(P)
        h_prefix = h.hash(P[:r])
        x_d = h.power(d)
        x_r = h.power(r)
        algebraic = (h_p * phi(q, x_d, P61) % P61 * x_r % P61 + h_prefix) % P61
        assert direct == algebraic

    def test_single_byte_run_length(self):
        """RLE case: d=1, pattern is single byte."""
        h = PolynomialHash(prime=P61, base=131)
        P = b"\x42"  # d = 1
        l = 1000
        d = 1
        q, r = divmod(l, d)  # q = 1000, r = 0

        direct = h.hash(P * l)

        h_p = h.hash(P)
        x_d = h.power(d)
        algebraic = (h_p * phi(q, x_d, P61)) % P61
        assert direct == algebraic

    def test_various_patterns_and_lengths(self):
        """Sweep over multiple pattern sizes and repetition lengths."""
        h = PolynomialHash(prime=P61, base=131)
        import os
        for d in [1, 2, 3, 5, 8, 13]:
            P = os.urandom(d)
            for l in [d, d + 1, 2 * d, 2 * d + 1, 5 * d, 5 * d + 3]:
                q, r = divmod(l, d)
                W = (P * q) + P[:r]
                direct = h.hash(W)

                h_p = h.hash(P)
                h_prefix = h.hash(P[:r]) if r > 0 else 0
                x_d = h.power(d)
                x_r = h.power(r)
                algebraic = (h_p * phi(q, x_d, P61) % P61 * x_r % P61 + h_prefix) % P61
                assert direct == algebraic, f"Failed: d={d}, l={l}, q={q}, r={r}"


# ---------------------------------------------------------------------------
# Power computation (Lemma 13)
# ---------------------------------------------------------------------------

class TestPowerComputation:
    """x^n computed via repeated squaring."""

    def test_power_zero(self):
        h = PolynomialHash(prime=P61, base=131)
        assert h.power(0) == 1

    def test_power_one(self):
        h = PolynomialHash(prime=P61, base=131)
        assert h.power(1) == 131

    def test_power_matches_builtin(self):
        h = PolynomialHash(prime=P61, base=131)
        for n in [2, 3, 10, 50, 100, 1000]:
            assert h.power(n) == pow(131, n, P61)
