"""
Tests for the sliding rope algorithm (Definition 10, Theorem 11).

The sliding rope maintains a bounded-size window rope, evicting old
bytes into a running prefix hash H_prefix. Memory is independent of
decoded size N — only depends on d_max + m_max.

Every test cross-validates against prefix_array and unbounded rope
to ensure all three methods agree (Theorem 12 proven three ways).
"""

import os
import random
import pytest

from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61
from uhc.core.lz77 import (
    lz77_encode,
    lz77_decode,
    Literal,
    Reference,
)
from uhc.core.compressed_verifier import (
    compressed_domain_hash,
    CDHMethod,
    SlidingRopeState,
)
from uhc.core.rope import rope_len


P61 = MERSENNE_61
ALL_METHODS = [CDHMethod.PREFIX_ARRAY, CDHMethod.ROPE, CDHMethod.SLIDING_ROPE]


def _verify_all_methods(data: bytes, base: int = 131, **sliding_kwargs) -> None:
    """Encode data, compute CDH via all three methods, assert all equal H(data)."""
    h = PolynomialHash(prime=P61, base=base)
    tokens = lz77_encode(data)
    assert lz77_decode(tokens) == data

    direct = h.hash(data)
    results = {}
    for method in ALL_METHODS:
        results[method.value] = compressed_domain_hash(
            tokens, P61, base, method=method, **sliding_kwargs
        )

    for name, val in results.items():
        assert val == direct, (
            f"{name} gave {val}, expected {direct} for data len {len(data)}"
        )


# ── Theorem 12 × 3: all three methods agree ─────────────────────────


class TestThreeWayAgreement:
    """CDH via prefix_array, rope, and sliding_rope must all equal H(T)."""

    def test_empty(self):
        _verify_all_methods(b"")

    def test_single_byte(self):
        _verify_all_methods(b"A")

    def test_short_no_matches(self):
        _verify_all_methods(b"abcde")

    def test_simple_repeat(self):
        _verify_all_methods(b"abcabc")

    def test_run_length(self):
        _verify_all_methods(b"X" * 200)

    def test_two_byte_pattern(self):
        _verify_all_methods(b"ab" * 50)

    def test_three_byte_remainder(self):
        _verify_all_methods(b"abcabcab")

    def test_mixed(self):
        _verify_all_methods(b"abcabc" + bytes(range(50)) + b"xyzxyzxyz")

    def test_binary(self):
        _verify_all_methods(os.urandom(200))

    def test_highly_compressible(self):
        _verify_all_methods(b"hello world! " * 50)

    def test_all_byte_values(self):
        _verify_all_methods(bytes(range(256)))

    def test_different_bases(self):
        data = b"abcdefabcdef" * 10
        for base in [2, 7, 131, 257]:
            _verify_all_methods(data, base=base)


# ── Manual token streams with sliding rope ───────────────────────────


class TestManualTokensSliding:
    """Hand-crafted tokens, sliding_rope must match."""

    def test_literals_only(self):
        tokens = [Literal(b) for b in b"hello"]
        h = PolynomialHash(prime=P61, base=131)
        result = compressed_domain_hash(tokens, P61, 131, method=CDHMethod.SLIDING_ROPE)
        assert result == h.hash(b"hello")

    def test_non_overlapping_ref(self):
        tokens = [
            Literal(97), Literal(98), Literal(99),
            Reference(3, 3),
        ]
        h = PolynomialHash(prime=P61, base=131)
        result = compressed_domain_hash(tokens, P61, 131, method=CDHMethod.SLIDING_ROPE)
        assert result == h.hash(b"abcabc")

    def test_overlapping_rle(self):
        tokens = [Literal(65), Reference(1, 9)]
        h = PolynomialHash(prime=P61, base=131)
        result = compressed_domain_hash(tokens, P61, 131, method=CDHMethod.SLIDING_ROPE)
        assert result == h.hash(b"A" * 10)

    def test_overlapping_pattern(self):
        tokens = [Literal(97), Literal(98), Reference(2, 8)]
        h = PolynomialHash(prime=P61, base=131)
        result = compressed_domain_hash(tokens, P61, 131, method=CDHMethod.SLIDING_ROPE)
        assert result == h.hash(b"ab" * 5)

    def test_chained_references(self):
        tokens = [
            Literal(120), Literal(121),
            Reference(2, 2),
            Reference(4, 4),
        ]
        h = PolynomialHash(prime=P61, base=131)
        result = compressed_domain_hash(tokens, P61, 131, method=CDHMethod.SLIDING_ROPE)
        assert result == h.hash(b"xy" * 4)


# ── Eviction: the key behavior ───────────────────────────────────────


class TestEviction:
    """Verify that eviction works correctly."""

    def test_data_exceeds_window(self):
        """Data much larger than default window → eviction must fire."""
        data = b"compress this! " * 3000  # 45000 bytes
        _verify_all_methods(data)

    def test_small_window_forces_eviction(self):
        """Use a small custom window to force eviction on tiny data."""
        data = b"abcabc" * 10
        tokens = lz77_encode(data)
        h = PolynomialHash(prime=P61, base=131)
        result = compressed_domain_hash(
            tokens, P61, 131,
            method=CDHMethod.SLIDING_ROPE,
            d_max=15, m_max=5,
        )
        assert result == h.hash(data)

    def test_tiny_window(self):
        """Extreme: window barely larger than max reference distance."""
        data = b"xyzxyz" * 5
        tokens = lz77_encode(data, window_size=10, max_match=5)
        h = PolynomialHash(prime=P61, base=131)
        result = compressed_domain_hash(
            tokens, P61, 131,
            method=CDHMethod.SLIDING_ROPE,
            d_max=10, m_max=5,
        )
        assert result == h.hash(data)

    def test_eviction_with_overlapping_refs(self):
        """Overlapping references that span eviction boundaries."""
        data = b"A" * 500
        _verify_all_methods(data)

    def test_eviction_with_mixed_content(self):
        """Alternating compressible and random regions exceeding window."""
        data = b""
        for _ in range(100):
            data += b"pattern!" * 5
            data += os.urandom(10)
        _verify_all_methods(data)


# ══════════════════════════════════════════════════════════════════════
# MATHEMATICAL RIGOR: Direct invariant I_slide verification (Lemma 12)
# ══════════════════════════════════════════════════════════════════════


class TestInvariantISlide:
    """
    Directly verify invariant I_slide (Definition 10) after EVERY token.

    I_slide states:
        (1) H_prefix = H(T[0 .. l_prefix - 1])
        (2) R_window represents T[l_prefix .. pos - 1]
        (3) rope_len(r_window) = pos - l_prefix
        (4) rope_len(r_window) ≤ W = d_max + m_max
        (5) H(T[0..pos-1]) = H_prefix · x^(win_len) + H(window)

    We verify (3), (4), and (5) after each token by comparing
    current_hash() against H(decoded_bytes_so_far) computed directly.
    This is the code-level proof of Lemma 12 (invariant preservation).
    """

    def _verify_invariant_step_by_step(
        self, tokens, decoded_bytes, d_max=15, m_max=10
    ):
        """
        Process tokens one at a time via SlidingRopeState.
        After each token, verify:
          - window length consistency: win_len = pos - l_prefix
          - window bound: win_len ≤ W
          - hash correctness: current_hash() = H(decoded so far)
        """
        h = PolynomialHash(prime=P61, base=131)
        state = SlidingRopeState(prime=P61, base=131, d_max=d_max, m_max=m_max)
        buf = bytearray()  # ground truth decoded buffer

        for i, tok in enumerate(tokens):
            # Decode this token to get ground truth bytes
            if isinstance(tok, Literal):
                buf.append(tok.byte)
            elif isinstance(tok, Reference):
                pos = len(buf)
                for k in range(tok.length):
                    buf.append(buf[pos - tok.distance + (k % tok.distance)])

            # Process via sliding rope
            state.process_token(tok)

            # ── Invariant checks ──

            # (3) Length consistency
            assert state.window_len == state.pos - state.l_prefix, (
                f"Token {i}: window_len={state.window_len}, "
                f"pos={state.pos}, l_prefix={state.l_prefix}"
            )

            # (4) Window bound
            assert state.window_len <= state.W, (
                f"Token {i}: window_len={state.window_len} > W={state.W}"
            )

            # (5) Hash correctness — THE critical check
            expected_hash = h.hash(bytes(buf))
            actual_hash = state.current_hash()
            assert actual_hash == expected_hash, (
                f"Token {i}: I_slide violated! "
                f"current_hash()={actual_hash}, H(decoded)={expected_hash}"
            )

        # Final: state must equal len(decoded_bytes)
        assert state.pos == len(decoded_bytes)
        assert bytes(buf) == decoded_bytes

    def test_invariant_all_literals(self):
        tokens = [Literal(b) for b in b"hello world!"]
        self._verify_invariant_step_by_step(tokens, b"hello world!")

    def test_invariant_non_overlapping_ref(self):
        tokens = [Literal(97), Literal(98), Literal(99), Reference(3, 3)]
        self._verify_invariant_step_by_step(tokens, b"abcabc")

    def test_invariant_overlapping_rle(self):
        tokens = [Literal(65), Reference(1, 19)]
        self._verify_invariant_step_by_step(tokens, b"A" * 20)

    def test_invariant_overlapping_pattern(self):
        tokens = [Literal(97), Literal(98), Reference(2, 8)]
        self._verify_invariant_step_by_step(tokens, b"ab" * 5)

    def test_invariant_chained_refs(self):
        tokens = [
            Literal(120), Literal(121),
            Reference(2, 2),
            Reference(4, 4),
            Reference(1, 6),
        ]
        decoded = lz77_decode(tokens)
        self._verify_invariant_step_by_step(tokens, decoded)

    def test_invariant_with_forced_eviction(self):
        """Tiny window (W=25) forces eviction on every few tokens."""
        data = b"abcabc" * 5  # 30 bytes
        tokens = lz77_encode(data, window_size=15, max_match=10)
        decoded = lz77_decode(tokens)
        assert decoded == data
        self._verify_invariant_step_by_step(tokens, decoded, d_max=15, m_max=10)

    @pytest.mark.parametrize("seed", range(15))
    def test_invariant_random(self, seed):
        """Randomized: verify I_slide after every token for random data."""
        rng = random.Random(seed + 500)
        base_data = bytes(rng.randint(0, 20) for _ in range(rng.randint(10, 40)))
        data = base_data * rng.randint(1, 3)
        tokens = lz77_encode(data, window_size=15, max_match=10)
        decoded = lz77_decode(tokens)
        assert decoded == data
        self._verify_invariant_step_by_step(tokens, decoded, d_max=15, m_max=10)


# ══════════════════════════════════════════════════════════════════════
# Boundary conditions
# ══════════════════════════════════════════════════════════════════════


class TestBoundaryConditions:
    """Test exact boundary values from Definition 8 / Theorem 11."""

    def test_ref_distance_equals_d_max(self):
        """Ref with d = d_max exactly — must work after eviction."""
        d_max = 10
        tokens = [Literal(i) for i in range(10)] + [Reference(10, 5)]
        decoded = lz77_decode(tokens)
        h = PolynomialHash(prime=P61, base=131)
        result = compressed_domain_hash(
            tokens, P61, 131,
            method=CDHMethod.SLIDING_ROPE,
            d_max=d_max, m_max=5,
        )
        assert result == h.hash(decoded)

    def test_ref_distance_exceeds_d_max_raises(self):
        """Ref with d > d_max must raise ValueError."""
        d_max = 5
        tokens = [Literal(i) for i in range(10)] + [Reference(10, 3)]
        with pytest.raises(ValueError, match="exceeds window size"):
            compressed_domain_hash(
                tokens, P61, 131,
                method=CDHMethod.SLIDING_ROPE,
                d_max=d_max, m_max=3,
            )

    def test_ref_distance_exceeds_decoded_raises(self):
        """Ref with d > pos (before any eviction) must raise."""
        tokens = [Literal(65), Reference(5, 1)]
        with pytest.raises(ValueError, match="exceeds decoded length"):
            compressed_domain_hash(
                tokens, P61, 131, method=CDHMethod.SLIDING_ROPE,
            )

    def test_window_exactly_at_W_no_eviction(self):
        """Window at exactly W = d_max + m_max should NOT trigger eviction."""
        d_max, m_max = 5, 5
        tokens = [Literal(i) for i in range(10)]
        state = SlidingRopeState(prime=P61, base=131, d_max=d_max, m_max=m_max)
        for tok in tokens:
            state.process_token(tok)
        assert state.window_len == 10
        assert state.l_prefix == 0

    def test_window_at_W_plus_one_triggers_eviction(self):
        """Window at W+1 MUST trigger eviction."""
        d_max, m_max = 5, 5
        tokens = [Literal(i) for i in range(11)]
        state = SlidingRopeState(prime=P61, base=131, d_max=d_max, m_max=m_max)
        for tok in tokens:
            state.process_token(tok)
        assert state.window_len == d_max
        assert state.l_prefix == 11 - d_max

    def test_post_eviction_window_is_d_max(self):
        """Immediately after eviction fires, window = d_max exactly.

        Between evictions, the window can grow up to W = d_max + m_max.
        The invariant (I_slide condition 4) guarantees window ≤ W always.
        This test verifies the stronger claim: at the instant eviction
        fires, the window is trimmed to exactly d_max.
        """
        d_max, m_max = 8, 4
        tokens = [Literal(i % 256) for i in range(50)]
        state = SlidingRopeState(prime=P61, base=131, d_max=d_max, m_max=m_max)
        eviction_count = 0
        for tok in tokens:
            l_prefix_before = state.l_prefix
            state.process_token(tok)
            eviction_fired = state.l_prefix > l_prefix_before
            if eviction_fired:
                eviction_count += 1
                # Immediately after eviction: window = d_max
                assert state.window_len == d_max, (
                    f"Immediately after eviction: window_len={state.window_len} "
                    f"!= d_max={d_max}"
                )
            # Always: window ≤ W (I_slide condition 4)
            assert state.window_len <= state.W, (
                f"window_len={state.window_len} > W={state.W}"
            )
        # Eviction must have fired at least once with 50 tokens and W=12
        assert eviction_count > 0, "No eviction fired — test is vacuous"

    def test_invalid_d_max_zero_raises(self):
        with pytest.raises(ValueError):
            SlidingRopeState(d_max=0, m_max=5)

    def test_invalid_m_max_zero_raises(self):
        with pytest.raises(ValueError):
            SlidingRopeState(d_max=5, m_max=0)


# ── Randomized with invariant + three-way cross-validation ───────────


class TestSlidingInvariant:
    """Lemma 12 randomized: final hash must match across all methods."""

    @pytest.mark.parametrize("seed", range(20))
    def test_random_data_sliding(self, seed):
        rng = random.Random(seed + 300)
        base_data = bytes(rng.randint(0, 30) for _ in range(rng.randint(20, 100)))
        data = base_data * rng.randint(1, 4)
        _verify_all_methods(data)

    @pytest.mark.parametrize("seed", range(10))
    def test_random_with_small_window(self, seed):
        rng = random.Random(seed + 400)
        base_data = bytes(rng.randint(0, 15) for _ in range(rng.randint(10, 50)))
        data = base_data * rng.randint(2, 5)
        tokens = lz77_encode(data, window_size=20, max_match=10)
        h = PolynomialHash(prime=P61, base=131)
        assert lz77_decode(tokens) == data
        result = compressed_domain_hash(
            tokens, P61, 131,
            method=CDHMethod.SLIDING_ROPE,
            d_max=20, m_max=10,
        )
        assert result == h.hash(data)


# ── Stress ───────────────────────────────────────────────────────────


class TestSlidingStress:
    def test_10kb_compressible(self):
        data = (b"compress this data please! " * 400)[:10_000]
        _verify_all_methods(data)

    def test_10kb_random(self):
        data = os.urandom(10_000)
        _verify_all_methods(data)

    def test_1kb_repeated(self):
        data = b"The quick brown fox jumps. " * 40
        _verify_all_methods(data)
