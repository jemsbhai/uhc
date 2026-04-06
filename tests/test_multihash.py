"""
Tests for the k-tuple multi-hash extension.

Maps to:
- Theorem 20: k-wise collision bound — Pr[collision] ≤ (N/p)^k
- Theorem 21: k-hash rope correctness — all k components maintained independently
- Corollary 5: Concrete security parameters

TDD: these tests are written BEFORE the implementation.
"""

from __future__ import annotations

import pytest

from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61, phi, mersenne_mul
from uhc.core.lz77 import Literal, Reference, lz77_decode, lz77_encode
from uhc.core.rope import (
    Leaf,
    rope_concat,
    rope_split,
    rope_repeat,
    rope_len,
    rope_hash,
    Node,
)
from uhc.core.compressed_verifier import (
    compressed_domain_hash,
    CDHMethod,
    SlidingRopeState,
)


# ===================================================================
# Fixtures
# ===================================================================

BASES_K2 = [131, 257]
BASES_K3 = [131, 257, 509]


@pytest.fixture
def h_single():
    """Single-base hash (existing behavior)."""
    return PolynomialHash(base=131)


@pytest.fixture
def hashes_k2():
    """Two independent PolynomialHash instances for k=2."""
    return [PolynomialHash(base=b) for b in BASES_K2]


@pytest.fixture
def hashes_k3():
    """Three independent PolynomialHash instances for k=3."""
    return [PolynomialHash(base=b) for b in BASES_K3]


# ===================================================================
# Part A: MultiHash — k-tuple polynomial hash (Theorem 21 foundation)
# ===================================================================


class TestMultiHash:
    """Tests for MultiHash: a k-tuple wrapper over PolynomialHash."""

    def test_empty_string_returns_k_zeros(self):
        """H^(k)(ε) = (0, 0, ..., 0) by Definition 2."""
        from uhc.core.multihash import MultiHash

        mh = MultiHash(bases=BASES_K2)
        result = mh.hash(b"")
        assert result == (0, 0)

    def test_single_byte_returns_k_tuple(self):
        """Each component is an independent hash of the same byte."""
        from uhc.core.multihash import MultiHash

        mh = MultiHash(bases=BASES_K2)
        result = mh.hash(b"\x41")  # 'A' = 65
        # Each component: (65 + 1) = 66
        assert result == (66, 66)

    def test_multibyte_matches_independent_hashes(self, hashes_k2):
        """H^(k)(s)[i] = H_{x_i}(s) for each i (Theorem 21)."""
        from uhc.core.multihash import MultiHash

        data = b"hello world"
        mh = MultiHash(bases=BASES_K2)
        result = mh.hash(data)

        for i, h in enumerate(hashes_k2):
            assert result[i] == h.hash(data), f"Component {i} mismatch"

    def test_k3_matches_independent(self, hashes_k3):
        """Same test with k=3."""
        from uhc.core.multihash import MultiHash

        data = b"\x00\xff\x80\x01"
        mh = MultiHash(bases=BASES_K3)
        result = mh.hash(data)

        for i, h in enumerate(hashes_k3):
            assert result[i] == h.hash(data)

    def test_hash_concat_theorem1(self, hashes_k2):
        """H^(k)(A‖B) = H^(k)(A)·x^|B| + H^(k)(B) component-wise (Theorem 1)."""
        from uhc.core.multihash import MultiHash

        a, b = b"hello", b" world"
        mh = MultiHash(bases=BASES_K2)

        h_a = mh.hash(a)
        h_b = mh.hash(b)
        h_ab = mh.hash(a + b)
        h_composed = mh.hash_concat(h_a, len(b), h_b)

        assert h_composed == h_ab

    def test_hash_repeat_theorem2(self, hashes_k2):
        """H^(k)(S^q) = H^(k)(S)·Φ(q, x^d) component-wise (Theorem 2)."""
        from uhc.core.multihash import MultiHash

        s = b"abc"
        q = 7
        mh = MultiHash(bases=BASES_K2)

        h_s = mh.hash(s)
        h_sq = mh.hash(s * q)
        h_repeated = mh.hash_repeat(h_s, len(s), q)

        assert h_repeated == h_sq

    def test_hash_overlap_theorem5(self, hashes_k2):
        """Overlapping back-reference hash (Theorem 5) — k-tuple version."""
        from uhc.core.multihash import MultiHash

        pattern = b"ab"
        d = len(pattern)
        l = 7  # 3 full copies + 1 remainder byte
        expected = (pattern * 4)[:l]  # "abababa"
        mh = MultiHash(bases=BASES_K2)

        h_p = mh.hash(pattern)
        r = l % d  # 1
        h_prefix = mh.hash(pattern[:r])
        h_overlap = mh.hash_overlap(h_p, d, l, h_prefix)
        h_expected = mh.hash(expected)

        assert h_overlap == h_expected

    def test_k1_degenerates_to_single(self, h_single):
        """k=1 MultiHash should match the single PolynomialHash."""
        from uhc.core.multihash import MultiHash

        data = b"test data 12345"
        mh = MultiHash(bases=[131])
        result = mh.hash(data)

        assert result == (h_single.hash(data),)

    def test_bases_must_be_nonempty(self):
        """k=0 is invalid."""
        from uhc.core.multihash import MultiHash

        with pytest.raises(ValueError):
            MultiHash(bases=[])


# ===================================================================
# Part B: k-tuple CDH verifier (Theorem 12 + Theorem 21)
# ===================================================================


class TestMultiHashCDH:
    """CDH with k-tuple hashing produces correct k-tuple results."""

    def test_all_literals(self):
        """CDH^(k) on all-literal stream equals H^(k)(data)."""
        from uhc.core.multihash import MultiHash, multi_cdh

        data = b"hello"
        tokens = [Literal(b) for b in data]
        mh = MultiHash(bases=BASES_K2)

        result = multi_cdh(tokens, mh)
        expected = mh.hash(data)
        assert result == expected

    def test_nonoverlapping_ref(self):
        """CDH^(k) with non-overlapping back-reference."""
        from uhc.core.multihash import MultiHash, multi_cdh

        # "abcabc" = Lit(a), Lit(b), Lit(c), Ref(3, 3)
        tokens = [Literal(97), Literal(98), Literal(99), Reference(3, 3)]
        mh = MultiHash(bases=BASES_K2)

        decoded = lz77_decode(tokens)
        assert decoded == b"abcabc"

        result = multi_cdh(tokens, mh)
        expected = mh.hash(decoded)
        assert result == expected

    def test_overlapping_ref(self):
        """CDH^(k) with overlapping back-reference (Theorem 5)."""
        from uhc.core.multihash import MultiHash, multi_cdh

        # "aaaaaa" = Lit(a), Ref(1, 5)
        tokens = [Literal(97), Reference(1, 5)]
        mh = MultiHash(bases=BASES_K2)

        decoded = lz77_decode(tokens)
        assert decoded == b"aaaaaa"

        result = multi_cdh(tokens, mh)
        expected = mh.hash(decoded)
        assert result == expected

    def test_mixed_tokens_k3(self):
        """CDH^(k=3) on a mixed token stream."""
        from uhc.core.multihash import MultiHash, multi_cdh

        data = b"abcabcxyzxyzxyz"
        tokens = lz77_encode(data)
        decoded = lz77_decode(tokens)
        assert decoded == data

        mh = MultiHash(bases=BASES_K3)
        result = multi_cdh(tokens, mh)
        expected = mh.hash(data)
        assert result == expected

    def test_sliding_rope_k_tuple(self):
        """Sliding rope CDH^(k) matches unbounded CDH^(k)."""
        from uhc.core.multihash import MultiHash, multi_cdh, multi_cdh_sliding

        data = b"abcabcabcxyzxyz"
        tokens = lz77_encode(data)
        mh = MultiHash(bases=BASES_K2)

        result_rope = multi_cdh(tokens, mh)
        result_sliding = multi_cdh_sliding(tokens, mh, d_max=32768, m_max=258)

        assert result_rope == result_sliding
        assert result_rope == mh.hash(data)

    def test_roundtrip_encode_decode_multihash(self):
        """Full roundtrip: encode → CDH^(k) == H^(k)(original)."""
        from uhc.core.multihash import MultiHash, multi_cdh

        data = b"the quick brown fox jumps over the lazy dog" * 3
        tokens = lz77_encode(data)
        mh = MultiHash(bases=BASES_K2)

        result = multi_cdh(tokens, mh)
        expected = mh.hash(data)
        assert result == expected


# ===================================================================
# Part C: Independence verification (Theorem 20)
# ===================================================================


class TestIndependence:
    """Verify that k components are truly independent evaluations."""

    def test_different_bases_give_different_hashes(self):
        """For non-trivial data, distinct bases produce distinct hash values."""
        from uhc.core.multihash import MultiHash

        data = b"test independence"
        mh = MultiHash(bases=BASES_K2)
        result = mh.hash(data)

        assert result[0] != result[1], "Different bases should (almost certainly) give different hashes"

    def test_collision_in_one_component_not_all(self):
        """
        Theorem 20: collision requires ALL k components to collide.
        """
        from uhc.core.multihash import MultiHash

        mh = MultiHash(bases=BASES_K3)
        a = b"collision test A"
        b_data = b"collision test B"

        h_a = mh.hash(a)
        h_b = mh.hash(b_data)

        for i in range(3):
            assert h_a[i] != h_b[i], f"Component {i} collided — astronomically unlikely"

    def test_k_tuple_equality_iff_all_match(self):
        """k-tuple comparison: equal iff ALL components equal."""
        from uhc.core.multihash import MultiHash

        mh = MultiHash(bases=BASES_K2)
        data = b"same data"

        h1 = mh.hash(data)
        h2 = mh.hash(data)
        assert h1 == h2

        h3 = mh.hash(b"different")
        assert h1 != h3


# ===================================================================
# Part D: Backward compatibility
# ===================================================================


class TestBackwardCompatibility:
    """Ensure existing single-hash API still works unchanged."""

    def test_existing_cdh_unchanged(self):
        """compressed_domain_hash() with default args still returns int."""
        data = b"backward compat"
        tokens = lz77_encode(data)
        h = PolynomialHash(base=131)

        result = compressed_domain_hash(tokens, base=131)
        expected = h.hash(data)
        assert result == expected
        assert isinstance(result, int)

    def test_existing_rope_unchanged(self):
        """Leaf/Internal/RepeatNode still work with single hash_val."""
        h = PolynomialHash(base=131)
        leaf = Leaf(b"test", h)
        assert isinstance(leaf.hash_val, int)

    def test_existing_sliding_rope_unchanged(self):
        """SlidingRopeState still works with single hash."""
        data = b"test sliding"
        tokens = lz77_encode(data)
        h = PolynomialHash(base=131)

        state = SlidingRopeState(base=131, d_max=100, m_max=50)
        for tok in tokens:
            state.process_token(tok)
        result = state.final_hash()

        assert result == h.hash(data)
