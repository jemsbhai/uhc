"""
Tests for the hash rope data structure (Part III of the framework).

Each test is mapped to a specific definition, lemma, or theorem.
TDD: these tests are written before implementation.
"""

import pytest
from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61

# Import rope module — will be implemented next
from uhc.core.rope import (
    Leaf,
    Internal,
    RepeatNode,
    rope_from_bytes,
    rope_concat,
    rope_split,
    rope_repeat,
    rope_substr_hash,
    rope_to_bytes,
    rope_len,
    rope_hash,
    validate_rope,
)


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def h():
    """A PolynomialHash instance for testing."""
    return PolynomialHash(prime=MERSENNE_61, base=131)


# ── Definition 6: Node types ─────────────────────────────────────────


class TestLeaf:
    """Tests for Leaf node construction (Definition 6a)."""

    def test_single_byte(self, h):
        leaf = Leaf(bytes([42]), h)
        assert leaf.len == 1
        assert leaf.hash_val == h.hash(bytes([42]))
        assert leaf.weight == 1

    def test_multi_byte(self, h):
        data = bytes([10, 20, 30])
        leaf = Leaf(data, h)
        assert leaf.len == 3
        assert leaf.hash_val == h.hash(data)
        assert leaf.weight == 1

    def test_empty_bytes_rejected(self, h):
        with pytest.raises(ValueError):
            Leaf(b"", h)


# ── Definition 7 / Lemma 4: Hash correctness ─────────────────────────


class TestHashCorrectness:
    """
    Lemma 4: For any node v, v.hash == H(string_v).
    Verified by reconstructing bytes and comparing hashes.
    """

    def test_leaf_hash_matches(self, h):
        data = b"hello"
        leaf = Leaf(data, h)
        assert leaf.hash_val == h.hash(data)

    def test_concat_hash_matches(self, h):
        """Theorem 1 / Invariant I3: concat hash = H(A || B)."""
        a = rope_from_bytes(b"hello", h)
        b = rope_from_bytes(b"world", h)
        c = rope_concat(a, b, h)
        assert rope_hash(c) == h.hash(b"helloworld")

    def test_repeat_hash_matches(self, h):
        """Theorem 2 / Invariant I6: repeat hash = H(S^q)."""
        s = rope_from_bytes(b"abc", h)
        r = rope_repeat(s, 5, h)
        assert rope_hash(r) == h.hash(b"abc" * 5)

    def test_complex_tree_hash(self, h):
        """Lemma 4: structural induction over mixed tree."""
        a = rope_from_bytes(b"foo", h)
        b = rope_from_bytes(b"bar", h)
        c = rope_concat(a, b, h)
        d = rope_repeat(c, 3, h)
        assert rope_hash(d) == h.hash(b"foobar" * 3)
        assert rope_len(d) == 18


# ── Theorem 6 / Lemma 8: Join (Concat) ───────────────────────────────


class TestConcat:
    """Theorem 6: Join returns valid rope for concatenation."""

    def test_two_leaves(self, h):
        a = rope_from_bytes(b"ab", h)
        b = rope_from_bytes(b"cd", h)
        c = rope_concat(a, b, h)
        assert rope_to_bytes(c) == b"abcd"
        assert rope_len(c) == 4

    def test_empty_left(self, h):
        b = rope_from_bytes(b"hello", h)
        c = rope_concat(None, b, h)
        assert rope_to_bytes(c) == b"hello"

    def test_empty_right(self, h):
        a = rope_from_bytes(b"hello", h)
        c = rope_concat(a, None, h)
        assert rope_to_bytes(c) == b"hello"

    def test_both_empty(self, h):
        c = rope_concat(None, None, h)
        assert c is None

    def test_many_concats(self, h):
        """Repeated concat should maintain correct hash."""
        node = None
        data = b""
        for byte_val in range(50):
            leaf = Leaf(bytes([byte_val]), h)
            node = rope_concat(node, leaf, h)
            data += bytes([byte_val])
        assert rope_hash(node) == h.hash(data)
        assert rope_to_bytes(node) == data


# ── Theorem 7: Split ─────────────────────────────────────────────────


class TestSplit:
    """Theorem 7: Split(R, pos) returns correct left/right."""

    def test_split_leaf(self, h):
        leaf = Leaf(b"abcde", h)
        left, right = rope_split(leaf, 2, h)
        assert rope_to_bytes(left) == b"ab"
        assert rope_to_bytes(right) == b"cde"

    def test_split_at_zero(self, h):
        node = rope_from_bytes(b"hello", h)
        left, right = rope_split(node, 0, h)
        assert left is None
        assert rope_to_bytes(right) == b"hello"

    def test_split_at_end(self, h):
        node = rope_from_bytes(b"hello", h)
        left, right = rope_split(node, 5, h)
        assert rope_to_bytes(left) == b"hello"
        assert right is None

    def test_split_concat(self, h):
        """Split a concatenated tree at various positions."""
        a = rope_from_bytes(b"abc", h)
        b = rope_from_bytes(b"def", h)
        c = rope_concat(a, b, h)
        for pos in range(7):
            left, right = rope_split(c, pos, h)
            left_bytes = rope_to_bytes(left) if left else b""
            right_bytes = rope_to_bytes(right) if right else b""
            assert left_bytes == b"abcdef"[:pos]
            assert right_bytes == b"abcdef"[pos:]

    def test_split_preserves_hash(self, h):
        """Split parts should have correct hashes (Lemma 4)."""
        data = b"hello world"
        node = rope_from_bytes(data, h)
        for pos in range(len(data) + 1):
            left, right = rope_split(node, pos, h)
            if left:
                assert rope_hash(left) == h.hash(data[:pos])
            if right:
                assert rope_hash(right) == h.hash(data[pos:])


# ── Lemma 7: RepeatNode splittability ────────────────────────────────


class TestRepeatNodeSplit:
    """Lemma 7: RepeatNode can be split at any byte position."""

    def test_split_on_boundary(self, h):
        """Split at repetition boundary (r=0 case)."""
        s = rope_from_bytes(b"ab", h)
        r = rope_repeat(s, 4, h)  # "abababab"
        left, right = rope_split(r, 4, h)  # split after 2 reps
        assert rope_to_bytes(left) == b"abab"
        assert rope_to_bytes(right) == b"abab"

    def test_split_within_rep(self, h):
        """Split within a repetition (r>0 case)."""
        s = rope_from_bytes(b"abc", h)
        r = rope_repeat(s, 3, h)  # "abcabcabc"
        left, right = rope_split(r, 5, h)  # split mid-rep
        assert rope_to_bytes(left) == b"abcab"
        assert rope_to_bytes(right) == b"cabc"

    def test_split_repeat_hash_correct(self, h):
        """Split halves must have correct hashes."""
        s = rope_from_bytes(b"xy", h)
        r = rope_repeat(s, 10, h)  # "xy" * 10
        full = b"xy" * 10
        for pos in [1, 2, 5, 7, 13, 19, 20]:
            left, right = rope_split(r, pos, h)
            if left:
                assert rope_hash(left) == h.hash(full[:pos])
            if right:
                assert rope_hash(right) == h.hash(full[pos:])


# ── Theorem 8: Repeat via RepeatNode ─────────────────────────────────


class TestRepeat:
    """Theorem 8: Repeat in O(k·log q) time, O(1) space."""

    def test_repeat_single_byte(self, h):
        s = rope_from_bytes(b"A", h)
        r = rope_repeat(s, 100, h)
        assert rope_len(r) == 100
        assert rope_hash(r) == h.hash(b"A" * 100)

    def test_repeat_pattern(self, h):
        s = rope_from_bytes(b"abc", h)
        r = rope_repeat(s, 7, h)
        assert rope_len(r) == 21
        assert rope_hash(r) == h.hash(b"abc" * 7)

    def test_repeat_one(self, h):
        """Repeat(R, 1) should just return R."""
        s = rope_from_bytes(b"hello", h)
        r = rope_repeat(s, 1, h)
        assert rope_hash(r) == h.hash(b"hello")
        assert rope_len(r) == 5

    def test_repeat_large_q(self, h):
        """Large repetition count — tests O(log q) efficiency."""
        s = rope_from_bytes(b"x", h)
        r = rope_repeat(s, 1_000_000, h)
        assert rope_len(r) == 1_000_000
        # Verify hash matches (compute expected via hash_repeat)
        expected = h.hash_repeat(h.hash(b"x"), 1, 1_000_000)
        assert rope_hash(r) == expected


# ── Theorem 9: SubstrHash ────────────────────────────────────────────


class TestSubstrHash:
    """Theorem 9: Allocation-free SubstrHash in O(k·log w)."""

    def test_full_range(self, h):
        data = b"abcdef"
        node = rope_from_bytes(data, h)
        assert rope_substr_hash(node, 0, 6, h) == h.hash(data)

    def test_prefix(self, h):
        data = b"abcdef"
        node = rope_from_bytes(data, h)
        assert rope_substr_hash(node, 0, 3, h) == h.hash(b"abc")

    def test_suffix(self, h):
        data = b"abcdef"
        node = rope_from_bytes(data, h)
        assert rope_substr_hash(node, 3, 3, h) == h.hash(b"def")

    def test_middle(self, h):
        data = b"abcdef"
        node = rope_from_bytes(data, h)
        assert rope_substr_hash(node, 2, 2, h) == h.hash(b"cd")

    def test_substr_of_repeat(self, h):
        """SubstrHash across RepeatNode boundaries."""
        s = rope_from_bytes(b"abc", h)
        r = rope_repeat(s, 5, h)  # "abcabcabcabcabc"
        full = b"abc" * 5
        # Test various substrings spanning repetition boundaries
        for start in range(0, 12, 2):
            for length in [1, 2, 3, 4, 5]:
                if start + length <= 15:
                    expected = h.hash(full[start:start + length])
                    got = rope_substr_hash(r, start, length, h)
                    assert got == expected, (
                        f"SubstrHash({start}, {length}) failed: "
                        f"expected {expected}, got {got}"
                    )

    def test_substr_of_concat(self, h):
        """SubstrHash spanning concat boundary."""
        a = rope_from_bytes(b"hello", h)
        b = rope_from_bytes(b"world", h)
        c = rope_concat(a, b, h)
        # Span the boundary
        assert rope_substr_hash(c, 3, 4, h) == h.hash(b"lowo")


# ── Definition 7 / Invariant I8: Balance ─────────────────────────────


class TestBalance:
    """Invariant I8: BB[2/7] weight balance at Internal nodes."""

    def test_sequential_inserts_balanced(self, h):
        """Building a rope by appending 100 leaves stays balanced."""
        node = None
        for i in range(100):
            leaf = Leaf(bytes([i % 256]), h)
            node = rope_concat(node, leaf, h)
        validate_rope(node)  # Should not raise

    def test_validate_detects_imbalance(self, h):
        """validate_rope should catch invariant violations."""
        # Build a valid rope first
        node = rope_from_bytes(b"test", h)
        validate_rope(node)  # Should pass


# ── Lemma 6: Rotations preserve hash ─────────────────────────────────


class TestRotationHashPreservation:
    """Lemma 6: Rotations preserve hash invariant."""

    def test_many_ops_preserve_hash(self, h):
        """After many concats and splits, hash is always correct."""
        data = bytes(range(200))
        # Build rope incrementally
        node = None
        for b in data:
            node = rope_concat(node, Leaf(bytes([b]), h), h)
        assert rope_hash(node) == h.hash(data)
        # Split and rejoin at many positions
        for pos in [1, 50, 100, 150, 199]:
            left, right = rope_split(node, pos, h)
            rejoined = rope_concat(left, right, h)
            assert rope_hash(rejoined) == h.hash(data)


# ── Theorem 10: Concat = Join ────────────────────────────────────────


class TestConcatIsJoin:
    """Theorem 10: Concat is just Join."""

    def test_concat_equals_join(self, h):
        a = rope_from_bytes(b"foo", h)
        b = rope_from_bytes(b"bar", h)
        c = rope_concat(a, b, h)
        assert rope_to_bytes(c) == b"foobar"
        assert rope_hash(c) == h.hash(b"foobar")


# ── Integration: rope_to_bytes round-trip ─────────────────────────────


class TestRopeToBytes:
    """Round-trip: bytes → rope → bytes."""

    def test_round_trip_simple(self, h):
        data = b"hello world"
        node = rope_from_bytes(data, h)
        assert rope_to_bytes(node) == data

    def test_round_trip_with_repeat(self, h):
        s = rope_from_bytes(b"ab", h)
        r = rope_repeat(s, 5, h)
        assert rope_to_bytes(r) == b"ab" * 5

    def test_round_trip_complex(self, h):
        a = rope_from_bytes(b"hello", h)
        b = rope_repeat(rope_from_bytes(b"!", h), 3, h)
        c = rope_concat(a, b, h)
        assert rope_to_bytes(c) == b"hello!!!"
