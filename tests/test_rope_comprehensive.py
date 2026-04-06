"""
Comprehensive rope tests ensuring mathematical rigor.

Focuses on:
- Randomized property-based testing (many inputs)
- Split-concat roundtrip identity
- Rope-based CDH = H(T) (Theorem 12 via rope)
- Nested RepeatNodes
- SubstrHash cross-validated against split
- Balance invariant under stress
- Edge cases: single byte, large patterns, degenerate reps
"""

import random
import pytest

from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61, phi, mersenne_mul
from uhc.core.lz77 import Literal, Reference, lz77_decode, lz77_encode
from uhc.core.rope import (
    Leaf,
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


@pytest.fixture
def h():
    return PolynomialHash(prime=MERSENNE_61, base=131)


# ── Property: split-concat roundtrip is identity (Theorems 6+7) ──────


class TestSplitConcatIdentity:
    """For any rope R and position pos: concat(split(R, pos)) represents same string."""

    def test_leaf_all_positions(self, h):
        data = b"abcdefgh"
        node = rope_from_bytes(data, h)
        for pos in range(len(data) + 1):
            left, right = rope_split(node, pos, h)
            rejoined = rope_concat(left, right, h)
            assert rope_hash(rejoined) == h.hash(data) if rejoined else pos == 0 or pos == len(data)
            if rejoined:
                assert rope_to_bytes(rejoined) == data

    def test_complex_tree_all_positions(self, h):
        """Build a complex tree, split-rejoin at every position."""
        a = rope_from_bytes(b"abc", h)
        b = rope_repeat(rope_from_bytes(b"xy", h), 3, h)  # "xyxyxy"
        c = rope_from_bytes(b"Z", h)
        tree = rope_concat(rope_concat(a, b, h), c, h)  # "abcxyxyxyZ"
        full = b"abcxyxyxyZ"
        assert rope_to_bytes(tree) == full
        for pos in range(len(full) + 1):
            left, right = rope_split(tree, pos, h)
            rejoined = rope_concat(left, right, h)
            if rejoined:
                assert rope_hash(rejoined) == h.hash(full), f"Failed at pos={pos}"
                assert rope_to_bytes(rejoined) == full


# ── Property: randomized hash correctness ────────────────────────────


class TestRandomizedCorrectness:
    """Randomized tests: build ropes many ways, hash must always match."""

    @pytest.mark.parametrize("seed", range(20))
    def test_random_concat_sequence(self, h, seed):
        """Concat random-length chunks; hash must equal H(full)."""
        rng = random.Random(seed)
        data = bytes(rng.randint(0, 255) for _ in range(rng.randint(10, 200)))
        node = None
        pos = 0
        while pos < len(data):
            chunk_len = rng.randint(1, min(20, len(data) - pos))
            chunk = rope_from_bytes(data[pos:pos + chunk_len], h)
            node = rope_concat(node, chunk, h)
            pos += chunk_len
        assert rope_hash(node) == h.hash(data)
        assert rope_to_bytes(node) == data

    @pytest.mark.parametrize("seed", range(10))
    def test_random_split_rejoin(self, h, seed):
        """Random data, random split point, rejoin must preserve hash."""
        rng = random.Random(seed + 100)
        data = bytes(rng.randint(0, 255) for _ in range(rng.randint(20, 150)))
        node = rope_from_bytes(data, h)
        pos = rng.randint(0, len(data))
        left, right = rope_split(node, pos, h)
        rejoined = rope_concat(left, right, h)
        if rejoined:
            assert rope_hash(rejoined) == h.hash(data)


# ── SubstrHash cross-validation against direct hash ──────────────────


class TestSubstrHashCrossValidation:
    """
    Theorem 9: SubstrHash must match H(substring) for all ranges.
    Cross-validate by computing H(data[a:a+l]) directly.
    """

    def test_all_substrings_small(self, h):
        """Exhaustive: every substring of a 15-byte string."""
        data = b"abcdefghijklmno"
        node = rope_from_bytes(data, h)
        for start in range(len(data)):
            for length in range(1, len(data) - start + 1):
                expected = h.hash(data[start:start + length])
                got = rope_substr_hash(node, start, length, h)
                assert got == expected, f"Failed at [{start}:{start+length}]"

    def test_substr_of_repeat_exhaustive(self, h):
        """Every substring of a repeated pattern."""
        pattern = b"abcd"
        reps = 4
        full = pattern * reps
        node = rope_repeat(rope_from_bytes(pattern, h), reps, h)
        for start in range(len(full)):
            for length in range(1, len(full) - start + 1):
                expected = h.hash(full[start:start + length])
                got = rope_substr_hash(node, start, length, h)
                assert got == expected, f"Failed at [{start}:{start+length}]"

    def test_substr_spanning_concat_boundary(self, h):
        """Substrings that cross Internal node boundaries."""
        a = rope_from_bytes(b"hello", h)
        b = rope_from_bytes(b"world", h)
        c = rope_concat(a, b, h)
        full = b"helloworld"
        for start in range(len(full)):
            for length in range(1, len(full) - start + 1):
                expected = h.hash(full[start:start + length])
                got = rope_substr_hash(c, start, length, h)
                assert got == expected


# ── Nested RepeatNodes ───────────────────────────────────────────────


class TestNestedRepeat:
    """RepeatNode whose child is itself a RepeatNode or contains one."""

    def test_repeat_of_repeat(self, h):
        """(S^3)^4 = S^12."""
        s = rope_from_bytes(b"ab", h)
        r1 = rope_repeat(s, 3, h)       # "ababab"
        r2 = rope_repeat(r1, 4, h)      # "ababab" * 4
        assert rope_len(r2) == 24
        assert rope_hash(r2) == h.hash(b"ab" * 12)
        assert rope_to_bytes(r2) == b"ab" * 12

    def test_repeat_of_concat_containing_repeat(self, h):
        """(A ‖ B^3)^2."""
        a = rope_from_bytes(b"X", h)
        b = rope_repeat(rope_from_bytes(b"yz", h), 3, h)  # "yzyzyz"
        c = rope_concat(a, b, h)  # "Xyzyzyz"
        d = rope_repeat(c, 2, h)  # "XyzyzyzXyzyzyz"
        expected = b"Xyzyzyz" * 2
        assert rope_to_bytes(d) == expected
        assert rope_hash(d) == h.hash(expected)

    def test_split_nested_repeat(self, h):
        """Split through nested repeat structure."""
        s = rope_from_bytes(b"abc", h)
        r = rope_repeat(rope_repeat(s, 3, h), 2, h)  # "abc"*3 repeated 2x = "abc"*6
        full = b"abc" * 6
        for pos in [1, 3, 5, 9, 12, 17]:
            left, right = rope_split(r, pos, h)
            if left:
                assert rope_hash(left) == h.hash(full[:pos]), f"left fail at {pos}"
            if right:
                assert rope_hash(right) == h.hash(full[pos:]), f"right fail at {pos}"

    def test_substr_hash_nested_repeat(self, h):
        """SubstrHash into nested repeat."""
        s = rope_from_bytes(b"mn", h)
        r = rope_repeat(rope_repeat(s, 4, h), 3, h)  # "mn"*12
        full = b"mn" * 12
        for start in range(0, 20, 3):
            for length in [1, 2, 3, 5]:
                if start + length <= len(full):
                    expected = h.hash(full[start:start + length])
                    got = rope_substr_hash(r, start, length, h)
                    assert got == expected


# ── Rope-based CDH = H(T): Theorem 12 via rope ──────────────────────


class TestRopeBasedCDH:
    """
    The ultimate test: process LZ77 tokens using the rope (not prefix
    hash array) and verify CDH(τ) = H(T).
    
    This is the code-level proof of Theorem 12 using the rope data
    structure from Part III.
    """

    def _cdh_via_rope(self, tokens, h):
        """
        Compute CDH using rope for all substring queries.
        Mirrors compressed_verifier but uses rope instead of prefix array.
        """
        rope = None
        p = h.prime

        for tok in tokens:
            if isinstance(tok, Literal):
                leaf = Leaf(bytes([tok.byte]), h)
                rope = rope_concat(rope, leaf, h)

            elif isinstance(tok, Reference):
                d, l = tok.distance, tok.length
                pos = rope_len(rope)

                if d >= l:
                    # Non-overlapping: extract source from rope
                    start = pos - d
                    h_source = rope_substr_hash(rope, start, l, h)
                    # Build the copied segment
                    _, tmp = rope_split(rope, start, h)
                    source, _ = rope_split(tmp, l, h)
                    rope = rope_concat(rope, source, h)
                else:
                    # Overlapping: extract pattern, repeat
                    start = pos - d
                    _, tmp = rope_split(rope, start, h)
                    pattern, _ = rope_split(tmp, d, h)

                    q, r = divmod(l, d)
                    rep = rope_repeat(pattern, q, h) if q >= 1 else None
                    if r > 0:
                        partial, _ = rope_split(pattern, r, h)
                        rep = rope_concat(rep, partial, h)
                    rope = rope_concat(rope, rep, h)

        return rope_hash(rope) if rope else 0

    def test_all_literals(self, h):
        tokens = [Literal(b) for b in b"hello"]
        decoded = lz77_decode(tokens)
        assert self._cdh_via_rope(tokens, h) == h.hash(decoded)

    def test_non_overlapping_ref(self, h):
        # "abcabc" = Lit(a), Lit(b), Lit(c), Ref(3,3)
        tokens = [Literal(97), Literal(98), Literal(99), Reference(3, 3)]
        decoded = lz77_decode(tokens)
        assert decoded == b"abcabc"
        assert self._cdh_via_rope(tokens, h) == h.hash(decoded)

    def test_overlapping_ref(self, h):
        # "aaaaaa" = Lit(a), Ref(1,5)
        tokens = [Literal(97), Reference(1, 5)]
        decoded = lz77_decode(tokens)
        assert decoded == b"aaaaaa"
        assert self._cdh_via_rope(tokens, h) == h.hash(decoded)

    def test_overlapping_pattern(self, h):
        # "abababab" = Lit(a), Lit(b), Ref(2,6)
        tokens = [Literal(97), Literal(98), Reference(2, 6)]
        decoded = lz77_decode(tokens)
        assert decoded == b"abababab"
        assert self._cdh_via_rope(tokens, h) == h.hash(decoded)

    def test_overlapping_partial_remainder(self, h):
        # "abcabcab" = Lit(a), Lit(b), Lit(c), Ref(3, 5)
        # q=1, r=2 → "abc" ‖ "ab"... wait, q=⌊5/3⌋=1, but Ref(3,5) with d=3,l=5
        # Actually with the rope CDH: pattern="abc", q=1, r=2
        # rep = repeat(pattern, 1) = pattern itself, then partial = "ab"
        # total appended = "abc" + "ab" = "abcab" (length 5) ✓
        tokens = [Literal(97), Literal(98), Literal(99), Reference(3, 5)]
        decoded = lz77_decode(tokens)
        assert decoded == b"abcabcab"
        assert self._cdh_via_rope(tokens, h) == h.hash(decoded)

    @pytest.mark.parametrize("seed", range(15))
    def test_random_encode_decode_cdh(self, h, seed):
        """Encode random data, verify rope CDH matches H(data)."""
        rng = random.Random(seed + 200)
        # Use data with repetition to trigger back-references
        base_data = bytes(rng.randint(0, 20) for _ in range(rng.randint(10, 60)))
        data = base_data * rng.randint(1, 3)  # repeat to create matches
        tokens = lz77_encode(data, min_match=3, max_match=258, window_size=32768)
        decoded = lz77_decode(tokens)
        assert decoded == data
        assert self._cdh_via_rope(tokens, h) == h.hash(data)

    def test_mixed_refs(self, h):
        """Stream with both overlapping and non-overlapping refs."""
        # "abcdabcdaaaa" = Lit(a,b,c,d), Ref(4,4), Ref(1,4)
        tokens = [
            Literal(97), Literal(98), Literal(99), Literal(100),
            Reference(4, 4),   # non-overlapping copy of "abcd"
            Reference(1, 4),   # overlapping: repeat last byte 4 times
        ]
        decoded = lz77_decode(tokens)
        assert decoded == b"abcdabcddddd"
        assert self._cdh_via_rope(tokens, h) == h.hash(decoded)


# ── Balance invariant under stress ───────────────────────────────────


class TestBalanceStress:
    """Invariant I8 must hold after extensive operations."""

    def test_200_sequential_concats(self, h):
        node = None
        for i in range(200):
            node = rope_concat(node, Leaf(bytes([i % 256]), h), h)
        validate_rope(node)

    def test_split_rejoin_preserves_balance(self, h):
        """Build, split at many points, rejoin — balance must hold."""
        node = None
        for i in range(80):
            node = rope_concat(node, Leaf(bytes([i % 256]), h), h)
        for pos in [1, 10, 25, 40, 60, 79]:
            left, right = rope_split(node, pos, h)
            rejoined = rope_concat(left, right, h)
            validate_rope(rejoined)

    def test_repeat_then_split_balanced(self, h):
        """Large repeat, split, check balance."""
        s = rope_from_bytes(b"abc", h)
        r = rope_repeat(s, 100, h)
        left, right = rope_split(r, 150, h)
        if left:
            validate_rope(left)
        if right:
            validate_rope(right)


# ── Edge cases ───────────────────────────────────────────────────────


class TestEdgeCases:
    def test_single_byte_repeat(self, h):
        s = rope_from_bytes(b"\x00", h)
        r = rope_repeat(s, 5, h)
        assert rope_to_bytes(r) == b"\x00" * 5
        assert rope_hash(r) == h.hash(b"\x00" * 5)

    def test_all_byte_values(self, h):
        """Every byte value 0-255 in a rope."""
        data = bytes(range(256))
        node = rope_from_bytes(data, h)
        assert rope_hash(node) == h.hash(data)

    def test_repeat_two(self, h):
        """Minimum repeat count = 2."""
        s = rope_from_bytes(b"Q", h)
        r = rope_repeat(s, 2, h)
        assert rope_hash(r) == h.hash(b"QQ")

    def test_substr_hash_length_one(self, h):
        """Single-byte substring queries."""
        data = b"abcdef"
        node = rope_from_bytes(data, h)
        for i, byte in enumerate(data):
            assert rope_substr_hash(node, i, 1, h) == h.hash(bytes([byte]))

    def test_split_single_byte_leaf(self, h):
        """Can't split a 1-byte leaf at pos=0 or pos=1 (boundary cases)."""
        leaf = Leaf(b"X", h)
        left, right = rope_split(leaf, 0, h)
        assert left is None
        assert rope_to_bytes(right) == b"X"
        left, right = rope_split(leaf, 1, h)
        assert rope_to_bytes(left) == b"X"
        assert right is None
