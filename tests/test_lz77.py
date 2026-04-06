"""
Tests for uhc.core.lz77

Tests cover Definition 4 (LZ77 Token Stream), Definition 5 (LZ77 Decoding),
Theorem 4 (Overlapping Back-Reference Decomposition), and the naive encoder.
"""

import pytest

from uhc.core.lz77 import (
    Literal,
    Reference,
    lz77_encode,
    lz77_decode,
)


# ---------------------------------------------------------------------------
# Definition 4: Token types
# ---------------------------------------------------------------------------

class TestTokenTypes:
    """Lit(c) and Ref(d, l) are well-formed."""

    def test_literal_stores_byte(self):
        tok = Literal(65)
        assert tok.byte == 65

    def test_literal_rejects_out_of_range(self):
        with pytest.raises(ValueError):
            Literal(256)
        with pytest.raises(ValueError):
            Literal(-1)

    def test_reference_stores_distance_length(self):
        tok = Reference(distance=5, length=3)
        assert tok.distance == 5
        assert tok.length == 3

    def test_reference_rejects_zero_distance(self):
        with pytest.raises(ValueError):
            Reference(distance=0, length=3)

    def test_reference_rejects_zero_length(self):
        with pytest.raises(ValueError):
            Reference(distance=3, length=0)


# ---------------------------------------------------------------------------
# Definition 5: LZ77 Decoding — non-overlapping
# ---------------------------------------------------------------------------

class TestDecodeNonOverlapping:
    """Decode tokens where d >= l (simple copy)."""

    def test_literals_only(self):
        tokens = [Literal(b) for b in b"hello"]
        assert lz77_decode(tokens) == b"hello"

    def test_single_backreference(self):
        """'abcabc' = Lit(a,b,c) + Ref(3,3)."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=3),
        ]
        assert lz77_decode(tokens) == b"abcabc"

    def test_backreference_partial(self):
        """'abcab' = Lit(a,b,c) + Ref(3,2)."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=2),
        ]
        assert lz77_decode(tokens) == b"abcab"

    def test_empty_stream(self):
        assert lz77_decode([]) == b""

    def test_multiple_references(self):
        """'abcabcabc' = Lit(a,b,c) + Ref(3,3) + Ref(6,3)."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=3),
            Reference(distance=6, length=3),
        ]
        assert lz77_decode(tokens) == b"abcabcabc"

    def test_reference_validity_check(self):
        """Ref(d, l) at pos requires d <= pos."""
        tokens = [
            Literal(ord("a")),
            Reference(distance=5, length=1),  # d=5 but pos=1
        ]
        with pytest.raises(ValueError, match="distance"):
            lz77_decode(tokens)


# ---------------------------------------------------------------------------
# Definition 5 + Theorem 4: Overlapping back-references
# ---------------------------------------------------------------------------

class TestDecodeOverlapping:
    """Decode tokens where d < l (repeating pattern)."""

    def test_single_byte_rle(self):
        """'AAAA' = Lit(A) + Ref(1, 3) — run-length encoding."""
        tokens = [
            Literal(ord("A")),
            Reference(distance=1, length=3),
        ]
        assert lz77_decode(tokens) == b"AAAA"

    def test_two_byte_pattern(self):
        """'ababab' = Lit(a,b) + Ref(2, 4)."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")),
            Reference(distance=2, length=4),
        ]
        assert lz77_decode(tokens) == b"ababab"

    def test_three_byte_pattern_exact(self):
        """'abcabcabc' = Lit(a,b,c) + Ref(3, 6)."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=6),
        ]
        assert lz77_decode(tokens) == b"abcabcabc"

    def test_three_byte_pattern_with_remainder(self):
        """'abcabcab' = Lit(a,b,c) + Ref(3, 5) — q=1, r=2."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=5),
        ]
        assert lz77_decode(tokens) == b"abcabcab"

    def test_overlap_distance_one_long(self):
        """Extreme RLE: single byte repeated 100 times."""
        tokens = [
            Literal(0x42),
            Reference(distance=1, length=99),
        ]
        assert lz77_decode(tokens) == bytes([0x42] * 100)

    def test_overlap_complex_pattern(self):
        """'abcdabcdabcdab' = Lit(a,b,c,d) + Ref(4, 10)."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")),
            Literal(ord("c")), Literal(ord("d")),
            Reference(distance=4, length=10),
        ]
        # q=2, r=2: "abcd" * 2 + "ab" = "abcdabcdab"
        # total: "abcd" + "abcdabcdab" = "abcdabcdabcdab"
        assert lz77_decode(tokens) == b"abcdabcdabcdab"


# ---------------------------------------------------------------------------
# Encoder: roundtrip correctness
# ---------------------------------------------------------------------------

class TestEncoder:
    """lz77_encode produces tokens that decode to the original input."""

    def test_roundtrip_simple(self):
        data = b"abcabc"
        tokens = lz77_encode(data)
        assert lz77_decode(tokens) == data

    def test_roundtrip_repeated(self):
        data = b"aaaaaa"
        tokens = lz77_encode(data)
        assert lz77_decode(tokens) == data

    def test_roundtrip_no_matches(self):
        data = bytes(range(256))
        tokens = lz77_encode(data)
        assert lz77_decode(tokens) == data

    def test_roundtrip_empty(self):
        tokens = lz77_encode(b"")
        assert lz77_decode(tokens) == b""

    def test_roundtrip_single_byte(self):
        tokens = lz77_encode(b"x")
        assert lz77_decode(tokens) == b"x"

    def test_roundtrip_long_repeat(self):
        data = b"abcdef" * 100
        tokens = lz77_encode(data)
        assert lz77_decode(tokens) == data

    def test_roundtrip_binary(self):
        import os
        data = os.urandom(500)
        tokens = lz77_encode(data)
        assert lz77_decode(tokens) == data

    def test_encoder_produces_references(self):
        """Encoder should find the match in 'abcabc'."""
        data = b"abcabc"
        tokens = lz77_encode(data)
        has_ref = any(isinstance(t, Reference) for t in tokens)
        assert has_ref, "Encoder should find at least one back-reference"

    def test_encoder_produces_overlapping_ref(self):
        """Encoder should emit overlapping ref for 'aaaaaa'."""
        data = b"aaaaaa"
        tokens = lz77_encode(data)
        has_overlap = any(
            isinstance(t, Reference) and t.distance < t.length
            for t in tokens
        )
        assert has_overlap, "Encoder should produce overlapping reference for runs"

    def test_encoder_compression(self):
        """Repeated data should produce fewer tokens than bytes."""
        data = b"abcdefgh" * 50  # 400 bytes, highly compressible
        tokens = lz77_encode(data)
        assert len(tokens) < len(data)
