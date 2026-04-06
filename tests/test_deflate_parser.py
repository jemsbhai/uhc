"""
Tests for DEFLATE token extraction (Lemma 9).

Lemma 9: A DEFLATE stream (RFC 1951) can be parsed in O(n) time
to extract Lit/Ref tokens, and its back-reference semantics match
Definition 5.

Tests verify:
1. Token extraction produces valid Lit/Ref tokens
2. lz77_decode(extracted_tokens) == zlib.decompress(compressed)
3. CDH(extracted_tokens) == H(decompressed) — Theorem 12 over real DEFLATE

We use zlib.compress() to create DEFLATE streams as test fixtures.
"""

from __future__ import annotations

import zlib
import pytest

from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod


# ===================================================================
# Helpers
# ===================================================================

def raw_deflate(data: bytes, level: int = 6) -> bytes:
    """Produce raw DEFLATE stream (no zlib/gzip headers)."""
    # wbits=-15 gives raw DEFLATE (RFC 1951) without zlib header
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def raw_inflate(compressed: bytes) -> bytes:
    """Decompress raw DEFLATE stream."""
    return zlib.decompress(compressed, -15)


# ===================================================================
# Part A: Basic token extraction
# ===================================================================


class TestDeflateTokenExtraction:
    """Extract LZ77 tokens from real DEFLATE streams."""

    def test_empty_input(self):
        """Empty data produces empty token stream."""
        from uhc.core.deflate import deflate_extract_tokens

        compressed = raw_deflate(b"")
        tokens = deflate_extract_tokens(compressed)
        assert tokens == []

    def test_single_byte(self):
        """Single byte produces one Literal token."""
        from uhc.core.deflate import deflate_extract_tokens

        compressed = raw_deflate(b"A")
        tokens = deflate_extract_tokens(compressed)

        decoded = lz77_decode(tokens)
        assert decoded == b"A"

    def test_short_literals_only(self):
        """Short unique string — all literals, no matches."""
        from uhc.core.deflate import deflate_extract_tokens

        data = b"abcdefgh"
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        decoded = lz77_decode(tokens)
        assert decoded == data

    def test_repeated_pattern(self):
        """Repeated data should produce back-references."""
        from uhc.core.deflate import deflate_extract_tokens

        data = b"abcabc" * 10
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        # Must contain at least one Reference
        has_ref = any(isinstance(t, Reference) for t in tokens)
        assert has_ref, "Repeated data should produce back-references"

        decoded = lz77_decode(tokens)
        assert decoded == data

    def test_all_same_byte(self):
        """All-same-byte input — overlapping references expected."""
        from uhc.core.deflate import deflate_extract_tokens

        data = b"\x00" * 100
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        decoded = lz77_decode(tokens)
        assert decoded == data

    def test_various_compression_levels(self):
        """Token extraction works at all zlib compression levels."""
        from uhc.core.deflate import deflate_extract_tokens

        data = b"the quick brown fox jumps over the lazy dog " * 5

        for level in [1, 6, 9]:
            compressed = raw_deflate(data, level=level)
            tokens = deflate_extract_tokens(compressed)
            decoded = lz77_decode(tokens)
            assert decoded == data, f"Failed at level {level}"

    def test_binary_data(self):
        """Handles binary data with all byte values."""
        from uhc.core.deflate import deflate_extract_tokens

        data = bytes(range(256)) * 4
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        decoded = lz77_decode(tokens)
        assert decoded == data

    def test_stored_blocks(self):
        """Level 0 produces stored (uncompressed) DEFLATE blocks."""
        from uhc.core.deflate import deflate_extract_tokens

        data = b"stored block test data"
        compressed = raw_deflate(data, level=0)
        tokens = deflate_extract_tokens(compressed)

        decoded = lz77_decode(tokens)
        assert decoded == data

    def test_reference_constraints(self):
        """All extracted References satisfy DEFLATE constraints (Definition 8)."""
        from uhc.core.deflate import deflate_extract_tokens

        data = b"abcdefabcdef" * 50
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        for tok in tokens:
            if isinstance(tok, Reference):
                assert 3 <= tok.length <= 258, f"Length {tok.length} out of DEFLATE range"
                assert 1 <= tok.distance <= 32768, f"Distance {tok.distance} out of DEFLATE range"


# ===================================================================
# Part B: CDH correctness over DEFLATE tokens (Theorem 12)
# ===================================================================


class TestDeflateCDH:
    """CDH(deflate_tokens) == H(decompressed) — Theorem 12 on real data."""

    def _verify_cdh(self, data: bytes, level: int = 6):
        """Helper: compress with DEFLATE, extract tokens, verify CDH == H."""
        from uhc.core.deflate import deflate_extract_tokens

        h = PolynomialHash(base=131)
        compressed = raw_deflate(data, level=level)
        tokens = deflate_extract_tokens(compressed)

        # Ground truth
        expected = h.hash(data)

        # CDH via rope
        result_rope = compressed_domain_hash(tokens, base=131, method=CDHMethod.ROPE)
        assert result_rope == expected, "Rope CDH mismatch"

        # CDH via sliding rope
        result_sliding = compressed_domain_hash(
            tokens, base=131, method=CDHMethod.SLIDING_ROPE,
            d_max=32768, m_max=258,
        )
        assert result_sliding == expected, "Sliding rope CDH mismatch"

    def test_cdh_short_text(self):
        self._verify_cdh(b"hello world")

    def test_cdh_repeated_text(self):
        self._verify_cdh(b"the quick brown fox " * 20)

    def test_cdh_binary(self):
        self._verify_cdh(bytes(range(256)) * 2)

    def test_cdh_all_same(self):
        self._verify_cdh(b"\xff" * 500)

    def test_cdh_level1(self):
        self._verify_cdh(b"abcabc" * 100, level=1)

    def test_cdh_level9(self):
        self._verify_cdh(b"abcabc" * 100, level=9)

    def test_cdh_large_ish(self):
        """~10KB input — still fast for a test."""
        data = (b"pattern1 " * 50 + b"pattern2 " * 50) * 10
        self._verify_cdh(data)

    def test_cdh_stored_blocks(self):
        self._verify_cdh(b"stored block CDH test", level=0)


# ===================================================================
# Part C: Multi-hash CDH over DEFLATE (Theorem 21)
# ===================================================================


class TestDeflateMultiCDH:
    """k-tuple CDH over real DEFLATE tokens."""

    def test_k2_deflate(self):
        from uhc.core.deflate import deflate_extract_tokens
        from uhc.core.multihash import MultiHash, multi_cdh

        data = b"multi-hash deflate test " * 10
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        mh = MultiHash(bases=[131, 257])
        result = multi_cdh(tokens, mh)
        expected = mh.hash(data)
        assert result == expected
