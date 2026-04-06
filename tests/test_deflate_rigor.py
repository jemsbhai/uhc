"""
Extended rigor tests for DEFLATE token extraction (Lemma 9).

Covers gaps in the basic test suite:
- Explicit block type coverage (stored, fixed, dynamic)
- Multi-block streams
- Edge cases at DEFLATE limits (max length 258, max distance 32768)
- Randomized data
- Malformed input rejection
- Token-position consistency (decoded position tracking)
"""

from __future__ import annotations

import os
import zlib
import pytest

from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod
from uhc.core.deflate import deflate_extract_tokens


def raw_deflate(data: bytes, level: int = 6) -> bytes:
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def raw_inflate(compressed: bytes) -> bytes:
    return zlib.decompress(compressed, -15)


# ===================================================================
# Block type coverage
# ===================================================================


class TestBlockTypes:
    """Ensure all three DEFLATE block types are handled."""

    def test_stored_block_type0(self):
        """Level 0 forces BTYPE=00 (stored). Verify round-trip."""
        data = b"stored block explicit test"
        compressed = raw_deflate(data, level=0)
        tokens = deflate_extract_tokens(compressed)

        # Stored blocks produce only literals
        assert all(isinstance(t, Literal) for t in tokens)
        assert lz77_decode(tokens) == data

    def test_fixed_huffman_type1(self):
        """Level 1 typically uses BTYPE=01 (fixed Huffman)."""
        # Short data with some repetition — level 1 usually picks fixed
        data = b"abcabcabc"
        compressed = raw_deflate(data, level=1)
        tokens = deflate_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_dynamic_huffman_type2(self):
        """Longer data at higher levels uses BTYPE=10 (dynamic Huffman)."""
        # Enough data with skewed distribution to trigger dynamic tables
        data = (b"a" * 100 + b"b" * 50 + b"c" * 25 + b"defghij") * 5
        compressed = raw_deflate(data, level=9)
        tokens = deflate_extract_tokens(compressed)
        assert lz77_decode(tokens) == data


# ===================================================================
# Multi-block streams
# ===================================================================


class TestMultiBlock:
    """DEFLATE streams with multiple blocks."""

    def test_large_data_forces_multiple_blocks(self):
        """~100KB should produce multiple DEFLATE blocks."""
        data = os.urandom(50_000) + b"pattern" * 7000  # mix random + compressible
        compressed = raw_deflate(data, level=6)
        tokens = deflate_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_manual_multiblock_via_flush(self):
        """Force multiple blocks by flushing mid-stream."""
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        part1 = c.compress(b"first block data " * 10)
        part1 += c.flush(zlib.Z_FULL_FLUSH)
        part2 = c.compress(b"second block data " * 10)
        part2 += c.flush(zlib.Z_FINISH)

        compressed = part1 + part2
        tokens = deflate_extract_tokens(compressed)
        expected = b"first block data " * 10 + b"second block data " * 10
        assert lz77_decode(tokens) == expected


# ===================================================================
# DEFLATE limit edge cases (Definition 8)
# ===================================================================


class TestDeflateLimits:
    """Edge cases at DEFLATE parameter boundaries."""

    def test_max_match_length_258(self):
        """Pattern that should produce length-258 matches."""
        # 258 copies of the same 3-byte pattern
        data = b"xyz" * 300
        compressed = raw_deflate(data, level=9)
        tokens = deflate_extract_tokens(compressed)

        decoded = lz77_decode(tokens)
        assert decoded == data

        # Verify all references are within DEFLATE limits
        for t in tokens:
            if isinstance(t, Reference):
                assert t.length <= 258
                assert t.distance <= 32768

    def test_distance_near_max(self):
        """Data with back-references near distance 32768."""
        # Create a pattern, add ~32KB of filler, then repeat the pattern
        pattern = b"UNIQUE_PATTERN_HERE"
        filler = bytes(range(256)) * 127  # ~32512 bytes
        data = pattern + filler + pattern
        compressed = raw_deflate(data, level=9)
        tokens = deflate_extract_tokens(compressed)

        decoded = lz77_decode(tokens)
        assert decoded == data

    def test_minimum_match_length_3(self):
        """DEFLATE minimum match is 3 bytes. 2-byte repeats stay literals."""
        data = b"ababababab"
        compressed = raw_deflate(data, level=9)
        tokens = deflate_extract_tokens(compressed)

        for t in tokens:
            if isinstance(t, Reference):
                assert t.length >= 3

        assert lz77_decode(tokens) == data


# ===================================================================
# Randomized testing
# ===================================================================


class TestRandomized:
    """Randomized inputs for broader coverage."""

    @pytest.mark.parametrize("size", [1, 10, 100, 1000, 10000])
    def test_random_data_roundtrip(self, size):
        """Random bytes: extract tokens, decode, verify match."""
        data = os.urandom(size)
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    @pytest.mark.parametrize("size", [100, 1000, 5000])
    def test_random_data_cdh(self, size):
        """Random bytes: CDH(deflate_tokens) == H(data)."""
        data = os.urandom(size)
        h = PolynomialHash(base=131)
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        result = compressed_domain_hash(tokens, base=131, method=CDHMethod.ROPE)
        assert result == h.hash(data)

    @pytest.mark.parametrize("seed", range(5))
    def test_seeded_random_reproducible(self, seed):
        """Seeded random for reproducibility on failure."""
        rng = __import__("random").Random(seed)
        size = rng.randint(50, 5000)
        data = bytes(rng.getrandbits(8) for _ in range(size))

        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        assert lz77_decode(tokens) == data


# ===================================================================
# Token-position consistency
# ===================================================================


class TestTokenPositionConsistency:
    """Verify that token positions are internally consistent."""

    def test_decoded_length_matches(self):
        """Sum of token decoded lengths == len(original data)."""
        data = b"position consistency check " * 20
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        total = 0
        for t in tokens:
            if isinstance(t, Literal):
                total += 1
            elif isinstance(t, Reference):
                total += t.length

        assert total == len(data)

    def test_references_dont_exceed_decoded_position(self):
        """No Reference(d, l) where d > current decoded position."""
        data = b"back reference validity " * 30
        compressed = raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)

        pos = 0
        for t in tokens:
            if isinstance(t, Literal):
                pos += 1
            elif isinstance(t, Reference):
                assert t.distance <= pos, (
                    f"Reference distance {t.distance} exceeds decoded "
                    f"position {pos}"
                )
                pos += t.length


# ===================================================================
# Malformed input
# ===================================================================


class TestMalformedInput:
    """Reject or handle malformed DEFLATE streams gracefully."""

    def test_empty_compressed_stream_raises(self):
        """Empty bytes is not a valid DEFLATE stream."""
        with pytest.raises((ValueError, IndexError)):
            deflate_extract_tokens(b"")

    def test_truncated_stream_raises(self):
        """Truncated DEFLATE stream should raise."""
        data = b"hello world" * 10
        compressed = raw_deflate(data)
        truncated = compressed[:len(compressed) // 2]

        with pytest.raises((ValueError, IndexError)):
            deflate_extract_tokens(truncated)

    def test_invalid_block_type_raises(self):
        """BTYPE=11 is reserved and must be rejected."""
        # Craft bytes where first 3 bits are: BFINAL=1, BTYPE=11
        # Bits: bit0=1 (BFINAL), bit1=1, bit2=1 (BTYPE=11) → byte = 0b00000111 = 7
        with pytest.raises(ValueError, match="Invalid DEFLATE block type"):
            deflate_extract_tokens(bytes([0x07]))
