"""
Tests for LZ4 token extraction (Lemma 10).

Covers both raw block format and LZ4 frame format.
Tests verify:
1. Token extraction round-trips correctly
2. CDH(tokens) == H(decompressed) — Theorem 12
3. Frame format parsing with checksums, content size, etc.
4. Edge cases: long literals/matches (255-continuation), overlapping refs
"""

from __future__ import annotations

import os
import pytest
import lz4.block
import lz4.frame

from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod


# ===================================================================
# Helpers
# ===================================================================

def lz4_compress_block(data: bytes) -> bytes:
    """Compress to raw LZ4 block (no frame header)."""
    return lz4.block.compress(data, store_size=False)


def lz4_compress_frame(data: bytes) -> bytes:
    """Compress to LZ4 frame format."""
    return lz4.frame.compress(data)


# ===================================================================
# Part A: Raw block format
# ===================================================================


class TestLZ4BlockExtraction:

    def test_empty_input(self):
        from uhc.core.lz4_parser import lz4_extract_tokens
        tokens = lz4_extract_tokens(b"")
        assert tokens == []

    def test_single_byte(self):
        from uhc.core.lz4_parser import lz4_extract_tokens
        compressed = lz4_compress_block(b"A")
        tokens = lz4_extract_tokens(compressed)
        assert lz77_decode(tokens) == b"A"

    def test_short_literals_only(self):
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = b"abcdefgh"
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_repeated_pattern(self):
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = b"abcdabcd" * 10
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        has_ref = any(isinstance(t, Reference) for t in tokens)
        assert has_ref
        assert lz77_decode(tokens) == data

    def test_all_same_byte(self):
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = b"\x00" * 200
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_binary_data(self):
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = bytes(range(256)) * 4
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_reference_constraints(self):
        """All References satisfy LZ4 constraints (Definition 8)."""
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = b"abcdefabcdef" * 50
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        for tok in tokens:
            if isinstance(tok, Reference):
                assert tok.length >= 4, f"LZ4 min match is 4, got {tok.length}"
                assert 1 <= tok.distance <= 65535


# ===================================================================
# Part B: LZ4 frame format
# ===================================================================


class TestLZ4FrameExtraction:

    def test_frame_single_byte(self):
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        compressed = lz4_compress_frame(b"X")
        tokens = lz4_frame_extract_tokens(compressed)
        assert lz77_decode(tokens) == b"X"

    def test_frame_short_text(self):
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        data = b"hello world frame format"
        compressed = lz4_compress_frame(data)
        tokens = lz4_frame_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_frame_repeated(self):
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        data = b"abcdabcd" * 50
        compressed = lz4_compress_frame(data)
        tokens = lz4_frame_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_frame_large_data(self):
        """Large enough to potentially span multiple blocks in frame."""
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        data = os.urandom(100_000)
        compressed = lz4_compress_frame(data)
        tokens = lz4_frame_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_frame_with_content_size(self):
        """Frame compressed with content_size flag enabled."""
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        data = b"content size test " * 20
        compressed = lz4.frame.compress(data, content_checksum=True,
                                         store_size=True)
        tokens = lz4_frame_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_frame_with_block_checksum(self):
        """Frame with block-level checksums enabled."""
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        data = b"block checksum test " * 20
        compressed = lz4.frame.compress(data, block_checksum=True)
        tokens = lz4_frame_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_frame_invalid_magic(self):
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        with pytest.raises(ValueError, match="Invalid LZ4 frame magic"):
            lz4_frame_extract_tokens(b"\x00\x00\x00\x00\x00\x00\x00")

    def test_frame_too_short(self):
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        with pytest.raises(ValueError):
            lz4_frame_extract_tokens(b"\x04")

    def test_frame_cdh_matches(self):
        """CDH over frame-extracted tokens == H(original)."""
        from uhc.core.lz4_parser import lz4_frame_extract_tokens
        data = b"frame CDH test " * 30
        h = PolynomialHash(base=131)
        compressed = lz4_compress_frame(data)
        tokens = lz4_frame_extract_tokens(compressed)
        result = compressed_domain_hash(tokens, base=131, method=CDHMethod.ROPE)
        assert result == h.hash(data)


# ===================================================================
# Part C: CDH correctness — block format (Theorem 12)
# ===================================================================


class TestLZ4CDH:

    def _verify_cdh(self, data: bytes):
        from uhc.core.lz4_parser import lz4_extract_tokens
        h = PolynomialHash(base=131)
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        expected = h.hash(data)
        result = compressed_domain_hash(tokens, base=131, method=CDHMethod.ROPE)
        assert result == expected

    def test_cdh_short_text(self):
        self._verify_cdh(b"hello world")

    def test_cdh_repeated(self):
        self._verify_cdh(b"the quick brown fox " * 20)

    def test_cdh_binary(self):
        self._verify_cdh(bytes(range(256)) * 2)

    def test_cdh_all_same(self):
        self._verify_cdh(b"\xff" * 500)

    def test_cdh_large(self):
        data = (b"pattern1 " * 50 + b"pattern2 " * 50) * 10
        self._verify_cdh(data)


# ===================================================================
# Part D: Edge cases & rigor
# ===================================================================


class TestLZ4EdgeCases:

    def test_long_literal_continuation(self):
        """Literal length > 15 triggers 255-continuation scheme."""
        from uhc.core.lz4_parser import lz4_extract_tokens
        # 300 unique-ish bytes — forces long literal run
        data = bytes((i * 7 + 13) % 256 for i in range(300))
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_long_match_continuation(self):
        """Match length > 19 (15+4) triggers 255-continuation scheme."""
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = b"abcd" * 5000  # very long repeated pattern
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_overlapping_reference(self):
        """Overlapping ref: distance < length (run of same byte)."""
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = b"a" * 1000
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)

        # Should have overlapping refs (distance 1, length >> 1)
        has_overlap = any(
            isinstance(t, Reference) and t.distance < t.length
            for t in tokens
        )
        assert has_overlap, "Expected overlapping back-references"
        assert lz77_decode(tokens) == data

    @pytest.mark.parametrize("size", [1, 10, 100, 1000, 10000])
    def test_random_roundtrip(self, size):
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = os.urandom(size)
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    @pytest.mark.parametrize("size", [100, 1000, 5000])
    def test_random_cdh(self, size):
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = os.urandom(size)
        h = PolynomialHash(base=131)
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        assert compressed_domain_hash(tokens, base=131, method=CDHMethod.ROPE) == h.hash(data)

    def test_token_position_consistency(self):
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = b"position check " * 30
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        total = sum(1 if isinstance(t, Literal) else t.length for t in tokens)
        assert total == len(data)

    def test_references_within_decoded_position(self):
        from uhc.core.lz4_parser import lz4_extract_tokens
        data = b"ref validity " * 40
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        pos = 0
        for t in tokens:
            if isinstance(t, Literal):
                pos += 1
            elif isinstance(t, Reference):
                assert t.distance <= pos
                pos += t.length

    @pytest.mark.parametrize("seed", range(5))
    def test_seeded_random(self, seed):
        from uhc.core.lz4_parser import lz4_extract_tokens
        rng = __import__("random").Random(seed)
        size = rng.randint(50, 5000)
        data = bytes(rng.getrandbits(8) for _ in range(size))
        compressed = lz4_compress_block(data)
        tokens = lz4_extract_tokens(compressed)
        assert lz77_decode(tokens) == data
