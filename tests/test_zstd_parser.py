"""
Tests for Zstandard token extraction (Lemma 11).

Covers Zstandard frame format (RFC 8478).
Tests verify:
1. Token extraction round-trips correctly: lz77_decode(tokens) == original
2. CDH(tokens) == H(decompressed) — Theorem 12
3. Various data patterns: literals, back-refs, overlapping refs
4. Multiple block types: raw, RLE, compressed
5. Repeat-offset cache correctness
6. Edge cases: empty, single byte, large data, high compression ratio
"""

from __future__ import annotations

import os
import pytest

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod

pytestmark = pytest.mark.skipif(
    not HAS_ZSTD,
    reason=(
        "Zstandard parser tests require the optional 'zstandard' binding; "
        "install with: python -m pip install -e '.[dev,formats]'"
    ),
)


# ===================================================================
# Helpers
# ===================================================================

def zstd_compress(data: bytes, level: int = 3) -> bytes:
    """Compress data using zstandard library."""
    cctx = zstd.ZstdCompressor(level=level)
    return cctx.compress(data)


def import_parser():
    """Import the zstd parser (deferred to let tests fail with ImportError info)."""
    from uhc.core.zstd_parser import zstd_extract_tokens
    return zstd_extract_tokens


# ===================================================================
# Part A: Basic token extraction round-trip
# ===================================================================


class TestZstdBasicExtraction:
    """Token extraction produces tokens that decode to the original data."""

    def test_single_byte(self):
        zstd_extract_tokens = import_parser()
        data = b"A"
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_short_literals_only(self):
        zstd_extract_tokens = import_parser()
        data = b"abcdefgh"
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_repeated_pattern(self):
        """Repeated data should produce back-references."""
        zstd_extract_tokens = import_parser()
        data = b"abcdabcd" * 10
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        has_ref = any(isinstance(t, Reference) for t in tokens)
        assert has_ref
        assert lz77_decode(tokens) == data

    def test_all_same_byte(self):
        """Run-length case: all same byte, overlapping ref with d=1."""
        zstd_extract_tokens = import_parser()
        data = b"\x00" * 200
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_binary_data(self):
        zstd_extract_tokens = import_parser()
        data = bytes(range(256)) * 4
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_lorem_ipsum(self):
        zstd_extract_tokens = import_parser()
        data = (b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 20)
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_medium_data(self):
        zstd_extract_tokens = import_parser()
        data = os.urandom(4096) + b"pattern" * 500 + os.urandom(4096)
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_large_data(self):
        zstd_extract_tokens = import_parser()
        data = (b"abcdefghijklmnop" * 1000 + os.urandom(1000)) * 5
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data


# ===================================================================
# Part B: CDH correctness — Theorem 12
# ===================================================================


class TestZstdCDHCorrectness:
    """CDH(tokens) must equal H(decompressed) for all inputs."""

    def _verify_cdh(self, data: bytes, base: int = 131):
        zstd_extract_tokens = import_parser()
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)

        ph = PolynomialHash(base=base)
        expected = ph.hash(data)

        # Rope method
        actual_rope = compressed_domain_hash(
            tokens, base=base, method=CDHMethod.ROPE
        )
        assert actual_rope == expected, (
            f"CDH(rope) mismatch: {actual_rope} != {expected}"
        )

        # Sliding rope method — needs d_max, m_max from Zstandard spec
        actual_sliding = compressed_domain_hash(
            tokens, base=base, method=CDHMethod.SLIDING_ROPE,
            d_max=131072, m_max=131074,
        )
        assert actual_sliding == expected, (
            f"CDH(sliding) mismatch: {actual_sliding} != {expected}"
        )

    def test_cdh_short_text(self):
        self._verify_cdh(b"hello world")

    def test_cdh_repeated(self):
        self._verify_cdh(b"abcd" * 100)

    def test_cdh_all_same(self):
        self._verify_cdh(b"\xff" * 300)

    def test_cdh_binary_random(self):
        self._verify_cdh(os.urandom(2048))

    def test_cdh_mixed(self):
        data = b"hello" * 50 + os.urandom(100) + b"world" * 50
        self._verify_cdh(data)

    def test_cdh_large(self):
        data = (b"compress me! " * 500) + os.urandom(500)
        self._verify_cdh(data)

    def test_cdh_multiple_bases(self):
        """Verify with different polynomial bases."""
        zstd_extract_tokens = import_parser()
        data = b"test data for multiple bases" * 20
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)

        for base in [131, 257, 65537]:
            ph = PolynomialHash(base=base)
            expected = ph.hash(data)
            actual = compressed_domain_hash(tokens, base=base, method=CDHMethod.ROPE)
            assert actual == expected, f"CDH mismatch for base={base}"


# ===================================================================
# Part C: Overlapping references (Theorem 4)
# ===================================================================


class TestZstdOverlapping:
    """Overlapping back-references must decode correctly."""

    def test_run_of_single_byte(self):
        """d=1 overlap: single byte repeated many times."""
        zstd_extract_tokens = import_parser()
        data = b"A" * 500
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_short_period_repeat(self):
        """d=2 overlap: two-byte pattern repeated."""
        zstd_extract_tokens = import_parser()
        data = b"ab" * 300
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_three_byte_period(self):
        zstd_extract_tokens = import_parser()
        data = b"abc" * 200
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data


# ===================================================================
# Part D: Compression levels
# ===================================================================


class TestZstdCompressionLevels:
    """Parser must work across different compression levels."""

    @pytest.mark.parametrize("level", [1, 3, 5, 9, 15])
    def test_level(self, level):
        zstd_extract_tokens = import_parser()
        data = b"The quick brown fox jumps over the lazy dog. " * 50
        compressed = zstd_compress(data, level=level)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    @pytest.mark.parametrize("level", [1, 3, 9])
    def test_cdh_across_levels(self, level):
        zstd_extract_tokens = import_parser()
        data = b"hello world! " * 100
        compressed = zstd_compress(data, level=level)
        tokens = zstd_extract_tokens(compressed)
        ph = PolynomialHash(base=131)
        expected = ph.hash(data)
        actual = compressed_domain_hash(tokens, base=131, method=CDHMethod.ROPE)
        assert actual == expected


# ===================================================================
# Part E: Edge cases
# ===================================================================


class TestZstdEdgeCases:

    def test_empty_data(self):
        """Empty input should produce empty tokens."""
        zstd_extract_tokens = import_parser()
        compressed = zstd_compress(b"")
        tokens = zstd_extract_tokens(compressed)
        assert tokens == []
        assert lz77_decode(tokens) == b""

    def test_single_literal(self):
        zstd_extract_tokens = import_parser()
        data = b"X"
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert len(tokens) == 1
        assert isinstance(tokens[0], Literal)
        assert tokens[0].byte == ord("X")

    def test_two_bytes(self):
        zstd_extract_tokens = import_parser()
        data = b"AB"
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_256_unique_bytes(self):
        zstd_extract_tokens = import_parser()
        data = bytes(range(256))
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

    def test_high_compression_ratio(self):
        """Very repetitive data with high compression ratio."""
        zstd_extract_tokens = import_parser()
        data = b"\x00" * 100_000
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

        # Verify CDH too
        ph = PolynomialHash(base=131)
        expected = ph.hash(data)
        actual = compressed_domain_hash(tokens, base=131, method=CDHMethod.ROPE)
        assert actual == expected


# ===================================================================
# Part F: Token type verification
# ===================================================================


class TestZstdTokenTypes:

    def test_literals_are_valid_bytes(self):
        zstd_extract_tokens = import_parser()
        data = bytes(range(256))
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        for t in tokens:
            if isinstance(t, Literal):
                assert 0 <= t.byte <= 255

    def test_references_have_positive_distance(self):
        zstd_extract_tokens = import_parser()
        data = b"abcdef" * 100
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        for t in tokens:
            if isinstance(t, Reference):
                assert t.distance >= 1
                assert t.length >= 1

    def test_reference_distance_within_bounds(self):
        """Back-reference distance must not exceed current position."""
        zstd_extract_tokens = import_parser()
        data = b"hello world! " * 200
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        pos = 0
        for t in tokens:
            if isinstance(t, Literal):
                pos += 1
            elif isinstance(t, Reference):
                assert t.distance <= pos, (
                    f"Ref distance {t.distance} exceeds position {pos}"
                )
                pos += t.length
