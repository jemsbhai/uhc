"""
Tests for the unified pipeline API (uhc.engine.pipeline).

Validates the clean public interface that wires together
CDC + format parsers + CDH + hash composition.
"""

from __future__ import annotations

import os
import random
import zlib
import pytest
import lz4.block
import lz4.frame

from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61
from uhc.engine.pipeline import (
    Format,
    extract_tokens,
    uhc_hash,
    uhc_hash_compressed,
    uhc_hash_multi,
    uhc_hash_compressed_multi,
    uhc_verify,
)


def _rng_bytes(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def raw_deflate(data: bytes, level: int = 6) -> bytes:
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


# ===================================================================
# extract_tokens
# ===================================================================


class TestExtractTokens:

    def test_raw_format_produces_literals(self):
        from uhc.core.lz77 import Literal, lz77_decode
        tokens = extract_tokens(b"hello", Format.RAW)
        assert all(isinstance(t, Literal) for t in tokens)
        assert lz77_decode(tokens) == b"hello"

    def test_deflate_format(self):
        from uhc.core.lz77 import lz77_decode
        data = b"test deflate extract" * 5
        compressed = raw_deflate(data)
        tokens = extract_tokens(compressed, Format.DEFLATE)
        assert lz77_decode(tokens) == data

    def test_lz4_block_format(self):
        from uhc.core.lz77 import lz77_decode
        data = b"test lz4 extract" * 5
        compressed = lz4.block.compress(data, store_size=False)
        tokens = extract_tokens(compressed, Format.LZ4_BLOCK)
        assert lz77_decode(tokens) == data

    def test_lz4_frame_format(self):
        from uhc.core.lz77 import lz77_decode
        data = b"test lz4 frame" * 5
        compressed = lz4.frame.compress(data)
        tokens = extract_tokens(compressed, Format.LZ4_FRAME)
        assert lz77_decode(tokens) == data


# ===================================================================
# uhc_hash — single hash
# ===================================================================


class TestUhcHash:

    def test_raw_data(self):
        h = PolynomialHash(base=131)
        data = b"hello world"
        assert uhc_hash(data) == h.hash(data)

    def test_raw_data_large_with_chunking(self):
        h = PolynomialHash(base=131)
        data = _rng_bytes(1, 50_000)
        assert uhc_hash(data) == h.hash(data)

    def test_raw_no_chunking(self):
        h = PolynomialHash(base=131)
        data = _rng_bytes(2, 50_000)
        assert uhc_hash(data, chunk=False) == h.hash(data)

    def test_compressed_deflate(self):
        h = PolynomialHash(base=131)
        data = b"compressed deflate test " * 20
        compressed = raw_deflate(data)
        result = uhc_hash(compressed, fmt=Format.DEFLATE)
        assert result == h.hash(data)

    def test_compressed_lz4_block(self):
        h = PolynomialHash(base=131)
        data = b"compressed lz4 test " * 20
        compressed = lz4.block.compress(data, store_size=False)
        result = uhc_hash(compressed, fmt=Format.LZ4_BLOCK)
        assert result == h.hash(data)

    def test_compressed_lz4_frame(self):
        h = PolynomialHash(base=131)
        data = b"compressed lz4 frame " * 20
        compressed = lz4.frame.compress(data)
        result = uhc_hash(compressed, fmt=Format.LZ4_FRAME)
        assert result == h.hash(data)

    def test_custom_base(self):
        h = PolynomialHash(base=257)
        data = b"custom base"
        assert uhc_hash(data, base=257) == h.hash(data)


# ===================================================================
# uhc_hash_compressed
# ===================================================================


class TestUhcHashCompressed:

    def test_deflate(self):
        h = PolynomialHash(base=131)
        data = b"verify compressed " * 30
        compressed = raw_deflate(data)
        assert uhc_hash_compressed(compressed, Format.DEFLATE) == h.hash(data)

    def test_lz4_block(self):
        h = PolynomialHash(base=131)
        data = b"verify lz4 " * 30
        compressed = lz4.block.compress(data, store_size=False)
        assert uhc_hash_compressed(compressed, Format.LZ4_BLOCK) == h.hash(data)

    def test_raw_passthrough(self):
        h = PolynomialHash(base=131)
        data = b"raw passthrough"
        assert uhc_hash_compressed(data, Format.RAW) == h.hash(data)


# ===================================================================
# uhc_hash_multi — k-tuple
# ===================================================================


class TestUhcHashMulti:

    def test_raw_default_k2(self):
        from uhc.core.multihash import MultiHash
        mh = MultiHash(bases=[131, 257])
        data = b"multi hash test"
        result = uhc_hash_multi(data)
        assert result == mh.hash(data)

    def test_custom_bases(self):
        from uhc.core.multihash import MultiHash
        bases = [131, 257, 509]
        mh = MultiHash(bases=bases)
        data = b"custom k3"
        result = uhc_hash_multi(data, bases=bases)
        assert result == mh.hash(data)

    def test_compressed_deflate_multi(self):
        from uhc.core.multihash import MultiHash
        mh = MultiHash(bases=[131, 257])
        data = b"multi deflate " * 20
        compressed = raw_deflate(data)
        result = uhc_hash_multi(compressed, fmt=Format.DEFLATE)
        assert result == mh.hash(data)


# ===================================================================
# uhc_hash_compressed_multi
# ===================================================================


class TestUhcHashCompressedMulti:

    def test_deflate_k2(self):
        from uhc.core.multihash import MultiHash
        mh = MultiHash(bases=[131, 257])
        data = b"compressed multi " * 20
        compressed = raw_deflate(data)
        result = uhc_hash_compressed_multi(compressed, Format.DEFLATE)
        assert result == mh.hash(data)

    def test_lz4_k2(self):
        from uhc.core.multihash import MultiHash
        mh = MultiHash(bases=[131, 257])
        data = b"lz4 multi " * 20
        compressed = lz4.block.compress(data, store_size=False)
        result = uhc_hash_compressed_multi(compressed, Format.LZ4_BLOCK)
        assert result == mh.hash(data)


# ===================================================================
# uhc_verify
# ===================================================================


class TestUhcVerify:

    def test_same_raw_data(self):
        data = b"verify same"
        assert uhc_verify(data, data) is True

    def test_different_raw_data(self):
        assert uhc_verify(b"aaa", b"bbb") is False

    def test_raw_vs_deflate(self):
        """Raw data and its DEFLATE compression should verify as equal."""
        data = b"cross format verify " * 20
        compressed = raw_deflate(data)
        assert uhc_verify(data, compressed, fmt_a=Format.RAW, fmt_b=Format.DEFLATE) is True

    def test_raw_vs_lz4(self):
        data = b"cross lz4 verify " * 20
        compressed = lz4.block.compress(data, store_size=False)
        assert uhc_verify(data, compressed, fmt_a=Format.RAW, fmt_b=Format.LZ4_BLOCK) is True

    def test_deflate_vs_lz4(self):
        """Same data compressed with different formats should verify as equal."""
        data = b"deflate vs lz4 " * 20
        deflate_data = raw_deflate(data)
        lz4_data = lz4.block.compress(data, store_size=False)
        assert uhc_verify(
            deflate_data, lz4_data,
            fmt_a=Format.DEFLATE, fmt_b=Format.LZ4_BLOCK
        ) is True

    def test_different_content_different_formats(self):
        data_a = b"content A " * 20
        data_b = b"content B " * 20
        comp_a = raw_deflate(data_a)
        comp_b = lz4.block.compress(data_b, store_size=False)
        assert uhc_verify(
            comp_a, comp_b,
            fmt_a=Format.DEFLATE, fmt_b=Format.LZ4_BLOCK
        ) is False

    @pytest.mark.parametrize("seed", range(5))
    def test_random_cross_format(self, seed):
        """Randomized cross-format verification."""
        data = _rng_bytes(seed + 10000, 10_000)
        compressed = raw_deflate(data)
        assert uhc_verify(data, compressed, fmt_a=Format.RAW, fmt_b=Format.DEFLATE) is True
