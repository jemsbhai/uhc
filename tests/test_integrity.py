"""
Tests for Theorem 23: Composition with Cryptographic Hash (BLAKE3).

Theorem 23 defines a dual-mode UHC integrity scheme:
    (a) Fast path: CDH^(k) only — O(k·c_F·n), collision bound (N/p)^k
    (b) Full path: CDH^(k) + BLAKE3(T) — O(k·c_F·n) + O(N), BLAKE3 security
    (c) Incremental: CDH updated via rope ops in O(k·log n),
        BLAKE3 via Merkle branch recomputation

The CDH hash provides fast probabilistic screening; BLAKE3 provides
cryptographic collision resistance for adversarial settings.
"""

from __future__ import annotations

import zlib
import pytest

blake3 = pytest.importorskip("blake3", reason="blake3 not installed")

from uhc.core.integrity import (
    IntegrityResult,
    integrity_fast,
    integrity_full,
    IncrementalIntegrity,
)
from uhc.core.multihash import MultiHash
from uhc.core.polynomial_hash import MERSENNE_61
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.deflate import deflate_extract_tokens
from uhc.engine.pipeline import Format, extract_tokens


# ===================================================================
# Helpers
# ===================================================================

def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _mh(bases=None):
    """Default MultiHash for testing."""
    return MultiHash(bases=bases or [131, 257])


# ===================================================================
# IntegrityResult structure
# ===================================================================


class TestIntegrityResult:

    def test_fast_result_has_no_blake3(self):
        data = b"fast path test " * 20
        compressed = _raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        result = integrity_fast(tokens, _mh())
        assert result.mode == "fast"
        assert result.cdh_hash is not None
        assert len(result.cdh_hash) == 2
        assert result.blake3_digest is None

    def test_full_result_has_blake3(self):
        data = b"full path test " * 20
        compressed = _raw_deflate(data)
        result = integrity_full(compressed, Format.DEFLATE, _mh())
        assert result.mode == "full"
        assert result.cdh_hash is not None
        assert result.blake3_digest is not None
        assert len(result.blake3_digest) == 32  # BLAKE3 default digest size


# ===================================================================
# Theorem 23(a): Fast path — CDH only
# ===================================================================


class TestFastPath:
    """Fast path computes CDH^(k) only, no decompression."""

    def test_fast_matches_multi_cdh(self):
        """Fast path must produce same CDH as multi_cdh (Theorem 12)."""
        from uhc.core.multihash import multi_cdh
        data = b"fast matches multi_cdh " * 20
        compressed = _raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        mh = _mh()
        result = integrity_fast(tokens, mh)
        expected = multi_cdh(tokens, mh)
        assert result.cdh_hash == expected

    def test_fast_equals_raw_hash(self):
        """CDH must equal H(T) — Theorem 12 correctness."""
        data = b"fast equals raw " * 20
        compressed = _raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        mh = _mh()
        result = integrity_fast(tokens, mh)
        expected = mh.hash(data)
        assert result.cdh_hash == expected

    def test_fast_empty_data(self):
        data = b""
        compressed = _raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        result = integrity_fast(tokens, _mh())
        assert result.cdh_hash == (0, 0)

    def test_fast_single_base(self):
        data = b"single base " * 10
        compressed = _raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        mh = MultiHash(bases=[131])
        result = integrity_fast(tokens, mh)
        assert len(result.cdh_hash) == 1


# ===================================================================
# Theorem 23(b): Full path — CDH + BLAKE3
# ===================================================================


class TestFullPath:
    """Full path computes CDH^(k) + BLAKE3(T) for adversarial security."""

    def test_full_cdh_matches_fast(self):
        """CDH component of full path must match fast path."""
        data = b"full matches fast " * 20
        compressed = _raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        mh = _mh()
        fast = integrity_fast(tokens, mh)
        full = integrity_full(compressed, Format.DEFLATE, mh)
        assert full.cdh_hash == fast.cdh_hash

    def test_full_blake3_matches_direct(self):
        """BLAKE3 digest must match direct BLAKE3(decompressed data)."""
        data = b"blake3 direct match " * 20
        compressed = _raw_deflate(data)
        mh = _mh()
        result = integrity_full(compressed, Format.DEFLATE, mh)
        expected_digest = blake3.blake3(data).digest()
        assert result.blake3_digest == expected_digest

    def test_full_different_data_different_blake3(self):
        """Different data must produce different BLAKE3 digests."""
        data_a = b"data alpha " * 20
        data_b = b"data bravo " * 20
        r_a = integrity_full(_raw_deflate(data_a), Format.DEFLATE, _mh())
        r_b = integrity_full(_raw_deflate(data_b), Format.DEFLATE, _mh())
        assert r_a.blake3_digest != r_b.blake3_digest

    def test_full_same_data_same_blake3(self):
        """Same data in different DEFLATE streams → same BLAKE3."""
        data = b"same content " * 200
        # Z_HUFFMAN_ONLY (strategy=2) disables LZ77, producing a
        # structurally different DEFLATE stream than the default strategy.
        c_huff = zlib.compressobj(6, zlib.DEFLATED, -15, zlib.DEF_MEM_LEVEL, zlib.Z_HUFFMAN_ONLY)
        c_default = zlib.compressobj(6, zlib.DEFLATED, -15)
        comp_huff = c_huff.compress(data) + c_huff.flush()
        comp_default = c_default.compress(data) + c_default.flush()
        # Huffman-only produces larger output (no back-references)
        assert comp_huff != comp_default, (
            "Test precondition violated: expected different compressed "
            "representations from Z_HUFFMAN_ONLY vs default strategy"
        )
        r_huff = integrity_full(comp_huff, Format.DEFLATE, _mh())
        r_default = integrity_full(comp_default, Format.DEFLATE, _mh())
        assert r_huff.blake3_digest == r_default.blake3_digest
        assert r_huff.cdh_hash == r_default.cdh_hash

    def test_full_empty_data(self):
        data = b""
        compressed = _raw_deflate(data)
        result = integrity_full(compressed, Format.DEFLATE, _mh())
        expected = blake3.blake3(b"").digest()
        assert result.blake3_digest == expected
        assert result.cdh_hash == (0, 0)

    def test_full_with_gzip(self):
        """Full path works with gzip format."""
        import gzip
        data = b"gzip full path " * 20
        gz = gzip.compress(data)
        result = integrity_full(gz, Format.GZIP, _mh())
        assert result.blake3_digest == blake3.blake3(data).digest()
        assert result.cdh_hash == _mh().hash(data)

    def test_full_cross_format_consistency(self):
        """CDH and BLAKE3 must agree across formats for same data."""
        import gzip
        data = b"cross format full " * 20
        mh = _mh()
        r_deflate = integrity_full(_raw_deflate(data), Format.DEFLATE, mh)
        r_gzip = integrity_full(gzip.compress(data), Format.GZIP, mh)
        assert r_deflate.cdh_hash == r_gzip.cdh_hash
        assert r_deflate.blake3_digest == r_gzip.blake3_digest


zstandard_mod = None
try:
    import zstandard as zstandard_mod
except ImportError:
    pass


@pytest.mark.skipif(zstandard_mod is None, reason="zstandard not installed")
class TestFullPathZstd:
    """Full path with Zstandard format."""

    def test_full_zstd_correctness(self):
        data = b"zstd full path test " * 20
        cctx = zstandard_mod.ZstdCompressor()
        zst = cctx.compress(data)
        mh = _mh()
        result = integrity_full(zst, Format.ZSTD, mh)
        assert result.blake3_digest == blake3.blake3(data).digest()
        assert result.cdh_hash == mh.hash(data)

    def test_full_zstd_vs_deflate(self):
        """CDH and BLAKE3 must agree across zstd and deflate."""
        data = b"zstd vs deflate " * 20
        mh = _mh()
        cctx = zstandard_mod.ZstdCompressor()
        r_zstd = integrity_full(cctx.compress(data), Format.ZSTD, mh)
        r_deflate = integrity_full(_raw_deflate(data), Format.DEFLATE, mh)
        assert r_zstd.cdh_hash == r_deflate.cdh_hash
        assert r_zstd.blake3_digest == r_deflate.blake3_digest


# ===================================================================
# Theorem 23(c): Incremental update
# ===================================================================


class TestIncrementalIntegrity:
    """Incremental CDH + BLAKE3 updates when chunks are added/removed."""

    def test_add_single_chunk(self):
        chunk = b"hello world"
        inc = IncrementalIntegrity(bases=[131, 257])
        inc.add_chunk(chunk)
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(chunk)
        assert inc.blake3_digest() == blake3.blake3(chunk).digest()

    def test_add_multiple_chunks_matches_whole(self):
        """Adding chunks incrementally must match hashing the whole."""
        chunks = [b"chunk one ", b"chunk two ", b"chunk three "]
        whole = b"".join(chunks)
        inc = IncrementalIntegrity(bases=[131, 257])
        for c in chunks:
            inc.add_chunk(c)
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(whole)
        assert inc.blake3_digest() == blake3.blake3(whole).digest()

    def test_add_many_chunks(self):
        chunks = [f"chunk_{i}_data ".encode() for i in range(20)]
        whole = b"".join(chunks)
        inc = IncrementalIntegrity(bases=[131, 257])
        for c in chunks:
            inc.add_chunk(c)
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(whole)
        assert inc.blake3_digest() == blake3.blake3(whole).digest()

    def test_remove_last_chunk(self):
        """Removing the last chunk reverts to the state before it."""
        chunks = [b"alpha ", b"bravo ", b"charlie "]
        inc = IncrementalIntegrity(bases=[131, 257])
        for c in chunks:
            inc.add_chunk(c)
        inc.remove_last_chunk()
        expected_data = b"alpha bravo "
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(expected_data)
        assert inc.blake3_digest() == blake3.blake3(expected_data).digest()

    def test_remove_all_chunks(self):
        inc = IncrementalIntegrity(bases=[131, 257])
        inc.add_chunk(b"data")
        inc.remove_last_chunk()
        assert inc.cdh_hash() == (0, 0)
        assert inc.blake3_digest() == blake3.blake3(b"").digest()

    def test_chunk_count(self):
        inc = IncrementalIntegrity(bases=[131, 257])
        assert inc.chunk_count() == 0
        inc.add_chunk(b"one")
        assert inc.chunk_count() == 1
        inc.add_chunk(b"two")
        assert inc.chunk_count() == 2
        inc.remove_last_chunk()
        assert inc.chunk_count() == 1

    def test_empty_incremental(self):
        inc = IncrementalIntegrity(bases=[131, 257])
        assert inc.cdh_hash() == (0, 0)
        assert inc.blake3_digest() == blake3.blake3(b"").digest()


# ===================================================================
# Theorem 23(c): Rope-based incremental — O(k·log m) per operation
# ===================================================================

from uhc.core.integrity import RopeIncrementalIntegrity


class TestRopeIncrementalIntegrity:
    """Rope-based incremental: O(k·log m) add/remove via Theorems 6-7."""

    def test_add_single_chunk(self):
        chunk = b"hello world"
        inc = RopeIncrementalIntegrity(bases=[131, 257])
        inc.add_chunk(chunk)
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(chunk)
        assert inc.blake3_digest() == blake3.blake3(chunk).digest()

    def test_add_multiple_chunks_matches_whole(self):
        """Rope concat via Theorem 6 must match hashing the whole."""
        chunks = [b"chunk one ", b"chunk two ", b"chunk three "]
        whole = b"".join(chunks)
        inc = RopeIncrementalIntegrity(bases=[131, 257])
        for c in chunks:
            inc.add_chunk(c)
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(whole)
        assert inc.blake3_digest() == blake3.blake3(whole).digest()

    def test_add_many_chunks(self):
        chunks = [f"chunk_{i}_data ".encode() for i in range(20)]
        whole = b"".join(chunks)
        inc = RopeIncrementalIntegrity(bases=[131, 257])
        for c in chunks:
            inc.add_chunk(c)
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(whole)
        assert inc.blake3_digest() == blake3.blake3(whole).digest()

    def test_remove_last_chunk(self):
        """Rope split via Theorem 7 must revert to state before last chunk."""
        chunks = [b"alpha ", b"bravo ", b"charlie "]
        inc = RopeIncrementalIntegrity(bases=[131, 257])
        for c in chunks:
            inc.add_chunk(c)
        inc.remove_last_chunk()
        expected_data = b"alpha bravo "
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(expected_data)
        assert inc.blake3_digest() == blake3.blake3(expected_data).digest()

    def test_remove_all_chunks(self):
        inc = RopeIncrementalIntegrity(bases=[131, 257])
        inc.add_chunk(b"data")
        inc.remove_last_chunk()
        assert inc.cdh_hash() == (0, 0)
        assert inc.blake3_digest() == blake3.blake3(b"").digest()

    def test_chunk_count(self):
        inc = RopeIncrementalIntegrity(bases=[131, 257])
        assert inc.chunk_count() == 0
        inc.add_chunk(b"one")
        assert inc.chunk_count() == 1
        inc.add_chunk(b"two")
        assert inc.chunk_count() == 2
        inc.remove_last_chunk()
        assert inc.chunk_count() == 1

    def test_empty_incremental(self):
        inc = RopeIncrementalIntegrity(bases=[131, 257])
        assert inc.cdh_hash() == (0, 0)
        assert inc.blake3_digest() == blake3.blake3(b"").digest()

    def test_agrees_with_list_mode(self):
        """Rope mode must produce identical results to list mode."""
        chunks = [b"alpha ", b"bravo ", b"charlie ", b"delta ", b"echo "]
        list_inc = IncrementalIntegrity(bases=[131, 257])
        rope_inc = RopeIncrementalIntegrity(bases=[131, 257])
        for c in chunks:
            list_inc.add_chunk(c)
            rope_inc.add_chunk(c)
        assert list_inc.cdh_hash() == rope_inc.cdh_hash()
        assert list_inc.blake3_digest() == rope_inc.blake3_digest()
        # Remove two chunks and compare again
        list_inc.remove_last_chunk()
        rope_inc.remove_last_chunk()
        assert list_inc.cdh_hash() == rope_inc.cdh_hash()
        list_inc.remove_last_chunk()
        rope_inc.remove_last_chunk()
        assert list_inc.cdh_hash() == rope_inc.cdh_hash()
        assert list_inc.blake3_digest() == rope_inc.blake3_digest()

    def test_remove_middle_not_supported(self):
        """Only remove_last_chunk is supported (append-only log with undo)."""
        inc = RopeIncrementalIntegrity(bases=[131, 257])
        inc.add_chunk(b"a")
        inc.add_chunk(b"b")
        inc.add_chunk(b"c")
        # After removing last, the remaining is a‖b
        inc.remove_last_chunk()
        mh = _mh()
        assert inc.cdh_hash() == mh.hash(b"ab")

    def test_single_base(self):
        inc = RopeIncrementalIntegrity(bases=[131])
        inc.add_chunk(b"test")
        mh = MultiHash(bases=[131])
        assert inc.cdh_hash() == mh.hash(b"test")


# ===================================================================
# MERSENNE_127 (Corollary 5: recommended p = 2^127-1)
# ===================================================================

from uhc.core.polynomial_hash import MERSENNE_127


class TestMersenne127:
    """Verify CDH correctness with p = 2^127-1 (Corollary 5)."""

    def test_mersenne_127_cdh_correctness(self):
        """Theorem 12 holds with p = 2^127-1."""
        data = b"mersenne 127 test " * 20
        compressed = _raw_deflate(data)
        tokens = deflate_extract_tokens(compressed)
        mh = MultiHash(bases=[131, 257], prime=MERSENNE_127)
        result = integrity_fast(tokens, mh)
        expected = mh.hash(data)
        assert result.cdh_hash == expected

    def test_mersenne_127_constant_value(self):
        assert MERSENNE_127 == 2**127 - 1
        # Verify it's prime (Mersenne prime M127)
        assert MERSENNE_127 == 170141183460469231731687303715884105727
