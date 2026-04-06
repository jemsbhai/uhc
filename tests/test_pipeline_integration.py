"""
End-to-end pipeline integration tests.

Validates the full UHC flow:
    data → CDC chunk → compress (DEFLATE/LZ4) → extract tokens → CDH → compose

The key property (derived from Theorem 1 + Theorem 12):
    For any data split into chunks C_1, ..., C_m:
        H(data) = compose(CDH(tokens(compress(C_1))), ..., CDH(tokens(compress(C_m))))

    where compose applies Theorem 1 iteratively:
        H(A‖B) = H(A)·x^|B| + H(B)

This proves that:
1. Chunking is transparent to hashing (Theorem 1)
2. Compression is transparent to hashing (Theorem 12)
3. The pipeline produces the same hash as direct hashing
4. Multi-hash (Theorem 21) works end-to-end
"""

from __future__ import annotations

import os
import random
import zlib
import pytest
import lz4.block

from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod
from uhc.core.deflate import deflate_extract_tokens
from uhc.core.lz4_parser import lz4_extract_tokens
from uhc.core.multihash import MultiHash, multi_cdh
from uhc.chunking.cdc import cdc_chunk


# ===================================================================
# Helpers
# ===================================================================

def _rng_bytes(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def raw_deflate(data: bytes, level: int = 6) -> bytes:
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def pipeline_hash_deflate(
    data: bytes, h: PolynomialHash, level: int = 6
) -> int:
    """Full pipeline: CDC → DEFLATE compress → extract tokens → CDH → compose."""
    chunks = cdc_chunk(data)
    running = 0
    for chunk in chunks:
        compressed = raw_deflate(chunk, level=level)
        tokens = deflate_extract_tokens(compressed)
        chunk_hash = compressed_domain_hash(
            tokens, prime=h.prime, base=h.base, method=CDHMethod.ROPE
        )
        running = h.hash_concat(running, len(chunk), chunk_hash)
    return running


def pipeline_hash_lz4(data: bytes, h: PolynomialHash) -> int:
    """Full pipeline: CDC → LZ4 compress → extract tokens → CDH → compose."""
    chunks = cdc_chunk(data)
    running = 0
    for chunk in chunks:
        compressed = lz4.block.compress(chunk, store_size=False)
        tokens = lz4_extract_tokens(compressed)
        chunk_hash = compressed_domain_hash(
            tokens, prime=h.prime, base=h.base, method=CDHMethod.ROPE
        )
        running = h.hash_concat(running, len(chunk), chunk_hash)
    return running


def pipeline_hash_multihash_deflate(
    data: bytes, mh: MultiHash, level: int = 6
) -> tuple[int, ...]:
    """Full pipeline with k-tuple multi-hash over DEFLATE."""
    chunks = cdc_chunk(data)
    running = mh.zero()
    for chunk in chunks:
        compressed = raw_deflate(chunk, level=level)
        tokens = deflate_extract_tokens(compressed)
        chunk_hash = multi_cdh(tokens, mh)
        running = mh.hash_concat(running, len(chunk), chunk_hash)
    return running


# ===================================================================
# Part A: Core pipeline correctness
# ===================================================================


class TestPipelineCorrectness:
    """pipeline_hash(data) == H(data) for all inputs."""

    def test_deflate_short(self):
        h = PolynomialHash(base=131)
        data = b"hello world pipeline test"
        assert pipeline_hash_deflate(data, h) == h.hash(data)

    def test_lz4_short(self):
        h = PolynomialHash(base=131)
        data = b"hello world pipeline test"
        assert pipeline_hash_lz4(data, h) == h.hash(data)

    def test_deflate_repeated(self):
        h = PolynomialHash(base=131)
        data = b"the quick brown fox " * 100
        assert pipeline_hash_deflate(data, h) == h.hash(data)

    def test_lz4_repeated(self):
        h = PolynomialHash(base=131)
        data = b"the quick brown fox " * 100
        assert pipeline_hash_lz4(data, h) == h.hash(data)

    def test_deflate_binary(self):
        h = PolynomialHash(base=131)
        data = bytes(range(256)) * 20
        assert pipeline_hash_deflate(data, h) == h.hash(data)

    def test_lz4_binary(self):
        h = PolynomialHash(base=131)
        data = bytes(range(256)) * 20
        assert pipeline_hash_lz4(data, h) == h.hash(data)

    def test_deflate_all_same(self):
        h = PolynomialHash(base=131)
        data = b"\xaa" * 10_000
        assert pipeline_hash_deflate(data, h) == h.hash(data)

    def test_lz4_all_same(self):
        h = PolynomialHash(base=131)
        data = b"\xaa" * 10_000
        assert pipeline_hash_lz4(data, h) == h.hash(data)


# ===================================================================
# Part B: Cross-format consistency
# ===================================================================


class TestCrossFormat:
    """DEFLATE and LZ4 pipelines produce the same hash for the same data."""

    @pytest.mark.parametrize("seed", range(5))
    def test_deflate_equals_lz4(self, seed):
        h = PolynomialHash(base=131)
        data = _rng_bytes(seed + 2000, 20_000)

        h_deflate = pipeline_hash_deflate(data, h)
        h_lz4 = pipeline_hash_lz4(data, h)

        assert h_deflate == h_lz4 == h.hash(data)


# ===================================================================
# Part C: Multi-hash pipeline (Theorem 21)
# ===================================================================


class TestPipelineMultiHash:
    """k-tuple pipeline: CDC → compress → CDH^(k) → compose."""

    def test_k2_deflate_pipeline(self):
        mh = MultiHash(bases=[131, 257])
        data = b"multihash pipeline test " * 50
        result = pipeline_hash_multihash_deflate(data, mh)
        assert result == mh.hash(data)

    def test_k3_deflate_pipeline(self):
        mh = MultiHash(bases=[131, 257, 509])
        data = _rng_bytes(3000, 30_000)
        result = pipeline_hash_multihash_deflate(data, mh)
        assert result == mh.hash(data)


# ===================================================================
# Part D: Sliding rope pipeline (bounded memory)
# ===================================================================


class TestPipelineSlidingRope:
    """Pipeline using sliding rope CDH for bounded memory."""

    def test_deflate_sliding(self):
        h = PolynomialHash(base=131)
        data = b"sliding rope pipeline " * 100

        chunks = cdc_chunk(data)
        running = 0
        for chunk in chunks:
            compressed = raw_deflate(chunk)
            tokens = deflate_extract_tokens(compressed)
            chunk_hash = compressed_domain_hash(
                tokens, prime=h.prime, base=h.base,
                method=CDHMethod.SLIDING_ROPE,
                d_max=32768, m_max=258,
            )
            running = h.hash_concat(running, len(chunk), chunk_hash)

        assert running == h.hash(data)

    def test_lz4_sliding(self):
        h = PolynomialHash(base=131)
        data = b"sliding lz4 pipeline " * 100

        chunks = cdc_chunk(data)
        running = 0
        for chunk in chunks:
            compressed = lz4.block.compress(chunk, store_size=False)
            tokens = lz4_extract_tokens(compressed)
            chunk_hash = compressed_domain_hash(
                tokens, prime=h.prime, base=h.base,
                method=CDHMethod.SLIDING_ROPE,
                d_max=65535, m_max=65536,
            )
            running = h.hash_concat(running, len(chunk), chunk_hash)

        assert running == h.hash(data)


# ===================================================================
# Part E: Randomized end-to-end
# ===================================================================


class TestPipelineRandomized:
    """Randomized full-pipeline tests with seeded RNG."""

    @pytest.mark.parametrize("seed", range(10))
    def test_random_deflate_pipeline(self, seed):
        h = PolynomialHash(base=131)
        size = random.Random(seed).randint(100, 50_000)
        data = _rng_bytes(seed + 5000, size)
        assert pipeline_hash_deflate(data, h) == h.hash(data)

    @pytest.mark.parametrize("seed", range(10))
    def test_random_lz4_pipeline(self, seed):
        h = PolynomialHash(base=131)
        size = random.Random(seed).randint(100, 50_000)
        data = _rng_bytes(seed + 6000, size)
        assert pipeline_hash_lz4(data, h) == h.hash(data)

    @pytest.mark.parametrize("level", [1, 6, 9])
    def test_deflate_levels(self, level):
        h = PolynomialHash(base=131)
        data = _rng_bytes(7000, 30_000)
        assert pipeline_hash_deflate(data, h, level=level) == h.hash(data)


# ===================================================================
# Part F: Deduplication scenario
# ===================================================================


class TestDeduplication:
    """
    Simulate a dedup scenario: two files sharing content.
    CDC + CDH should identify shared chunks by hash.
    """

    def test_shared_chunks_detected(self):
        h = PolynomialHash(base=131)

        shared_block = _rng_bytes(8000, 30_000)
        file_a = _rng_bytes(8001, 10_000) + shared_block + _rng_bytes(8002, 10_000)
        file_b = _rng_bytes(8003, 15_000) + shared_block + _rng_bytes(8004, 5_000)

        chunks_a = cdc_chunk(file_a)
        chunks_b = cdc_chunk(file_b)

        # Hash each chunk via CDH over DEFLATE
        def chunk_hashes(chunks):
            result = {}
            for chunk in chunks:
                compressed = raw_deflate(chunk)
                tokens = deflate_extract_tokens(compressed)
                ch = compressed_domain_hash(
                    tokens, prime=h.prime, base=h.base, method=CDHMethod.ROPE
                )
                result[ch] = chunk
            return result

        hashes_a = chunk_hashes(chunks_a)
        hashes_b = chunk_hashes(chunks_b)

        # Shared chunks should have matching hashes
        shared_hashes = set(hashes_a.keys()) & set(hashes_b.keys())
        assert len(shared_hashes) > 0, "Shared content should produce shared chunk hashes"

        # Verify shared hashes correspond to identical content
        for sh in shared_hashes:
            assert hashes_a[sh] == hashes_b[sh]

    def test_whole_file_hash_consistent(self):
        """Both files hash correctly despite shared chunks."""
        h = PolynomialHash(base=131)

        shared = _rng_bytes(9000, 20_000)
        file_a = _rng_bytes(9001, 10_000) + shared
        file_b = shared + _rng_bytes(9002, 10_000)

        assert pipeline_hash_deflate(file_a, h) == h.hash(file_a)
        assert pipeline_hash_deflate(file_b, h) == h.hash(file_b)
        # And they should differ (different files)
        assert h.hash(file_a) != h.hash(file_b)
