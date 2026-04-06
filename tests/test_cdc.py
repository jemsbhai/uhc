"""
Tests for Content-Defined Chunking (CDC).

CDC splits data into variable-size chunks at content-determined boundaries,
enabling deduplication. Uses a Gear-based rolling hash (FastCDC approach,
reference 9 in the framework).

Tests verify:
1. Chunk boundaries are deterministic and content-defined
2. Concatenation of chunks == original data
3. Chunk sizes respect min/max constraints
4. Average chunk size is statistically near the target
5. Identical content produces identical chunks regardless of position
6. Integration with polynomial hash and multi-hash

Note: CDC is an engineering component, not derived from a specific theorem.
Rigor here means empirical correctness and property-based testing.
"""

from __future__ import annotations

import os
import random
import pytest


# Seeded RNG for reproducibility
def _rng_bytes(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


# ===================================================================
# Part A: Basic chunking properties
# ===================================================================


class TestCDCBasic:

    def test_empty_input(self):
        from uhc.chunking.cdc import cdc_chunk
        chunks = cdc_chunk(b"")
        assert chunks == []

    def test_single_byte(self):
        from uhc.chunking.cdc import cdc_chunk
        chunks = cdc_chunk(b"A")
        assert len(chunks) == 1
        assert chunks[0] == b"A"

    def test_concatenation_equals_original(self):
        """Fundamental property: joining all chunks reproduces input."""
        from uhc.chunking.cdc import cdc_chunk
        data = _rng_bytes(42, 10000)
        chunks = cdc_chunk(data)
        assert b"".join(chunks) == data

    def test_deterministic(self):
        """Same input always produces same chunks."""
        from uhc.chunking.cdc import cdc_chunk
        data = _rng_bytes(99, 5000)
        assert cdc_chunk(data) == cdc_chunk(data)

    def test_multiple_chunks_produced(self):
        """Sufficiently large data produces more than one chunk."""
        from uhc.chunking.cdc import cdc_chunk
        data = _rng_bytes(7, 100_000)
        chunks = cdc_chunk(data)
        assert len(chunks) > 1

    def test_min_chunk_size_respected(self):
        """No chunk smaller than min_size (except possibly the last)."""
        from uhc.chunking.cdc import cdc_chunk
        data = _rng_bytes(10, 50_000)
        min_size = 2048
        chunks = cdc_chunk(data, min_size=min_size)
        for chunk in chunks[:-1]:
            assert len(chunk) >= min_size

    def test_max_chunk_size_respected(self):
        """No chunk larger than max_size."""
        from uhc.chunking.cdc import cdc_chunk
        data = _rng_bytes(11, 50_000)
        max_size = 8192
        chunks = cdc_chunk(data, max_size=max_size)
        for chunk in chunks:
            assert len(chunk) <= max_size

    def test_custom_sizes(self):
        """Custom min/avg/max sizes work."""
        from uhc.chunking.cdc import cdc_chunk
        data = _rng_bytes(12, 100_000)
        chunks = cdc_chunk(data, min_size=1024, avg_size=4096, max_size=16384)
        total = sum(len(c) for c in chunks)
        assert total == len(data)
        for chunk in chunks:
            assert len(chunk) <= 16384
        for chunk in chunks[:-1]:
            assert len(chunk) >= 1024


# ===================================================================
# Part B: Average chunk size (statistical)
# ===================================================================


class TestCDCAverageSize:
    """Verify that the average chunk size is statistically near the target."""

    @pytest.mark.parametrize("avg_target", [4096, 8192, 16384])
    def test_average_within_factor_of_2(self, avg_target):
        """
        Over 1MB of random data, actual average chunk size should be
        within a factor of 2 of the target. This is a loose bound to
        avoid flaky tests while still catching gross miscalibration.
        """
        from uhc.chunking.cdc import cdc_chunk

        data = _rng_bytes(avg_target, 1_000_000)
        chunks = cdc_chunk(data, min_size=avg_target // 4,
                           avg_size=avg_target,
                           max_size=avg_target * 4)

        avg_actual = len(data) / len(chunks)
        assert avg_target / 2 < avg_actual < avg_target * 2, (
            f"Average chunk size {avg_actual:.0f} is too far from "
            f"target {avg_target}"
        )


# ===================================================================
# Part C: Content-defined boundary property
# ===================================================================


class TestCDCContentDefined:

    def test_insertion_only_affects_adjacent_chunks(self):
        """
        Core CDC property: inserting data in the middle should only
        change chunks near the insertion point.
        """
        from uhc.chunking.cdc import cdc_chunk

        base = _rng_bytes(100, 50_000)
        insert_pos = 25_000
        insertion = b"INSERTED_DATA_HERE"
        modified = base[:insert_pos] + insertion + base[insert_pos:]

        chunks_original = cdc_chunk(base)
        chunks_modified = cdc_chunk(modified)

        original_set = set(chunks_original)
        modified_set = set(chunks_modified)
        shared = original_set & modified_set

        assert len(shared) > 0, "CDC should preserve chunks away from edit point"

    def test_append_preserves_existing_chunks(self):
        """Appending data should not change existing chunk boundaries."""
        from uhc.chunking.cdc import cdc_chunk

        base = _rng_bytes(200, 50_000)
        extended = base + _rng_bytes(201, 10_000)

        chunks_base = cdc_chunk(base)
        chunks_extended = cdc_chunk(extended)

        # All original chunks except possibly the last should appear
        # in the extended chunking
        for chunk in chunks_base[:-1]:
            assert chunk in chunks_extended, "Append should not affect earlier chunks"

    def test_identical_content_different_context(self):
        """Same content block produces same internal chunk boundaries."""
        from uhc.chunking.cdc import cdc_chunk

        common = _rng_bytes(300, 20_000)
        suffix = _rng_bytes(301, 20_000)

        data_a = _rng_bytes(302, 20_000) + common + suffix
        data_b = _rng_bytes(303, 30_000) + common + suffix

        chunks_a = set(cdc_chunk(data_a))
        chunks_b = set(cdc_chunk(data_b))

        shared = chunks_a & chunks_b
        assert len(shared) > 0


# ===================================================================
# Part D: Integration with polynomial hash
# ===================================================================


class TestCDCHashIntegration:

    def test_chunk_hashes_are_deterministic(self):
        from uhc.chunking.cdc import cdc_chunk
        from uhc.core.polynomial_hash import PolynomialHash

        h = PolynomialHash(base=131)
        data = _rng_bytes(400, 20_000)
        chunks = cdc_chunk(data)

        hashes = [h.hash(c) for c in chunks]
        hashes2 = [h.hash(c) for c in cdc_chunk(data)]
        assert hashes == hashes2

    def test_multihash_over_chunks(self):
        """k-tuple hash of each chunk for stronger dedup guarantees."""
        from uhc.chunking.cdc import cdc_chunk
        from uhc.core.multihash import MultiHash

        mh = MultiHash(bases=[131, 257])
        data = _rng_bytes(500, 20_000)
        chunks = cdc_chunk(data)

        hashes = [mh.hash(c) for c in chunks]
        assert all(isinstance(h, tuple) and len(h) == 2 for h in hashes)

    def test_whole_file_hash_from_chunks(self):
        """
        H(file) can be reconstructed from chunk hashes via Theorem 1
        (concatenation composability).
        """
        from uhc.chunking.cdc import cdc_chunk
        from uhc.core.polynomial_hash import PolynomialHash

        h = PolynomialHash(base=131)
        data = _rng_bytes(600, 30_000)
        chunks = cdc_chunk(data)

        # Compose chunk hashes via Theorem 1
        running = 0
        for chunk in chunks:
            chunk_hash = h.hash(chunk)
            running = h.hash_concat(running, len(chunk), chunk_hash)

        assert running == h.hash(data)


# ===================================================================
# Part E: Edge cases
# ===================================================================


class TestCDCEdgeCases:

    def test_data_smaller_than_min_size(self):
        from uhc.chunking.cdc import cdc_chunk
        data = b"short"
        chunks = cdc_chunk(data, min_size=4096)
        assert len(chunks) == 1
        assert chunks[0] == data

    def test_data_exactly_max_size(self):
        from uhc.chunking.cdc import cdc_chunk
        data = _rng_bytes(700, 8192)
        chunks = cdc_chunk(data, max_size=8192)
        total = sum(len(c) for c in chunks)
        assert total == len(data)

    def test_all_zeros(self):
        from uhc.chunking.cdc import cdc_chunk
        data = b"\x00" * 50_000
        chunks = cdc_chunk(data)
        assert b"".join(chunks) == data

    def test_all_ones(self):
        from uhc.chunking.cdc import cdc_chunk
        data = b"\xff" * 50_000
        chunks = cdc_chunk(data)
        assert b"".join(chunks) == data

    @pytest.mark.parametrize("size", [100, 1000, 10000, 100000])
    def test_various_sizes_roundtrip(self, size):
        from uhc.chunking.cdc import cdc_chunk
        data = _rng_bytes(size, size)
        chunks = cdc_chunk(data)
        assert b"".join(chunks) == data

    def test_invalid_size_params(self):
        from uhc.chunking.cdc import cdc_chunk
        with pytest.raises(ValueError):
            cdc_chunk(b"data", min_size=8192, max_size=4096)
        with pytest.raises(ValueError):
            cdc_chunk(b"data", min_size=0)

    @pytest.mark.parametrize("seed", range(10))
    def test_seeded_random_roundtrip(self, seed):
        """Seeded randomized testing for broad coverage."""
        from uhc.chunking.cdc import cdc_chunk
        rng = random.Random(seed)
        size = rng.randint(1, 50_000)
        data = _rng_bytes(seed + 1000, size)
        chunks = cdc_chunk(data)
        assert b"".join(chunks) == data
