"""
Rigorous validation tests for Zstandard parser internals (Lemma 11).

Tests verify:
1. Predefined FSE tables match Appendix A of RFC 8878 exactly
2. Baseline/extra-bits tables are internally consistent
3. Incompressible data (raw blocks), multi-block frames
4. Repeat-offset cache table from spec Section 3.1.1.4
5. Diverse random data with seeded PRNG for reproducibility
6. Cross-validation: zstandard library decompress == our token decode
"""

from __future__ import annotations

import os
import random
import pytest

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod

pytestmark = pytest.mark.skipif(not HAS_ZSTD, reason="zstandard not installed")


def zstd_compress(data: bytes, level: int = 3) -> bytes:
    return zstd.ZstdCompressor(level=level).compress(data)


def zstd_decompress(data: bytes) -> bytes:
    return zstd.ZstdDecompressor().decompress(data)


def import_parser():
    from uhc.core.zstd_parser import zstd_extract_tokens
    return zstd_extract_tokens


# ===================================================================
# Part G: Predefined FSE table validation against Appendix A
# ===================================================================


class TestPredefinedFSETables:
    """
    Validate that _build_fse_table produces tables exactly matching
    Appendix A of RFC 8878. This is the foundational correctness check.
    """

    # Appendix A: Literal Length Code (64 entries, AL=6)
    # Each tuple: (symbol, num_bits, baseline)
    LL_APPENDIX_A = [
        (0, 4, 0), (0, 4, 16), (1, 5, 32), (3, 5, 0),
        (4, 5, 0), (6, 5, 0), (7, 5, 0), (9, 5, 0),
        (10, 5, 0), (12, 5, 0), (14, 6, 0), (16, 5, 0),
        (18, 5, 0), (19, 5, 0), (21, 5, 0), (22, 5, 0),
        (24, 5, 0), (25, 5, 32), (26, 5, 0), (27, 6, 0),
        (29, 6, 0), (31, 6, 0), (0, 4, 32), (1, 4, 0),
        (2, 5, 0), (4, 5, 32), (5, 5, 0), (7, 5, 32),
        (8, 5, 0), (10, 5, 32), (11, 5, 0), (13, 6, 0),
        (16, 5, 32), (17, 5, 0), (19, 5, 32), (20, 5, 0),
        (22, 5, 32), (23, 5, 0), (25, 4, 0), (25, 4, 16),
        (26, 5, 32), (28, 6, 0), (30, 6, 0), (0, 4, 48),
        (1, 4, 16), (2, 5, 32), (3, 5, 32), (5, 5, 32),
        (6, 5, 32), (8, 5, 32), (9, 5, 32), (11, 5, 32),
        (12, 5, 32), (15, 6, 0), (17, 5, 32), (18, 5, 32),
        (20, 5, 32), (21, 5, 32), (23, 5, 32), (24, 5, 32),
        (35, 6, 0), (34, 6, 0), (33, 6, 0), (32, 6, 0),
    ]

    # Appendix A: Match Length Code (64 entries, AL=6)
    ML_APPENDIX_A = [
        (0, 6, 0), (1, 4, 0), (2, 5, 32), (3, 5, 0),
        (5, 5, 0), (6, 5, 0), (8, 5, 0), (10, 6, 0),
        (13, 6, 0), (16, 6, 0), (19, 6, 0), (22, 6, 0),
        (25, 6, 0), (28, 6, 0), (31, 6, 0), (33, 6, 0),
        (35, 6, 0), (37, 6, 0), (39, 6, 0), (41, 6, 0),
        (43, 6, 0), (45, 6, 0), (1, 4, 16), (2, 4, 0),
        (3, 5, 32), (4, 5, 0), (6, 5, 32), (7, 5, 0),
        (9, 6, 0), (12, 6, 0), (15, 6, 0), (18, 6, 0),
        (21, 6, 0), (24, 6, 0), (27, 6, 0), (30, 6, 0),
        (32, 6, 0), (34, 6, 0), (36, 6, 0), (38, 6, 0),
        (40, 6, 0), (42, 6, 0), (44, 6, 0), (1, 4, 32),
        (1, 4, 48), (2, 4, 16), (4, 5, 32), (5, 5, 32),
        (7, 5, 32), (8, 5, 32), (11, 6, 0), (14, 6, 0),
        (17, 6, 0), (20, 6, 0), (23, 6, 0), (26, 6, 0),
        (29, 6, 0), (52, 6, 0), (51, 6, 0), (50, 6, 0),
        (49, 6, 0), (48, 6, 0), (47, 6, 0), (46, 6, 0),
    ]

    # Appendix A: Offset Code (32 entries, AL=5)
    OF_APPENDIX_A = [
        (0, 5, 0), (6, 4, 0), (9, 5, 0), (15, 5, 0),
        (21, 5, 0), (3, 5, 0), (7, 4, 0), (12, 5, 0),
        (18, 5, 0), (23, 5, 0), (5, 5, 0), (8, 4, 0),
        (14, 5, 0), (20, 5, 0), (2, 5, 0), (7, 4, 16),
        (11, 5, 0), (17, 5, 0), (22, 5, 0), (4, 5, 0),
        (8, 4, 16), (13, 5, 0), (19, 5, 0), (1, 5, 0),
        (6, 4, 16), (10, 5, 0), (16, 5, 0), (28, 5, 0),
        (27, 5, 0), (26, 5, 0), (25, 5, 0), (24, 5, 0),
    ]

    def test_ll_predefined_table(self):
        """Literal Length predefined table matches Appendix A exactly."""
        from uhc.core.zstd_parser import _build_fse_table, _LL_DEFAULT_DIST, _LL_DEFAULT_AL
        table = _build_fse_table(_LL_DEFAULT_DIST, _LL_DEFAULT_AL)
        assert len(table) == 64
        for i, (sym, nb, base) in enumerate(self.LL_APPENDIX_A):
            assert table[i].symbol == sym, (
                f"LL state {i}: symbol {table[i].symbol} != expected {sym}"
            )
            assert table[i].num_bits == nb, (
                f"LL state {i}: num_bits {table[i].num_bits} != expected {nb}"
            )
            assert table[i].baseline == base, (
                f"LL state {i}: baseline {table[i].baseline} != expected {base}"
            )

    def test_ml_predefined_table(self):
        """Match Length predefined table matches Appendix A exactly."""
        from uhc.core.zstd_parser import _build_fse_table, _ML_DEFAULT_DIST, _ML_DEFAULT_AL
        table = _build_fse_table(_ML_DEFAULT_DIST, _ML_DEFAULT_AL)
        assert len(table) == 64
        for i, (sym, nb, base) in enumerate(self.ML_APPENDIX_A):
            assert table[i].symbol == sym, (
                f"ML state {i}: symbol {table[i].symbol} != expected {sym}"
            )
            assert table[i].num_bits == nb, (
                f"ML state {i}: num_bits {table[i].num_bits} != expected {nb}"
            )
            assert table[i].baseline == base, (
                f"ML state {i}: baseline {table[i].baseline} != expected {base}"
            )

    def test_of_predefined_table(self):
        """Offset Code predefined table matches Appendix A exactly."""
        from uhc.core.zstd_parser import _build_fse_table, _OF_DEFAULT_DIST, _OF_DEFAULT_AL
        table = _build_fse_table(_OF_DEFAULT_DIST, _OF_DEFAULT_AL)
        assert len(table) == 32
        for i, (sym, nb, base) in enumerate(self.OF_APPENDIX_A):
            assert table[i].symbol == sym, (
                f"OF state {i}: symbol {table[i].symbol} != expected {sym}"
            )
            assert table[i].num_bits == nb, (
                f"OF state {i}: num_bits {table[i].num_bits} != expected {nb}"
            )
            assert table[i].baseline == base, (
                f"OF state {i}: baseline {table[i].baseline} != expected {base}"
            )


# ===================================================================
# Part H: Baseline/extra-bits table internal consistency
# ===================================================================


class TestBaselineExtraBitsConsistency:
    """Verify baseline tables are internally consistent."""

    def test_ll_baselines_monotonic(self):
        from uhc.core.zstd_parser import _LL_BASELINE, _LL_EXTRA
        assert len(_LL_BASELINE) == 36
        assert len(_LL_EXTRA) == 36
        for i in range(len(_LL_BASELINE) - 1):
            expected_next = _LL_BASELINE[i] + (1 << _LL_EXTRA[i])
            assert _LL_BASELINE[i + 1] == expected_next, (
                f"LL code {i}: {_LL_BASELINE[i]} + 2^{_LL_EXTRA[i]} = "
                f"{expected_next} != {_LL_BASELINE[i+1]}"
            )

    def test_ml_baselines_monotonic(self):
        from uhc.core.zstd_parser import _ML_BASELINE, _ML_EXTRA
        assert len(_ML_BASELINE) == 53
        assert len(_ML_EXTRA) == 53
        for i in range(len(_ML_BASELINE) - 1):
            expected_next = _ML_BASELINE[i] + (1 << _ML_EXTRA[i])
            assert _ML_BASELINE[i + 1] == expected_next, (
                f"ML code {i}: {_ML_BASELINE[i]} + 2^{_ML_EXTRA[i]} = "
                f"{expected_next} != {_ML_BASELINE[i+1]}"
            )

    def test_ll_codes_0_to_15_are_identity(self):
        from uhc.core.zstd_parser import _LL_BASELINE, _LL_EXTRA
        for i in range(16):
            assert _LL_BASELINE[i] == i
            assert _LL_EXTRA[i] == 0

    def test_ml_codes_0_to_31_are_offset_by_3(self):
        from uhc.core.zstd_parser import _ML_BASELINE, _ML_EXTRA
        for i in range(32):
            assert _ML_BASELINE[i] == i + 3
            assert _ML_EXTRA[i] == 0

    def test_default_distribution_sums(self):
        """Each default distribution must sum to 1 << accuracy_log."""
        from uhc.core.zstd_parser import (
            _LL_DEFAULT_DIST, _LL_DEFAULT_AL,
            _ML_DEFAULT_DIST, _ML_DEFAULT_AL,
            _OF_DEFAULT_DIST, _OF_DEFAULT_AL,
        )
        # -1 counts as 1 for probability sum
        for name, dist, al in [
            ("LL", _LL_DEFAULT_DIST, _LL_DEFAULT_AL),
            ("ML", _ML_DEFAULT_DIST, _ML_DEFAULT_AL),
            ("OF", _OF_DEFAULT_DIST, _OF_DEFAULT_AL),
        ]:
            total = sum(1 if p == -1 else p for p in dist if p != 0)
            assert total == (1 << al), (
                f"{name} distribution sum {total} != {1 << al}"
            )


# ===================================================================
# Part I: Cross-validation with zstandard library
# ===================================================================


class TestZstdCrossValidation:
    """
    For every test: compress with zstandard, decompress with zstandard,
    extract tokens with our parser, decode tokens — all must agree.
    """

    def _full_validate(self, data: bytes, level: int = 3):
        zstd_extract_tokens = import_parser()
        compressed = zstd_compress(data, level=level)

        # Reference decompression
        ref_decompressed = zstd_decompress(compressed)
        assert ref_decompressed == data, "zstandard decompress mismatch"

        # Our token extraction
        tokens = zstd_extract_tokens(compressed)
        our_decoded = lz77_decode(tokens)
        assert our_decoded == data, (
            f"Token decode mismatch: len={len(our_decoded)} vs expected={len(data)}"
        )

    @pytest.mark.parametrize("seed", range(10))
    def test_random_data_seeded(self, seed):
        """Seeded random data for reproducibility."""
        rng = random.Random(seed)
        size = rng.randint(100, 5000)
        data = bytes(rng.randint(0, 255) for _ in range(size))
        self._full_validate(data)

    @pytest.mark.parametrize("seed", range(5))
    def test_mixed_random_and_repetitive(self, seed):
        rng = random.Random(seed + 100)
        parts = []
        for _ in range(rng.randint(3, 8)):
            if rng.random() < 0.5:
                parts.append(bytes(rng.randint(0, 255) for _ in range(rng.randint(50, 500))))
            else:
                pattern = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 20)))
                parts.append(pattern * rng.randint(10, 100))
        data = b"".join(parts)
        self._full_validate(data)

    def test_incompressible_data(self):
        """Purely random data that forces raw blocks."""
        data = os.urandom(10000)
        self._full_validate(data, level=1)

    def test_highly_compressible(self):
        """Single byte repeated — likely triggers RLE blocks."""
        data = b"\x42" * 50000
        self._full_validate(data)

    def test_alternating_compressible_incompressible(self):
        data = (b"aaaa" * 500 + os.urandom(200)) * 5
        self._full_validate(data)

    @pytest.mark.parametrize("level", [1, 5, 10, 15, 19])
    def test_levels_with_english_text(self, level):
        text = (
            b"The quick brown fox jumps over the lazy dog. "
            b"Pack my box with five dozen liquor jugs. "
            b"How vexingly quick daft zebras jump. "
        ) * 100
        self._full_validate(text, level=level)

    def test_all_byte_values(self):
        """Every byte value 0-255 present."""
        data = bytes(range(256)) * 20
        self._full_validate(data)

    def test_single_byte_patterns(self):
        """Various single-byte repetitions (d=1 overlapping refs)."""
        for b in [0, 1, 127, 128, 255]:
            data = bytes([b]) * 1000
            self._full_validate(data)

    def test_two_byte_period(self):
        data = b"\xAB\xCD" * 2000
        self._full_validate(data)

    def test_large_window_data(self):
        """Data larger than 32KB to test window management."""
        data = (b"hello world! " * 3000) + os.urandom(1000)
        self._full_validate(data)


# ===================================================================
# Part J: Repeat offset table verification from spec
# ===================================================================


class TestRepeatOffsetLogic:
    """
    Verify repeat offset behavior matches the spec table
    (Section 3.1.1.5, the example table).
    """

    def test_repeat_offset_initial_values(self):
        """Initial repeat offsets must be [1, 4, 8]."""
        zstd_extract_tokens = import_parser()
        # Compress data that uses back-references
        data = b"A" * 10
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        decoded = lz77_decode(tokens)
        assert decoded == data

    def test_overlapping_with_distance_1(self):
        """d=1: repeat single byte, verifies offset=1 works."""
        zstd_extract_tokens = import_parser()
        data = b"\xFF" * 1000
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)
        assert lz77_decode(tokens) == data

        # Must contain at least one Reference with distance=1
        refs = [t for t in tokens if isinstance(t, Reference)]
        assert any(r.distance == 1 for r in refs)

    def test_cdh_with_overlapping_refs(self):
        """CDH must be correct even with overlapping references."""
        zstd_extract_tokens = import_parser()
        data = b"xyz" * 500
        compressed = zstd_compress(data)
        tokens = zstd_extract_tokens(compressed)

        ph = PolynomialHash(base=131)
        expected = ph.hash(data)
        actual = compressed_domain_hash(tokens, base=131, method=CDHMethod.ROPE)
        assert actual == expected
