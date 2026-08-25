"""
Cross-format verification matrix tests.

Proves Theorem 12 across the FULL format matrix:
    For any two formats F_a, F_b and any data T:
        CDH(F_a(T)) = CDH(F_b(T)) = H(T)

This is the most important practical claim of UHC: you can verify
that two files compressed with different schemes contain identical
content, without decompressing either file.

The test matrix covers:
    Formats: raw, deflate, gzip, lz4_block, lz4_frame, zstd, zip
    Sizes:   tiny (11B), small (1KB), medium (64KB), large (256KB)
    Data:    text-like, binary, repetitive, mixed

Every pair (F_a, F_b) × every size × every data pattern is tested.
"""

from __future__ import annotations

import gzip
import io
import itertools
import os
import sys
import tempfile
import zlib
import zipfile
import pytest

from uhc.cli import main
from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod
from uhc.core.lz77 import lz77_decode
from uhc.core.zip_parser import zip_list_entries, zip_entry_extract_tokens
from uhc.engine.pipeline import extract_tokens, Format
from uhc.core.multihash import MultiHash, multi_cdh


# ===================================================================
# Optional format imports
# ===================================================================

try:
    import lz4.block
    import lz4.frame
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

try:
    import zstandard
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

LZ4_SKIP_REASON = (
    "LZ4 matrix coverage requires the optional 'lz4' binding; "
    "install with: python -m pip install -e '.[dev,formats]'"
)
ZSTD_SKIP_REASON = (
    "Zstandard matrix coverage requires the optional 'zstandard' binding; "
    "install with: python -m pip install -e '.[dev,formats]'"
)


# ===================================================================
# Compression helpers — one per format
# ===================================================================

def _compress_raw(data: bytes) -> tuple[bytes, Format]:
    return data, Format.RAW


def _compress_deflate(data: bytes) -> tuple[bytes, Format]:
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush(), Format.DEFLATE


def _compress_gzip(data: bytes) -> tuple[bytes, Format]:
    return gzip.compress(data), Format.GZIP


def _compress_lz4_block(data: bytes) -> tuple[bytes, Format]:
    return lz4.block.compress(data, store_size=False), Format.LZ4_BLOCK


def _compress_lz4_frame(data: bytes) -> tuple[bytes, Format]:
    return lz4.frame.compress(data), Format.LZ4_FRAME


def _compress_zstd(data: bytes) -> tuple[bytes, Format]:
    cctx = zstandard.ZstdCompressor(level=3)
    return cctx.compress(data), Format.ZSTD


# Build the format list dynamically based on what's installed
FORMATS = [
    ("raw", _compress_raw),
    ("deflate", _compress_deflate),
    ("gzip", _compress_gzip),
]
if HAS_LZ4:
    FORMATS.append(("lz4_block", _compress_lz4_block))
    FORMATS.append(("lz4_frame", _compress_lz4_frame))
if HAS_ZSTD:
    FORMATS.append(("zstd", _compress_zstd))

FORMAT_NAMES = [name for name, _ in FORMATS]

OPTIONAL_FORMAT_CASES = [
    pytest.param(
        "lz4_block",
        _compress_lz4_block,
        marks=pytest.mark.skipif(not HAS_LZ4, reason=LZ4_SKIP_REASON),
    ),
    pytest.param(
        "lz4_frame",
        _compress_lz4_frame,
        marks=pytest.mark.skipif(not HAS_LZ4, reason=LZ4_SKIP_REASON),
    ),
    pytest.param(
        "zstd",
        _compress_zstd,
        marks=pytest.mark.skipif(not HAS_ZSTD, reason=ZSTD_SKIP_REASON),
    ),
]


# ===================================================================
# Test data generators
# ===================================================================

def _data_text_like(size: int) -> bytes:
    """Text-like data with natural repetition."""
    pattern = b"the quick brown fox jumps over the lazy dog "
    q, r = divmod(size, len(pattern))
    return pattern * q + pattern[:r]


def _data_binary(size: int) -> bytes:
    """Binary data — all byte values cycling."""
    pattern = bytes(range(256))
    q, r = divmod(size, 256)
    return pattern * q + pattern[:r]


def _data_repetitive(size: int) -> bytes:
    """Highly repetitive — period 3, maximizes overlapping refs."""
    pattern = b"abc"
    q, r = divmod(size, 3)
    return pattern * q + pattern[:r]


def _data_mixed(size: int) -> bytes:
    """Alternating compressible and incompressible blocks."""
    import random
    rng = random.Random(42)
    block = 64
    parts = []
    total = 0
    while total < size:
        # Compressible block
        parts.append(b"x" * min(block, size - total))
        total += block
        if total >= size:
            break
        # Random block
        rnd = bytes(rng.randint(0, 255) for _ in range(min(block, size - total)))
        parts.append(rnd)
        total += len(rnd)
    return b"".join(parts)[:size]


DATA_GENERATORS = [
    ("text", _data_text_like),
    ("binary", _data_binary),
    ("repetitive", _data_repetitive),
    ("mixed", _data_mixed),
]

SIZES = [
    ("tiny", 11),
    ("small", 1024),
    ("medium", 65536),
    ("large", 262144),
]


# ===================================================================
# Core: CDH equality across format pairs
# ===================================================================


class TestCrossFormatMatrix:
    """
    Full N×N format matrix: CDH(F_a(T)) = CDH(F_b(T)) = H(T).

    For every (format_a, format_b) pair, every data pattern, and
    every size, verify that compressed-domain hashing produces
    identical results regardless of compression format.
    """

    @pytest.mark.parametrize("fmt_name,compress_fn", OPTIONAL_FORMAT_CASES)
    def test_optional_format_coverage_is_explicit(self, fmt_name, compress_fn):
        """Run every optional path or report its actionable skip reason."""
        data = _data_text_like(4096)
        compressed, fmt = compress_fn(data)
        tokens = extract_tokens(compressed, fmt)
        assert lz77_decode(tokens) == data, fmt_name

    @pytest.mark.parametrize("data_name,data_fn", DATA_GENERATORS,
                             ids=[d[0] for d in DATA_GENERATORS])
    @pytest.mark.parametrize("size_name,size", SIZES,
                             ids=[s[0] for s in SIZES])
    def test_all_formats_agree_on_hash(self, data_name, data_fn, size_name, size):
        """
        All formats must produce identical CDH for the same input data.

        This tests the full row of the matrix at once: compute CDH for
        each format, then assert all are equal to H(T).
        """
        data = data_fn(size)
        h = PolynomialHash(base=131)
        h_direct = h.hash(data)

        for fmt_name, compress_fn in FORMATS:
            compressed, fmt = compress_fn(data)
            tokens = extract_tokens(compressed, fmt)
            cdh = compressed_domain_hash(tokens, method=CDHMethod.ROPE)
            assert cdh == h_direct, (
                f"CDH mismatch: format={fmt_name}, data={data_name}, "
                f"size={size_name} ({size}B). "
                f"CDH={cdh}, H(T)={h_direct}"
            )

    @pytest.mark.parametrize(
        "fmt_a_name,fmt_b_name",
        [(a, b) for a, b in itertools.combinations(FORMAT_NAMES, 2)],
        ids=[f"{a}_vs_{b}" for a, b in itertools.combinations(FORMAT_NAMES, 2)],
    )
    def test_pairwise_verify(self, fmt_a_name, fmt_b_name):
        """
        Every pair of formats must agree on CDH for the same data.

        Uses medium-sized text data (most representative case).
        """
        data = _data_text_like(10_000)
        fmt_a_fn = dict(FORMATS)[fmt_a_name]
        fmt_b_fn = dict(FORMATS)[fmt_b_name]

        comp_a, fmt_a = fmt_a_fn(data)
        comp_b, fmt_b = fmt_b_fn(data)

        tokens_a = extract_tokens(comp_a, fmt_a)
        tokens_b = extract_tokens(comp_b, fmt_b)

        cdh_a = compressed_domain_hash(tokens_a, method=CDHMethod.ROPE)
        cdh_b = compressed_domain_hash(tokens_b, method=CDHMethod.ROPE)

        assert cdh_a == cdh_b, (
            f"Pairwise CDH mismatch: {fmt_a_name}={cdh_a} vs {fmt_b_name}={cdh_b}"
        )


# ===================================================================
# Cross-format with multi-hash k-tuple (Theorem 21)
# ===================================================================


class TestCrossFormatMultiHash:
    """k-tuple multi-hash must agree across formats (Theorems 12 + 21)."""

    @pytest.mark.parametrize("data_name,data_fn", DATA_GENERATORS,
                             ids=[d[0] for d in DATA_GENERATORS])
    def test_multihash_all_formats(self, data_name, data_fn):
        data = data_fn(8192)
        mh = MultiHash(bases=[131, 257])
        h_direct = mh.hash(data)

        for fmt_name, compress_fn in FORMATS:
            compressed, fmt = compress_fn(data)
            tokens = extract_tokens(compressed, fmt)
            cdh_k = multi_cdh(tokens, mh)
            assert cdh_k == h_direct, (
                f"Multi-hash mismatch: format={fmt_name}, data={data_name}"
            )


# ===================================================================
# Cross-format with all three CDH strategies (Theorem 12)
# ===================================================================


class TestCrossFormatThreeWay:
    """All three CDH strategies must agree across all formats."""

    @pytest.mark.parametrize("fmt_name,compress_fn", FORMATS,
                             ids=FORMAT_NAMES)
    def test_three_strategies_agree(self, fmt_name, compress_fn):
        data = _data_text_like(20_000)
        h = PolynomialHash(base=131)
        h_direct = h.hash(data)

        compressed, fmt = compress_fn(data)
        tokens = extract_tokens(compressed, fmt)

        h_prefix = compressed_domain_hash(tokens, method=CDHMethod.PREFIX_ARRAY)
        h_rope = compressed_domain_hash(tokens, method=CDHMethod.ROPE)
        h_sliding = compressed_domain_hash(
            tokens, method=CDHMethod.SLIDING_ROPE, d_max=32768, m_max=258)

        assert h_prefix == h_direct, f"prefix_array mismatch for {fmt_name}"
        assert h_rope == h_direct, f"rope mismatch for {fmt_name}"
        assert h_sliding == h_direct, f"sliding_rope mismatch for {fmt_name}"


# ===================================================================
# ZIP entry cross-format verification
# ===================================================================


class TestCrossFormatZipEntries:
    """ZIP entry CDH must match other formats for the same data."""

    def _make_zip_entry(self, data: bytes, filename: str = "test.txt") -> tuple[bytes, str]:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(filename, data)
        return buf.getvalue(), filename

    def _cdh_zip_entry(self, zip_data: bytes, filename: str) -> int:
        entries = zip_list_entries(zip_data)
        entry = next(e for e in entries if e.filename == filename)
        tokens = zip_entry_extract_tokens(zip_data, entry)
        return compressed_domain_hash(tokens, method=CDHMethod.ROPE)

    @pytest.mark.parametrize("fmt_name,compress_fn", FORMATS,
                             ids=FORMAT_NAMES)
    def test_zip_vs_each_format(self, fmt_name, compress_fn):
        """ZIP entry CDH must equal CDH of the same data in any format."""
        data = _data_text_like(10_000)
        zip_data, fname = self._make_zip_entry(data)
        cdh_zip = self._cdh_zip_entry(zip_data, fname)

        compressed, fmt = compress_fn(data)
        tokens = extract_tokens(compressed, fmt)
        cdh_other = compressed_domain_hash(tokens, method=CDHMethod.ROPE)

        assert cdh_zip == cdh_other, (
            f"ZIP vs {fmt_name} mismatch: zip={cdh_zip}, {fmt_name}={cdh_other}"
        )

    @pytest.mark.parametrize("size_name,size", SIZES,
                             ids=[s[0] for s in SIZES])
    def test_zip_vs_raw_at_various_sizes(self, size_name, size):
        """ZIP entry CDH = H(T) at every test size."""
        data = _data_text_like(size)
        zip_data, fname = self._make_zip_entry(data)
        cdh_zip = self._cdh_zip_entry(zip_data, fname)

        h = PolynomialHash(base=131)
        assert cdh_zip == h.hash(data), (
            f"ZIP CDH != H(T) at size {size_name} ({size}B)"
        )

    def test_zip_stored_vs_all_formats(self):
        """ZIP stored entry CDH must equal other formats."""
        data = _data_text_like(5000)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("stored.txt", data)
        zip_data = buf.getvalue()

        entries = zip_list_entries(zip_data)
        tokens_zip = zip_entry_extract_tokens(zip_data, entries[0])
        cdh_zip = compressed_domain_hash(tokens_zip, method=CDHMethod.ROPE)

        h = PolynomialHash(base=131)
        assert cdh_zip == h.hash(data)


# ===================================================================
# CLI cross-format verify
# ===================================================================

class CLIRunner:
    def __init__(self):
        self.exit_code = 0
        self.stdout = ""
        self.stderr = ""

    def run(self, args):
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = out, err
            try:
                main(args)
                self.exit_code = 0
            except SystemExit as e:
                self.exit_code = e.code if e.code is not None else 0
        finally:
            sys.stdout, sys.stderr = old_out, old_err
            self.stdout = out.getvalue()
            self.stderr = err.getvalue()
        return self


def _write_temp(data: bytes, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    return path


class TestCLICrossFormatVerify:
    """CLI `uhc verify` must work across all format pairs."""

    @pytest.fixture
    def cli(self):
        return CLIRunner()

    @pytest.fixture
    def test_data(self):
        return b"CLI cross-format verification test data " * 50

    def test_cli_raw_vs_deflate(self, cli, test_data):
        p_raw = _write_temp(test_data)
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        p_def = _write_temp(c.compress(test_data) + c.flush())
        try:
            cli.run(["verify", p_raw, p_def,
                      "--format-a", "raw", "--format-b", "deflate"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_raw)
            os.unlink(p_def)

    def test_cli_gzip_vs_deflate(self, cli, test_data):
        p_gz = _write_temp(gzip.compress(test_data))
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        p_def = _write_temp(c.compress(test_data) + c.flush())
        try:
            cli.run(["verify", p_gz, p_def,
                      "--format-a", "gzip", "--format-b", "deflate"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_gz)
            os.unlink(p_def)

    @pytest.mark.skipif(not HAS_ZSTD, reason=ZSTD_SKIP_REASON)
    def test_cli_gzip_vs_zstd(self, cli, test_data):
        p_gz = _write_temp(gzip.compress(test_data))
        cctx = zstandard.ZstdCompressor()
        p_zst = _write_temp(cctx.compress(test_data))
        try:
            cli.run(["verify", p_gz, p_zst,
                      "--format-a", "gzip", "--format-b", "zstd"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_gz)
            os.unlink(p_zst)

    @pytest.mark.skipif(not HAS_LZ4, reason=LZ4_SKIP_REASON)
    def test_cli_deflate_vs_lz4(self, cli, test_data):
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        p_def = _write_temp(c.compress(test_data) + c.flush())
        p_lz4 = _write_temp(lz4.frame.compress(test_data))
        try:
            cli.run(["verify", p_def, p_lz4,
                      "--format-a", "deflate", "--format-b", "lz4_frame"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_def)
            os.unlink(p_lz4)

    @pytest.mark.skipif(
        not (HAS_LZ4 and HAS_ZSTD),
        reason=f"{LZ4_SKIP_REASON}; {ZSTD_SKIP_REASON}",
    )
    def test_cli_lz4_vs_zstd(self, cli, test_data):
        p_lz4 = _write_temp(lz4.frame.compress(test_data))
        cctx = zstandard.ZstdCompressor()
        p_zst = _write_temp(cctx.compress(test_data))
        try:
            cli.run(["verify", p_lz4, p_zst,
                      "--format-a", "lz4_frame", "--format-b", "zstd"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_lz4)
            os.unlink(p_zst)

    def test_cli_different_data_mismatch(self, cli):
        """Different data must report MISMATCH regardless of format."""
        data_a = b"alpha content " * 50
        data_b = b"bravo content " * 50
        p_gz = _write_temp(gzip.compress(data_a))
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        p_def = _write_temp(c.compress(data_b) + c.flush())
        try:
            cli.run(["verify", p_gz, p_def,
                      "--format-a", "gzip", "--format-b", "deflate"])
            assert "mismatch" in cli.stdout.lower() or cli.exit_code != 0
        finally:
            os.unlink(p_gz)
            os.unlink(p_def)
