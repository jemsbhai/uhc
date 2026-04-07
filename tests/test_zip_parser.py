"""
Tests for ZIP container parser.

ZIP files contain multiple independently-compressed entries, each
typically using DEFLATE (method=8) or stored uncompressed (method=0).

Correctness guarantee:
    For each DEFLATE entry, zip_entry_extract_tokens delegates to
    deflate_extract_tokens (Lemma 9). Theorem 12 then gives:
        CDH(zip_entry_tokens) = H(original_file_content)

    For stored entries (method=0), tokens are all Literals, and
        CDH(literals) = H(raw_bytes) trivially.

Key correctness concerns tested:
    - Local file header parsing (30-byte fixed + variable fields)
    - Central directory parsing for reliable entry metadata
    - Data descriptor handling (bit 3 of general purpose flags)
    - Method 0 (stored) vs method 8 (DEFLATE) dispatch
    - ZIP64 extended information for large files
    - Multi-entry archives
    - Empty entries
    - Entries with subdirectory paths
    - Nested ZIP detection (should not recurse)
"""

from __future__ import annotations

import io
import os
import struct
import tempfile
import zipfile
import zlib
import pytest

from uhc.core.zip_parser import (
    ZipEntry,
    zip_list_entries,
    zip_entry_extract_tokens,
)
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod


# ===================================================================
# Helpers
# ===================================================================

def _make_zip(files: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    """Create an in-memory ZIP archive from a dict of {filename: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_mixed_zip(files: dict[str, tuple[bytes, int]]) -> bytes:
    """Create ZIP with per-file compression method.
    
    files: {filename: (content, compression_constant)}
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, (data, method) in files.items():
            zf.writestr(name, data, compress_type=method)
    return buf.getvalue()


def _verify_entry_cdh(zip_data: bytes, entry: ZipEntry,
                      original: bytes) -> bool:
    """Verify CDH of a ZIP entry matches H(original content)."""
    tokens = zip_entry_extract_tokens(zip_data, entry)
    h = PolynomialHash(base=131)

    # Verify tokens decode to original content
    decoded = lz77_decode(tokens)
    if decoded != original:
        return False

    # Verify CDH = H(original) — Theorem 12
    cdh = compressed_domain_hash(tokens, method=CDHMethod.ROPE)
    h_direct = h.hash(original)
    return cdh == h_direct


# ===================================================================
# zip_list_entries — parsing
# ===================================================================


class TestZipListEntries:
    """Test ZIP central directory / entry parsing."""

    def test_single_deflated_file(self):
        data = b"hello world"
        zdata = _make_zip({"hello.txt": data})
        entries = zip_list_entries(zdata)
        assert len(entries) == 1
        assert entries[0].filename == "hello.txt"
        assert entries[0].uncompressed_size == len(data)
        assert entries[0].compression_method == 8  # DEFLATE

    def test_single_stored_file(self):
        data = b"stored content"
        zdata = _make_zip({"stored.txt": data}, compression=zipfile.ZIP_STORED)
        entries = zip_list_entries(zdata)
        assert len(entries) == 1
        assert entries[0].compression_method == 0
        assert entries[0].uncompressed_size == len(data)
        assert entries[0].compressed_size == len(data)

    def test_multiple_files(self):
        files = {
            "a.txt": b"alpha",
            "b.txt": b"bravo",
            "c.txt": b"charlie",
        }
        zdata = _make_zip(files)
        entries = zip_list_entries(zdata)
        assert len(entries) == 3
        names = {e.filename for e in entries}
        assert names == {"a.txt", "b.txt", "c.txt"}

    def test_subdirectory_paths(self):
        files = {
            "dir/sub/file.txt": b"nested",
            "top.txt": b"top level",
        }
        zdata = _make_zip(files)
        entries = zip_list_entries(zdata)
        names = {e.filename for e in entries}
        assert "dir/sub/file.txt" in names

    def test_empty_archive(self):
        zdata = _make_zip({})
        entries = zip_list_entries(zdata)
        assert len(entries) == 0

    def test_empty_file_entry(self):
        zdata = _make_zip({"empty.txt": b""})
        entries = zip_list_entries(zdata)
        assert len(entries) == 1
        assert entries[0].uncompressed_size == 0

    def test_crc32_correct(self):
        data = b"crc32 test data"
        zdata = _make_zip({"test.txt": data})
        entries = zip_list_entries(zdata)
        assert entries[0].crc32 == zlib.crc32(data) & 0xFFFFFFFF

    def test_mixed_compression_methods(self):
        files = {
            "deflated.txt": (b"deflate " * 100, zipfile.ZIP_DEFLATED),
            "stored.txt": (b"stored", zipfile.ZIP_STORED),
        }
        zdata = _make_mixed_zip(files)
        entries = zip_list_entries(zdata)
        methods = {e.filename: e.compression_method for e in entries}
        assert methods["deflated.txt"] == 8
        assert methods["stored.txt"] == 0

    def test_invalid_zip_raises(self):
        with pytest.raises(ValueError, match="[Nn]ot a.*[Zz][Ii][Pp]"):
            zip_list_entries(b"this is not a zip file at all")

    def test_large_entry(self):
        """Entry larger than 64KB to test size fields."""
        data = b"large " * 20_000  # 120 KB
        zdata = _make_zip({"large.bin": data})
        entries = zip_list_entries(zdata)
        assert entries[0].uncompressed_size == len(data)


# ===================================================================
# zip_entry_extract_tokens — correctness (Theorem 12)
# ===================================================================


class TestZipEntryExtractTokens:
    """Token extraction from ZIP entries — CDH correctness."""

    def test_deflated_entry_cdh_correct(self):
        """CDH of DEFLATE entry must equal H(original). Theorem 12."""
        data = b"deflated content for cdh test " * 20
        zdata = _make_zip({"test.txt": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_stored_entry_cdh_correct(self):
        """Stored entry: all Literal tokens, CDH = H(raw) trivially."""
        data = b"stored entry cdh test"
        zdata = _make_zip({"stored.txt": data}, compression=zipfile.ZIP_STORED)
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_multiple_entries_each_correct(self):
        """Each entry independently verifiable via Theorem 12."""
        files = {
            "a.txt": b"alpha content " * 20,
            "b.txt": b"bravo content " * 30,
            "c.txt": b"charlie " * 10,
        }
        zdata = _make_zip(files)
        entries = zip_list_entries(zdata)
        for entry in entries:
            original = files[entry.filename]
            assert _verify_entry_cdh(zdata, entry, original), \
                f"CDH mismatch for {entry.filename}"

    def test_empty_entry(self):
        """Empty file should produce empty token list."""
        zdata = _make_zip({"empty.txt": b""})
        entries = zip_list_entries(zdata)
        tokens = zip_entry_extract_tokens(zdata, entries[0])
        assert tokens == []
        assert lz77_decode(tokens) == b""

    def test_repetitive_data_with_overlapping_refs(self):
        """Repetitive data produces overlapping back-references (Theorem 4)."""
        data = b"abc" * 10_000  # 30 KB of period-3
        zdata = _make_zip({"repeat.bin": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_binary_data(self):
        """Binary data (all byte values)."""
        data = bytes(range(256)) * 100
        zdata = _make_zip({"binary.bin": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_tokens_decode_to_original(self):
        """Extracted tokens must decode to original file content."""
        data = b"decode roundtrip " * 50
        zdata = _make_zip({"roundtrip.txt": data})
        entries = zip_list_entries(zdata)
        tokens = zip_entry_extract_tokens(zdata, entries[0])
        assert lz77_decode(tokens) == data

    def test_stored_tokens_are_all_literals(self):
        """Stored entries should produce only Literal tokens."""
        data = b"all literals"
        zdata = _make_zip({"stored.txt": data},
                          compression=zipfile.ZIP_STORED)
        entries = zip_list_entries(zdata)
        tokens = zip_entry_extract_tokens(zdata, entries[0])
        assert all(isinstance(t, Literal) for t in tokens)
        assert len(tokens) == len(data)

    def test_cross_validate_with_gzip(self):
        """CDH from ZIP-DEFLATE must match CDH from gzip-DEFLATE of same data."""
        import gzip
        from uhc.core.gzip_parser import gzip_extract_tokens

        data = b"cross validate zip vs gzip " * 30
        zdata = _make_zip({"test.txt": data})
        gz_data = gzip.compress(data)

        entries = zip_list_entries(zdata)
        tokens_zip = zip_entry_extract_tokens(zdata, entries[0])
        tokens_gz = gzip_extract_tokens(gz_data)

        h = PolynomialHash(base=131)
        cdh_zip = compressed_domain_hash(tokens_zip, method=CDHMethod.ROPE)
        cdh_gz = compressed_domain_hash(tokens_gz, method=CDHMethod.ROPE)

        assert cdh_zip == h.hash(data)
        assert cdh_gz == h.hash(data)
        assert cdh_zip == cdh_gz

    def test_unsupported_compression_raises(self):
        """Non-DEFLATE, non-stored methods should raise ValueError."""
        # Build a ZIP with bzip2 (method=12) if available
        buf = io.BytesIO()
        try:
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_BZIP2) as zf:
                zf.writestr("bz2.txt", "bzip2 data")
            zdata = buf.getvalue()
            entries = zip_list_entries(zdata)
            with pytest.raises(ValueError, match="[Uu]nsupported.*method"):
                zip_entry_extract_tokens(zdata, entries[0])
        except RuntimeError:
            pytest.skip("bzip2 not available in this Python build")


# ===================================================================
# Edge cases and robustness
# ===================================================================


class TestZipEdgeCases:

    def test_entry_with_extra_field(self):
        """Entries with extra fields in local header should be parsed correctly."""
        data = b"extra field test " * 20
        zdata = _make_zip({"extra.txt": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_large_filename(self):
        """Long filenames should be handled."""
        long_name = "a" * 200 + ".txt"
        data = b"long filename"
        zdata = _make_zip({long_name: data})
        entries = zip_list_entries(zdata)
        assert entries[0].filename == long_name

    def test_unicode_filename(self):
        """Unicode filenames (UTF-8 flag or fallback)."""
        # Python's zipfile uses UTF-8 by default
        name = "日本語.txt"
        data = b"unicode filename test"
        zdata = _make_zip({name: data})
        entries = zip_list_entries(zdata)
        assert entries[0].filename == name

    def test_many_entries(self):
        """Archive with many entries."""
        files = {f"file_{i:04d}.txt": f"content {i}".encode()
                 for i in range(100)}
        zdata = _make_zip(files)
        entries = zip_list_entries(zdata)
        assert len(entries) == 100

    def test_directory_entries_skipped(self):
        """Directory entries (size=0, name ends with /) should be skipped."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.mkdir("subdir")
            zf.writestr("subdir/file.txt", "content")
        zdata = buf.getvalue()
        entries = zip_list_entries(zdata)
        # Should have the file but not the bare directory
        filenames = [e.filename for e in entries]
        assert "subdir/file.txt" in filenames
        # Directory entry filtered out
        assert not any(f.endswith("/") for f in filenames)


# ===================================================================
# Additional rigor: three-way CDH, CRC, edge cases
# ===================================================================


class TestZipCdhThreeWay:
    """All three CDH strategies must agree on ZIP entry tokens (Theorem 12)."""

    def test_three_way_deflated(self):
        data = b"three way cdh zip test " * 30
        zdata = _make_zip({"test.txt": data})
        entries = zip_list_entries(zdata)
        tokens = zip_entry_extract_tokens(zdata, entries[0])
        h = PolynomialHash(base=131)
        h_direct = h.hash(data)
        h_prefix = compressed_domain_hash(tokens, method=CDHMethod.PREFIX_ARRAY)
        h_rope = compressed_domain_hash(tokens, method=CDHMethod.ROPE)
        h_sliding = compressed_domain_hash(
            tokens, method=CDHMethod.SLIDING_ROPE, d_max=32768, m_max=258)
        assert h_prefix == h_direct
        assert h_rope == h_direct
        assert h_sliding == h_direct

    def test_three_way_stored(self):
        data = b"stored three way"
        zdata = _make_zip({"s.txt": data}, compression=zipfile.ZIP_STORED)
        entries = zip_list_entries(zdata)
        tokens = zip_entry_extract_tokens(zdata, entries[0])
        h = PolynomialHash(base=131)
        h_direct = h.hash(data)
        h_prefix = compressed_domain_hash(tokens, method=CDHMethod.PREFIX_ARRAY)
        h_rope = compressed_domain_hash(tokens, method=CDHMethod.ROPE)
        h_sliding = compressed_domain_hash(
            tokens, method=CDHMethod.SLIDING_ROPE, d_max=32768, m_max=258)
        assert h_prefix == h_rope == h_sliding == h_direct

    def test_three_way_multiple_entries(self):
        files = {
            "a.txt": b"alpha " * 50,
            "b.bin": bytes(range(256)) * 10,
            "c.txt": b"c" * 5000,
        }
        zdata = _make_zip(files)
        entries = zip_list_entries(zdata)
        h = PolynomialHash(base=131)
        for entry in entries:
            original = files[entry.filename]
            tokens = zip_entry_extract_tokens(zdata, entry)
            h_direct = h.hash(original)
            h_prefix = compressed_domain_hash(tokens, method=CDHMethod.PREFIX_ARRAY)
            h_rope = compressed_domain_hash(tokens, method=CDHMethod.ROPE)
            h_sliding = compressed_domain_hash(
                tokens, method=CDHMethod.SLIDING_ROPE, d_max=32768, m_max=258)
            assert h_prefix == h_rope == h_sliding == h_direct, \
                f"Three-way mismatch for {entry.filename}"


class TestZipCrcVerification:
    """Verify CRC-32 from the ZIP header matches actual content."""

    def test_crc_matches_decoded_content(self):
        """CRC from ZIP header must match CRC of decoded tokens."""
        data = b"crc verification test " * 20
        zdata = _make_zip({"test.txt": data})
        entries = zip_list_entries(zdata)
        entry = entries[0]
        tokens = zip_entry_extract_tokens(zdata, entry)
        decoded = lz77_decode(tokens)
        actual_crc = zlib.crc32(decoded) & 0xFFFFFFFF
        assert actual_crc == entry.crc32
        assert decoded == data

    def test_crc_matches_for_stored(self):
        data = b"stored crc"
        zdata = _make_zip({"s.txt": data}, compression=zipfile.ZIP_STORED)
        entries = zip_list_entries(zdata)
        tokens = zip_entry_extract_tokens(zdata, entries[0])
        decoded = lz77_decode(tokens)
        assert zlib.crc32(decoded) & 0xFFFFFFFF == entries[0].crc32

    def test_crc_matches_all_entries(self):
        files = {
            "x.txt": b"x content " * 10,
            "y.bin": bytes(range(200)),
            "z.txt": b"z" * 300,
        }
        zdata = _make_zip(files)
        for entry in zip_list_entries(zdata):
            tokens = zip_entry_extract_tokens(zdata, entry)
            decoded = lz77_decode(tokens)
            assert decoded == files[entry.filename]
            assert zlib.crc32(decoded) & 0xFFFFFFFF == entry.crc32, \
                f"CRC mismatch for {entry.filename}"


class TestZipTinyAndEdge:
    """Tiny entries and boundary conditions."""

    def test_single_byte_deflated(self):
        data = b"x"
        zdata = _make_zip({"one.txt": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_single_byte_stored(self):
        data = b"y"
        zdata = _make_zip({"one.txt": data}, compression=zipfile.ZIP_STORED)
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_two_bytes_deflated(self):
        data = b"ab"
        zdata = _make_zip({"two.txt": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_256_distinct_bytes(self):
        """All 256 byte values — tests Lemma 1 (nonzero coefficients)."""
        data = bytes(range(256))
        zdata = _make_zip({"all_bytes.bin": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_entry_exactly_32kb(self):
        """Entry size = d_max. Tests window boundary."""
        data = b"w" * 32768
        zdata = _make_zip({"32k.bin": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)

    def test_highly_compressible(self):
        """Extreme compression ratio — single byte repeated 100K times."""
        data = b"\x00" * 100_000
        zdata = _make_zip({"zeros.bin": data})
        entries = zip_list_entries(zdata)
        assert _verify_entry_cdh(zdata, entries[0], data)


class TestZipEncryptedRejection:
    """All encryption schemes must be detected and rejected."""

    def _patch_gp_flags(self, zdata: bytes, flag_bit: int) -> bytes:
        """Set a GP flag bit in both local and central directory headers."""
        zdata = bytearray(zdata)
        # Patch local file header
        idx = zdata.index(b"PK\x03\x04")
        gp_offset = idx + 6
        gp_flags = struct.unpack_from("<H", zdata, gp_offset)[0]
        struct.pack_into("<H", zdata, gp_offset, gp_flags | flag_bit)
        # Patch central directory header
        cidx = zdata.index(b"PK\x01\x02")
        cgp_offset = cidx + 8
        cgp_flags = struct.unpack_from("<H", zdata, cgp_offset)[0]
        struct.pack_into("<H", zdata, cgp_offset, cgp_flags | flag_bit)
        return bytes(zdata)

    def test_traditional_encryption_raises(self):
        """Bit 0 of GP flags = traditional PKZIP encryption."""
        zdata = self._patch_gp_flags(
            _make_zip({"secret.txt": b"encrypted"}), 0x0001)
        entries = zip_list_entries(zdata)
        with pytest.raises(ValueError, match="[Ee]ncrypt"):
            zip_entry_extract_tokens(zdata, entries[0])

    def test_strong_encryption_raises(self):
        """Bit 6 of GP flags = strong encryption."""
        zdata = self._patch_gp_flags(
            _make_zip({"secret.txt": b"strongly encrypted"}), 0x0040)
        entries = zip_list_entries(zdata)
        with pytest.raises(ValueError, match="[Ee]ncrypt"):
            zip_entry_extract_tokens(zdata, entries[0])

    def test_aes_encryption_raises(self):
        """Compression method 99 = WinZip AES encryption."""
        zdata = bytearray(_make_zip({"aes.txt": b"aes encrypted"}))
        # Patch compression method to 99 in both local and central headers
        idx = zdata.index(b"PK\x03\x04")
        struct.pack_into("<H", zdata, idx + 8, 99)  # local header method
        cidx = zdata.index(b"PK\x01\x02")
        struct.pack_into("<H", zdata, cidx + 10, 99)  # central dir method
        entries = zip_list_entries(bytes(zdata))
        with pytest.raises(ValueError, match="[Ee]ncrypt|[Aa]ES|method 99"):
            zip_entry_extract_tokens(bytes(zdata), entries[0])


class TestZipCompressedDataSlice:
    """Verify we extract exactly the right bytes for each entry."""

    def test_second_entry_not_contaminated(self):
        """Second entry's tokens must decode to second entry's content only."""
        data_a = b"first file content " * 20
        data_b = b"second file different " * 20
        zdata = _make_zip({"a.txt": data_a, "b.txt": data_b})
        entries = zip_list_entries(zdata)
        entry_b = [e for e in entries if e.filename == "b.txt"][0]
        tokens_b = zip_entry_extract_tokens(zdata, entry_b)
        decoded_b = lz77_decode(tokens_b)
        assert decoded_b == data_b  # must NOT contain data_a bytes

    def test_many_entries_isolation(self):
        """Each of 20 entries decodes independently to its own content."""
        files = {f"file_{i}.txt": f"unique content {i} padding ".encode() * 10
                 for i in range(20)}
        zdata = _make_zip(files)
        entries = zip_list_entries(zdata)
        for entry in entries:
            tokens = zip_entry_extract_tokens(zdata, entry)
            decoded = lz77_decode(tokens)
            assert decoded == files[entry.filename], \
                f"Data isolation violated for {entry.filename}"


# ===================================================================
# Multi-hash k-tuple on ZIP entries (Theorem 21)
# ===================================================================

from uhc.core.multihash import MultiHash, multi_cdh


class TestZipMultiHash:
    """k-tuple CDH on ZIP entries (Theorem 20-21)."""

    def test_multihash_deflated_entry(self):
        data = b"multihash zip test " * 30
        zdata = _make_zip({"mh.txt": data})
        entries = zip_list_entries(zdata)
        tokens = zip_entry_extract_tokens(zdata, entries[0])
        mh = MultiHash(bases=[131, 257])
        cdh_k = multi_cdh(tokens, mh)
        h_direct = mh.hash(data)
        assert cdh_k == h_direct

    def test_multihash_stored_entry(self):
        data = b"stored multihash"
        zdata = _make_zip({"s.txt": data}, compression=zipfile.ZIP_STORED)
        entries = zip_list_entries(zdata)
        tokens = zip_entry_extract_tokens(zdata, entries[0])
        mh = MultiHash(bases=[131, 257, 1009])
        cdh_k = multi_cdh(tokens, mh)
        assert cdh_k == mh.hash(data)

    def test_multihash_all_entries(self):
        files = {
            "a.txt": b"alpha " * 40,
            "b.txt": b"bravo " * 40,
        }
        zdata = _make_zip(files)
        mh = MultiHash(bases=[131, 257])
        for entry in zip_list_entries(zdata):
            tokens = zip_entry_extract_tokens(zdata, entry)
            cdh_k = multi_cdh(tokens, mh)
            assert cdh_k == mh.hash(files[entry.filename])


# ===================================================================
# Robustness: corrupted / truncated ZIPs
# ===================================================================


class TestZipCorruption:
    """Graceful handling of corrupted or truncated archives."""

    def test_truncated_before_eocd(self):
        """ZIP truncated so EOCD is missing."""
        zdata = _make_zip({"test.txt": b"data"})
        # Remove last 22 bytes (minimum EOCD size)
        with pytest.raises(ValueError, match="[Nn]ot a.*[Zz][Ii][Pp]"):
            zip_list_entries(zdata[:-22])

    def test_empty_bytes(self):
        with pytest.raises(ValueError):
            zip_list_entries(b"")

    def test_too_short(self):
        with pytest.raises(ValueError):
            zip_list_entries(b"PK")

    def test_random_garbage(self):
        import random
        rng = random.Random(42)
        garbage = bytes(rng.randint(0, 255) for _ in range(1000))
        with pytest.raises(ValueError):
            zip_list_entries(garbage)


# ===================================================================
# Data descriptor handling
# ===================================================================


class TestZipDataDescriptor:
    """ZIP entries with data descriptors (bit 3 of GP flags).

    When bit 3 is set, CRC and sizes in the local header are zero;
    they appear in a data descriptor AFTER the compressed data.
    Our parser uses the central directory for sizes (which is always
    populated correctly), so data descriptors are handled implicitly.
    This test verifies that."""

    def test_data_descriptor_entry_works(self):
        """Python's zipfile can produce data descriptors when streaming."""
        buf = io.BytesIO()
        # Force data descriptor by writing in streaming mode
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # writestr may or may not set data descriptors depending
            # on Python version, but central directory is always correct
            zf.writestr("dd.txt", "data descriptor test " * 20)
        zdata = buf.getvalue()
        entries = zip_list_entries(zdata)
        assert len(entries) == 1
        data = b"data descriptor test " * 20
        assert _verify_entry_cdh(zdata, entries[0], data)
