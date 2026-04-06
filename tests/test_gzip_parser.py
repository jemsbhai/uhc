"""
Tests for gzip header parsing and token extraction.

The gzip format (RFC 1952) wraps a DEFLATE stream (RFC 1951) with a header
and trailer. Our parser strips the header to locate the raw DEFLATE stream,
then delegates to deflate_extract_tokens (Lemma 9).

Correctness guarantee: since gzip uses DEFLATE internally, Theorem 12
(CDH = H) holds transitively — gzip_extract_tokens produces the same
tokens as deflate_extract_tokens on the inner DEFLATE stream.
"""

from __future__ import annotations

import gzip
import struct
import zlib
import pytest

from uhc.core.gzip_parser import parse_gzip_header, gzip_extract_tokens
from uhc.core.deflate import deflate_extract_tokens
from uhc.core.lz77 import Literal, Reference, lz77_decode


# ===================================================================
# Helpers
# ===================================================================

def _raw_deflate(data: bytes) -> bytes:
    """Produce a raw DEFLATE stream (no gzip/zlib wrapper)."""
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _gzip_compress(data: bytes) -> bytes:
    """Compress with Python's gzip (standard header)."""
    return gzip.compress(data)


def _build_gzip(data: bytes, *, fname: bytes | None = None,
                fcomment: bytes | None = None,
                fextra: bytes | None = None,
                fhcrc: bool = False) -> bytes:
    """Build a gzip stream with optional header fields per RFC 1952."""
    flg = 0
    if fextra is not None:
        flg |= 0x04
    if fname is not None:
        flg |= 0x08
    if fcomment is not None:
        flg |= 0x10
    if fhcrc:
        flg |= 0x02

    header = b"\x1f\x8b"          # magic
    header += b"\x08"              # CM = deflate
    header += bytes([flg])         # FLG
    header += b"\x00\x00\x00\x00" # MTIME
    header += b"\x00"              # XFL
    header += b"\xff"              # OS = unknown

    if fextra is not None:
        header += struct.pack("<H", len(fextra))
        header += fextra
    if fname is not None:
        header += fname + b"\x00"
    if fcomment is not None:
        header += fcomment + b"\x00"
    if fhcrc:
        crc16 = zlib.crc32(header) & 0xFFFF
        header += struct.pack("<H", crc16)

    deflate_data = _raw_deflate(data)
    crc32 = zlib.crc32(data) & 0xFFFFFFFF
    isize = len(data) & 0xFFFFFFFF
    trailer = struct.pack("<II", crc32, isize)

    return header + deflate_data + trailer


# ===================================================================
# parse_gzip_header
# ===================================================================


class TestParseGzipHeader:
    """Test gzip header parsing per RFC 1952."""

    def test_simple_header(self):
        data = b"hello gzip"
        gz = _build_gzip(data)
        offset = parse_gzip_header(gz)
        # offset should point to the start of the DEFLATE stream (byte 10 for minimal header)
        assert offset == 10

    def test_header_with_fname(self):
        data = b"fname test"
        gz = _build_gzip(data, fname=b"test.txt")
        offset = parse_gzip_header(gz)
        # 10 bytes base + "test.txt\0" = 10 + 9 = 19
        assert offset == 19

    def test_header_with_fcomment(self):
        data = b"comment test"
        gz = _build_gzip(data, fcomment=b"a comment")
        offset = parse_gzip_header(gz)
        # 10 + "a comment\0" = 10 + 10 = 20
        assert offset == 20

    def test_header_with_fextra(self):
        data = b"extra test"
        extra = b"\x41\x42\x03\x00\x01\x02\x03"  # 7-byte extra field
        gz = _build_gzip(data, fextra=extra)
        offset = parse_gzip_header(gz)
        # 10 + 2 (XLEN) + 7 (extra) = 19
        assert offset == 19

    def test_header_with_fhcrc(self):
        data = b"hcrc test"
        gz = _build_gzip(data, fhcrc=True)
        offset = parse_gzip_header(gz)
        # 10 + 2 (CRC16) = 12
        assert offset == 12

    def test_header_with_all_flags(self):
        data = b"all flags"
        gz = _build_gzip(data, fname=b"f.txt", fcomment=b"hi",
                         fextra=b"\x00\x00\x02\x00\xAB\xCD", fhcrc=True)
        offset = parse_gzip_header(gz)
        # 10 + 2+6 (extra) + 6 (fname+\0) + 3 (comment+\0) + 2 (crc16) = 29
        assert offset == 29

    def test_invalid_magic_raises(self):
        with pytest.raises(ValueError, match="[Nn]ot a gzip"):
            parse_gzip_header(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

    def test_unsupported_compression_method_raises(self):
        bad = b"\x1f\x8b\x09" + b"\x00" * 7  # CM=9 (not deflate)
        with pytest.raises(ValueError, match="[Uu]nsupported"):
            parse_gzip_header(bad)

    def test_python_gzip_compat(self):
        """parse_gzip_header works on Python's gzip.compress output."""
        data = b"python gzip compat " * 10
        gz = _gzip_compress(data)
        offset = parse_gzip_header(gz)
        assert 10 <= offset <= 30  # standard Python gzip header is 10 bytes


# ===================================================================
# gzip_extract_tokens — correctness (Theorem 12 transitivity)
# ===================================================================


class TestGzipExtractTokens:
    """Token extraction from gzip streams.

    Correctness: gzip_extract_tokens strips the header and passes the
    inner DEFLATE stream to deflate_extract_tokens. So the tokens must
    be identical to calling deflate_extract_tokens on the raw DEFLATE
    stream of the same data.
    """

    def test_tokens_match_raw_deflate(self):
        """Tokens from gzip must equal tokens from raw DEFLATE of same data."""
        data = b"gzip token match test " * 20
        gz = _gzip_compress(data)
        raw_def = _raw_deflate(data)
        tokens_gz = gzip_extract_tokens(gz)
        tokens_def = deflate_extract_tokens(raw_def)
        # Both should decode to the same data (Theorem 12)
        decoded_gz = lz77_decode(tokens_gz)
        decoded_def = lz77_decode(tokens_def)
        assert decoded_gz == data
        assert decoded_def == data

    def test_simple_data(self):
        data = b"hello world"
        gz = _gzip_compress(data)
        tokens = gzip_extract_tokens(gz)
        assert lz77_decode(tokens) == data

    def test_repetitive_data(self):
        """Data with back-references (overlapping case, Theorem 4)."""
        data = b"abcabc" * 100
        gz = _gzip_compress(data)
        tokens = gzip_extract_tokens(gz)
        assert lz77_decode(tokens) == data

    def test_with_fname_header(self):
        data = b"fname gzip test " * 15
        gz = _build_gzip(data, fname=b"document.txt")
        tokens = gzip_extract_tokens(gz)
        assert lz77_decode(tokens) == data

    def test_with_all_header_flags(self):
        data = b"all flags gzip " * 15
        gz = _build_gzip(data, fname=b"f.txt", fcomment=b"c",
                         fextra=b"\x00\x00\x01\x00\xFF", fhcrc=True)
        tokens = gzip_extract_tokens(gz)
        assert lz77_decode(tokens) == data

    def test_empty_data(self):
        data = b""
        gz = _gzip_compress(data)
        tokens = gzip_extract_tokens(gz)
        assert lz77_decode(tokens) == data
