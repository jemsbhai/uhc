"""
Gzip header parser and token extractor (RFC 1952).

Gzip wraps a DEFLATE stream (RFC 1951) with a header and trailer.
This module parses the header to locate the raw DEFLATE stream, then
delegates token extraction to deflate_extract_tokens (Lemma 9).

Since gzip uses DEFLATE internally with identical back-reference
semantics (Definition 5), Theorem 12 (CDH = H) holds transitively:
    CDH(gzip_extract_tokens(gzip_data)) = H(original_data)

Header structure (RFC 1952, Section 2.3):
    Offset  Size  Field
    0       2     Magic number (0x1f, 0x8b)
    2       1     Compression method (8 = deflate)
    3       1     FLG flags
    4       4     MTIME
    8       1     XFL
    9       1     OS
    10      ...   Optional fields (FEXTRA, FNAME, FCOMMENT, FHCRC)
    ...     ...   DEFLATE compressed data
    ...     4     CRC32
    ...     4     ISIZE (original size mod 2^32)
"""

from __future__ import annotations

import struct
from uhc.core.lz77 import Token
from uhc.core.deflate import deflate_extract_tokens


# FLG bit masks (RFC 1952, Section 2.3.1)
_FTEXT = 0x01
_FHCRC = 0x02
_FEXTRA = 0x04
_FNAME = 0x08
_FCOMMENT = 0x10


def parse_gzip_header(data: bytes) -> int:
    """
    Parse a gzip header and return the byte offset where the DEFLATE
    stream begins.

    Parameters
    ----------
    data : bytes
        Gzip-compressed data.

    Returns
    -------
    int
        Byte offset of the start of the raw DEFLATE stream.

    Raises
    ------
    ValueError
        If data is not a valid gzip stream or uses unsupported compression.
    """
    if len(data) < 10 or data[0:2] != b"\x1f\x8b":
        raise ValueError("Not a gzip stream: invalid magic bytes")

    cm = data[2]
    if cm != 8:
        raise ValueError(f"Unsupported compression method: {cm} (only deflate=8 supported)")

    flg = data[3]
    offset = 10  # fixed header size

    # FEXTRA: 2-byte XLEN followed by XLEN bytes of extra data
    if flg & _FEXTRA:
        if offset + 2 > len(data):
            raise ValueError("Truncated gzip header: FEXTRA length missing")
        xlen = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + xlen

    # FNAME: null-terminated original filename
    if flg & _FNAME:
        end = data.index(0, offset)
        offset = end + 1

    # FCOMMENT: null-terminated comment
    if flg & _FCOMMENT:
        end = data.index(0, offset)
        offset = end + 1

    # FHCRC: 2-byte CRC16 of the header
    if flg & _FHCRC:
        offset += 2

    return offset


def gzip_extract_tokens(data: bytes) -> list[Token]:
    """
    Extract LZ77 tokens from a gzip stream by stripping the header
    and passing the inner DEFLATE stream to deflate_extract_tokens.

    The 8-byte trailer (CRC32 + ISIZE) is stripped from the end.

    Parameters
    ----------
    data : bytes
        Complete gzip-compressed data.

    Returns
    -------
    list[Token]
        LZ77 tokens from the inner DEFLATE stream.
    """
    offset = parse_gzip_header(data)
    # Strip 8-byte trailer (CRC32 + ISIZE)
    deflate_stream = data[offset:-8] if len(data) > offset + 8 else data[offset:]
    return deflate_extract_tokens(deflate_stream)
