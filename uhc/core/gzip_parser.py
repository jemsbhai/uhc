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
import zlib
from collections.abc import Iterator

from uhc.core.lz77 import Literal, Reference, Token
from uhc.core.deflate import _iter_deflate_tokens_with_consumed


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
    return _parse_gzip_header(data, 0)


def _parse_gzip_header(data: bytes, start: int) -> int:
    """Parse one member header beginning at ``start``."""
    if len(data) - start < 10 or data[start:start + 2] != b"\x1f\x8b":
        raise ValueError("Not a gzip stream: invalid magic bytes")

    cm = data[start + 2]
    if cm != 8:
        raise ValueError(f"Unsupported compression method: {cm} (only deflate=8 supported)")

    flg = data[start + 3]
    if flg & 0xE0:
        raise ValueError(f"Invalid gzip header: reserved FLG bits set (0x{flg:02x})")
    offset = start + 10  # fixed header size

    # FEXTRA: 2-byte XLEN followed by XLEN bytes of extra data
    if flg & _FEXTRA:
        if offset + 2 > len(data):
            raise ValueError("Truncated gzip header: FEXTRA length missing")
        xlen = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + xlen
        if offset > len(data):
            raise ValueError("Truncated gzip header: FEXTRA data missing")

    # FNAME: null-terminated original filename
    if flg & _FNAME:
        try:
            end = data.index(0, offset)
        except ValueError as exc:
            raise ValueError("Truncated gzip header: FNAME terminator missing") from exc
        offset = end + 1

    # FCOMMENT: null-terminated comment
    if flg & _FCOMMENT:
        try:
            end = data.index(0, offset)
        except ValueError as exc:
            raise ValueError("Truncated gzip header: FCOMMENT terminator missing") from exc
        offset = end + 1

    # FHCRC: 2-byte CRC16 of the header
    if flg & _FHCRC:
        if offset + 2 > len(data):
            raise ValueError("Truncated gzip header: FHCRC missing")
        expected = struct.unpack_from("<H", data, offset)[0]
        actual = zlib.crc32(data[start:offset]) & 0xFFFF
        if actual != expected:
            raise ValueError(
                f"Gzip header CRC mismatch: expected 0x{expected:04x}, got 0x{actual:04x}"
            )
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
    return list(iter_gzip_tokens(data))


class _GzipMemberValidator:
    """Bounded DEFLATE reconstruction used only for gzip trailer checks."""

    __slots__ = ("crc", "size", "window")

    def __init__(self) -> None:
        self.crc = 0
        self.size = 0
        self.window = bytearray()

    def consume(self, token: Token) -> None:
        if isinstance(token, Literal):
            produced = bytes((token.byte,))
        elif isinstance(token, Reference):
            if token.distance > self.size or token.distance > len(self.window):
                raise ValueError(
                    f"Invalid gzip back-reference distance {token.distance} "
                    f"at decoded offset {self.size}"
                )
            output = bytearray()
            for _ in range(token.length):
                byte = self.window[-token.distance]
                output.append(byte)
                self.window.append(byte)
            produced = bytes(output)
        else:  # pragma: no cover - parser only constructs known token types
            raise TypeError(f"Unsupported gzip token {type(token).__name__}")

        if isinstance(token, Literal):
            self.window.extend(produced)
        if len(self.window) > 32768:
            del self.window[:-32768]
        self.crc = zlib.crc32(produced, self.crc) & 0xFFFFFFFF
        self.size += len(produced)


def iter_gzip_tokens(data: bytes) -> Iterator[Token]:
    """Yield concatenated gzip-member tokens with bounded trailer validation."""
    if not data:
        raise ValueError("Empty gzip stream")

    member_start = 0
    member_index = 0
    while member_start < len(data):
        if data[member_start:member_start + 2] != b"\x1f\x8b":
            raise ValueError(
                f"Trailing data after gzip member {member_index}: "
                f"expected gzip magic at byte {member_start}"
            )
        deflate_start = _parse_gzip_header(data, member_start)
        validator = _GzipMemberValidator()
        iterator = _iter_deflate_tokens_with_consumed(data[deflate_start:])
        while True:
            try:
                token = next(iterator)
            except StopIteration as stop:
                compressed_size = stop.value
                break
            validator.consume(token)
            yield token
        trailer_start = deflate_start + compressed_size
        trailer_end = trailer_start + 8
        if trailer_end > len(data):
            raise ValueError(f"Truncated gzip trailer for member {member_index}")

        expected_crc, expected_size = struct.unpack_from("<II", data, trailer_start)
        actual_crc = validator.crc
        actual_size = validator.size & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError(
                f"Gzip CRC mismatch in member {member_index}: "
                f"expected 0x{expected_crc:08x}, got 0x{actual_crc:08x}"
            )
        if actual_size != expected_size:
            raise ValueError(
                f"Gzip ISIZE mismatch in member {member_index}: "
                f"expected {expected_size}, got {actual_size}"
            )
        member_start = trailer_end
        member_index += 1
