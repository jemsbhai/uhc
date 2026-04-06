"""
LZ4 token extractor (Lemma 10).

Supports both raw LZ4 block format and LZ4 frame format.

Parses LZ4 streams to extract LZ77 Lit/Ref tokens without decompressing.
Satisfies conditions C1 and C2 (Definition 9).

LZ4 format parameters (Definition 8):
    m_min = 4, m_max = ∞, d_max = 65535, E = raw

LZ4 block format (per sequence):
    1. Token byte: high nibble = literal length, low nibble = match length - 4
    2. Optional literal length extension (255-continuation scheme)
    3. Literal bytes
    4. 2-byte little-endian offset (not present in last sequence)
    5. Optional match length extension (255-continuation scheme)

LZ4 frame format:
    Magic (4 bytes, 0x184D2204) | Frame Descriptor | Block(s) | EndMark | [Checksum]
    Each block: block_size (4 bytes, MSB=1 if uncompressed) | block_data
"""

from __future__ import annotations

import struct

from uhc.core.lz77 import Token, Literal, Reference


# ---------------------------------------------------------------------------
# LZ4 frame constants
# ---------------------------------------------------------------------------

_LZ4_FRAME_MAGIC = 0x184D2204


# ---------------------------------------------------------------------------
# Raw block parser
# ---------------------------------------------------------------------------


def lz4_extract_tokens(compressed: bytes) -> list[Token]:
    """
    Parse a raw LZ4 block and extract LZ77 tokens.

    Parameters
    ----------
    compressed : bytes
        Raw LZ4 block data (no frame header).

    Returns
    -------
    list[Token]
        Sequence of Literal and Reference tokens.
    """
    tokens: list[Token] = []
    pos = 0
    n = len(compressed)

    if n == 0:
        return tokens

    while pos < n:
        # 1. Read token byte
        token_byte = compressed[pos]
        pos += 1

        lit_len = (token_byte >> 4) & 0x0F
        match_len_raw = token_byte & 0x0F

        # 2. Extended literal length
        if lit_len == 15:
            while pos < n:
                extra = compressed[pos]
                pos += 1
                lit_len += extra
                if extra != 255:
                    break

        # 3. Read literal bytes
        if lit_len > 0:
            if pos + lit_len > n:
                raise ValueError(
                    f"LZ4: literal length {lit_len} exceeds remaining data "
                    f"at position {pos}"
                )
            for i in range(lit_len):
                tokens.append(Literal(compressed[pos + i]))
            pos += lit_len

        # 4. Check if this is the last sequence (no match follows)
        if pos >= n:
            break

        # 5. Read 2-byte offset (little-endian)
        if pos + 2 > n:
            raise ValueError(f"LZ4: truncated offset at position {pos}")
        offset = compressed[pos] | (compressed[pos + 1] << 8)
        pos += 2

        if offset == 0:
            raise ValueError("LZ4: zero offset is invalid")

        # 6. Match length = raw + 4, with optional extension
        match_len = match_len_raw + 4
        if match_len_raw == 15:
            while pos < n:
                extra = compressed[pos]
                pos += 1
                match_len += extra
                if extra != 255:
                    break

        tokens.append(Reference(distance=offset, length=match_len))

    return tokens


# ---------------------------------------------------------------------------
# Frame format parser
# ---------------------------------------------------------------------------


def lz4_frame_extract_tokens(data: bytes) -> list[Token]:
    """
    Parse an LZ4 frame and extract LZ77 tokens from all blocks.

    Handles the LZ4 frame format:
        Magic (4B) | FLG (1B) | BD (1B) | [Content Size] | HC (1B)
        Block(s): size (4B) | data
        EndMark: 0x00000000

    Parameters
    ----------
    data : bytes
        Complete LZ4 frame data.

    Returns
    -------
    list[Token]
        Sequence of Literal and Reference tokens from all blocks.
    """
    if len(data) < 7:
        raise ValueError("LZ4 frame too short")

    pos = 0

    # Magic number
    magic = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    if magic != _LZ4_FRAME_MAGIC:
        raise ValueError(f"Invalid LZ4 frame magic: 0x{magic:08X}")

    # Frame descriptor
    flg = data[pos]
    pos += 1
    bd = data[pos]
    pos += 1

    version = (flg >> 6) & 0x03
    if version != 1:
        raise ValueError(f"Unsupported LZ4 frame version: {version}")

    b_indep = (flg >> 5) & 1       # Block independence flag
    b_checksum = (flg >> 4) & 1    # Block checksum flag
    c_size_flag = (flg >> 3) & 1   # Content size flag
    c_checksum = (flg >> 2) & 1    # Content checksum flag
    # dict_id_flag = (flg >> 0) & 1  # Dictionary ID flag (not supported)

    # Optional content size (8 bytes)
    if c_size_flag:
        pos += 8

    # Dictionary ID (4 bytes) — skip if present
    dict_id_flag = flg & 1
    if dict_id_flag:
        pos += 4

    # Header checksum (1 byte)
    pos += 1

    # Parse blocks
    tokens: list[Token] = []

    while pos + 4 <= len(data):
        block_size_raw = struct.unpack_from("<I", data, pos)[0]
        pos += 4

        # EndMark
        if block_size_raw == 0:
            break

        # MSB indicates uncompressed block
        is_uncompressed = (block_size_raw >> 31) & 1
        block_size = block_size_raw & 0x7FFFFFFF

        if pos + block_size > len(data):
            raise ValueError(
                f"LZ4 frame: block size {block_size} exceeds remaining data"
            )

        block_data = data[pos:pos + block_size]
        pos += block_size

        if is_uncompressed:
            # Uncompressed block — all literals
            for byte in block_data:
                tokens.append(Literal(byte))
        else:
            # Compressed block — parse as LZ4 block
            tokens.extend(lz4_extract_tokens(block_data))

        # Optional block checksum
        if b_checksum:
            pos += 4

    # Optional content checksum at the end
    # (just skip — we don't verify checksums, only extract tokens)

    return tokens
