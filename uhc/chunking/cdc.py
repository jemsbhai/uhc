"""
Content-Defined Chunking (CDC) using Gear-based rolling hash.

Based on FastCDC (Xia et al., USENIX ATC '16, reference 9 in framework).

CDC splits data into variable-size chunks at content-determined boundaries.
Unlike fixed-size chunking, insertions or deletions only affect chunks near
the edit point — chunks far away remain identical, enabling efficient
deduplication.

Algorithm:
    1. Slide a window over the data
    2. At each byte, update a Gear rolling hash: fp = (fp << 1) + GEAR[byte]
    3. If (fp & mask) == 0, cut here (boundary found)
    4. Enforce min_size / max_size constraints

The Gear hash uses a precomputed random table (one 64-bit value per byte
value 0-255) for fast, content-sensitive fingerprinting. The mask determines
expected average chunk size: mask with k bits set → avg chunk ~2^k bytes.
"""

from __future__ import annotations

import struct
import hashlib
from collections.abc import Iterator


# ---------------------------------------------------------------------------
# Gear table: 256 random 64-bit values, deterministically generated
# ---------------------------------------------------------------------------

def _build_gear_table() -> list[int]:
    """
    Generate 256 deterministic random 64-bit values for the Gear hash.

    Uses SHA-256 seeded with index to ensure reproducibility across
    platforms and Python versions.
    """
    table = []
    for i in range(256):
        h = hashlib.sha256(b"uhc-gear-table-" + i.to_bytes(2, "big")).digest()
        val = struct.unpack("<Q", h[:8])[0]
        table.append(val)
    return table


_GEAR: list[int] = _build_gear_table()
_MASK_64 = (1 << 64) - 1


# ---------------------------------------------------------------------------
# Mask computation
# ---------------------------------------------------------------------------

def _mask_for_bits(bits: int) -> int:
    """Create a mask with `bits` low bits set."""
    return (1 << bits) - 1


def _avg_to_bits(avg_size: int) -> int:
    """Convert average chunk size to number of mask bits."""
    # avg_size ≈ 2^bits, so bits = log2(avg_size)
    bits = 0
    v = avg_size
    while v > 1:
        v >>= 1
        bits += 1
    return bits


# ---------------------------------------------------------------------------
# CDC chunking
# ---------------------------------------------------------------------------

def cdc_chunk(
    data: bytes,
    min_size: int = 2048,
    avg_size: int = 8192,
    max_size: int = 65536,
) -> list[bytes]:
    """
    Split data into variable-size chunks using Gear-based CDC.

    Parameters
    ----------
    data : bytes
        Input data to chunk.
    min_size : int
        Minimum chunk size (no boundary checks before this). Default: 2KB.
    avg_size : int
        Target average chunk size. Default: 8KB.
    max_size : int
        Maximum chunk size (forced cut). Default: 64KB.

    Returns
    -------
    list[bytes]
        List of chunks whose concatenation equals the input.

    Raises
    ------
    ValueError
        If size parameters are invalid.
    """
    return [data[start:end] for start, end in cdc_ranges(
        data, min_size=min_size, avg_size=avg_size, max_size=max_size
    )]


def cdc_ranges(
    data: bytes,
    min_size: int = 2048,
    avg_size: int = 8192,
    max_size: int = 65536,
) -> Iterator[tuple[int, int]]:
    """Yield half-open CDC byte ranges in one scan without copying chunks."""
    if min_size < 1:
        raise ValueError(f"min_size must be >= 1, got {min_size}")
    if max_size < min_size:
        raise ValueError(
            f"max_size ({max_size}) must be >= min_size ({min_size})"
        )
    if avg_size < min_size or avg_size > max_size:
        avg_size = min(max(avg_size, min_size), max_size)

    n = len(data)
    if n == 0:
        return

    mask_bits = _avg_to_bits(avg_size)
    # FastCDC uses a two-level mask: a harder mask (fewer bits) before
    # the average point and an easier mask (more bits) after, to normalize
    # the chunk size distribution. We use:
    #   - mask_hard (mask_bits + 1 bits) for positions [min_size, avg_size)
    #   - mask_easy (mask_bits - 1 bits) for positions [avg_size, max_size)
    mask_hard = _mask_for_bits(min(mask_bits + 1, 63))
    mask_easy = _mask_for_bits(max(mask_bits - 1, 1))

    chunk_start = 0

    while chunk_start < n:
        chunk_end = min(chunk_start + max_size, n)
        # If remaining data fits in one chunk, take it all
        if chunk_end - chunk_start <= min_size:
            yield chunk_start, chunk_end
            break

        fp = 0
        boundary = chunk_end  # default: forced cut at max_size

        for i in range(chunk_start, chunk_end):
            fp = ((fp << 1) + _GEAR[data[i]]) & _MASK_64
            offset = i - chunk_start + 1  # 1-based offset into chunk

            if offset < min_size:
                continue

            # Two-level masking (normalized chunking)
            if offset < avg_size:
                if (fp & mask_hard) == 0:
                    boundary = i + 1
                    break
            else:
                if (fp & mask_easy) == 0:
                    boundary = i + 1
                    break

        yield chunk_start, boundary
        chunk_start = boundary
