"""
Unified pipeline for compressed-domain hashing.

Provides a clean public API that wires together:
    CDC chunking → compression format parsing → CDH → hash composition

Supports:
    - DEFLATE and LZ4 compressed inputs (Lemmas 9-10)
    - Raw byte inputs (auto-compressed for CDH)
    - Single-hash and k-tuple multi-hash (Theorems 12, 21)
    - Streaming (chunk-at-a-time) and one-shot modes
    - Whole-file hash composition via Theorem 1

Usage:
    from uhc.engine.pipeline import uhc_hash, uhc_hash_file, Format

    # One-shot hash of raw data (auto-chunks, auto-compresses)
    h = uhc_hash(data)

    # Hash with multi-hash for stronger collision resistance
    h_k = uhc_hash(data, bases=[131, 257])

    # Hash pre-compressed data
    h = uhc_hash_compressed(compressed_bytes, format=Format.DEFLATE)
"""

from __future__ import annotations

from enum import Enum
from typing import Sequence

from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61
from uhc.core.lz77 import Token
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod
from uhc.core.deflate import deflate_extract_tokens
from uhc.core.lz4_parser import lz4_extract_tokens, lz4_frame_extract_tokens
from uhc.core.multihash import MultiHash, multi_cdh
from uhc.chunking.cdc import cdc_chunk


# ---------------------------------------------------------------------------
# Format enum
# ---------------------------------------------------------------------------


class Format(str, Enum):
    """Supported compression formats."""
    DEFLATE = "deflate"
    LZ4_BLOCK = "lz4_block"
    LZ4_FRAME = "lz4_frame"
    RAW = "raw"  # uncompressed — will auto-compress with DEFLATE


# Format → (token extractor, CDH d_max, CDH m_max)
_FORMAT_CONFIG = {
    Format.DEFLATE:   (deflate_extract_tokens, 32768, 258),
    Format.LZ4_BLOCK: (lz4_extract_tokens, 65535, 65536),
    Format.LZ4_FRAME: (lz4_frame_extract_tokens, 65535, 65536),
}


# ---------------------------------------------------------------------------
# Token extraction
# ---------------------------------------------------------------------------


def extract_tokens(data: bytes, fmt: Format) -> list[Token]:
    """
    Extract LZ77 tokens from compressed data.

    Parameters
    ----------
    data : bytes
        Compressed data in the specified format.
    fmt : Format
        Compression format.

    Returns
    -------
    list[Token]
        Extracted LZ77 tokens.
    """
    if fmt == Format.RAW:
        from uhc.core.lz77 import Literal
        return [Literal(b) for b in data]

    extractor = _FORMAT_CONFIG[fmt][0]
    return extractor(data)


# ---------------------------------------------------------------------------
# Single-hash API
# ---------------------------------------------------------------------------


def uhc_hash(
    data: bytes,
    *,
    prime: int = MERSENNE_61,
    base: int = 131,
    fmt: Format = Format.RAW,
    chunk: bool = True,
    min_chunk: int = 2048,
    avg_chunk: int = 8192,
    max_chunk: int = 65536,
    cdh_method: CDHMethod = CDHMethod.ROPE,
) -> int:
    """
    Compute the polynomial hash of data.

    When fmt=RAW, data is uncompressed bytes. CDC chunking is applied,
    each chunk is hashed via CDH, and results are composed via Theorem 1.

    When fmt is a compression format, data is already compressed.
    Tokens are extracted and hashed directly (no CDC chunking).

    Parameters
    ----------
    data : bytes
        Input data (raw or compressed depending on fmt).
    prime : int
        Mersenne prime for hash ring.
    base : int
        Hash base.
    fmt : Format
        Input format. RAW for uncompressed, others for compressed.
    chunk : bool
        Whether to apply CDC chunking (only for RAW format).
    min_chunk, avg_chunk, max_chunk : int
        CDC chunking parameters.
    cdh_method : CDHMethod
        CDH back-end strategy.

    Returns
    -------
    int
        Polynomial hash H(data) in [0, p-1].
    """
    h = PolynomialHash(prime=prime, base=base)

    if fmt != Format.RAW:
        # Pre-compressed: extract tokens, CDH directly
        tokens = extract_tokens(data, fmt)
        d_max, m_max = _FORMAT_CONFIG[fmt][1], _FORMAT_CONFIG[fmt][2]
        return compressed_domain_hash(
            tokens, prime=prime, base=base, method=cdh_method,
            d_max=d_max, m_max=m_max,
        )

    if not chunk or len(data) <= max_chunk:
        # No chunking — hash directly
        return h.hash(data)

    # CDC chunk → hash each chunk → compose via Theorem 1
    chunks = cdc_chunk(data, min_size=min_chunk, avg_size=avg_chunk,
                       max_size=max_chunk)
    running = 0
    for c in chunks:
        running = h.hash_concat(running, len(c), h.hash(c))
    return running


def uhc_hash_compressed(
    data: bytes,
    fmt: Format,
    *,
    prime: int = MERSENNE_61,
    base: int = 131,
    cdh_method: CDHMethod = CDHMethod.ROPE,
) -> int:
    """
    Compute the polynomial hash of the decompressed content of data,
    without decompressing.

    Parameters
    ----------
    data : bytes
        Compressed data.
    fmt : Format
        Compression format (DEFLATE, LZ4_BLOCK, LZ4_FRAME).

    Returns
    -------
    int
        H(decompressed data).
    """
    if fmt == Format.RAW:
        return PolynomialHash(prime=prime, base=base).hash(data)

    tokens = extract_tokens(data, fmt)
    d_max, m_max = _FORMAT_CONFIG[fmt][1], _FORMAT_CONFIG[fmt][2]
    return compressed_domain_hash(
        tokens, prime=prime, base=base, method=cdh_method,
        d_max=d_max, m_max=m_max,
    )


# ---------------------------------------------------------------------------
# Multi-hash API (Theorem 21)
# ---------------------------------------------------------------------------


def uhc_hash_multi(
    data: bytes,
    *,
    bases: list[int] | None = None,
    prime: int = MERSENNE_61,
    fmt: Format = Format.RAW,
    cdh_method: CDHMethod = CDHMethod.ROPE,
) -> tuple[int, ...]:
    """
    Compute k-tuple polynomial hash for stronger collision resistance.

    Default: k=2 with bases [131, 257], giving collision bound
    < (N/p)^2 ≈ 2^(-82) for 1GB files with p = 2^61-1 (Corollary 5).

    Parameters
    ----------
    data : bytes
        Input data (raw or compressed).
    bases : list[int]
        k hash bases. Default: [131, 257].
    prime : int
        Mersenne prime.
    fmt : Format
        Input format.

    Returns
    -------
    tuple[int, ...]
        k-tuple of hash values.
    """
    if bases is None:
        bases = [131, 257]

    mh = MultiHash(bases=bases, prime=prime)

    if fmt != Format.RAW:
        tokens = extract_tokens(data, fmt)
        return multi_cdh(tokens, mh)

    return mh.hash(data)


def uhc_hash_compressed_multi(
    data: bytes,
    fmt: Format,
    *,
    bases: list[int] | None = None,
    prime: int = MERSENNE_61,
) -> tuple[int, ...]:
    """
    Compute k-tuple hash of decompressed content without decompressing.

    Parameters
    ----------
    data : bytes
        Compressed data.
    fmt : Format
        Compression format.

    Returns
    -------
    tuple[int, ...]
        k-tuple of H(decompressed data).
    """
    if bases is None:
        bases = [131, 257]

    mh = MultiHash(bases=bases, prime=prime)

    if fmt == Format.RAW:
        return mh.hash(data)

    tokens = extract_tokens(data, fmt)
    return multi_cdh(tokens, mh)


# ---------------------------------------------------------------------------
# Convenience: verify two datasets match
# ---------------------------------------------------------------------------


def uhc_verify(
    data_a: bytes,
    data_b: bytes,
    *,
    bases: list[int] | None = None,
    prime: int = MERSENNE_61,
    fmt_a: Format = Format.RAW,
    fmt_b: Format = Format.RAW,
) -> bool:
    """
    Verify that two datasets (possibly in different formats) represent
    the same content.

    Uses k-tuple multi-hash for collision resistance.

    Returns
    -------
    bool
        True if hash tuples match (content is identical with high probability).
    """
    h_a = uhc_hash_multi(data_a, bases=bases, prime=prime, fmt=fmt_a)
    h_b = uhc_hash_multi(data_b, bases=bases, prime=prime, fmt=fmt_b)
    return h_a == h_b
