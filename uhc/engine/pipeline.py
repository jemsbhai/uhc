"""
Unified pipeline for compressed-domain hashing.

Provides a clean public API that wires together:
    CDC chunking → compression format parsing → CDH → hash composition

Supports:
    - DEFLATE, LZ4, and Zstandard compressed inputs (Lemmas 9-11)
    - Raw byte inputs (auto-compressed for CDH)
    - Single-hash and k-tuple multi-hash (Theorems 12, 21)
    - Streaming (chunk-at-a-time) and one-shot modes
    - Whole-file hash composition via Theorem 1

Usage:
    from uhc.engine.pipeline import uhc_hash, uhc_hash_file, Format

    # One-shot hash of raw data (auto-chunks, auto-compresses)
    h = uhc_hash(data)

    # Multiple polynomial hashes reduce accidental-collision probability;
    # they do not provide adversarial collision resistance.
    h_k = uhc_hash(data, bases=[131, 257])

    # Hash pre-compressed data
    h = uhc_hash_compressed(compressed_bytes, format=Format.DEFLATE)
"""

from __future__ import annotations

from enum import Enum
from collections.abc import Iterator

from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61
from uhc.core.lz77 import Literal, Token, iter_validated_tokens
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod
from uhc.core.deflate import iter_deflate_tokens
from uhc.core.gzip_parser import iter_gzip_tokens
from uhc.core.lz4_parser import iter_lz4_tokens, iter_lz4_frame_tokens
from uhc.core.zstd_parser import iter_zstd_tokens
from uhc.core.multihash import MultiHash, multi_cdh
from uhc.chunking.cdc import cdc_ranges
from uhc.core.exact import compare_exact_decoded
from uhc.core.resources import DEFAULT_LIMITS, ResourceLimits


# ---------------------------------------------------------------------------
# Format enum
# ---------------------------------------------------------------------------


class Format(str, Enum):
    """Supported compression formats."""
    DEFLATE = "deflate"
    GZIP = "gzip"
    LZ4_BLOCK = "lz4_block"
    LZ4_FRAME = "lz4_frame"
    ZSTD = "zstd"
    ZIP = "zip"
    RAW = "raw"  # uncompressed — will auto-compress with DEFLATE


class UnsupportedFormatError(ValueError):
    """A recognized format is intentionally unavailable for this operation."""


def _reject_zip(fmt: Format, operation: str) -> None:
    if fmt == Format.ZIP:
        raise UnsupportedFormatError(
            f"ZIP archives are multi-entry containers and cannot be {operation} "
            "as one byte stream. Use uhc.core.zip_parser to select one stored "
            "or DEFLATE entry explicitly."
        )


# Format → (token extractor, CDH d_max, CDH m_max)
_FORMAT_CONFIG = {
    Format.DEFLATE:   (iter_deflate_tokens, 32768, 258),
    Format.GZIP:      (iter_gzip_tokens, 32768, 258),
    Format.LZ4_BLOCK: (iter_lz4_tokens, 65535, 65536),
    Format.LZ4_FRAME: (iter_lz4_frame_tokens, 65535, 65536),
    Format.ZSTD:      (iter_zstd_tokens, 2**27, 131074),
}


# ---------------------------------------------------------------------------
# Token extraction
# ---------------------------------------------------------------------------


def extract_tokens(
    data: bytes,
    fmt: Format,
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> list[Token]:
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
    return list(iter_tokens(data, fmt, limits=limits))


def iter_tokens(
    data: bytes,
    fmt: Format,
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> Iterator[Token]:
    """Yield validated format tokens with finite input/output/token budgets."""
    limits.check_input(len(data))
    _reject_zip(fmt, "processed")
    source = (
        (Literal(byte) for byte in data)
        if fmt == Format.RAW
        else _FORMAT_CONFIG[fmt][0](data)
    )
    return iter_validated_tokens(source, limits=limits)


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
    limits: ResourceLimits = DEFAULT_LIMITS,
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
    limits.check_input(len(data))
    if fmt == Format.RAW:
        limits.check_output(len(data))

    if fmt != Format.RAW:
        # Pre-compressed: extract tokens, CDH directly
        tokens = iter_tokens(data, fmt, limits=limits)
        d_max, m_max = _FORMAT_CONFIG[fmt][1], _FORMAT_CONFIG[fmt][2]
        return compressed_domain_hash(
            tokens, prime=prime, base=base, method=cdh_method,
            d_max=d_max, m_max=m_max,
            limits=limits,
        )

    if not chunk or len(data) <= max_chunk:
        # No chunking — hash directly
        return h.hash(data)

    # CDC chunk → hash each chunk → compose via Theorem 1
    running = 0
    for start, end in cdc_ranges(
        data, min_size=min_chunk, avg_size=avg_chunk, max_size=max_chunk
    ):
        chunk_hash = h.hash_iter((memoryview(data)[start:end],))
        running = h.hash_concat(running, end - start, chunk_hash)
    return running


def uhc_hash_compressed(
    data: bytes,
    fmt: Format,
    *,
    prime: int = MERSENNE_61,
    base: int = 131,
    cdh_method: CDHMethod = CDHMethod.ROPE,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> int:
    """
    Compute the polynomial hash of the decompressed content of data,
    without decompressing.

    Parameters
    ----------
    data : bytes
        Compressed data.
    fmt : Format
        Compression format (DEFLATE, LZ4_BLOCK, LZ4_FRAME, ZSTD).

    Returns
    -------
    int
        H(decompressed data).
    """
    if fmt == Format.RAW:
        return PolynomialHash(prime=prime, base=base).hash(data)

    limits.check_input(len(data))
    if fmt == Format.RAW:
        limits.check_output(len(data))
    tokens = iter_tokens(data, fmt, limits=limits)
    d_max, m_max = _FORMAT_CONFIG[fmt][1], _FORMAT_CONFIG[fmt][2]
    return compressed_domain_hash(
        tokens, prime=prime, base=base, method=cdh_method,
        d_max=d_max, m_max=m_max,
        limits=limits,
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
    d_max: int | None = None,
    m_max: int | None = None,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> tuple[int, ...]:
    """
    Compute a k-tuple polynomial hash for probabilistic screening.

    Multiple components can reduce accidental-collision probability under the
    framework's random-base model. They do not make this a cryptographic hash;
    known or fixed bases permit constructed adversarial collisions.

    Parameters
    ----------
    data : bytes
        Input data (raw or compressed).
    bases : list[int]
        k hash bases. Default: [131, 257].
    prime : int
        Mersenne prime.
    fmt : Format
        Input format. ZIP is recognized but intentionally rejected because an
        archive has no single decoded byte stream.
    cdh_method : CDHMethod
        CDH back-end used for every component on compressed input.

    Returns
    -------
    tuple[int, ...]
        k-tuple of hash values.
    """
    if bases is None:
        bases = [131, 257]

    mh = MultiHash(bases=bases, prime=prime)
    limits.check_input(len(data))
    if fmt == Format.RAW:
        limits.check_output(len(data))

    if fmt != Format.RAW:
        tokens = iter_tokens(data, fmt, limits=limits)
        default_d_max, default_m_max = _FORMAT_CONFIG[fmt][1:]
        resolved_d_max = default_d_max if d_max is None else d_max
        resolved_m_max = default_m_max if m_max is None else m_max
        if limits == DEFAULT_LIMITS:
            return multi_cdh(
                tokens,
                mh,
                method=cdh_method,
                d_max=resolved_d_max,
                m_max=resolved_m_max,
            )
        return multi_cdh(
            tokens,
            mh,
            method=cdh_method,
            d_max=resolved_d_max,
            m_max=resolved_m_max,
            limits=limits,
        )

    return mh.hash_iter((data,))


def uhc_hash_compressed_multi(
    data: bytes,
    fmt: Format,
    *,
    bases: list[int] | None = None,
    prime: int = MERSENNE_61,
    cdh_method: CDHMethod = CDHMethod.ROPE,
    d_max: int | None = None,
    m_max: int | None = None,
    limits: ResourceLimits = DEFAULT_LIMITS,
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
    limits.check_input(len(data))
    if fmt == Format.RAW:
        limits.check_output(len(data))

    if fmt == Format.RAW:
        return mh.hash_iter((data,))

    tokens = iter_tokens(data, fmt, limits=limits)
    default_d_max, default_m_max = _FORMAT_CONFIG[fmt][1:]
    resolved_d_max = default_d_max if d_max is None else d_max
    resolved_m_max = default_m_max if m_max is None else m_max
    if limits == DEFAULT_LIMITS:
        return multi_cdh(
            tokens,
            mh,
            method=cdh_method,
            d_max=resolved_d_max,
            m_max=resolved_m_max,
        )
    return multi_cdh(
        tokens,
        mh,
        method=cdh_method,
        d_max=resolved_d_max,
        m_max=resolved_m_max,
        limits=limits,
    )


# ---------------------------------------------------------------------------
# Exact decoded-byte verification
# ---------------------------------------------------------------------------


def uhc_verify_exact(
    data_a: bytes,
    data_b: bytes,
    *,
    bases: list[int] | None = None,
    prime: int = MERSENNE_61,
    fmt_a: Format = Format.RAW,
    fmt_b: Format = Format.RAW,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bool:
    """
    Strictly decode two datasets and compare their bytes exactly.

    Native format decoders validate compressed syntax, checksums where the
    format provides them, concatenated gzip/Zstandard streams, and complete
    input consumption. SHA-256 provides a cryptographic precheck; a final
    constant-time byte comparison makes the result exact even in the
    hypothetical event of a digest collision.

    ``bases`` and ``prime`` remain accepted for source compatibility with the
    former probabilistic verifier. They are validated but do not participate
    in the exact comparison.

    Returns
    -------
    bool
        True if and only if the decoded byte strings are equal.
    """
    if bases is None:
        from uhc.core.polynomial_hash import validate_mersenne_prime

        validate_mersenne_prime(prime)
    else:
        MultiHash(bases=bases, prime=prime)

    return compare_exact_decoded(
        data_a, fmt_a, data_b, fmt_b, limits=limits
    )


def uhc_verify(
    data_a: bytes,
    data_b: bytes,
    *,
    bases: list[int] | None = None,
    prime: int = MERSENNE_61,
    fmt_a: Format = Format.RAW,
    fmt_b: Format = Format.RAW,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bool:
    """Compatibility name for :func:`uhc_verify_exact`.

    Unlike the polynomial-hash APIs, this function performs authoritative
    decoded-byte equality checking. It does not authenticate either input.
    """
    return uhc_verify_exact(
        data_a,
        data_b,
        bases=bases,
        prime=prime,
        fmt_a=fmt_a,
        fmt_b=fmt_b,
        limits=limits,
    )
