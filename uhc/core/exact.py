"""Strict native decoding for authoritative byte verification.

Polynomial hashes remain useful as a screening primitive, but equality of
fixed polynomial hashes is not an exact comparison.  This module deliberately
uses mature native decoders, rejects truncation and trailing bytes, and returns
the decoded bytes that the verification API compares exactly.
"""

from __future__ import annotations

import hashlib
import hmac
import zlib
from collections.abc import Iterator

from uhc.core.resources import DEFAULT_LIMITS, ResourceLimitError, ResourceLimits


class ExactDecodeError(ValueError):
    """A compressed input is malformed, truncated, or has trailing data."""


def _zstd_window_limit_bytes(limits: ResourceLimits) -> int:
    """Translate public budgets to the native Zstandard window guard.

    The binding accepts no value below 1 KiB. A declared frame window larger
    than either the permitted decoded output or reference distance is rejected
    before the native decoder allocates it.
    """

    relevant_bytes = min(
        limits.max_output_bytes,
        limits.max_reference_distance,
    )
    return max(1024, relevant_bytes)


def _check_zstd_frame_window(
    zstd: object,
    data: bytes,
    limits: ResourceLimits,
) -> None:
    parameters = zstd.get_frame_parameters(data)  # type: ignore[attr-defined]
    allowed = _zstd_window_limit_bytes(limits)
    if parameters.window_size > allowed:
        raise ResourceLimitError(
            f"Zstandard frame window {parameters.window_size} exceeds "
            f"resource limit {allowed} derived from "
            f"max_output_bytes={limits.max_output_bytes} and "
            f"max_reference_distance={limits.max_reference_distance}"
        )


def _decode_deflate(data: bytes) -> bytes:
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    try:
        decoded = decoder.decompress(data) + decoder.flush()
    except zlib.error as exc:
        raise ExactDecodeError(f"Invalid raw DEFLATE stream: {exc}") from exc
    if not decoder.eof:
        raise ExactDecodeError("Truncated raw DEFLATE stream")
    if decoder.unconsumed_tail or decoder.unused_data:
        trailing = len(decoder.unconsumed_tail) + len(decoder.unused_data)
        raise ExactDecodeError(f"Trailing data after raw DEFLATE stream: {trailing} byte(s)")
    return decoded


def _decode_gzip(data: bytes) -> bytes:
    if not data:
        raise ExactDecodeError("Empty gzip stream")
    chunks: list[bytes] = []
    remaining = data
    member = 0
    while remaining:
        if not remaining.startswith(b"\x1f\x8b"):
            raise ExactDecodeError(f"Trailing data after gzip member {member}")
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            chunks.append(decoder.decompress(remaining) + decoder.flush())
        except zlib.error as exc:
            raise ExactDecodeError(f"Invalid gzip member {member}: {exc}") from exc
        if not decoder.eof:
            raise ExactDecodeError(f"Truncated gzip member {member}")
        consumed = len(remaining) - len(decoder.unused_data)
        if consumed <= 0:
            raise ExactDecodeError(f"Gzip member {member} consumed no input")
        remaining = decoder.unused_data
        member += 1
    return b"".join(chunks)


def _decode_zstd(
    data: bytes,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bytes:
    try:
        import zstandard as zstd
    except ImportError as exc:
        raise ImportError(
            "zstandard package required for exact Zstandard verification; "
            "install with: pip install 'uhc[formats]'"
        ) from exc

    if not data:
        raise ExactDecodeError("Empty Zstandard input")
    chunks: list[bytes] = []
    remaining = data
    frame = 0
    while remaining:
        try:
            _check_zstd_frame_window(zstd, remaining, limits)
            decoder = zstd.ZstdDecompressor(
                max_window_size=_zstd_window_limit_bytes(limits)
            ).decompressobj()
            chunks.append(decoder.decompress(remaining) + decoder.flush())
        except zstd.ZstdError as exc:
            raise ExactDecodeError(f"Invalid Zstandard frame {frame}: {exc}") from exc
        if not decoder.eof:
            raise ExactDecodeError(f"Truncated Zstandard frame {frame}")
        consumed = len(remaining) - len(decoder.unused_data)
        if consumed <= 0:
            raise ExactDecodeError(f"Zstandard frame {frame} consumed no input")
        remaining = decoder.unused_data
        frame += 1
    return b"".join(chunks)


def _decode_lz4_frame(data: bytes) -> bytes:
    try:
        import lz4.frame
    except ImportError as exc:
        raise ImportError(
            "lz4 package required for exact LZ4 verification; "
            "install with: pip install 'uhc[formats]'"
        ) from exc
    try:
        decoded, consumed = lz4.frame.decompress(data, return_bytes_read=True)
    except RuntimeError as exc:
        raise ExactDecodeError(f"Invalid LZ4 frame: {exc}") from exc
    if consumed != len(data):
        raise ExactDecodeError(f"Trailing data after LZ4 frame: {len(data) - consumed} byte(s)")
    return bytes(decoded)


def _decode_lz4_block(
    data: bytes,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bytes:
    try:
        import lz4.block
    except ImportError as exc:
        raise ImportError(
            "lz4 package required for exact LZ4 verification; "
            "install with: pip install 'uhc[formats]'"
        ) from exc

    # Raw LZ4 blocks do not carry their decoded size.  Obtain the size from the
    # project parser, then require the native implementation to reproduce the
    # exact same bytes at that size.  The parser is never the sole verifier.
    from uhc.core.lz4_parser import iter_lz4_tokens
    from uhc.core.lz77 import iter_lz77_decode, validate_tokens

    decoded_size = validate_tokens(iter_lz4_tokens(data), max_distance=65535)
    limits.check_output(decoded_size)
    try:
        native = bytes(lz4.block.decompress(data, uncompressed_size=decoded_size))
    except lz4.block.LZ4BlockError as exc:
        raise ExactDecodeError(f"Invalid LZ4 block: {exc}") from exc
    parsed = b"".join(
        iter_lz77_decode(iter_lz4_tokens(data), limits=limits)
    )
    if native != parsed:
        raise ExactDecodeError("LZ4 parser/native decoder disagreement")
    return native


def _iter_zstd_native(data: bytes, limits: ResourceLimits) -> Iterator[bytes]:
    try:
        import zstandard as zstd
    except ImportError as exc:
        raise ImportError(
            "zstandard package required for exact Zstandard verification; "
            "install with: pip install 'uhc[formats]'"
        ) from exc

    if not data:
        raise ExactDecodeError("Empty Zstandard input")
    remaining = data
    total = 0
    compressed_chunk_size = max(
        1,
        min(4096, limits.io_chunk_size // (128 * 1024 // 4)),
    )
    frame = 0
    while remaining:
        offset = 0
        try:
            _check_zstd_frame_window(zstd, remaining, limits)
            decoder = zstd.ZstdDecompressor(
                max_window_size=_zstd_window_limit_bytes(limits)
            ).decompressobj()
            # The binding's decompression object has no max-output argument.
            # A minimal RLE block can expand four input bytes to a 128 KiB
            # Zstandard block. Scale input chunks by that worst-case ratio so
            # each native result stays near the requested I/O budget while we
            # retain an authoritative EOF signal for frame boundaries.
            while offset < len(remaining) and not decoder.eof:
                next_offset = min(len(remaining), offset + compressed_chunk_size)
                output = decoder.decompress(remaining[offset:next_offset])
                offset = next_offset
                if output:
                    total += len(output)
                    limits.check_output(total)
                    for start in range(0, len(output), limits.io_chunk_size):
                        yield bytes(output[start:start + limits.io_chunk_size])
            flushed = decoder.flush()
            if flushed:
                total += len(flushed)
                limits.check_output(total)
                for start in range(0, len(flushed), limits.io_chunk_size):
                    yield bytes(flushed[start:start + limits.io_chunk_size])
        except zstd.ZstdError as exc:
            raise ExactDecodeError(
                f"Invalid Zstandard frame {frame}: {exc}"
            ) from exc
        if not decoder.eof:
            raise ExactDecodeError(f"Truncated Zstandard frame {frame}")

        trailing = decoder.unused_data + remaining[offset:]
        consumed = len(remaining) - len(trailing)
        if consumed <= 0:
            raise ExactDecodeError(f"Zstandard frame {frame} consumed no input")
        remaining = trailing
        frame += 1


def _iter_lz4_frame_native(data: bytes, limits: ResourceLimits) -> Iterator[bytes]:
    try:
        import lz4.frame
    except ImportError as exc:
        raise ImportError(
            "lz4 package required for exact LZ4 verification; "
            "install with: pip install 'uhc[formats]'"
        ) from exc

    decoder = lz4.frame.LZ4FrameDecompressor()
    pending = data
    total = 0
    try:
        while True:
            chunk = decoder.decompress(pending, max_length=limits.io_chunk_size)
            pending = b""
            if chunk:
                total += len(chunk)
                limits.check_output(total)
                yield bytes(chunk)
            if decoder.eof:
                if decoder.unused_data:
                    raise ExactDecodeError(
                        f"Trailing data after LZ4 frame: {len(decoder.unused_data)} byte(s)"
                    )
                return
            if decoder.needs_input:
                raise ExactDecodeError("Truncated LZ4 frame")
    except RuntimeError as exc:
        raise ExactDecodeError(f"Invalid LZ4 frame: {exc}") from exc


def _iter_zlib_decode(
    data: bytes,
    *,
    wbits: int,
    concatenated: bool,
    magic: bytes | None,
    label: str,
    limits: ResourceLimits,
) -> Iterator[bytes]:
    """Incrementally decode strict zlib-backed streams with bounded output."""
    remaining = data
    member = 0
    total = 0
    while remaining:
        if magic is not None and not remaining.startswith(magic):
            raise ExactDecodeError(f"Trailing data after {label} member {member}")
        decoder = zlib.decompressobj(wbits)
        pending = remaining
        try:
            while True:
                output = decoder.decompress(pending, limits.io_chunk_size)
                pending = decoder.unconsumed_tail
                if output:
                    total += len(output)
                    limits.check_output(total)
                    yield output
                if decoder.eof:
                    break
                if pending:
                    continue
                drained = decoder.decompress(b"", limits.io_chunk_size)
                if drained:
                    total += len(drained)
                    limits.check_output(total)
                    yield drained
                    continue
                raise ExactDecodeError(f"Truncated {label} stream")
        except zlib.error as exc:
            raise ExactDecodeError(f"Invalid {label} stream: {exc}") from exc

        trailing = decoder.unused_data
        if not concatenated:
            if pending or trailing:
                count = len(pending) + len(trailing)
                raise ExactDecodeError(
                    f"Trailing data after {label} stream: {count} byte(s)"
                )
            return
        consumed = len(remaining) - len(trailing)
        if consumed <= 0:
            raise ExactDecodeError(f"{label} member {member} consumed no input")
        remaining = trailing
        member += 1


def iter_decode_exact(
    data: bytes,
    fmt: object,
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> Iterator[bytes]:
    """Strictly decode to bounded chunks instead of one materialized buffer."""
    limits.check_input(len(data))
    value = getattr(fmt, "value", fmt)
    if value == "raw":
        limits.check_output(len(data))
        for start in range(0, len(data), limits.io_chunk_size):
            yield data[start:start + limits.io_chunk_size]
        return
    if value == "deflate":
        if not data:
            raise ExactDecodeError("Empty raw DEFLATE stream")
        yield from _iter_zlib_decode(
            data,
            wbits=-zlib.MAX_WBITS,
            concatenated=False,
            magic=None,
            label="raw DEFLATE",
            limits=limits,
        )
        return
    if value == "gzip":
        if not data:
            raise ExactDecodeError("Empty gzip stream")
        yield from _iter_zlib_decode(
            data,
            wbits=16 + zlib.MAX_WBITS,
            concatenated=True,
            magic=b"\x1f\x8b",
            label="gzip",
            limits=limits,
        )
        return

    if value == "zstd":
        yield from _iter_zstd_native(data, limits)
        return
    if value == "lz4_frame":
        yield from _iter_lz4_frame_native(data, limits)
        return
    if value == "lz4_block":
        decoded = _decode_lz4_block(data, limits)
    elif value == "zip":
        raise ExactDecodeError(
            "ZIP archives are multi-entry containers and cannot be verified "
            "as one byte stream; select an entry with uhc.core.zip_parser"
        )
    else:
        raise ValueError(f"Unsupported exact-verification format: {value!r}")

    limits.check_output(len(decoded))
    for start in range(0, len(decoded), limits.io_chunk_size):
        yield decoded[start:start + limits.io_chunk_size]


def compare_exact_decoded(
    data_a: bytes,
    fmt_a: object,
    data_b: bytes,
    fmt_b: object,
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bool:
    """Compare strict decoded streams exactly while retaining bounded chunks."""
    iter_a = iter(iter_decode_exact(data_a, fmt_a, limits=limits))
    iter_b = iter(iter_decode_exact(data_b, fmt_b, limits=limits))
    chunk_a = b""
    chunk_b = b""
    offset_a = 0
    offset_b = 0
    digest_a = hashlib.sha256()
    digest_b = hashlib.sha256()
    exact = True
    done_a = False
    done_b = False

    while True:
        if not done_a and offset_a == len(chunk_a):
            try:
                chunk_a = next(iter_a)
                digest_a.update(chunk_a)
                offset_a = 0
            except StopIteration:
                done_a = True
        if not done_b and offset_b == len(chunk_b):
            try:
                chunk_b = next(iter_b)
                digest_b.update(chunk_b)
                offset_b = 0
            except StopIteration:
                done_b = True

        if done_a or done_b:
            if done_a != done_b:
                exact = False
            if not done_a:
                for remainder in iter_a:
                    digest_a.update(remainder)
            if not done_b:
                for remainder in iter_b:
                    digest_b.update(remainder)
            break

        available_a = len(chunk_a) - offset_a
        available_b = len(chunk_b) - offset_b
        if available_a == 0 or available_b == 0:
            continue

        size = min(available_a, available_b)
        if not hmac.compare_digest(
            chunk_a[offset_a:offset_a + size],
            chunk_b[offset_b:offset_b + size],
        ):
            exact = False
        offset_a += size
        offset_b += size

    return exact and hmac.compare_digest(digest_a.digest(), digest_b.digest())


def decode_exact(
    data: bytes,
    fmt: object,
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> bytes:
    """Strictly decode one supported input according to ``fmt``."""
    return b"".join(iter_decode_exact(data, fmt, limits=limits))
