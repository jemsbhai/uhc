"""Atheris target comparing strict UHC acceptance with native decoders.

Run from the repository root after installing Atheris and UHC format extras:

    python fuzz/python/fuzz_native_differential.py fuzz/corpus/python_native
"""

from __future__ import annotations

import io
import binascii
import struct
import sys
import zipfile
import zlib

import atheris

with atheris.instrument_imports():
    from uhc.core.exact import decode_exact
    from uhc.core.lz77 import iter_lz77_decode
    from uhc.core.resources import ResourceLimits
    from uhc.core.zip_parser import ZipEntry, zip_list_entries
    from uhc.engine.pipeline import Format, iter_tokens

try:
    import zstandard as zstd
except ImportError:
    zstd = None


MAX_FUZZ_INPUT_BYTES = 4096
MAX_STREAM_OUTPUT_BYTES = 64 * 1024
MAX_STREAM_TOKENS = 64 * 1024
MAX_ZIP_ENTRIES = 32
MAX_ZIP_ENTRY_OUTPUT_BYTES = 32 * 1024
MAX_ZIP_AGGREGATE_OUTPUT_BYTES = 64 * 1024

FUZZ_LIMITS = ResourceLimits(
    max_input_bytes=MAX_FUZZ_INPUT_BYTES,
    max_output_bytes=MAX_STREAM_OUTPUT_BYTES,
    max_tokens=MAX_STREAM_TOKENS,
    max_depth=64,
    max_reference_distance=MAX_STREAM_OUTPUT_BYTES,
    max_reference_length=MAX_STREAM_OUTPUT_BYTES,
    io_chunk_size=4096,
)
ZIP_ENTRY_LIMITS = ResourceLimits(
    max_input_bytes=MAX_FUZZ_INPUT_BYTES,
    max_output_bytes=MAX_ZIP_ENTRY_OUTPUT_BYTES,
    max_tokens=MAX_ZIP_ENTRY_OUTPUT_BYTES,
    max_depth=64,
    max_reference_distance=MAX_ZIP_ENTRY_OUTPUT_BYTES,
    max_reference_length=MAX_ZIP_ENTRY_OUTPUT_BYTES,
    io_chunk_size=4096,
)


def _append_bounded(
    output: list[bytes], chunk: bytes, total: int, limit: int
) -> int:
    next_total = total + len(chunk)
    if next_total > limit:
        raise ValueError(f"decoded output exceeds fuzz limit {limit}")
    output.append(chunk)
    return next_total


def _native_zlib(data: bytes, wbits: int, concatenated: bool) -> bytes:
    FUZZ_LIMITS.check_input(len(data))
    remaining = data
    output: list[bytes] = []
    total = 0
    if not remaining:
        raise ValueError("empty stream")
    while remaining:
        if concatenated and not remaining.startswith(b"\x1f\x8b"):
            raise ValueError("trailing non-member data")
        decoder = zlib.decompressobj(wbits)
        available = MAX_STREAM_OUTPUT_BYTES - total
        decoded = decoder.decompress(remaining, available + 1)
        total = _append_bounded(
            output, decoded, total, MAX_STREAM_OUTPUT_BYTES
        )
        if decoder.unconsumed_tail:
            raise ValueError("native zlib output exceeds fuzz limit")
        if not decoder.eof or decoder.unconsumed_tail:
            raise ValueError("incomplete native stream")
        if not concatenated:
            if decoder.unused_data:
                raise ValueError("trailing native stream data")
            break
        remaining = decoder.unused_data
    return b"".join(output)


def _native_zstd(data: bytes) -> bytes:
    if zstd is None or not data:
        raise ValueError("Zstandard unavailable or empty")
    FUZZ_LIMITS.check_input(len(data))
    remaining = data
    output: list[bytes] = []
    total = 0
    while remaining:
        decoder = zstd.ZstdDecompressor(
            max_window_size=MAX_STREAM_OUTPUT_BYTES
        ).decompressobj()
        decoded = decoder.decompress(remaining) + decoder.flush()
        total = _append_bounded(
            output, decoded, total, MAX_STREAM_OUTPUT_BYTES
        )
        if not decoder.eof:
            raise ValueError("truncated native Zstandard frame")
        if decoder.unconsumed_tail:
            raise ValueError("unconsumed native Zstandard input")
        remaining = decoder.unused_data
    return b"".join(output)


def _project_tokens(data: bytes, fmt: Format, limits: ResourceLimits) -> bytes:
    return b"".join(
        iter_lz77_decode(iter_tokens(data, fmt, limits=limits), limits=limits)
    )


def _accepted(callable_):
    try:
        return True, callable_()
    except (EOFError, RuntimeError, ValueError, zlib.error, zipfile.BadZipFile):
        return False, None
    except Exception as exc:
        if zstd is not None and isinstance(exc, zstd.ZstdError):
            return False, None
        raise


def _fuzz_stream(selector: int, payload: bytes) -> None:
    if selector == 0:
        def native():
            return _native_zlib(payload, -zlib.MAX_WBITS, False)

        def project():
            return decode_exact(payload, Format.DEFLATE, limits=FUZZ_LIMITS)

        def tokens():
            return _project_tokens(payload, Format.DEFLATE, FUZZ_LIMITS)
    elif selector == 1:
        def native():
            return _native_zlib(payload, 16 + zlib.MAX_WBITS, True)

        def project():
            return decode_exact(payload, Format.GZIP, limits=FUZZ_LIMITS)

        def tokens():
            return _project_tokens(payload, Format.GZIP, FUZZ_LIMITS)
    else:
        if zstd is None:
            return
        def native():
            return _native_zstd(payload)

        def project():
            return decode_exact(payload, Format.ZSTD, limits=FUZZ_LIMITS)

        def tokens():
            return _project_tokens(payload, Format.ZSTD, FUZZ_LIMITS)

    native_ok, native_output = _accepted(native)
    project_ok, project_output = _accepted(project)
    assert native_ok == project_ok
    if project_ok:
        token_ok, token_output = _accepted(tokens)
        assert token_ok
        assert native_output == project_output == token_output


def _check_zip_metadata(entries: list[ZipEntry]) -> list[ZipEntry]:
    if len(entries) > MAX_ZIP_ENTRIES:
        raise ValueError(f"ZIP entry count exceeds fuzz limit {MAX_ZIP_ENTRIES}")
    aggregate = 0
    for entry in entries:
        if entry.uncompressed_size > MAX_ZIP_ENTRY_OUTPUT_BYTES:
            raise ValueError(
                f"ZIP entry size exceeds fuzz limit {MAX_ZIP_ENTRY_OUTPUT_BYTES}"
            )
        aggregate += entry.uncompressed_size
        if aggregate > MAX_ZIP_AGGREGATE_OUTPUT_BYTES:
            raise ValueError(
                "ZIP aggregate size exceeds fuzz limit "
                f"{MAX_ZIP_AGGREGATE_OUTPUT_BYTES}"
            )
    return entries


def _project_zip_contents(payload: bytes, entries: list[ZipEntry]) -> dict[str, bytes]:
    output: dict[str, bytes] = {}
    aggregate = 0
    for entry in entries:
        flags = struct.unpack_from("<H", payload, entry.local_header_offset + 6)[0]
        if flags & (0x0001 | 0x0040):
            raise ValueError("encrypted ZIP entries are unsupported")
        data_end = entry.data_offset + entry.compressed_size
        compressed = payload[entry.data_offset:data_end]
        if entry.compression_method == 0:
            decoded = compressed
        elif entry.compression_method == 8:
            decoded = _project_tokens(
                compressed, Format.DEFLATE, ZIP_ENTRY_LIMITS
            )
        else:
            raise ValueError("unsupported ZIP compression method")
        if len(decoded) != entry.uncompressed_size:
            raise ValueError("ZIP decoded size mismatch")
        if binascii.crc32(decoded) & 0xFFFFFFFF != entry.crc32:
            raise ValueError("ZIP CRC mismatch")
        aggregate += len(decoded)
        if aggregate > MAX_ZIP_AGGREGATE_OUTPUT_BYTES:
            raise ValueError("ZIP decoded aggregate exceeds fuzz limit")
        output[entry.filename] = decoded
    return output


def _fuzz_zip(payload: bytes) -> None:
    FUZZ_LIMITS.check_input(len(payload))
    entries_ok, project_entries = _accepted(
        lambda: _check_zip_metadata(zip_list_entries(payload))
    )
    if not entries_ok:
        return  # UHC intentionally supports a strict, fuzz-bounded ZIP subset.

    def native_contents() -> dict[str, bytes]:
        output: dict[str, bytes] = {}
        aggregate = 0
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            if len(infos) > MAX_ZIP_ENTRIES:
                raise ValueError("native ZIP entry count exceeds fuzz limit")
            for info in infos:
                if info.file_size > MAX_ZIP_ENTRY_OUTPUT_BYTES:
                    raise ValueError("native ZIP entry size exceeds fuzz limit")
                with archive.open(info) as stream:
                    decoded = stream.read(MAX_ZIP_ENTRY_OUTPUT_BYTES + 1)
                    if len(decoded) > MAX_ZIP_ENTRY_OUTPUT_BYTES or stream.read(1):
                        raise ValueError("native ZIP entry output exceeds fuzz limit")
                aggregate += len(decoded)
                if aggregate > MAX_ZIP_AGGREGATE_OUTPUT_BYTES:
                    raise ValueError("native ZIP aggregate exceeds fuzz limit")
                output[info.filename] = decoded
        return output

    project_ok, project = _accepted(
        lambda: _project_zip_contents(payload, project_entries)
    )
    if not project_ok:
        return  # Native ZIP may support methods outside UHC's strict subset.
    native_ok, native = _accepted(native_contents)
    assert native_ok
    assert project == native


def test_one_input(data: bytes) -> None:
    if len(data) > MAX_FUZZ_INPUT_BYTES:
        return
    if data.startswith(b"hex:"):
        try:
            data = bytes.fromhex(data[4:].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError):
            return
    if not data or len(data) > MAX_FUZZ_INPUT_BYTES:
        return
    selector = data[0] % 4
    payload = data[1:]
    if selector == 3:
        _fuzz_zip(payload)
    else:
        _fuzz_stream(selector, payload)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
