"""Atheris target comparing strict UHC acceptance with native decoders.

Run from the repository root after installing Atheris and UHC format extras:

    python fuzz/python/fuzz_native_differential.py fuzz/corpus/python_native
"""

from __future__ import annotations

import io
import sys
import zipfile
import zlib

import atheris

with atheris.instrument_imports():
    from uhc.core.deflate import deflate_extract_tokens
    from uhc.core.exact import decode_exact
    from uhc.core.gzip_parser import gzip_extract_tokens
    from uhc.core.lz77 import lz77_decode
    from uhc.core.zip_parser import zip_entry_extract_tokens, zip_list_entries
    from uhc.engine.pipeline import Format

try:
    import zstandard as zstd
except ImportError:
    zstd = None


def _native_zlib(data: bytes, wbits: int, concatenated: bool) -> bytes:
    remaining = data
    output: list[bytes] = []
    if not remaining:
        raise ValueError("empty stream")
    while remaining:
        if concatenated and not remaining.startswith(b"\x1f\x8b"):
            raise ValueError("trailing non-member data")
        decoder = zlib.decompressobj(wbits)
        output.append(decoder.decompress(remaining) + decoder.flush())
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
    output: list[bytes] = []
    remaining = data
    while remaining:
        decoder = zstd.ZstdDecompressor().decompressobj()
        output.append(decoder.decompress(remaining) + decoder.flush())
        if not decoder.eof:
            raise ValueError("incomplete native Zstandard frame")
        remaining = decoder.unused_data
    return b"".join(output)


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
            return decode_exact(payload, Format.DEFLATE)

        def tokens():
            return lz77_decode(deflate_extract_tokens(payload))
    elif selector == 1:
        def native():
            return _native_zlib(payload, 16 + zlib.MAX_WBITS, True)

        def project():
            return decode_exact(payload, Format.GZIP)

        def tokens():
            return lz77_decode(gzip_extract_tokens(payload))
    else:
        if zstd is None:
            return
        from uhc.core.zstd_parser import zstd_extract_tokens

        def native():
            return _native_zstd(payload)

        def project():
            return decode_exact(payload, Format.ZSTD)

        def tokens():
            return lz77_decode(zstd_extract_tokens(payload))

    native_ok, native_output = _accepted(native)
    project_ok, project_output = _accepted(project)
    assert native_ok == project_ok
    if project_ok:
        token_ok, token_output = _accepted(tokens)
        assert token_ok
        assert native_output == project_output == token_output


def _fuzz_zip(payload: bytes) -> None:
    project_ok, project_entries = _accepted(lambda: zip_list_entries(payload))
    if not project_ok:
        return  # UHC intentionally supports a strict ZIP subset.

    def native_contents() -> dict[str, bytes]:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            return {
                info.filename: archive.read(info)
                for info in archive.infolist()
                if not info.is_dir()
            }

    native_ok, native = _accepted(native_contents)
    assert native_ok
    project = {
        entry.filename: lz77_decode(zip_entry_extract_tokens(payload, entry))
        for entry in project_entries
    }
    assert project == native


def test_one_input(data: bytes) -> None:
    if data.startswith(b"hex:"):
        try:
            data = bytes.fromhex(data[4:].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError):
            return
    if not data:
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
