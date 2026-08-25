"""UHC 05 native differential, property, and malformed-corpus checks."""

from __future__ import annotations

import gzip
import io
from functools import partial
from pathlib import Path
import zipfile
import zlib

from hypothesis import given, settings, strategies as st
import pytest

from uhc.core.deflate import deflate_extract_tokens
from uhc.core.exact import decode_exact
from uhc.core.gzip_parser import gzip_extract_tokens
from uhc.core.lz77 import lz77_decode
from uhc.core.zip_parser import zip_entry_extract_tokens, zip_list_entries
from uhc.engine.pipeline import Format, uhc_verify_exact

try:
    import zstandard as zstd
except ImportError:  # pragma: no cover - exercised in minimal-dependency jobs
    zstd = None


ZSTD_SKIP_REASON = (
    "Zstandard differential tests require the optional 'zstandard' binding; "
    "install with: python -m pip install -e '.[dev,formats]'"
)
CORPUS_ROOT = Path(__file__).with_name("corpus")

# Keep local runs deterministic and bounded. A failing example is printed as a
# replay blob, while permanent regressions belong in tests/corpus/.
PROPERTY_SETTINGS = settings(
    max_examples=40,
    deadline=None,
    derandomize=True,
    database=None,
    print_blob=True,
)


def _raw_deflate(data: bytes, level: int, strategy: int) -> bytes:
    compressor = zlib.compressobj(
        level=level,
        method=zlib.DEFLATED,
        wbits=-zlib.MAX_WBITS,
        strategy=strategy,
    )
    return compressor.compress(data) + compressor.flush()


def _strict_zlib_native(
    data: bytes,
    *,
    wbits: int,
    concatenated: bool,
    magic: bytes | None,
) -> bytes:
    """Use zlib's native decoder while enforcing UHC's strict boundaries."""
    remaining = data
    chunks: list[bytes] = []
    if not remaining:
        raise ValueError("empty compressed stream")
    while remaining:
        if magic is not None and not remaining.startswith(magic):
            raise ValueError("non-member trailing data")
        decoder = zlib.decompressobj(wbits)
        chunks.append(decoder.decompress(remaining) + decoder.flush())
        if not decoder.eof:
            raise ValueError("truncated compressed stream")
        if decoder.unconsumed_tail:
            raise ValueError("unconsumed compressed input")
        trailing = decoder.unused_data
        if not concatenated:
            if trailing:
                raise ValueError("trailing compressed input")
            break
        if not trailing:
            break
        remaining = trailing
    return b"".join(chunks)


def _strict_zstd_native(data: bytes) -> bytes:
    if zstd is None:
        raise RuntimeError(ZSTD_SKIP_REASON)
    if not data:
        raise ValueError("empty Zstandard input")
    chunks: list[bytes] = []
    remaining = data
    while remaining:
        decoder = zstd.ZstdDecompressor().decompressobj()
        chunks.append(decoder.decompress(remaining) + decoder.flush())
        if not decoder.eof:
            raise ValueError("truncated Zstandard frame")
        if not decoder.unused_data:
            break
        remaining = decoder.unused_data
    return b"".join(chunks)


def _make_zip(payloads: list[bytes], compression: int) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for index, payload in enumerate(payloads):
            info = zipfile.ZipInfo(
                f"entry-{index:02d}.bin",
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = compression
            archive.writestr(info, payload)
    return output.getvalue()


def _native_zip_contents(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if not info.is_dir()
        }


def _project_zip_contents(data: bytes) -> dict[str, bytes]:
    return {
        entry.filename: lz77_decode(zip_entry_extract_tokens(data, entry))
        for entry in zip_list_entries(data)
    }


@PROPERTY_SETTINGS
@given(
    data=st.binary(max_size=4096),
    level=st.sampled_from([0, 1, 6, 9]),
    strategy=st.sampled_from([zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED]),
)
def test_raw_deflate_matches_native_zlib(
    data: bytes, level: int, strategy: int
) -> None:
    compressed = _raw_deflate(data, level, strategy)
    native = _strict_zlib_native(
        compressed,
        wbits=-zlib.MAX_WBITS,
        concatenated=False,
        magic=None,
    )
    parsed = lz77_decode(deflate_extract_tokens(compressed))
    assert native == parsed == data
    assert decode_exact(compressed, Format.DEFLATE) == native


@PROPERTY_SETTINGS
@given(members=st.lists(st.binary(max_size=1024), min_size=1, max_size=5))
def test_concatenated_gzip_matches_native(members: list[bytes]) -> None:
    compressed = b"".join(gzip.compress(member, mtime=0) for member in members)
    native = _strict_zlib_native(
        compressed,
        wbits=16 + zlib.MAX_WBITS,
        concatenated=True,
        magic=b"\x1f\x8b",
    )
    parsed = lz77_decode(gzip_extract_tokens(compressed))
    assert native == gzip.decompress(compressed) == parsed == b"".join(members)
    assert decode_exact(compressed, Format.GZIP) == native


@pytest.mark.skipif(zstd is None, reason=ZSTD_SKIP_REASON)
@PROPERTY_SETTINGS
@given(
    members=st.lists(st.binary(max_size=1536), min_size=1, max_size=4),
    level=st.sampled_from([1, 3, 9]),
)
def test_concatenated_zstd_matches_native(
    members: list[bytes], level: int
) -> None:
    from uhc.core.zstd_parser import zstd_extract_tokens

    compressor = zstd.ZstdCompressor(level=level)
    compressed = b"".join(compressor.compress(member) for member in members)
    native = _strict_zstd_native(compressed)
    parsed = lz77_decode(zstd_extract_tokens(compressed))
    assert native == parsed == b"".join(members)
    assert decode_exact(compressed, Format.ZSTD) == native


@PROPERTY_SETTINGS
@given(
    payloads=st.lists(st.binary(max_size=1024), max_size=6),
    compression=st.sampled_from([zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED]),
)
def test_zip_entries_match_native_zipfile(
    payloads: list[bytes], compression: int
) -> None:
    archive = _make_zip(payloads, compression)
    assert _project_zip_contents(archive) == _native_zip_contents(archive)


def _read_hex(relative: str) -> bytes:
    text = (CORPUS_ROOT / relative).read_text(encoding="ascii")
    return bytes.fromhex("".join(line for line in text.splitlines() if not line.startswith("#")))


MALFORMED_STREAMS = [
    pytest.param("deflate", "malformed/deflate/truncated.hex", id="deflate-truncated"),
    pytest.param("deflate", "malformed/deflate/trailing.hex", id="deflate-trailing"),
    pytest.param("gzip", "malformed/gzip/bad-crc.hex", id="gzip-bad-crc"),
    pytest.param("gzip", "malformed/gzip/truncated.hex", id="gzip-truncated"),
    pytest.param("gzip", "malformed/gzip/trailing.hex", id="gzip-trailing"),
    pytest.param(
        "zstd",
        "malformed/zstd/bad-magic.hex",
        id="zstd-bad-magic",
        marks=pytest.mark.skipif(zstd is None, reason=ZSTD_SKIP_REASON),
    ),
    pytest.param(
        "zstd",
        "malformed/zstd/truncated.hex",
        id="zstd-truncated",
        marks=pytest.mark.skipif(zstd is None, reason=ZSTD_SKIP_REASON),
    ),
    pytest.param(
        "zstd",
        "malformed/zstd/trailing.hex",
        id="zstd-trailing",
        marks=pytest.mark.skipif(zstd is None, reason=ZSTD_SKIP_REASON),
    ),
]


@pytest.mark.parametrize("kind,relative", MALFORMED_STREAMS)
def test_malformed_stream_corpus_matches_native_rejection(
    kind: str, relative: str
) -> None:
    data = _read_hex(relative)
    if kind == "deflate":
        native = partial(
            _strict_zlib_native,
            data,
            wbits=-zlib.MAX_WBITS,
            concatenated=False,
            magic=None,
        )
        fmt = Format.DEFLATE
        native_errors = (ValueError, zlib.error)
    elif kind == "gzip":
        native = partial(
            _strict_zlib_native,
            data,
            wbits=16 + zlib.MAX_WBITS,
            concatenated=True,
            magic=b"\x1f\x8b",
        )
        fmt = Format.GZIP
        native_errors = (ValueError, zlib.error)
    else:
        native = partial(_strict_zstd_native, data)
        fmt = Format.ZSTD
        native_errors = (ValueError, zstd.ZstdError)

    with pytest.raises(native_errors):
        native()
    with pytest.raises(ValueError):
        decode_exact(data, fmt)


@pytest.mark.parametrize(
    "relative",
    ["malformed/zip/bad-crc.hex", "malformed/zip/truncated-eocd.hex"],
)
def test_malformed_zip_corpus_matches_native_rejection(relative: str) -> None:
    data = _read_hex(relative)
    with pytest.raises((ValueError, zipfile.BadZipFile)):
        _native_zip_contents(data)
    with pytest.raises(ValueError):
        _project_zip_contents(data)


def test_audit_polynomial_collision_is_not_exact_equality() -> None:
    left = _read_hex("audit/python-polynomial-collision-left.hex")
    right = _read_hex("audit/python-polynomial-collision-right.hex")
    assert not uhc_verify_exact(left, right, fmt_a=Format.RAW, fmt_b=Format.RAW)


def test_audit_concatenated_gzip_seed() -> None:
    compressed = _read_hex("audit/gzip-concatenated.hex")
    assert decode_exact(compressed, Format.GZIP) == b"leftright"


@pytest.mark.skipif(zstd is None, reason=ZSTD_SKIP_REASON)
def test_audit_concatenated_zstd_seed() -> None:
    compressed = _read_hex("audit/zstd-concatenated.hex")
    assert decode_exact(compressed, Format.ZSTD) == b"leftright"
