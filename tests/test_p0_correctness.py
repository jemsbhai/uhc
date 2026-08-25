"""Focused UHC 02 adversarial correctness regressions."""

from __future__ import annotations

import gzip
import zlib

import pytest

from uhc.core.compressed_verifier import compressed_domain_hash
from uhc.core.deflate import deflate_extract_tokens
from uhc.core.gzip_parser import gzip_extract_tokens
from uhc.core.lz77 import Literal, Reference, lz77_decode, validate_tokens
from uhc.core.multihash import MultiHash, multi_cdh
from uhc.core.polynomial_hash import PolynomialHash
from uhc.engine.pipeline import Format, extract_tokens, uhc_verify


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def test_known_polynomial_collision_fails_exact_verification() -> None:
    left = bytes.fromhex("002900da1a0032db003000b40000")
    right = bytes.fromhex("0e005a0000d8000041007900f8d8")

    assert left != right
    for base in (131, 257):
        assert PolynomialHash(base=base).hash(left) == PolynomialHash(base=base).hash(right)
    assert uhc_verify(left, right) is False


def test_raw_deflate_rejects_trailing_bytes() -> None:
    stream = _raw_deflate(b"strict deflate")
    with pytest.raises(ValueError, match="Trailing data"):
        deflate_extract_tokens(stream + b"junk")
    with pytest.raises(ValueError, match="Trailing data"):
        uhc_verify(
            b"strict deflate",
            stream + b"junk",
            fmt_a=Format.RAW,
            fmt_b=Format.DEFLATE,
        )


def test_gzip_concatenated_members_are_all_verified() -> None:
    encoded = gzip.compress(b"first-") + gzip.compress(b"second")
    assert lz77_decode(gzip_extract_tokens(encoded)) == b"first-second"
    assert uhc_verify(
        b"first-second", encoded, fmt_a=Format.RAW, fmt_b=Format.GZIP
    )


def test_gzip_rejects_trailing_data_and_bad_trailer() -> None:
    encoded = gzip.compress(b"payload")
    with pytest.raises(ValueError, match="Trailing data"):
        gzip_extract_tokens(encoded + b"junk")

    damaged = bytearray(encoded)
    damaged[-8] ^= 1
    with pytest.raises(ValueError, match="CRC mismatch"):
        gzip_extract_tokens(bytes(damaged))


def test_zstd_concatenated_frames_and_trailing_data() -> None:
    zstd = pytest.importorskip("zstandard", reason="zstandard optional dependency absent")
    compressor = zstd.ZstdCompressor(write_checksum=True)
    encoded = compressor.compress(b"first-") + compressor.compress(b"second")

    assert lz77_decode(extract_tokens(encoded, Format.ZSTD)) == b"first-second"
    assert uhc_verify(
        b"first-second", encoded, fmt_a=Format.RAW, fmt_b=Format.ZSTD
    )
    with pytest.raises(ValueError, match="Trailing data"):
        extract_tokens(encoded + b"junk", Format.ZSTD)
    with pytest.raises(ValueError):
        uhc_verify(
            b"first-second",
            encoded + b"junk",
            fmt_a=Format.RAW,
            fmt_b=Format.ZSTD,
        )


@pytest.mark.parametrize("invalid_prime", [15, 63, 2_047, 17])
def test_invalid_hash_moduli_are_rejected(invalid_prime: int) -> None:
    with pytest.raises(ValueError):
        PolynomialHash(prime=invalid_prime, base=2)


def test_duplicate_multi_hash_bases_are_rejected() -> None:
    with pytest.raises(ValueError, match="distinct"):
        MultiHash(bases=[131, 131])


def test_token_validation_is_shared_by_decode_and_hash_paths() -> None:
    invalid = [Reference(distance=1, length=3)]
    with pytest.raises(ValueError, match="decoded length"):
        validate_tokens(invalid)
    with pytest.raises(ValueError, match="decoded length"):
        lz77_decode(invalid)
    with pytest.raises(ValueError, match="decoded length"):
        compressed_domain_hash(invalid)
    with pytest.raises(ValueError, match="decoded length"):
        multi_cdh(invalid, MultiHash(bases=[131, 257]))


def test_token_fields_reject_boolean_values() -> None:
    with pytest.raises(ValueError):
        Literal(True)
    with pytest.raises(ValueError):
        Reference(True, 3)
    with pytest.raises(ValueError):
        Reference(1, False)
