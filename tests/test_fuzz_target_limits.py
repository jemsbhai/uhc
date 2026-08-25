"""Focused checks for the bounded optional Atheris differential harness."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import types
import zipfile
import zlib
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def fuzz_target():
    stub = types.ModuleType("atheris")
    stub.instrument_imports = contextlib.nullcontext
    previous = sys.modules.get("atheris")
    sys.modules["atheris"] = stub
    try:
        path = (
            Path(__file__).resolve().parents[1]
            / "fuzz"
            / "python"
            / "fuzz_native_differential.py"
        )
        spec = importlib.util.spec_from_file_location("uhc_fuzz_limits", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
    finally:
        if previous is None:
            sys.modules.pop("atheris", None)
        else:
            sys.modules["atheris"] = previous


def _raw_deflate(data: bytes) -> bytes:
    encoder = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return encoder.compress(data) + encoder.flush()


def _zip_bytes(payloads: list[bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, payload in enumerate(payloads):
            archive.writestr(f"entry-{index}.bin", payload)
    return output.getvalue()


def test_stream_bomb_is_rejected_by_native_exact_and_token_paths(fuzz_target):
    raw = b"A" * (fuzz_target.MAX_STREAM_OUTPUT_BYTES + 1)
    encoded = _raw_deflate(raw)
    assert len(encoded) < fuzz_target.MAX_FUZZ_INPUT_BYTES

    native_ok, _ = fuzz_target._accepted(
        lambda: fuzz_target._native_zlib(encoded, -zlib.MAX_WBITS, False)
    )
    exact_ok, _ = fuzz_target._accepted(
        lambda: fuzz_target.decode_exact(
            encoded,
            fuzz_target.Format.DEFLATE,
            limits=fuzz_target.FUZZ_LIMITS,
        )
    )
    token_ok, _ = fuzz_target._accepted(
        lambda: fuzz_target._project_tokens(
            encoded,
            fuzz_target.Format.DEFLATE,
            fuzz_target.FUZZ_LIMITS,
        )
    )
    assert (native_ok, exact_ok, token_ok) == (False, False, False)


def test_zstd_native_oracle_enforces_output_budget(fuzz_target):
    if fuzz_target.zstd is None:
        pytest.skip("optional zstandard binding is unavailable")
    raw = b"Z" * (fuzz_target.MAX_STREAM_OUTPUT_BYTES + 1)
    encoded = fuzz_target.zstd.ZstdCompressor().compress(raw)
    assert len(encoded) < fuzz_target.MAX_FUZZ_INPUT_BYTES

    native_ok, _ = fuzz_target._accepted(
        lambda: fuzz_target._native_zstd(encoded)
    )
    exact_ok, _ = fuzz_target._accepted(
        lambda: fuzz_target.decode_exact(
            encoded,
            fuzz_target.Format.ZSTD,
            limits=fuzz_target.FUZZ_LIMITS,
        )
    )
    assert (native_ok, exact_ok) == (False, False)


def test_zstd_native_oracle_rejects_truncated_frame(fuzz_target):
    if fuzz_target.zstd is None:
        pytest.skip("optional zstandard binding is unavailable")
    truncated = b"Q"

    native_ok, _ = fuzz_target._accepted(
        lambda: fuzz_target._native_zstd(truncated)
    )
    exact_ok, _ = fuzz_target._accepted(
        lambda: fuzz_target.decode_exact(
            truncated,
            fuzz_target.Format.ZSTD,
            limits=fuzz_target.FUZZ_LIMITS,
        )
    )

    assert (native_ok, exact_ok) == (False, False)
    fuzz_target._fuzz_stream(2, truncated)


def test_zip_entry_and_aggregate_metadata_budgets(fuzz_target):
    oversized = _zip_bytes([b"B" * (fuzz_target.MAX_ZIP_ENTRY_OUTPUT_BYTES + 1)])
    assert len(oversized) < fuzz_target.MAX_FUZZ_INPUT_BYTES
    with pytest.raises(ValueError, match="entry size"):
        fuzz_target._check_zip_metadata(fuzz_target.zip_list_entries(oversized))

    per_entry = fuzz_target.MAX_ZIP_ENTRY_OUTPUT_BYTES
    aggregate = _zip_bytes([b"C" * per_entry] * 3)
    assert len(aggregate) < fuzz_target.MAX_FUZZ_INPUT_BYTES
    with pytest.raises(ValueError, match="aggregate size"):
        fuzz_target._check_zip_metadata(fuzz_target.zip_list_entries(aggregate))


def test_zip_reserved_deflate_distance_is_a_clean_rejection(fuzz_target):
    archive = bytes.fromhex(
        "504b0304140000000800000021004193e9700f0000001e00000009000000"
        "61756469742e7478744b2c4dc91cd12f4e4d4d49c4c20600"
        "504b01021400140000000800000021004193e9700f0000001e00000009000000"
        "000000000000000080010000000061756469742e747874"
        "504b0506000000000100010037000000360000000000"
    )

    fuzz_target._fuzz_zip(archive)
