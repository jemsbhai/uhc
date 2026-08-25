"""UHC 04 streaming and bounded-resource regressions."""

from __future__ import annotations

import tracemalloc
import zlib

import pytest

from uhc.chunking.cdc import cdc_chunk, cdc_ranges
from uhc.cli import main
from uhc.core.compressed_verifier import CDHMethod, compressed_domain_hash
from uhc.core.deflate import iter_deflate_tokens
from uhc.core.exact import compare_exact_decoded, iter_decode_exact
from uhc.core.lz77 import Literal, Reference
from uhc.core.multihash import MultiHash, multi_cdh
from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.resources import ResourceLimitError, ResourceLimits
from uhc.engine.pipeline import Format, iter_tokens, uhc_hash, uhc_hash_multi


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


class _OnePassTokens:
    def __init__(self, tokens):
        self._tokens = iter(tokens)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        if self.iterations > 1:
            raise AssertionError("token stream was traversed more than once")
        return self

    def __next__(self):
        return next(self._tokens)


def test_tuple_cdh_consumes_token_iterator_once_for_every_method():
    tokens = [Literal(ord("a")), Literal(ord("b")), Reference(2, 6)]
    expected = MultiHash([131, 257]).hash(b"abababab")
    for method in CDHMethod:
        source = _OnePassTokens(tokens)
        assert multi_cdh(source, MultiHash([131, 257]), method=method) == expected
        assert source.iterations == 1


def test_format_parser_and_pipeline_expose_iterators():
    data = b"streamed parser tokens " * 100
    encoded = _raw_deflate(data)
    token_iterator = iter_deflate_tokens(encoded)
    assert iter(token_iterator) is token_iterator
    assert compressed_domain_hash(token_iterator) == PolynomialHash().hash(data)
    assert not isinstance(iter_tokens(encoded, Format.DEFLATE), list)


def test_raw_tuple_hash_is_one_pass_and_matches_components():
    chunks = [b"alpha", b"beta", b"gamma"]
    mh = MultiHash([131, 257, 521])
    assert mh.hash_iter(iter(chunks)) == tuple(
        PolynomialHash(base=base).hash(b"".join(chunks))
        for base in (131, 257, 521)
    )


def test_cdc_ranges_match_compatibility_chunks_without_rescan():
    data = bytes(range(256)) * 1000
    ranges = list(cdc_ranges(data, min_size=64, avg_size=256, max_size=1024))
    chunks = cdc_chunk(data, min_size=64, avg_size=256, max_size=1024)
    assert [data[start:end] for start, end in ranges] == chunks
    assert ranges[0][0] == 0
    assert ranges[-1][1] == len(data)
    assert all(left[1] == right[0] for left, right in zip(ranges, ranges[1:]))


def test_cdc_range_iteration_has_constant_auxiliary_memory():
    data = b"x" * (2 * 1024 * 1024)
    tracemalloc.start()
    count = sum(1 for _ in cdc_ranges(data, min_size=64, avg_size=256, max_size=1024))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert count > 0
    assert peak < 512 * 1024


def test_input_output_token_reference_and_depth_budgets():
    with pytest.raises(ResourceLimitError, match="max_input_bytes"):
        uhc_hash(b"12345", limits=ResourceLimits(max_input_bytes=4))
    with pytest.raises(ResourceLimitError, match="max_output_bytes"):
        uhc_hash(b"12345", limits=ResourceLimits(max_output_bytes=4))
    with pytest.raises(ResourceLimitError, match="max_tokens"):
        list(iter_tokens(b"abc", Format.RAW, limits=ResourceLimits(max_tokens=2)))
    with pytest.raises(ResourceLimitError, match="reference length"):
        compressed_domain_hash(
            [Literal(1), Reference(1, 5)],
            limits=ResourceLimits(max_reference_length=4),
        )
    with pytest.raises(ResourceLimitError, match="max_depth"):
        compressed_domain_hash(
            [Literal(1), Literal(2)],
            limits=ResourceLimits(max_depth=1),
        )


def test_exact_decoder_enforces_expansion_budget_before_returning_result():
    data = b"A" * 100_000
    encoded = _raw_deflate(data)
    limits = ResourceLimits(max_output_bytes=4096, io_chunk_size=1024)
    with pytest.raises(ResourceLimitError, match="max_output_bytes"):
        list(iter_decode_exact(encoded, Format.DEFLATE, limits=limits))


def test_native_frame_decoders_enforce_streaming_expansion_budgets():
    zstd = pytest.importorskip(
        "zstandard", reason="optional Zstandard binding is not installed"
    )
    lz4_frame = pytest.importorskip(
        "lz4.frame", reason="optional LZ4 binding is not installed"
    )
    data = b"B" * 100_000
    limits = ResourceLimits(max_output_bytes=4096, io_chunk_size=1024)

    with pytest.raises(ResourceLimitError, match="max_output_bytes"):
        list(iter_decode_exact(
            zstd.ZstdCompressor().compress(data), Format.ZSTD, limits=limits
        ))
    with pytest.raises(ResourceLimitError, match="max_output_bytes"):
        list(iter_decode_exact(
            lz4_frame.compress(data), Format.LZ4_FRAME, limits=limits
        ))


def test_exact_stream_comparison_handles_different_chunk_boundaries():
    data = b"chunk boundaries must not affect equality" * 1000
    encoded = _raw_deflate(data)
    limits = ResourceLimits(io_chunk_size=127)
    assert compare_exact_decoded(
        encoded, Format.DEFLATE, data, Format.RAW, limits=limits
    )
    assert not compare_exact_decoded(
        encoded, Format.DEFLATE, data + b"!", Format.RAW, limits=limits
    )


def test_cli_rejects_oversize_input_with_nonzero_exit(tmp_path, capsys):
    path = tmp_path / "large.bin"
    path.write_bytes(b"x" * 32)
    with pytest.raises(SystemExit) as exc:
        main(["hash", str(path), "--max-input-bytes", "16"])
    assert exc.value.code == 2
    assert "max_input_bytes=16" in capsys.readouterr().err


def test_pipeline_tuple_budget_is_forwarded_to_incremental_states():
    data = _raw_deflate(b"abc")
    with pytest.raises(ResourceLimitError, match="max_depth"):
        uhc_hash_multi(
            data,
            fmt=Format.DEFLATE,
            cdh_method=CDHMethod.ROPE,
            limits=ResourceLimits(max_depth=1),
        )
