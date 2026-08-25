"""Focused UHC 03 public API, CLI, ZIP, and rope contract regressions."""

from __future__ import annotations

import io
import json
import zipfile
import zlib

import pytest

import uhc.engine.pipeline as pipeline
from uhc.cli import detect_format, main
from uhc.core.compressed_verifier import CDHMethod
from uhc.core.exact import ExactDecodeError
from uhc.core.polynomial_hash import PolynomialHash
from uhc.core.rope import (
    rope_concat,
    rope_from_bytes,
    rope_repeat,
    rope_split,
    rope_substr_hash,
)
from uhc.engine.pipeline import Format, UnsupportedFormatError


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.txt", b"payload")
    return output.getvalue()


def _write_pair(tmp_path, first: bytes, second: bytes):
    path_a = tmp_path / "a.bin"
    path_b = tmp_path / "b.bin"
    path_a.write_bytes(first)
    path_b.write_bytes(second)
    return path_a, path_b


def test_multi_hash_pipeline_forwards_requested_cdh_method(monkeypatch):
    data = _raw_deflate(b"method forwarding " * 20)
    calls: list[tuple[object, int, int]] = []

    def fake_multi_cdh(tokens, mh, *, method, d_max, m_max):
        calls.append((method, d_max, m_max))
        return tuple(range(mh.k))

    monkeypatch.setattr(pipeline, "multi_cdh", fake_multi_cdh)

    assert pipeline.uhc_hash_multi(
        data,
        fmt=Format.DEFLATE,
        cdh_method=CDHMethod.PREFIX_ARRAY,
        d_max=123,
        m_max=45,
    ) == (0, 1)
    assert calls[-1] == (CDHMethod.PREFIX_ARRAY, 123, 45)

    assert pipeline.uhc_hash_compressed_multi(
        data,
        Format.DEFLATE,
        cdh_method=CDHMethod.SLIDING_ROPE,
        d_max=321,
        m_max=54,
    ) == (0, 1)
    assert calls[-1] == (CDHMethod.SLIDING_ROPE, 321, 54)


@pytest.mark.parametrize("method", list(CDHMethod))
def test_multi_hash_methods_match_direct_hash(method):
    raw = b"real multi-method regression " * 30
    compressed = _raw_deflate(raw)
    expected = pipeline.uhc_hash_multi(raw, bases=[131, 257])
    assert pipeline.uhc_hash_compressed_multi(
        compressed,
        Format.DEFLATE,
        bases=[131, 257],
        cdh_method=method,
    ) == expected


def test_cli_multi_hash_forwards_requested_method(monkeypatch, tmp_path, capsys):
    path = tmp_path / "payload.deflate"
    path.write_bytes(_raw_deflate(b"cli method " * 20))
    seen: dict[str, object] = {}

    def fake_multi_cdh(tokens, mh, *, method, d_max, m_max):
        seen.update(method=method, d_max=d_max, m_max=m_max)
        return (11, 22)

    monkeypatch.setattr("uhc.cli.multi_cdh", fake_multi_cdh)
    main([
        "hash",
        str(path),
        "--format",
        "deflate",
        "--bases",
        "131",
        "257",
        "--method",
        "prefix_array",
        "--d-max",
        "123",
        "--m-max",
        "45",
        "--output",
        "json",
    ])

    output = json.loads(capsys.readouterr().out)
    assert seen == {
        "method": CDHMethod.PREFIX_ARRAY,
        "d_max": 123,
        "m_max": 45,
    }
    assert output["method"] == "prefix_array"
    assert output["operation"] == "probabilistic_polynomial_screening"
    assert output["authoritative"] is False


def test_verify_json_mismatch_exits_one(tmp_path, capsys):
    path_a, path_b = _write_pair(tmp_path, b"first", b"second")
    with pytest.raises(SystemExit) as raised:
        main([
            "verify",
            str(path_a),
            str(path_b),
            "--output",
            "json",
            "--timing",
        ])
    assert raised.value.code == 1
    output = json.loads(capsys.readouterr().out)
    assert output["match"] is False
    assert output["authoritative"] is True
    assert output["elapsed_ms"] >= 0


def test_malformed_verify_exits_two_without_traceback(tmp_path, capsys):
    path_a, path_b = _write_pair(tmp_path, b"\x03", b"anything")
    with pytest.raises(SystemExit) as raised:
        main([
            "verify",
            str(path_a),
            str(path_b),
            "--format-a",
            "deflate",
            "--format-b",
            "raw",
        ])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err.lower()
    assert "traceback" not in captured.err.lower()


def test_zip_is_detected_and_rejected_consistently(tmp_path, capsys):
    archive = _zip_bytes()
    assert detect_format(archive) == Format.ZIP

    with pytest.raises(UnsupportedFormatError, match="multi-entry"):
        pipeline.extract_tokens(archive, Format.ZIP)
    with pytest.raises(UnsupportedFormatError, match="multi-entry"):
        pipeline.uhc_hash(archive, fmt=Format.ZIP)
    with pytest.raises(UnsupportedFormatError, match="multi-entry"):
        pipeline.uhc_hash_multi(archive, fmt=Format.ZIP)
    with pytest.raises(ExactDecodeError, match="multi-entry"):
        pipeline.uhc_verify_exact(
            archive,
            archive,
            fmt_a=Format.ZIP,
            fmt_b=Format.ZIP,
        )

    archive_path = tmp_path / "archive.zip"
    archive_path.write_bytes(archive)
    with pytest.raises(SystemExit) as raised:
        main(["hash", str(archive_path)])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "multi-entry" in captured.err
    assert captured.out == ""


def test_exact_verification_has_an_explicit_public_name():
    assert pipeline.uhc_verify_exact(b"same", b"same") is True
    assert pipeline.uhc_verify_exact(b"same", b"different") is False
    assert pipeline.uhc_verify(b"same", b"same") is True


def test_python_rope_rejects_invalid_ranges_and_hasher_mixing():
    h = PolynomialHash(base=131)
    other = PolynomialHash(base=257)
    node = rope_from_bytes(b"abcdef", h)

    with pytest.raises(IndexError, match="split position"):
        rope_split(node, -1, h)
    with pytest.raises(IndexError, match="split position"):
        rope_split(node, 7, h)
    with pytest.raises(ValueError, match="non-negative"):
        rope_substr_hash(node, -1, 1, h)
    with pytest.raises(ValueError, match="non-negative"):
        rope_substr_hash(node, 0, -1, h)
    with pytest.raises(IndexError, match="outside"):
        rope_substr_hash(node, 5, 2, h)

    with pytest.raises(ValueError, match="hasher mismatch"):
        rope_concat(node, None, other)
    with pytest.raises(ValueError, match="hasher mismatch"):
        rope_split(node, 0, other)
    with pytest.raises(ValueError, match="hasher mismatch"):
        rope_substr_hash(node, 0, 1, other)
    with pytest.raises(ValueError, match="hasher mismatch"):
        rope_repeat(node, 2, other)
