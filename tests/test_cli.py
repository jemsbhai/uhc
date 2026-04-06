"""
Tests for the UHC CLI.

Covers:
    uhc hash — raw, compressed, multi-hash, hex, JSON, quiet, stdin, method, d-max/m-max
    uhc verify — same, different, cross-format, JSON, quiet exit codes
    uhc chunks — table, JSON, custom sizes
    uhc inspect — token dumping, JSON, limit
    Format autodetection via magic bytes
"""

from __future__ import annotations

import io
import json
import os
import sys
import zlib
import tempfile
import pytest

from uhc.cli import main, build_parser, detect_format
from uhc.engine.pipeline import Format


# ===================================================================
# Helpers
# ===================================================================

def _write_temp(data: bytes, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    return path


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


class CLIRunner:
    """Run CLI commands and capture output."""

    def __init__(self):
        self.exit_code = 0
        self.stdout = ""
        self.stderr = ""

    def run(self, args: list[str], stdin_data: bytes | None = None) -> "CLIRunner":
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err, old_in = sys.stdout, sys.stderr, sys.stdin
        try:
            sys.stdout, sys.stderr = out, err
            if stdin_data is not None:
                sys.stdin = type("FakeStdin", (), {"buffer": io.BytesIO(stdin_data)})()
            try:
                main(args)
                self.exit_code = 0
            except SystemExit as e:
                self.exit_code = e.code if e.code is not None else 0
        finally:
            sys.stdout, sys.stderr, sys.stdin = old_out, old_err, old_in
            self.stdout = out.getvalue()
            self.stderr = err.getvalue()
        return self


@pytest.fixture
def cli():
    return CLIRunner()


@pytest.fixture
def raw_file():
    data = b"the quick brown fox jumps over the lazy dog " * 20
    path = _write_temp(data)
    yield path, data
    os.unlink(path)


@pytest.fixture
def deflate_file():
    data = b"deflate cli test " * 30
    compressed = _raw_deflate(data)
    path = _write_temp(compressed, suffix=".deflate")
    yield path, data
    os.unlink(path)


# ===================================================================
# Format autodetection
# ===================================================================


class TestFormatAutodetect:

    def test_lz4_frame_magic(self):
        assert detect_format(b"\x04\x22\x4d\x18" + b"\x00" * 10) == Format.LZ4_FRAME

    def test_gzip_magic(self):
        assert detect_format(b"\x1f\x8b" + b"\x00" * 10) == Format.GZIP

    def test_unknown_returns_none(self):
        assert detect_format(b"\x00\x00\x00\x00") is None

    def test_short_data_returns_none(self):
        assert detect_format(b"\x00") is None


# ===================================================================
# Parser
# ===================================================================


class TestParser:

    def test_hash_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["hash", "file.bin"])
        assert args.command == "hash"
        assert args.file == "file.bin"

    def test_hash_with_method(self):
        parser = build_parser()
        args = parser.parse_args(["hash", "f.bin", "--method", "sliding_rope"])
        assert args.method == "sliding_rope"

    def test_hash_with_d_max_m_max(self):
        parser = build_parser()
        args = parser.parse_args(["hash", "f.bin", "--d-max", "1000", "--m-max", "500"])
        assert args.d_max == 1000
        assert args.m_max == 500

    def test_verify_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["verify", "a.bin", "b.bin"])
        assert args.command == "verify"

    def test_chunks_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["chunks", "file.bin"])
        assert args.command == "chunks"

    def test_inspect_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["inspect", "f.bin", "-f", "deflate"])
        assert args.command == "inspect"

    def test_no_subcommand_fails(self, cli):
        cli.run([])
        assert cli.exit_code != 0


# ===================================================================
# General CLI improvements
# ===================================================================


class TestTimingFlag:
    """--timing flag shows elapsed time on any command."""

    def test_timing_on_hash(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["hash", path, "--timing"])
        assert cli.exit_code == 0
        assert "time" in cli.stdout.lower() or "ms" in cli.stdout.lower()

    def test_timing_on_info(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["info", path, "--timing"])
        assert cli.exit_code == 0
        assert "time" in cli.stdout.lower() or "ms" in cli.stdout.lower()

    def test_timing_on_verify(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["verify", path, path, "--timing"])
        assert cli.exit_code == 0
        assert "time" in cli.stdout.lower() or "ms" in cli.stdout.lower()

    def test_timing_json_adds_field(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["hash", path, "--timing", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert "elapsed_ms" in out


class TestVerboseFlag:
    """--verbose / -v flag for detailed output."""

    def test_verbose_hash_shows_extra(self, cli, deflate_file):
        path, _ = deflate_file
        cli.run(["hash", path, "-f", "deflate", "-v"])
        assert cli.exit_code == 0
        # Verbose should show format, method, token count
        assert "token" in cli.stdout.lower() or "format" in cli.stdout.lower()

    def test_verbose_short_flag(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["hash", path, "-v"])
        assert cli.exit_code == 0


class TestVersionOutput:
    """--version shows version string."""

    def test_version(self, cli):
        cli.run(["--version"])
        # argparse prints version and exits with 0
        assert cli.exit_code == 0
        assert "0.1.4" in cli.stdout or "uhc" in cli.stdout.lower()


# ===================================================================
# uhc hash
# ===================================================================


class TestHashCommand:

    def test_hash_raw_file(self, cli, raw_file):
        path, data = raw_file
        cli.run(["hash", path])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_deflate_file(self, cli, deflate_file):
        path, data = deflate_file
        cli.run(["hash", path, "-f", "deflate"])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_with_multihash(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["hash", path, "--bases", "131", "257"])
        assert cli.exit_code == 0
        assert "," in cli.stdout

    def test_hash_hex_output(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["hash", path, "--hex"])
        assert cli.exit_code == 0
        line = cli.stdout.strip().split("\n")[0].strip()
        assert all(c in "0123456789abcdef" for c in line)

    def test_hash_json_output(self, cli, raw_file):
        path, data = raw_file
        cli.run(["hash", path, "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert "hash" in out
        assert "hash_hex" in out
        assert out["format"] == "raw"
        from uhc.core.polynomial_hash import PolynomialHash
        assert out["hash"] == PolynomialHash(base=131).hash(data)

    def test_hash_json_multihash(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["hash", path, "--bases", "131", "257", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert out["k"] == 2
        assert len(out["hashes"]) == 2

    def test_hash_quiet(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["hash", path, "-q"])
        assert cli.exit_code == 0
        # Should be just the hash value, nothing else
        assert cli.stdout.strip().isdigit()

    def test_hash_method_sliding_rope(self, cli, deflate_file):
        path, data = deflate_file
        cli.run(["hash", path, "-f", "deflate", "--method", "sliding_rope"])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_method_prefix_array(self, cli, deflate_file):
        path, data = deflate_file
        cli.run(["hash", path, "-f", "deflate", "--method", "prefix_array"])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_custom_d_max_m_max(self, cli, deflate_file):
        path, data = deflate_file
        cli.run(["hash", path, "-f", "deflate", "--method", "sliding_rope",
                  "--d-max", "32768", "--m-max", "258"])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_stdin(self, cli):
        data = b"stdin hash test"
        cli.run(["hash", "-"], stdin_data=data)
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_nonexistent_file(self, cli):
        cli.run(["hash", "nonexistent_file.bin"])
        assert cli.exit_code != 0


# ===================================================================
# uhc verify
# ===================================================================


class TestVerifyCommand:

    def test_same_file(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["verify", path, path])
        assert cli.exit_code == 0
        assert "match" in cli.stdout.lower()

    def test_different_files(self, cli):
        p1 = _write_temp(b"file one content")
        p2 = _write_temp(b"file two content")
        try:
            cli.run(["verify", p1, p2])
            assert "mismatch" in cli.stdout.lower() or cli.exit_code != 0
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_raw_vs_deflate(self, cli):
        data = b"cross format verify cli " * 20
        p_raw = _write_temp(data)
        p_deflate = _write_temp(_raw_deflate(data))
        try:
            cli.run(["verify", p_raw, p_deflate,
                      "--format-a", "raw", "--format-b", "deflate"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_raw)
            os.unlink(p_deflate)

    def test_verify_json_output(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["verify", path, path, "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert out["match"] is True

    def test_verify_quiet_match(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["verify", path, path, "-q"])
        assert cli.exit_code == 0
        assert cli.stdout.strip() == ""  # quiet match = no output, exit 0

    def test_verify_quiet_mismatch(self, cli):
        p1 = _write_temp(b"aaa")
        p2 = _write_temp(b"bbb")
        try:
            cli.run(["verify", p1, p2, "-q"])
            assert cli.exit_code == 1  # quiet mismatch = exit 1
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_verify_nonexistent(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["verify", path, "nonexistent.bin"])
        assert cli.exit_code != 0


# ===================================================================
# uhc chunks
# ===================================================================


class TestChunksCommand:

    def test_chunks_output(self, cli):
        data = b"chunk cli test " * 2000
        path = _write_temp(data)
        try:
            cli.run(["chunks", path])
            assert cli.exit_code == 0
            lines = cli.stdout.strip().split("\n")
            assert len(lines) >= 3
        finally:
            os.unlink(path)

    def test_chunks_json(self, cli):
        data = b"chunk json " * 2000
        path = _write_temp(data)
        try:
            cli.run(["chunks", path, "-o", "json"])
            assert cli.exit_code == 0
            out = json.loads(cli.stdout)
            assert "chunks" in out
            assert out["total_bytes"] == len(data)
            assert out["num_chunks"] > 0
        finally:
            os.unlink(path)

    def test_chunks_custom_sizes(self, cli):
        data = b"custom chunks " * 3000
        path = _write_temp(data)
        try:
            cli.run(["chunks", path, "--min-size", "1024",
                      "--avg-size", "4096", "--max-size", "16384"])
            assert cli.exit_code == 0
        finally:
            os.unlink(path)

    def test_chunks_small_file(self, cli):
        path = _write_temp(b"tiny")
        try:
            cli.run(["chunks", path])
            assert cli.exit_code == 0
            assert "1 chunk" in cli.stdout.lower() or "1" in cli.stdout
        finally:
            os.unlink(path)

    def test_chunks_stdin(self, cli):
        data = b"stdin chunk test " * 2000
        cli.run(["chunks", "-"], stdin_data=data)
        assert cli.exit_code == 0


# ===================================================================
# uhc inspect
# ===================================================================


class TestInspectCommand:

    def test_inspect_deflate(self, cli, deflate_file):
        path, _ = deflate_file
        cli.run(["inspect", path, "-f", "deflate"])
        assert cli.exit_code == 0
        assert "Lit(" in cli.stdout or "Ref(" in cli.stdout

    def test_inspect_json(self, cli, deflate_file):
        path, _ = deflate_file
        cli.run(["inspect", path, "-f", "deflate", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert "tokens" in out
        assert out["total_tokens"] > 0


# ===================================================================
# uhc info command
# ===================================================================


class TestInfoCommand:
    """uhc info — file metadata and token statistics."""

    def test_info_raw_file(self, cli, raw_file):
        path, data = raw_file
        cli.run(["info", path])
        assert cli.exit_code == 0
        assert str(len(data)) in cli.stdout
        assert "raw" in cli.stdout.lower()

    def test_info_deflate_file(self, cli, deflate_file):
        path, data = deflate_file
        cli.run(["info", path, "-f", "deflate"])
        assert cli.exit_code == 0
        assert "deflate" in cli.stdout.lower()
        # Should show token counts
        assert "token" in cli.stdout.lower()

    def test_info_gzip_file(self, cli, gzip_file):
        path, data = gzip_file
        cli.run(["info", path])
        assert cli.exit_code == 0
        assert "gzip" in cli.stdout.lower()

    def test_info_json_raw(self, cli, raw_file):
        path, data = raw_file
        cli.run(["info", path, "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert out["file"] == path
        assert out["file_size"] == len(data)
        assert out["format"] == "raw"

    def test_info_json_deflate(self, cli, deflate_file):
        path, data = deflate_file
        cli.run(["info", path, "-f", "deflate", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert out["format"] == "deflate"
        assert "total_tokens" in out
        assert "literals" in out
        assert "references" in out
        assert "overlapping_refs" in out
        assert out["total_tokens"] == out["literals"] + out["references"]

    def test_info_parser_accepts(self):
        parser = build_parser()
        args = parser.parse_args(["info", "file.bin"])
        assert args.command == "info"

    def test_info_nonexistent(self, cli):
        cli.run(["info", "nonexistent.bin"])
        assert cli.exit_code != 0


# ===================================================================
# uhc benchmark command
# ===================================================================


class TestBenchmarkCommand:
    """uhc benchmark — CDH vs DTH timing (Theorem 17)."""

    def test_benchmark_deflate(self, cli, deflate_file):
        path, _ = deflate_file
        cli.run(["benchmark", path, "-f", "deflate"])
        assert cli.exit_code == 0
        # Should show timing info
        assert "cdh" in cli.stdout.lower() or "time" in cli.stdout.lower()

    def test_benchmark_json(self, cli, deflate_file):
        path, _ = deflate_file
        cli.run(["benchmark", path, "-f", "deflate", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert "cdh_time" in out
        assert "dth_time" in out
        assert "speedup" in out
        assert "match" in out
        assert out["match"] is True  # CDH must equal DTH (Theorem 12)

    def test_benchmark_raw_rejected(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["benchmark", path, "-f", "raw"])
        assert cli.exit_code != 0

    def test_benchmark_parser_accepts(self):
        parser = build_parser()
        args = parser.parse_args(["benchmark", "file.bin", "-f", "deflate"])
        assert args.command == "benchmark"

    def test_benchmark_trials(self, cli, deflate_file):
        path, _ = deflate_file
        cli.run(["benchmark", path, "-f", "deflate", "--trials", "2", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert out["trials"] == 2


# ===================================================================
# Gzip CLI support (RFC 1952 wrapping DEFLATE / Lemma 9)
# ===================================================================

import gzip as _gzip_mod


def _gzip_compress(data: bytes) -> bytes:
    return _gzip_mod.compress(data)


@pytest.fixture
def gzip_file():
    data = b"gzip cli test data " * 30
    compressed = _gzip_compress(data)
    path = _write_temp(compressed, suffix=".gz")
    yield path, data
    os.unlink(path)


class TestGzipHashCommand:
    """uhc hash with gzip input — validates Theorem 12 via DEFLATE."""

    def test_hash_gzip_explicit_format(self, cli, gzip_file):
        path, data = gzip_file
        cli.run(["hash", path, "-f", "gzip"])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_gzip_autodetect(self, cli, gzip_file):
        path, data = gzip_file
        cli.run(["hash", path])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_gzip_json(self, cli, gzip_file):
        path, data = gzip_file
        cli.run(["hash", path, "-f", "gzip", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert out["format"] == "gzip"
        from uhc.core.polynomial_hash import PolynomialHash
        assert out["hash"] == PolynomialHash(base=131).hash(data)


class TestGzipVerifyCommand:
    """uhc verify with gzip — cross-format (Theorem 12)."""

    def test_verify_raw_vs_gzip(self, cli):
        data = b"cross format gzip verify " * 20
        p_raw = _write_temp(data)
        p_gz = _write_temp(_gzip_compress(data))
        try:
            cli.run(["verify", p_raw, p_gz,
                      "--format-a", "raw", "--format-b", "gzip"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_raw)
            os.unlink(p_gz)


class TestGzipInspectCommand:
    """uhc inspect with gzip format."""

    def test_inspect_gzip(self, cli, gzip_file):
        path, _ = gzip_file
        cli.run(["inspect", path, "-f", "gzip"])
        assert cli.exit_code == 0
        assert "Lit(" in cli.stdout or "Ref(" in cli.stdout

    def test_inspect_limit(self, cli, deflate_file):
        path, _ = deflate_file
        cli.run(["inspect", path, "-f", "deflate", "-n", "5"])
        assert cli.exit_code == 0
        # Should show at most 5 token lines
        token_lines = [l for l in cli.stdout.split("\n")
                       if "Lit(" in l or "Ref(" in l]
        assert len(token_lines) <= 5

    def test_inspect_raw_format_rejected(self, cli, raw_file):
        path, _ = raw_file
        cli.run(["inspect", path, "-f", "raw"])
        assert cli.exit_code != 0

    def test_inspect_stdin(self, cli):
        data = b"inspect stdin " * 20
        compressed = _raw_deflate(data)
        cli.run(["inspect", "-", "-f", "deflate"], stdin_data=compressed)
        assert cli.exit_code == 0
        assert "Lit(" in cli.stdout or "Ref(" in cli.stdout


# ===================================================================
# Zstandard CLI support (Lemma 11, Theorem 12)
# ===================================================================

zstandard = pytest.importorskip("zstandard", reason="zstandard not installed")


def _zstd_compress(data: bytes) -> bytes:
    """Compress data with zstandard."""
    cctx = zstandard.ZstdCompressor(level=3)
    return cctx.compress(data)


@pytest.fixture
def zstd_file():
    data = b"zstd cli test data " * 30
    compressed = _zstd_compress(data)
    path = _write_temp(compressed, suffix=".zst")
    yield path, data
    os.unlink(path)


class TestZstdFormatDetection:
    """Zstandard magic byte detection (b'\\x28\\xb5\\x2f\\xfd')."""

    def test_zstd_magic_detected(self):
        assert detect_format(b"\x28\xb5\x2f\xfd" + b"\x00" * 10) == Format.ZSTD


class TestZstdParserAccepted:
    """Parser accepts 'zstd' as a --format choice."""

    def test_hash_format_zstd(self):
        parser = build_parser()
        args = parser.parse_args(["hash", "f.zst", "-f", "zstd"])
        assert args.format == "zstd"

    def test_verify_format_a_zstd(self):
        parser = build_parser()
        args = parser.parse_args(["verify", "a.zst", "b.bin",
                                  "--format-a", "zstd"])
        assert args.format_a == "zstd"

    def test_verify_format_b_zstd(self):
        parser = build_parser()
        args = parser.parse_args(["verify", "a.bin", "b.zst",
                                  "--format-b", "zstd"])
        assert args.format_b == "zstd"

    def test_inspect_format_zstd(self):
        parser = build_parser()
        args = parser.parse_args(["inspect", "f.zst", "-f", "zstd"])
        assert args.format == "zstd"


class TestZstdHashCommand:
    """uhc hash with zstd input — validates Theorem 12 (CDH = H)."""

    def test_hash_zstd_explicit_format(self, cli, zstd_file):
        path, data = zstd_file
        cli.run(["hash", path, "-f", "zstd"])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_zstd_autodetect(self, cli, zstd_file):
        path, data = zstd_file
        cli.run(["hash", path])
        assert cli.exit_code == 0
        from uhc.core.polynomial_hash import PolynomialHash
        expected = str(PolynomialHash(base=131).hash(data))
        assert expected in cli.stdout

    def test_hash_zstd_json(self, cli, zstd_file):
        path, data = zstd_file
        cli.run(["hash", path, "-f", "zstd", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert out["format"] == "zstd"
        from uhc.core.polynomial_hash import PolynomialHash
        assert out["hash"] == PolynomialHash(base=131).hash(data)

    def test_hash_zstd_multihash(self, cli, zstd_file):
        path, data = zstd_file
        cli.run(["hash", path, "-f", "zstd", "--bases", "131", "257"])
        assert cli.exit_code == 0
        assert "," in cli.stdout


class TestZstdVerifyCommand:
    """uhc verify with zstd — cross-format verification (Theorem 12)."""

    def test_verify_raw_vs_zstd(self, cli):
        data = b"cross format zstd verify " * 20
        p_raw = _write_temp(data)
        p_zstd = _write_temp(_zstd_compress(data))
        try:
            cli.run(["verify", p_raw, p_zstd,
                      "--format-a", "raw", "--format-b", "zstd"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_raw)
            os.unlink(p_zstd)

    def test_verify_deflate_vs_zstd(self, cli):
        data = b"deflate vs zstd verify " * 20
        p_deflate = _write_temp(_raw_deflate(data))
        p_zstd = _write_temp(_zstd_compress(data))
        try:
            cli.run(["verify", p_deflate, p_zstd,
                      "--format-a", "deflate", "--format-b", "zstd"])
            assert cli.exit_code == 0
            assert "match" in cli.stdout.lower()
        finally:
            os.unlink(p_deflate)
            os.unlink(p_zstd)


class TestZstdInspectCommand:
    """uhc inspect with zstd format."""

    def test_inspect_zstd(self, cli, zstd_file):
        path, _ = zstd_file
        cli.run(["inspect", path, "-f", "zstd"])
        assert cli.exit_code == 0
        assert "Lit(" in cli.stdout or "Ref(" in cli.stdout

    def test_inspect_zstd_json(self, cli, zstd_file):
        path, _ = zstd_file
        cli.run(["inspect", path, "-f", "zstd", "-o", "json"])
        assert cli.exit_code == 0
        out = json.loads(cli.stdout)
        assert out["format"] == "zstd"
        assert out["total_tokens"] > 0
