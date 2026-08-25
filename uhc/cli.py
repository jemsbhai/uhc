"""
UHC command-line interface.

Commands:
    uhc hash <file>              Hash a file (raw or compressed)
    uhc verify <file_a> <file_b> Strictly decode and compare bytes exactly
    uhc chunks <file>            Show CDC chunk boundaries and hashes
    uhc inspect <file>           Dump extracted LZ77 tokens

Supports stdin via '-', format autodetection via magic bytes,
JSON output for automation, and tunable sliding window parameters.
"""

from __future__ import annotations

import argparse
import io
import json
import struct
import sys
import os
import time
from itertools import chain
from collections.abc import Iterator

from uhc.engine.pipeline import (
    Format,
    UnsupportedFormatError,
    uhc_verify_exact,
    extract_tokens,
    iter_tokens,
)
from uhc.chunking.cdc import cdc_ranges
from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod
from uhc.core.multihash import MultiHash, multi_cdh
from uhc.core.lz77 import Literal, Reference, lz77_decode
from uhc.core.resources import DEFAULT_LIMITS, ResourceLimits


_POLYNOMIAL_WARNING = (
    "Experimental polynomial screening only: collisions are possible; this "
    "result is not proof of equality, integrity, authenticity, or security. "
    "Use 'uhc verify' for exact decoded-byte comparison."
)
_CHUNK_WARNING = (
    "Experimental chunk boundaries and polynomial chunk hashes only: "
    "collisions are possible; do not use these values as authoritative "
    "content identifiers, integrity checks, or security decisions."
)
_BENCHMARK_WARNING = (
    "Experimental local research measurement only: timings and speedups are "
    "non-decision evidence, are not generalizable performance claims, and are "
    "outside the release-candidate surface. Parser agreement does not "
    "independently validate parser correctness."
)


# ---------------------------------------------------------------------------
# Format autodetection (magic bytes)
# ---------------------------------------------------------------------------

_MAGIC_BYTES = {
    b"PK\x03\x04":                      Format.ZIP,        # ZIP local header
    b"PK\x05\x06":                      Format.ZIP,        # empty ZIP EOCD
    b"PK\x07\x08":                      Format.ZIP,        # ZIP data descriptor
    b"\x1f\x8b":                         Format.GZIP,        # gzip (RFC 1952, wraps DEFLATE)
    b"\x04\x22\x4d\x18":                Format.LZ4_FRAME,  # LZ4 frame
    b"\x28\xb5\x2f\xfd":                Format.ZSTD,        # Zstandard (Lemma 11)
}

_FORMAT_CHOICES = [fmt.value for fmt in Format] + ["auto"]

# DEFLATE raw streams have no magic — detected by exclusion or --format flag


def detect_format(data: bytes) -> Format | None:
    """
    Detect compression format from magic bytes.

    Returns None if format cannot be determined (user must specify --format).
    """
    if len(data) < 4:
        return None

    # Check 4-byte magics first
    prefix4 = data[:4]
    if prefix4 in _MAGIC_BYTES:
        return _MAGIC_BYTES[prefix4]

    # Check 2-byte magics
    prefix2 = data[:2]
    if prefix2 in _MAGIC_BYTES:
        return _MAGIC_BYTES[prefix2]

    return None


# ---------------------------------------------------------------------------
# Format-specific defaults for d_max, m_max
# ---------------------------------------------------------------------------

_FORMAT_DEFAULTS = {
    Format.DEFLATE:   (32768, 258),
    Format.GZIP:      (32768, 258),
    Format.LZ4_BLOCK: (65535, 65536),
    Format.LZ4_FRAME: (65535, 65536),
    Format.ZSTD:      (2**27, 131074),
    Format.RAW:       (32768, 258),
}


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uhc",
        description="UHC — Unified Hash-Compression Engine. "
                    "Experimental polynomial-hash screening over compressed data; "
                    "not authentication or proof of byte equality.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_get_version()}")

    sub = parser.add_subparsers(dest="command", required=True)

    # --- Shared arguments ---
    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--format", "-f", default=None,
            choices=_FORMAT_CHOICES,
            help="Input format (default: auto-detect, falls back to raw)",
        )
        p.add_argument(
            "--output", "-o", default="text",
            choices=["text", "json"],
            help="Output format (default: text)",
        )
        p.add_argument("-q", "--quiet", action="store_true",
                       help="Suppress non-essential output, print only hash value(s)")
        p.add_argument("--timing", action="store_true",
                       help="Show elapsed time after command execution")
        p.add_argument("-v", "--verbose", action="store_true",
                       help="Show detailed output (format, method, token count)")
        p.add_argument("--max-input-bytes", type=int,
                       default=DEFAULT_LIMITS.max_input_bytes)
        p.add_argument("--max-output-bytes", type=int,
                       default=DEFAULT_LIMITS.max_output_bytes)
        p.add_argument("--max-tokens", type=int, default=DEFAULT_LIMITS.max_tokens)
        p.add_argument("--max-depth", type=int, default=DEFAULT_LIMITS.max_depth)
        p.add_argument("--max-reference-distance", type=int,
                       default=DEFAULT_LIMITS.max_reference_distance)
        p.add_argument("--max-reference-length", type=int,
                       default=DEFAULT_LIMITS.max_reference_length)
        p.add_argument("--io-chunk-size", type=int,
                       default=DEFAULT_LIMITS.io_chunk_size)

    # --- hash ---
    p_hash = sub.add_parser(
        "hash",
        help="Compute a probabilistic polynomial screening hash",
        description=(
            "Compute an experimental polynomial screening hash. Hash equality "
            "is not proof of byte equality; use 'uhc verify' for exact comparison."
        ),
    )
    p_hash.add_argument("file", help="Path to file, or '-' for stdin")
    _add_common(p_hash)
    p_hash.add_argument(
        "--bases", nargs="+", type=int, default=None,
        help="Hash bases for k-tuple multi-hash (e.g., --bases 131 257)",
    )
    p_hash.add_argument(
        "--base", type=int, default=131,
        help="Single hash base (default: 131, ignored if --bases is set)",
    )
    p_hash.add_argument("--hex", action="store_true", help="Output hash in hexadecimal")
    p_hash.add_argument(
        "--method", "-m", default="rope",
        choices=["rope", "prefix_array", "sliding_rope"],
        help="CDH algorithm (default: rope)",
    )
    p_hash.add_argument("--d-max", type=int, default=None,
                        help="Max back-reference distance (for sliding_rope)")
    p_hash.add_argument("--m-max", type=int, default=None,
                        help="Max match length (for sliding_rope)")
    p_hash.add_argument("--prime", type=int, default=MERSENNE_61,
                        help=f"Mersenne prime (default: 2^61-1 = {MERSENNE_61})")

    # --- verify ---
    p_verify = sub.add_parser(
        "verify",
        help="Strictly decode and compare file content bytes",
        description=(
            "Strictly decode both inputs with native format decoders, then "
            "perform a cryptographic precheck and exact byte comparison."
        ),
    )
    p_verify.add_argument("file_a", help="First file, or '-' for stdin")
    p_verify.add_argument("file_b", help="Second file")
    _add_common(p_verify)
    p_verify.add_argument("--format-a", default=None,
                          choices=_FORMAT_CHOICES,
                          help="Format of first file (overrides --format for file A)")
    p_verify.add_argument("--format-b", default=None,
                          choices=_FORMAT_CHOICES,
                          help="Format of second file (overrides --format for file B)")
    p_verify.add_argument("--bases", nargs="+", type=int, default=None,
                          help="Deprecated compatibility option; validated but not used")

    # --- chunks ---
    p_chunks = sub.add_parser(
        "chunks",
        help="Show experimental CDC boundaries and polynomial hashes",
        description=(
            "Show research-only CDC boundaries and polynomial chunk hashes. "
            "The hashes are probabilistic and non-authoritative."
        ),
    )
    p_chunks.add_argument("file", help="Path to file, or '-' for stdin")
    _add_common(p_chunks)
    p_chunks.add_argument("--min-size", type=int, default=2048)
    p_chunks.add_argument("--avg-size", type=int, default=8192)
    p_chunks.add_argument("--max-size", type=int, default=65536)
    p_chunks.add_argument("--hex", action="store_true", help="Output hashes in hexadecimal")

    # --- inspect ---
    p_inspect = sub.add_parser("inspect", help="Dump extracted LZ77 tokens")
    p_inspect.add_argument("file", help="Path to compressed file, or '-' for stdin")
    _add_common(p_inspect)
    p_inspect.add_argument("--limit", "-n", type=int, default=None,
                           help="Max number of tokens to show")

    # --- info ---
    p_info = sub.add_parser("info", help="Show file metadata and token statistics")
    p_info.add_argument("file", help="Path to file, or '-' for stdin")
    _add_common(p_info)

    # --- benchmark ---
    p_bench = sub.add_parser(
        "benchmark",
        help="Run an experimental, non-decision CDH timing comparison",
        description=(
            "Run a local research-only CDH versus decompress-then-hash timing "
            "comparison. Results are not generalizable performance evidence."
        ),
    )
    p_bench.add_argument("file", help="Path to compressed file, or '-' for stdin")
    _add_common(p_bench)
    p_bench.add_argument("--trials", type=int, default=3,
                         help="Number of timing trials (default: 3)")
    p_bench.add_argument("--base", type=int, default=131, help="Hash base")
    p_bench.add_argument("--prime", type=int, default=MERSENNE_61,
                         help="Mersenne prime (default: 2^61-1)")
    p_bench.add_argument("--method", "-m", default="rope",
                         choices=["rope", "prefix_array", "sliding_rope"],
                         help="CDH algorithm (default: rope)")
    p_bench.add_argument("--d-max", type=int, default=None)
    p_bench.add_argument("--m-max", type=int, default=None)

    return parser


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _get_version() -> str:
    try:
        from uhc import __version__
        return __version__
    except Exception:
        return "unknown"


def _limits_from_args(args: argparse.Namespace) -> ResourceLimits:
    return ResourceLimits(
        max_input_bytes=args.max_input_bytes,
        max_output_bytes=args.max_output_bytes,
        max_tokens=args.max_tokens,
        max_depth=args.max_depth,
        max_reference_distance=args.max_reference_distance,
        max_reference_length=args.max_reference_length,
        io_chunk_size=args.io_chunk_size,
    )


def _iter_input(
    path: str, limits: ResourceLimits = DEFAULT_LIMITS
) -> Iterator[bytes]:
    """Yield file/stdin chunks and reject oversize input before buffering it."""
    if path == "-":
        stream = sys.stdin.buffer
        close = False
    else:
        if not os.path.isfile(path):
            print(f"Error: file not found: {path}", file=sys.stderr)
            sys.exit(1)
        stream = open(path, "rb")
        close = True

    total = 0
    try:
        while True:
            chunk = stream.read(limits.io_chunk_size)
            if not chunk:
                break
            total += len(chunk)
            limits.check_input(total)
            yield chunk
    finally:
        if close:
            stream.close()


def _read_input(path: str, limits: ResourceLimits = DEFAULT_LIMITS) -> bytes:
    """Compatibility reader for parser paths that still require compressed bytes."""
    return b"".join(_iter_input(path, limits))


def _resolve_format(data: bytes, fmt_arg: str | None) -> Format:
    """Resolve format from argument or autodetect."""
    if fmt_arg and fmt_arg != "auto":
        return Format(fmt_arg)

    detected = detect_format(data)
    if detected is not None:
        return detected

    # Fall back to raw
    return Format.RAW


def _format_hash(value: int, use_hex: bool) -> str:
    return format(value, "x") if use_hex else str(value)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _cmd_hash(args: argparse.Namespace) -> None:
    limits = _limits_from_args(args)
    source = iter(_iter_input(args.file, limits))
    first = next(source, b"")
    fmt = _resolve_format(first, args.format)
    data = None if fmt == Format.RAW else b"".join(chain((first,), source))

    def raw_chunks() -> Iterator[bytes]:
        total = 0
        for chunk in chain((first,), source):
            total += len(chunk)
            limits.check_output(total)
            yield chunk

    method = CDHMethod(args.method)
    use_hex = args.hex

    # Resolve d_max / m_max
    d_max, m_max = _FORMAT_DEFAULTS.get(fmt, (32768, 258))
    if args.d_max is not None:
        d_max = args.d_max
    if args.m_max is not None:
        m_max = args.m_max

    if args.bases:
        # Multi-hash
        mh = MultiHash(bases=args.bases, prime=args.prime)
        if fmt == Format.RAW:
            result_tuple = mh.hash_iter(raw_chunks())
        else:
            assert data is not None
            tokens = iter_tokens(data, fmt, limits=limits)
            if limits == DEFAULT_LIMITS:
                result_tuple = multi_cdh(
                    tokens,
                    mh,
                    method=method,
                    d_max=d_max,
                    m_max=m_max,
                )
            else:
                result_tuple = multi_cdh(
                    tokens,
                    mh,
                    method=method,
                    d_max=d_max,
                    m_max=m_max,
                    limits=limits,
                )

        if args.output == "json":
            out = {"file": args.file, "format": fmt.value, "k": len(args.bases),
                   "bases": args.bases, "hashes": list(result_tuple),
                   "hashes_hex": [format(v, "x") for v in result_tuple],
                   "method": method.value,
                   "operation": "probabilistic_polynomial_screening",
                   "authoritative": False,
                   "warning": _POLYNOMIAL_WARNING}
            print(json.dumps(out))
        else:
            print(f"WARNING: {_POLYNOMIAL_WARNING}", file=sys.stderr)
            if args.quiet:
                print(", ".join(_format_hash(v, use_hex) for v in result_tuple))
            else:
                formatted = [_format_hash(v, use_hex) for v in result_tuple]
                print(", ".join(formatted))
    else:
        # Single hash
        if fmt == Format.RAW:
            result = PolynomialHash(prime=args.prime, base=args.base).hash_iter(raw_chunks())
        else:
            assert data is not None
            token_count = 0

            def counted_tokens():
                nonlocal token_count
                for token in iter_tokens(data, fmt, limits=limits):
                    token_count += 1
                    yield token

            result = compressed_domain_hash(
                counted_tokens(), prime=args.prime, base=args.base,
                method=method, d_max=d_max, m_max=m_max,
                limits=limits,
            )

        if args.output == "json":
            out = {"file": args.file, "format": fmt.value,
                   "method": method.value, "base": args.base,
                   "hash": result, "hash_hex": format(result, "x"),
                   "operation": "probabilistic_polynomial_screening",
                   "authoritative": False,
                   "warning": _POLYNOMIAL_WARNING}
            print(json.dumps(out))
        else:
            print(f"WARNING: {_POLYNOMIAL_WARNING}", file=sys.stderr)
            if args.quiet:
                print(_format_hash(result, use_hex))
            elif args.verbose and fmt != Format.RAW:
                print(f"Format:  {fmt.value}")
                print(f"Method:  {method.value}")
                print(f"Tokens:  {token_count}")
                print(f"Hash:    {_format_hash(result, use_hex)}")
            else:
                print(_format_hash(result, use_hex))


def _cmd_verify(args: argparse.Namespace) -> None:
    limits = _limits_from_args(args)
    data_a = _read_input(args.file_a, limits)
    data_b = _read_input(args.file_b, limits)

    fmt_a_arg = args.format_a if args.format_a else args.format
    fmt_b_arg = args.format_b if args.format_b else args.format
    fmt_a = _resolve_format(data_a, fmt_a_arg)
    fmt_b = _resolve_format(data_b, fmt_b_arg)

    match = uhc_verify_exact(
        data_a, data_b,
        fmt_a=fmt_a, fmt_b=fmt_b,
        bases=args.bases,
        limits=limits,
    )

    if args.output == "json":
        out = {"file_a": args.file_a, "file_b": args.file_b,
               "format_a": fmt_a.value, "format_b": fmt_b.value,
               "match": match,
               "comparison": "sha256_then_exact_bytes",
               "authoritative": True,
               "authentication": False}
        print(json.dumps(out))
        if not match:
            sys.exit(1)
    elif args.quiet:
        sys.exit(0 if match else 1)
    else:
        if match:
            print("BYTE MATCH — decoded contents are exactly equal")
        else:
            print("BYTE MISMATCH — decoded contents differ")
            sys.exit(1)


def _cmd_chunks(args: argparse.Namespace) -> None:
    limits = _limits_from_args(args)
    data = _read_input(args.file, limits)
    fmt = _resolve_format(data, args.format)
    if fmt == Format.ZIP:
        raise UnsupportedFormatError(
            "ZIP archives are multi-entry containers and cannot be chunked "
            "as one decoded byte stream"
        )
    h = PolynomialHash(base=131)
    use_hex = args.hex

    ranges = list(cdc_ranges(
        data, min_size=args.min_size, avg_size=args.avg_size,
        max_size=args.max_size,
    ))

    if args.output == "json":
        chunk_list = []
        for i, (start, end) in enumerate(ranges):
            ch = h.hash_iter((memoryview(data)[start:end],))
            chunk_list.append({
                "index": i, "offset": start, "size": end - start,
                "hash": ch, "hash_hex": format(ch, "x"),
            })

        avg = len(data) / len(ranges) if ranges else 0
        out = {"file": args.file, "total_bytes": len(data),
               "num_chunks": len(ranges), "avg_chunk_size": round(avg, 1),
               "operation": "experimental_cdc_polynomial_screening",
               "authoritative": False,
               "warning": _CHUNK_WARNING,
               "chunks": chunk_list}
        print(json.dumps(out))
    else:
        print(f"WARNING: {_CHUNK_WARNING}", file=sys.stderr)
        if not args.quiet:
            print(f"{'#':>4}  {'Offset':>10}  {'Size':>8}  {'Hash'}")
            print(f"{'—'*4}  {'—'*10}  {'—'*8}  {'—'*20}")

        for i, (start, end) in enumerate(ranges):
            ch = h.hash_iter((memoryview(data)[start:end],))
            print(f"{i+1:>4}  {start:>10}  {end-start:>8}  {_format_hash(ch, use_hex)}")

        if not args.quiet:
            avg = len(data) / len(ranges) if ranges else 0
            print(f"\n{len(ranges)} chunks, {len(data)} bytes total, avg {avg:.0f} bytes/chunk")


def _cmd_inspect(args: argparse.Namespace) -> None:
    limits = _limits_from_args(args)
    data = _read_input(args.file, limits)
    fmt = _resolve_format(data, args.format)

    if fmt == Format.RAW:
        print("Error: --format must specify a compression format for inspect", file=sys.stderr)
        sys.exit(1)

    tokens = extract_tokens(data, fmt, limits=limits)
    limit = args.limit

    if args.output == "json":
        token_list = []
        for i, tok in enumerate(tokens):
            if limit and i >= limit:
                break
            if isinstance(tok, Literal):
                token_list.append({"type": "literal", "byte": tok.byte,
                                   "char": chr(tok.byte) if 32 <= tok.byte < 127 else None})
            elif isinstance(tok, Reference):
                token_list.append({"type": "reference", "distance": tok.distance,
                                   "length": tok.length})

        out = {"file": args.file, "format": fmt.value,
               "total_tokens": len(tokens),
               "shown": len(token_list),
               "tokens": token_list}
        print(json.dumps(out))
    else:
        if not args.quiet:
            print(f"Format: {fmt.value} | Total tokens: {len(tokens)}")
            print()

        for i, tok in enumerate(tokens):
            if limit and i >= limit:
                if not args.quiet:
                    print(f"... ({len(tokens) - limit} more tokens)")
                break
            if isinstance(tok, Literal):
                ch = chr(tok.byte) if 32 <= tok.byte < 127 else f"\\x{tok.byte:02x}"
                print(f"  Lit({ch})")
            elif isinstance(tok, Reference):
                print(f"  Ref(d={tok.distance}, l={tok.length})")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _cmd_info(args: argparse.Namespace) -> None:
    limits = _limits_from_args(args)
    data = _read_input(args.file, limits)
    fmt = _resolve_format(data, args.format)
    file_size = len(data)

    if fmt == Format.RAW:
        if args.output == "json":
            out = {"file": args.file, "file_size": file_size, "format": fmt.value}
            print(json.dumps(out))
        else:
            print(f"File:    {args.file}")
            print(f"Size:    {file_size} bytes")
            print(f"Format:  {fmt.value}")
    else:
        tokens = extract_tokens(data, fmt, limits=limits)
        n_lit = sum(1 for t in tokens if isinstance(t, Literal))
        n_ref = sum(1 for t in tokens if isinstance(t, Reference))
        n_overlap = sum(
            1 for t in tokens
            if isinstance(t, Reference) and t.distance < t.length
        )
        decoded_size = sum(
            1 if isinstance(t, Literal) else t.length for t in tokens
        )

        if args.output == "json":
            out = {
                "file": args.file,
                "file_size": file_size,
                "format": fmt.value,
                "decoded_size": decoded_size,
                "compression_ratio": round(decoded_size / file_size, 2) if file_size > 0 else 0,
                "total_tokens": len(tokens),
                "literals": n_lit,
                "references": n_ref,
                "overlapping_refs": n_overlap,
            }
            print(json.dumps(out))
        else:
            cr = decoded_size / file_size if file_size > 0 else 0
            print(f"File:             {args.file}")
            print(f"Compressed size:  {file_size} bytes")
            print(f"Decoded size:     {decoded_size} bytes")
            print(f"Format:           {fmt.value}")
            print(f"Compression ratio: {cr:.2f}x")
            print(f"Total tokens:     {len(tokens)}")
            print(f"  Literals:       {n_lit}")
            print(f"  References:     {n_ref}")
            print(f"  Overlapping:    {n_overlap}")

def _cmd_benchmark(args: argparse.Namespace) -> None:
    limits = _limits_from_args(args)
    data = _read_input(args.file, limits)
    fmt = _resolve_format(data, args.format)

    if fmt == Format.RAW:
        print("Error: benchmark requires a compressed format (not raw)", file=sys.stderr)
        sys.exit(1)

    method = CDHMethod(args.method)
    d_max, m_max = _FORMAT_DEFAULTS.get(fmt, (32768, 258))
    if args.d_max is not None:
        d_max = args.d_max
    if args.m_max is not None:
        m_max = args.m_max

    trials = args.trials
    h = PolynomialHash(prime=args.prime, base=args.base)

    # --- CDH timing ---
    cdh_times = []
    cdh_hash = None
    for _ in range(trials):
        t0 = time.perf_counter()
        tokens = extract_tokens(data, fmt, limits=limits)
        cdh_hash = compressed_domain_hash(
            tokens, prime=args.prime, base=args.base,
            method=method, d_max=d_max, m_max=m_max,
            limits=limits,
        )
        cdh_times.append(time.perf_counter() - t0)

    # --- DTH timing (decompress-then-hash) ---
    dth_times = []
    dth_hash = None
    for _ in range(trials):
        t0 = time.perf_counter()
        tokens = extract_tokens(data, fmt, limits=limits)
        decompressed = lz77_decode(tokens)
        dth_hash = h.hash(decompressed)
        dth_times.append(time.perf_counter() - t0)

    match = cdh_hash == dth_hash
    cdh_best = min(cdh_times)
    dth_best = min(dth_times)
    speedup = dth_best / cdh_best if cdh_best > 0 else float('inf')

    if args.output == "json":
        out = {
            "file": args.file,
            "format": fmt.value,
            "method": method.value,
            "trials": trials,
            "cdh_time": round(cdh_best, 6),
            "dth_time": round(dth_best, 6),
            "speedup": round(speedup, 2),
            "match": match,
            "comparison": "cdh_vs_parser_reconstructed_polynomial_hash",
            "authoritative": False,
            "warning": _BENCHMARK_WARNING,
            "cdh_hash": cdh_hash,
            "dth_hash": dth_hash,
        }
        print(json.dumps(out))
    else:
        print(f"WARNING: {_BENCHMARK_WARNING}", file=sys.stderr)
        print(f"Format:     {fmt.value}")
        print(f"Method:     {method.value}")
        print(f"Trials:     {trials}")
        print(f"CDH time:   {cdh_best*1000:.2f} ms (best of {trials})")
        print(f"DTH time:   {dth_best*1000:.2f} ms (best of {trials})")
        print(f"Speedup:    {speedup:.2f}x")
        status = (
            "HASH MATCH on parser-reconstructed bytes (non-authoritative)"
            if match
            else "HASH MISMATCH — implementation discrepancy"
        )
        print(f"Cross-check: {status}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    use_timing = getattr(args, 'timing', False)
    t_start = time.perf_counter() if use_timing else None

    is_json = getattr(args, 'output', 'text') == 'json'
    captured: str | None = None
    capture_stream: io.StringIO | None = None
    old_stdout = sys.stdout
    pending_exit: SystemExit | None = None

    if use_timing and is_json:
        # Capture stdout so we can inject elapsed_ms into JSON
        capture_stream = io.StringIO()
        sys.stdout = capture_stream

    try:
        if args.command == "hash":
            _cmd_hash(args)
        elif args.command == "verify":
            _cmd_verify(args)
        elif args.command == "chunks":
            _cmd_chunks(args)
        elif args.command == "inspect":
            _cmd_inspect(args)
        elif args.command == "info":
            _cmd_info(args)
        elif args.command == "benchmark":
            _cmd_benchmark(args)
    except SystemExit as exc:
        pending_exit = exc
    except (ValueError, OSError, ImportError, EOFError, IndexError, struct.error) as exc:
        if is_json:
            print(
                json.dumps({"error": str(exc), "command": args.command}),
                file=sys.stderr,
            )
        else:
            print(f"Error: {exc}", file=sys.stderr)
        pending_exit = SystemExit(2)
    finally:
        if capture_stream is not None:
            captured = capture_stream.getvalue()
            sys.stdout = old_stdout

    if use_timing and t_start is not None:
        elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)
        if is_json and captured:
            try:
                obj = json.loads(captured)
                obj["elapsed_ms"] = elapsed_ms
                print(json.dumps(obj))
            except json.JSONDecodeError:
                print(captured, end="")
                print(f"\nElapsed time: {elapsed_ms:.2f} ms")
        else:
            print(f"\nElapsed time: {elapsed_ms:.2f} ms")

    if pending_exit is not None:
        raise pending_exit


if __name__ == "__main__":
    main()
