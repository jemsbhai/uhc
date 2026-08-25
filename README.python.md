# UHC Python package

> **RELEASE CONTAINMENT — EXPERIMENTAL / NOT PRODUCTION-SAFE.** `uhc_verify`
> now strictly decodes with native format implementations, applies a SHA-256
> precheck, and compares the decoded bytes exactly. It verifies content
> equality, not authenticity or provenance. The separate polynomial-hash APIs
> remain probabilistic screening: fixed or known parameters permit constructed
> collisions. Format token parsers and compressed-domain algorithms remain
> experimental and are not a production security boundary.

UHC is a pre-alpha Python research package for computing polynomial hashes over
raw bytes and LZ77-derived token streams. Its current APIs cover experimental
format parsing, compressed-domain hash calculation, chunking, and strict
cross-format byte comparison.

This document is the Python distribution's release description. The co-located
Rust crate has a separate manifest and release description, and neither its
sources nor the surrounding research artifacts are Python release inputs.

## Screening hashes versus exact verification

The `uhc_hash*` functions and `uhc hash` command compute polynomial hashes for
probabilistic screening. Matching values are not proof that two byte strings
are equal, and these hashes are not authentication tags. The explicit
`uhc_verify_exact` API and `uhc verify` command strictly decode supported
formats and compare the decoded bytes. `uhc_verify` remains as a compatible
name for the same exact operation.

```python
from uhc.core.compressed_verifier import CDHMethod
from uhc.engine.pipeline import Format, uhc_hash_multi, uhc_verify_exact

screen = uhc_hash_multi(
    compressed,
    fmt=Format.DEFLATE,
    cdh_method=CDHMethod.SLIDING_ROPE,
)
equal = uhc_verify_exact(
    raw,
    compressed,
    fmt_a=Format.RAW,
    fmt_b=Format.DEFLATE,
)
```

The requested `cdh_method` is applied to every component of single- and
multi-hash compressed-domain operations. JSON output from `uhc hash` identifies
the operation as `probabilistic_polynomial_screening` and marks it as
non-authoritative.

## Streaming and resource budgets

`iter_tokens` streams DEFLATE, gzip, LZ4, and Zstandard tokens without retaining
the complete token sequence. `multi_cdh` updates all tuple components during a
single traversal, and `MultiHash.hash_iter` / `PolynomialHash.hash_iter` accept
byte-chunk iterators. `iter_decode_exact` incrementally decodes raw DEFLATE and
concatenated gzip; exact comparison and full-integrity BLAKE3 consume bounded
chunks, including concatenated Zstandard and LZ4-frame decoding. The
compatibility `decode_exact` function still returns a materialized `bytes`
value by design. Raw LZ4 blocks carry no decoded size, so that compatibility
path validates the parser-derived size against the output budget before the
native block binding allocates its bounded result.

Public pipeline functions accept `ResourceLimits`, which bounds compressed
input, decoded output, tokens, rope depth, reference distance/length, and I/O
chunk size. The CLI exposes matching `--max-*` and `--io-chunk-size` options;
raw `uhc hash` input is hashed directly from file/stdin chunks. Larger trusted
workloads must opt into larger limits explicitly.

`cdc_ranges` yields half-open `(start, end)` boundaries in one scan without
copying chunks. `cdc_chunk` remains as the list-of-bytes compatibility wrapper.

## CLI status contract

- Exit `0`: command succeeded; for `verify`, decoded bytes matched exactly.
- Exit `1`: decoded bytes did not match, or a requested input file was absent.
- Exit `2`: malformed input, an unsupported operation, or invalid parameters.

Verification mismatches return `1` for text, quiet, and JSON output. Expected
input errors are printed without a Python traceback; JSON mode emits a JSON
error object on stderr.

## ZIP policy

ZIP magic is recognized as `Format.ZIP` and `--format zip`, but whole-archive
hashing, verification, inspection, and benchmarking are intentionally rejected.
A ZIP archive is a multi-entry container and has no single unambiguous decoded
byte stream. Advanced callers may use `uhc.core.zip_parser` to select one stored
or DEFLATE entry explicitly, then process that entry's token stream.

## Rope contracts

Python rope split and substring-hash operations reject negative or
out-of-bounds ranges instead of clamping or relying on Python slice behavior.
Rope nodes record their prime/base parameters, and concat, split, repeat, and
substring hashing reject a mismatched `PolynomialHash`. The Rust `byte_at` API
returns `Result`, with checked substring-hash/split helpers and explicit arena
hasher validation in `cdh_sort::byte_at`.

## Development check

From this directory:

```powershell
python -m pip install -e ".[dev,formats]"
python -m pytest
```

Native differential tests, deterministic Hypothesis/proptest commands,
malformed/audit corpus locations, and both fuzzing workflows are documented in
[`ADVERSARIAL_TESTING.md`](ADVERSARIAL_TESTING.md).

Existing files under `dist/` and `uhc.egg-info/` predate the containment work.
They are preserved as user-owned generated artifacts but are stale and must not
be uploaded or treated as release candidates.
