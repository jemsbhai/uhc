# Changelog

> **Release-containment notice:** Entries below are historical implementation
> notes, not production-safety guarantees. Polynomial-hash equality is
> probabilistic and is not collision-resistant authentication when parameters
> are known. Exact verification and sorting do not establish authenticity,
> provenance, or bounded-resource behavior; pre-existing `dist/` and
> `uhc.egg-info/` artifacts are stale and must not be published.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0rc1] - Unreleased — UHC 09 release-candidate audit

This is a Python-only prerelease candidate. It does not include or authorize a
Rust publication, final release, tag, or upload.

### Changed

- Scoped the candidate to exact decoded-byte verification, supported
  parser/resource contracts, package installation, and CLI/API behavior.
- Marked polynomial hashing and chunk hashes as explicit research opt-ins, with
  non-authoritative warnings in both text and JSON CLI output.
- Raised the Python package version from the stale `0.1.6` identity to
  `0.2.0rc1`; the Rust crate remains unpublished at `0.1.0`.
- Strengthened wheel, sdist, and crate inspection to require exact versions,
  core verification/resource files, release metadata, and clean Rust VCS
  provenance at the expected commit.
- Moved candidate builds to fresh external output directories and added
  install/import/exact-verification smoke checks for both wheel and sdist.

### Security

- No polynomial result is promoted to a security, authentication, integrity,
  or exact-equality decision. Short fuzz smoke runs remain bounded evidence,
  not substitutes for long campaigns.

## [Unreleased] — UHC 06

### Added
- Cross-platform Python and Rust CI matrices with explicit optional-codec,
  minimal-dependency, fuzz-target, lint, type, coverage, documentation, and
  package-build jobs. No workflow publishes artifacts.
- Wheel, source-distribution, and Rust crate content validation that rejects
  cross-project research/build inputs and requires each package's core files.
- Reproducible local quality-gate commands and tracked root/fuzz Cargo locks
  for every CI command that uses `--locked`.

### Changed
- Python packaging uses SPDX license metadata and includes lint, type, build,
  and metadata-check tools in the development extra.
- Existing Python source and Rust source/test/doc quality backlogs were brought
  under passing Ruff, Mypy, Rustfmt, Clippy, and rustdoc gates.

## UHC 05

### Added
- Deterministic Hypothesis differentials against native zlib/gzip/Zstandard
  decoders and Python `zipfile`, plus exact Rust proptest sorting/LCP checks.
- Checked-in malformed and audit corpora with every known correctness repro,
  exact replay commands, fixed seeds, and explicit optional-dependency skips.
- Runnable Atheris native-differential and cargo-fuzz exact-sort/rope-builder
  targets with checked-in seed corpora.

### Fixed
- Streaming exact Zstandard decoding now checks native per-frame EOF and rejects
  truncated frames without materializing the full decoded stream.
- Per-entry ZIP parsing now validates complete central/local boundaries,
  metadata consistency, decoded size, and CRC before returning tokens.

## UHC 04

### Added
- Iterator token APIs for DEFLATE, gzip, LZ4, and Zstandard, plus one-pass
  tuple CDH and byte-chunk polynomial hashing.
- Shared Python `ResourceLimits` for input, decoded output, token count, rope
  depth, reference fields, and I/O chunk size; matching CLI options.
- `cdc_ranges` for one-scan, zero-copy CDC boundary reporting.
- Rust `BuildLimits` / `build_rope_with_limits`, bounded literal leaves, and
  pre-reserved persistent arena-node growth.
- Focused memory, node-count, one-pass, expansion-budget, and CLI regressions.

### Changed
- Exact raw-DEFLATE/gzip comparison and full-integrity BLAKE3 operate on bounded
  decoded chunks. Raw CLI hashing streams file/stdin input.
- Compatibility APIs that return `bytes`, token lists, or CDC chunk lists are
  retained as explicit materializing wrappers.

## UHC 03

### Fixed
- Multi-hash pipeline and CLI calls now honor the requested CDH method and
  sliding-window parameters for every component.
- CLI verification mismatches exit `1` in JSON as well as text/quiet modes;
  malformed inputs and unsupported operations exit `2` without tracebacks.
- ZIP is detected but explicitly rejected as an ambiguous whole-archive byte
  stream across the API and CLI. Per-entry parsing remains available.
- Python rope ranges and prime/base ownership are checked. Rust byte/range
  access now has structured recoverable errors and checked helpers.

### Added
- `uhc_verify_exact`, the explicit name for authoritative decoded-byte
  comparison; `uhc_verify` remains compatible.

## UHC 02

### Fixed
- `uhc_verify` now strictly decodes through native format implementations,
  applies a SHA-256 precheck, and compares decoded bytes exactly. The known
  fixed-base collision no longer verifies equal.
- Raw DEFLATE rejects trailing bytes; gzip validates headers, CRC/ISIZE, every
  concatenated member, and trailing data; Zstandard iterates concatenated and
  skippable frames and rejects truncation or trailing bytes.
- LZ77 stream validation is centralized across decoding and CDH entry points.
- Polynomial-hash construction rejects composite/non-Mersenne moduli, and
  multi-hash construction rejects duplicate bases.
- Rust LCP/comparison uses exact structural byte traversal. CD-Mergesort is no
  longer vulnerable to polynomial-hash collisions.
- Rust CD-Radix and DTH-Radix use explicit iterative work stacks rather than
  recursive MSD calls that overflow on long shared prefixes.

### Changed
- Rust `build_rope` now returns `Result<Node, BuildError>` for malformed public
  token streams. This is an intentional API break for recoverable failure.

## [0.1.5] - 2026-04-06

### Added
- **Theorem 23: BLAKE3 integrity composition** (`uhc/core/integrity.py`):
  - `integrity_fast()` — CDH^(k) only, O(k·c_F·n), collision bound (N/p)^k (Theorem 23a)
  - `integrity_full()` — CDH^(k) + BLAKE3(T), cryptographic collision resistance (Theorem 23b)
  - `IncrementalIntegrity` — list-based incremental CDH + BLAKE3, O(k) add, O(k·m) remove (Theorem 23c)
  - `RopeIncrementalIntegrity` — rope-based incremental CDH via Theorems 6-7, O(k·log m) add/remove for CDH component (Theorem 23c)
- **`MERSENNE_127` constant** (`polynomial_hash.py`): p = 2^127−1, the recommended prime for high-security configurations (Corollary 5: collision bound < 2^(−174) for 1 TB files with k=2)
- Cross-format integrity tests: BLAKE3 + CDH verified across DEFLATE, gzip, and Zstandard
- 4 new tests (702 total)

### Fixed
- Removed dead code in `_fill_prefix_hashes` (unreachable `if byte_hash < 0` after Python `% p`)
- Corrected complexity documentation in `RopeIncrementalIntegrity`: BLAKE3 removal is O(N_remaining), not O(k·log m)

### Framework completeness
- All 24 theorems, 14 lemmas, 5 corollaries, 10 definitions now implemented and tested
- Zero unresolved assumptions

## [0.1.4] - 2026-04-06

### Added
- **Zstandard CLI support**: `--format zstd` accepted in all commands (hash, verify, inspect, info, benchmark). Magic byte auto-detection (`28 b5 2f fd`) enabled.
- **Gzip format** (`uhc/core/gzip_parser.py`): RFC 1952 header parser with support for FEXTRA, FNAME, FCOMMENT, FHCRC fields. `gzip_extract_tokens()` strips the header and delegates to `deflate_extract_tokens()`. `Format.GZIP` wired into pipeline and CLI with magic byte auto-detection (`1f 8b`).
- **`uhc info` command**: File metadata and token statistics — compressed/decoded size, compression ratio, token counts (literals, references, overlapping references). Text and JSON output.
- **`uhc benchmark` command**: Times CDH vs decompress-then-hash with configurable trial count. Reports speedup factor and verifies Theorem 12 correctness (CDH = DTH). Text and JSON output.
- **`--timing` flag**: Shows elapsed wall-clock time on any command. Injects `elapsed_ms` field into JSON output.
- **`--verbose` / `-v` flag**: Detailed output showing format, method, and token count on hash command.
- **README overhaul**: Comprehensive rewrite with badges, "How It Works" section, full CLI reference with usage examples for all 6 commands, format table with c_F values, expanded math section, updated architecture tree, citation block. Test count updated to 668.
- 52 new tests (668 total)

### Changed
- Gzip magic bytes (`1f 8b`) now map to `Format.GZIP` instead of `Format.DEFLATE` for proper header stripping.
- `Format` enum gains `GZIP` member; pipeline `_FORMAT_CONFIG` updated accordingly.

## [0.1.3] - 2026-04-05

### Added
- **k-tuple multi-hash** (`uhc/core/multihash.py`): `MultiHash` class wrapping k independent `PolynomialHash` instances. `multi_cdh()` and `multi_cdh_sliding()` compute k-tuple CDH. Implements Theorems 20-21, Corollary 5. Collision bound drops from N/p to (N/p)^k.
- **DEFLATE token extractor** (`uhc/core/deflate.py`): Pure-Python RFC 1951 parser extracting Lit/Ref tokens from raw DEFLATE streams. Handles stored, fixed Huffman, and dynamic Huffman blocks. Satisfies conditions C1/C2 (Lemma 9).
- **LZ4 token extractor** (`uhc/core/lz4_parser.py`): Parser for both raw LZ4 block format and LZ4 frame format. Handles 255-continuation scheme for long literals/matches. Satisfies conditions C1/C2 (Lemma 10).
- **Content-Defined Chunking** (`uhc/chunking/cdc.py`): Gear-based FastCDC implementation with normalized two-level masking. Configurable min/avg/max chunk sizes. Deterministic, content-defined boundaries.
- **Unified pipeline API** (`uhc/engine/pipeline.py`): Clean public interface — `uhc_hash()`, `uhc_hash_compressed()`, `uhc_hash_multi()`, `uhc_verify()`. Supports DEFLATE, LZ4 (block + frame), and RAW formats. Cross-format verification (e.g., compare DEFLATE vs LZ4 of same data).
- **End-to-end integration tests**: Full pipeline validation — CDC → compress → extract tokens → CDH → compose. Cross-format consistency, deduplication scenarios, randomized testing.
- 212 new tests (504 total)

## [0.1.2] - 2026-04-05

### Added
- **Sliding rope algorithm** (Definition 10, Theorem 11, Lemma 12): bounded-memory CDH via `SlidingRopeState` class with eviction. Memory independent of decoded size N — depends only on W = d_max + m_max.
- `CDHMethod.SLIDING_ROPE` — third CDH strategy, configurable via `d_max` and `m_max` parameters
- Runtime validation: raises `ValueError` if back-reference distance exceeds window or decoded length
- Direct invariant I_slide verification tests: checks conditions (3), (4), (5) after every single token
- Boundary condition tests: d = d_max exactly, window at W vs W+1, eviction trim to d_max, invalid parameter rejection
- 84 new tests (292 total), including 15 randomized step-by-step invariant proofs and three-way cross-validation (prefix_array, rope, sliding_rope)

## [0.1.1] - 2026-04-05

### Added
- **Hash rope data structure** (`uhc/core/rope.py`) — Leaf, Internal, RepeatNode with BB[2/7] weight balance (Part III: Definition 6-7, Lemmas 4-8, Theorems 6-10)
- `rope_concat`, `rope_split`, `rope_repeat`, `rope_substr_hash` operations
- `CDHMethod` enum for selecting CDH strategy ("prefix_array" or "rope")
- Rope-based CDH: computes H(T) from LZ77 tokens without materializing decoded bytes
- 114 new tests (208 total): randomized cross-validation, exhaustive SubstrHash, nested RepeatNodes, balance stress tests

### Changed
- `compressed_domain_hash()` now accepts `method` parameter (default: "rope")
- Both strategies cross-validated: prefix_array and rope produce identical results on all inputs

## [0.1.0] - 2026-04-04

### Added
- Project scaffolding
- Mathematical framework document (24 theorems, 14 lemmas, 5 corollaries)
- `polynomial_hash.py` — Mersenne arithmetic, PolynomialHash, phi()
- `lz77.py` — Literal/Reference tokens, encode/decode
- `compressed_verifier.py` — CDH(τ)=H(T) proven via prefix hash array
- 94 tests, all passing
