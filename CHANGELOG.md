# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
