# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
