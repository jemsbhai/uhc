# UHC — Unified Hash-Compression Engine

A Python framework for compressed-domain hashing over LZ77 streams.

UHC computes the polynomial hash of uncompressed data by operating directly on compressed token streams (DEFLATE, LZ4, Zstandard), without ever materializing the decompressed bytes.

## Key Features

- **Compressed-domain hashing:** Compute integrity hashes without decompression
- **Hash-augmented rope:** Novel data structure with RepeatNode for O(k·log q) overlapping back-reference resolution
- **Multi-hash collision resistance:** k-wise independent polynomial hashes with configurable security levels
- **Format compatible:** DEFLATE, LZ4, Zstandard support via unified token abstraction
- **Sliding window:** O(1) memory relative to decompressed size for bounded-window formats

## Installation

```bash
pip install uhc
```

## Quick Start

```python
import uhc

# Coming soon — Phase 1 implementation in progress
```

## Mathematical Foundation

The complete mathematical framework (24 theorems, 14 lemmas, 5 corollaries) with full proofs is available in `theory/compressed_domain_hashing_framework.md`.

## Project Status

**Phase 1:** Algebraic core — polynomial hash, naive LZ77, compressed-domain verifier

## License

MIT
