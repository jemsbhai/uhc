# UHC — Unified Hash-Compression Engine

A Python framework for compressed-domain hashing over LZ77 streams.

UHC computes the polynomial hash of uncompressed data by operating directly on compressed token streams (DEFLATE, LZ4, Zstandard), without ever materializing the decompressed bytes.

## Key Features

- **Compressed-domain hashing:** Compute integrity hashes without decompression (Theorem 12)
- **Hash-augmented rope:** Novel data structure with RepeatNode for O(k·log q) overlapping back-reference resolution
- **Multi-hash collision resistance:** k-wise independent polynomial hashes — collision bound (N/p)^k (Theorem 20)
- **Real format support:** DEFLATE (RFC 1951) and LZ4 (block + frame) token extraction
- **Content-defined chunking:** Gear-based FastCDC for deduplication workflows
- **Unified pipeline:** Clean API for hash, verify, and cross-format comparison
- **Sliding window:** O(1) memory relative to decompressed size for bounded-window formats

## Installation

```bash
pip install uhc
```

For format support:
```bash
pip install uhc[formats]   # adds lz4, zstandard, blake3
```

## Quick Start

```python
from uhc.engine.pipeline import uhc_hash, uhc_hash_compressed, uhc_verify, Format

# Hash raw data
h = uhc_hash(b"hello world")

# Hash pre-compressed data without decompressing
import zlib
compressed = zlib.compress(b"hello world", wbits=-15)
h = uhc_hash_compressed(compressed, Format.DEFLATE)

# k-tuple multi-hash for stronger collision resistance
from uhc.engine.pipeline import uhc_hash_multi
h_k = uhc_hash_multi(b"hello world", bases=[131, 257])

# Cross-format verification: does this DEFLATE and LZ4 contain the same data?
import lz4.block
raw_data = b"test data " * 100
deflate_bytes = zlib.compress(raw_data, wbits=-15)  # raw DEFLATE
lz4_bytes = lz4.block.compress(raw_data, store_size=False)
assert uhc_verify(deflate_bytes, lz4_bytes,
                  fmt_a=Format.DEFLATE, fmt_b=Format.LZ4_BLOCK)
```

## Architecture

```
uhc/
├── core/
│   ├── polynomial_hash.py    # Mersenne arithmetic, PolynomialHash, Φ()
│   ├── lz77.py               # Literal/Reference tokens, encode/decode
│   ├── rope.py               # Hash rope: Leaf, Internal, RepeatNode, BB[2/7]
│   ├── compressed_verifier.py # CDH: prefix_array, rope, sliding_rope
│   ├── multihash.py          # k-tuple multi-hash (Theorem 21)
│   ├── deflate.py            # DEFLATE token extractor (Lemma 9)
│   └── lz4_parser.py         # LZ4 block + frame parser (Lemma 10)
├── chunking/
│   └── cdc.py                # Gear-based FastCDC
└── engine/
    └── pipeline.py           # Unified public API
```

## Mathematical Foundation

The complete mathematical framework (24 theorems, 14 lemmas, 5 corollaries) with full proofs is available in `theory/compressed_domain_hashing_framework.md`.

Key results:
- **Theorem 12:** CDH(τ) = H(T) — compressed-domain hash equals direct hash for all inputs
- **Theorem 17:** Speedup = CR / c_F — faster than decompress-then-hash when compression ratio exceeds format constant
- **Theorem 20:** k-wise collision bound (N/p)^k with independent bases

## Test Coverage

504 tests covering algebraic foundations, rope operations, CDH correctness, format parsers, CDC chunking, and end-to-end pipeline integration. All tests map to specific theorems/lemmas from the framework.

## License

MIT
