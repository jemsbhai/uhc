# UHC — Unified Hash-Compression Engine

A Python framework for **compressed-domain hashing** over LZ77 streams.

UHC computes the polynomial hash of uncompressed data by operating directly on compressed token streams (DEFLATE, LZ4), **without ever materializing the decompressed bytes**. This means you can verify the integrity of a 1 TB compressed archive while reading only the compressed data — no decompression needed.

## Why?

Traditional integrity checking requires: **read compressed → decompress → hash the raw bytes**. For a 1 TB file compressed to 100 GB, that's 1.1 TB of data movement.

UHC's compressed-domain hashing (CDH) reads only the 100 GB compressed stream and computes the hash algebraically from the LZ77 tokens. The result is **mathematically identical** to hashing the decompressed data (Theorem 12), with speedup proportional to the compression ratio (Theorem 17).

| Scenario | Decompress-then-hash | UHC |
|:---------|:---------------------|:----|
| 1 TB file, 10:1 compression | 1.1 TB I/O | 100 GB I/O |
| DEFLATE, CR > 23 | Baseline | Faster (CPU) |
| Zstandard, CR > 44 | Baseline | Faster (CPU) |

## Installation

```bash
pip install uhc
```

For format support (LZ4, Zstandard, BLAKE3):

```bash
pip install uhc[formats]
```

## Quick Start

### Hash raw data

```python
from uhc.engine.pipeline import uhc_hash

h = uhc_hash(b"hello world")
```

### Hash compressed data without decompressing

```python
import zlib
from uhc.engine.pipeline import uhc_hash_compressed, Format

# Compress with raw DEFLATE (no zlib header)
data = b"the quick brown fox " * 1000
c = zlib.compressobj(6, zlib.DEFLATED, -15)
compressed = c.compress(data) + c.flush()

# Hash the decompressed content — without decompressing
h = uhc_hash_compressed(compressed, Format.DEFLATE)

# Verify: same as hashing the raw data directly
assert h == uhc_hash(data)
```

### Cross-format verification

```python
import lz4.block
from uhc.engine.pipeline import uhc_verify, Format

data = b"test data " * 100

# Compress the same data with two different formats
c = zlib.compressobj(6, zlib.DEFLATED, -15)
deflate_bytes = c.compress(data) + c.flush()
lz4_bytes = lz4.block.compress(data, store_size=False)

# Verify they contain the same content — without decompressing either
assert uhc_verify(deflate_bytes, lz4_bytes,
                  fmt_a=Format.DEFLATE, fmt_b=Format.LZ4_BLOCK)
```

### Multi-hash for stronger collision resistance

```python
from uhc.engine.pipeline import uhc_hash_multi

# k=2 independent hashes — collision probability drops to (N/p)^2
h_k = uhc_hash_multi(b"important data", bases=[131, 257])
# Returns tuple: (hash_with_base_131, hash_with_base_257)
```

### Content-defined chunking for deduplication

```python
from uhc.chunking.cdc import cdc_chunk
from uhc.core.polynomial_hash import PolynomialHash

h = PolynomialHash(base=131)
data = open("large_file.bin", "rb").read()

# Split into variable-size chunks at content-determined boundaries
chunks = cdc_chunk(data, min_size=2048, avg_size=8192, max_size=65536)

# Hash each chunk — identical content produces identical hashes
chunk_hashes = {h.hash(c): c for c in chunks}

# Reconstruct whole-file hash from chunks via Theorem 1
running = 0
for chunk in chunks:
    running = h.hash_concat(running, len(chunk), h.hash(chunk))
assert running == h.hash(data)
```

### Lower-level: direct token extraction and CDH

```python
from uhc.core.deflate import deflate_extract_tokens
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod

# Extract LZ77 tokens from a DEFLATE stream
tokens = deflate_extract_tokens(compressed)

# Compute hash via compressed-domain hashing (three strategies available)
h_rope = compressed_domain_hash(tokens, method=CDHMethod.ROPE)
h_sliding = compressed_domain_hash(tokens, method=CDHMethod.SLIDING_ROPE,
                                    d_max=32768, m_max=258)
h_prefix = compressed_domain_hash(tokens, method=CDHMethod.PREFIX_ARRAY)

# All three produce identical results (Theorem 12)
assert h_rope == h_sliding == h_prefix
```

## Architecture

```
uhc/
├── core/
│   ├── polynomial_hash.py     # Mersenne arithmetic, PolynomialHash, Φ()
│   ├── lz77.py                # Literal/Reference tokens, encode/decode
│   ├── rope.py                # Hash rope: Leaf, Internal, RepeatNode, BB[2/7]
│   ├── compressed_verifier.py # CDH: prefix_array, rope, sliding_rope strategies
│   ├── multihash.py           # k-tuple multi-hash (Theorem 21)
│   ├── deflate.py             # DEFLATE token extractor (Lemma 9)
│   └── lz4_parser.py          # LZ4 block + frame parser (Lemma 10)
├── chunking/
│   └── cdc.py                 # Gear-based FastCDC chunking
└── engine/
    └── pipeline.py            # Unified public API
```

### CDH Strategies

| Strategy | Space | Best for |
|:---------|:------|:---------|
| `PREFIX_ARRAY` | O(N) | Small files, debugging |
| `ROPE` | O(n·log N) | General use, unbounded streams |
| `SLIDING_ROPE` | O(W) | Large files, bounded memory (W = d_max + m_max) |

## Mathematical Foundation

The complete mathematical framework is in `theory/compressed_domain_hashing_framework.md`:

- **10 definitions**, **14 lemmas**, **24 theorems**, **5 corollaries** — all with complete proofs
- **Theorem 12 (Main Correctness):** CDH(τ) = H(T) for all valid LZ77 encodings
- **Theorem 17 (Speedup):** CDH is faster than decompress-then-hash when compression ratio exceeds the format constant c_F
- **Theorem 20 (Collision Bound):** Pr[collision] ≤ (N/p)^k with k independent bases
- **Corollary 5:** p = 2^127−1, k = 2 gives collision probability below 2^(−174) for 1 TB files

## Development

```bash
git clone https://github.com/jemsbhai/uhc.git
cd uhc/code
pip install -e ".[dev,formats]"
python -m pytest tests/ -v
```

### Test Coverage

504 tests covering:
- Algebraic foundations (polynomial hash, Φ, Mersenne arithmetic)
- LZ77 encode/decode with overlapping references
- Hash rope operations (concat, split, repeat, substr_hash, balance)
- Three-way CDH cross-validation (prefix_array, rope, sliding_rope)
- DEFLATE and LZ4 token extraction against real compressor output
- CDC chunking properties (determinism, boundary stability, size constraints)
- End-to-end pipeline integration with cross-format verification
- Randomized and seeded property-based tests

## Roadmap

### Done
- [x] Algebraic core (polynomial hash, geometric accumulator)
- [x] Hash rope data structure with RepeatNode
- [x] Compressed-domain hash verifier (three strategies)
- [x] k-tuple multi-hash
- [x] DEFLATE token extractor
- [x] LZ4 token extractor (block + frame)
- [x] Content-defined chunking (FastCDC)
- [x] Unified pipeline API

### Next
- [ ] Zstandard token extractor (Lemma 11)
- [ ] BLAKE3 Merkle wrapper for adversarial integrity
- [ ] MPHF index for chunk lookup
- [ ] Performance benchmarks
- [ ] C++ acceleration for inner loops

## License

MIT
