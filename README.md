# UHC — Unified Hash-Compression Engine

[![PyPI version](https://img.shields.io/pypi/v/uhc)](https://pypi.org/project/uhc/)
[![Python 3.10+](https://img.shields.io/pypi/pyversions/uhc)](https://pypi.org/project/uhc/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-670%2B%20passing-brightgreen)]()

A Python framework for **compressed-domain hashing** (CDH) over LZ77 streams.

UHC computes the polynomial hash of uncompressed data by operating directly on compressed token streams — **without ever materializing the decompressed bytes**. It supports DEFLATE, gzip, LZ4, and Zstandard formats, and produces results **mathematically identical** to hashing the decompressed data (Theorem 12).

---

## Why?

Traditional integrity checking requires: **read compressed → decompress → hash the raw bytes**.

For a 1 TB file compressed to 100 GB, that's **1.1 TB of data movement** — the compressed read plus the full decompression.

UHC's compressed-domain hashing reads only the 100 GB compressed stream and computes the hash algebraically from the LZ77 tokens. The speedup is proportional to the compression ratio (Theorem 17):

| Scenario | Decompress-then-hash | UHC CDH |
|:---------|:---------------------|:--------|
| 1 TB file, 10:1 compression | 1.1 TB I/O | 100 GB I/O |
| DEFLATE, CR > 23 | Baseline | **Faster** (CPU) |
| Zstandard, CR > 44 | Baseline | **Faster** (CPU) |
| LZ4, CR > 16·log N | Baseline | **Faster** (CPU) |

## How It Works

UHC exploits the algebraic structure of polynomial hash functions. The key insight: when an LZ77 back-reference says "copy 1000 bytes from offset 5", those 1000 bytes form a repeating pattern of period 5. The hash of a repeated pattern P^q can be computed in O(log q) time using a geometric accumulator (Theorem 2), without materializing the bytes.

The core data structure is a **hash rope** — a balanced binary tree (BB[2/7]) augmented with hash metadata at every node. A dedicated **RepeatNode** encodes repetitions as mathematical metadata (repetition count + Φ-based hash), keeping the structure a strict tree and avoiding the DAG paradox of structural sharing.

Three CDH strategies are available, trading space for generality:

| Strategy | Space | Best for |
|:---------|:------|:---------|
| `PREFIX_ARRAY` | O(N) | Small files, debugging |
| `ROPE` | O(n·log N) | General use, unbounded streams |
| `SLIDING_ROPE` | O(W) | Large files, bounded memory (W = d_max + m_max) |

All three produce identical results — this cross-validation is enforced by the test suite.

---

## Installation

```bash
pip install uhc
```

For optional format support (LZ4 compression, Zstandard compression, BLAKE3):

```bash
pip install uhc[formats]
```

**Requirements:** Python 3.10+. No required C dependencies — all parsers are pure Python.

---

## CLI Reference

UHC provides a command-line tool with six commands:

### `uhc hash` — Hash a file

```bash
# Hash a raw (uncompressed) file
uhc hash document.bin

# Hash a gzip file (auto-detected via magic bytes)
uhc hash archive.tar.gz

# Hash a DEFLATE stream with explicit format
uhc hash stream.deflate -f deflate

# Hash a Zstandard file
uhc hash data.zst -f zstd

# Multi-hash for stronger collision resistance (k=2)
uhc hash archive.gz --bases 131 257

# Output in hexadecimal
uhc hash data.zst --hex

# JSON output for scripting
uhc hash archive.gz -o json
# → {"file": "archive.gz", "format": "gzip", "method": "rope", "base": 131, "hash": 123456, "hash_hex": "1e240"}

# Choose CDH strategy
uhc hash data.deflate -f deflate --method sliding_rope

# Hash from stdin
cat file.gz | uhc hash -

# Quiet mode — hash value only
uhc hash archive.gz -q

# Show elapsed time
uhc hash archive.gz --timing

# Verbose — show format, method, token count
uhc hash archive.gz -v
```

### `uhc verify` — Cross-format integrity verification

Verify that two files (possibly in different compression formats) contain identical content:

```bash
# Same format
uhc verify copy1.gz copy2.gz

# Cross-format: raw vs gzip
uhc verify original.bin archive.gz --format-a raw --format-b gzip

# Cross-format: DEFLATE vs Zstandard
uhc verify data.deflate data.zst --format-a deflate --format-b zstd

# Cross-format: DEFLATE vs LZ4
uhc verify data.deflate data.lz4 --format-a deflate --format-b lz4_frame

# Quiet mode — exit code only (0 = match, 1 = mismatch)
uhc verify a.gz b.zst --format-a gzip --format-b zstd -q
echo $?   # 0 if match

# JSON output
uhc verify a.gz b.gz -o json
# → {"file_a": "a.gz", "file_b": "b.gz", "format_a": "gzip", "format_b": "gzip", "match": true}
```

### `uhc info` — File metadata and token statistics

```bash
# Raw file info
uhc info document.bin
# → File:    document.bin
#   Size:    1048576 bytes
#   Format:  raw

# Compressed file info — shows token breakdown
uhc info archive.gz
# → File:             archive.gz
#   Compressed size:  102400 bytes
#   Decoded size:     1048576 bytes
#   Format:           gzip
#   Compression ratio: 10.24x
#   Total tokens:     8234
#     Literals:       1205
#     References:     7029
#     Overlapping:    342

# JSON output
uhc info data.zst -o json
```

### `uhc benchmark` — CDH vs decompress-then-hash timing

Measures CDH performance against the traditional decompress-then-hash approach, verifying Theorem 17:

```bash
# Benchmark a DEFLATE file
uhc benchmark data.deflate -f deflate
# → Format:     deflate
#   Method:     rope
#   Trials:     3
#   CDH time:   12.45 ms (best of 3)
#   DTH time:   8.21 ms (best of 3)
#   Speedup:    0.66x
#   Correctness: MATCH (Theorem 12 holds)

# JSON output with custom trial count
uhc benchmark data.zst -f zstd --trials 10 -o json
# → {"file": "data.zst", "format": "zstd", "method": "rope", "trials": 10,
#    "cdh_time": 0.01245, "dth_time": 0.00821, "speedup": 0.66, "match": true, ...}
```

**Note:** CDH becomes faster than DTH when the compression ratio exceeds the format constant c_F (23 for DEFLATE, 44 for Zstandard). The pure-Python implementation adds overhead; C-accelerated inner loops (planned) will shift the break-even point.

### `uhc chunks` — Content-defined chunking

```bash
# Show CDC chunk boundaries
uhc chunks largefile.bin
# →    #      Offset      Size  Hash
#    ——    ——————————  ————————  ————————————————————
#      1           0      4096  1234567890123456789
#      2        4096      8192  9876543210987654321
#    ...
#    12 chunks, 98304 bytes total, avg 8192 bytes/chunk

# Custom chunk sizes
uhc chunks data.bin --min-size 1024 --avg-size 4096 --max-size 16384

# JSON output
uhc chunks data.bin -o json

# Hexadecimal hashes
uhc chunks data.bin --hex
```

### `uhc inspect` — Dump LZ77 tokens

```bash
# Inspect a DEFLATE stream
uhc inspect data.deflate -f deflate
# → Format: deflate | Total tokens: 1234
#
#   Lit(t)
#   Lit(h)
#   Lit(e)
#   Ref(d=5, l=10)
#   ...

# Inspect a gzip file (auto-detected)
uhc inspect archive.gz

# Limit output
uhc inspect data.zst -f zstd -n 20

# JSON output
uhc inspect data.deflate -f deflate -o json
```

### Global flags

All commands support:

| Flag | Description |
|:-----|:------------|
| `--format`, `-f` | Input format: `raw`, `deflate`, `gzip`, `lz4_block`, `lz4_frame`, `zstd`, `auto` |
| `--output`, `-o` | Output format: `text` (default), `json` |
| `--quiet`, `-q` | Minimal output (hash values only, exit codes only) |
| `--timing` | Show elapsed wall-clock time |
| `--verbose`, `-v` | Show detailed metadata (format, method, token count) |
| `--version` | Print version and exit |

Format auto-detection uses magic bytes:

| Magic bytes | Format |
|:------------|:-------|
| `1f 8b` | gzip |
| `04 22 4d 18` | LZ4 frame |
| `28 b5 2f fd` | Zstandard |
| *(none)* | Falls back to raw |

Raw DEFLATE streams have no magic bytes — use `--format deflate` explicitly.

---

## Python API

### Hash raw data

```python
from uhc.engine.pipeline import uhc_hash

h = uhc_hash(b"hello world")
```

### Hash compressed data without decompressing

```python
import zlib
from uhc.engine.pipeline import uhc_hash_compressed, Format

# Compress with raw DEFLATE (no zlib/gzip header)
data = b"the quick brown fox " * 1000
c = zlib.compressobj(6, zlib.DEFLATED, -15)
compressed = c.compress(data) + c.flush()

# Hash the decompressed content — without decompressing
h = uhc_hash_compressed(compressed, Format.DEFLATE)

# Verify: identical to hashing the raw data (Theorem 12)
assert h == uhc_hash(data)
```

### Hash a gzip file

```python
import gzip
from uhc.engine.pipeline import uhc_hash_compressed, uhc_hash, Format

data = b"gzip example " * 500
gz_bytes = gzip.compress(data)

h = uhc_hash_compressed(gz_bytes, Format.GZIP)
assert h == uhc_hash(data)  # Theorem 12
```

### Hash a Zstandard file

```python
import zstandard
from uhc.engine.pipeline import uhc_hash_compressed, uhc_hash, Format

data = b"zstandard example " * 500
cctx = zstandard.ZstdCompressor()
zst_bytes = cctx.compress(data)

h = uhc_hash_compressed(zst_bytes, Format.ZSTD)
assert h == uhc_hash(data)  # Theorem 12
```

### Cross-format verification

```python
import zlib, gzip
from uhc.engine.pipeline import uhc_verify, Format

data = b"verify across formats " * 100

c = zlib.compressobj(6, zlib.DEFLATED, -15)
deflate_bytes = c.compress(data) + c.flush()
gz_bytes = gzip.compress(data)

# Verify DEFLATE vs gzip contain the same content
assert uhc_verify(deflate_bytes, gz_bytes,
                  fmt_a=Format.DEFLATE, fmt_b=Format.GZIP)
```

### Multi-hash for stronger collision resistance

```python
from uhc.engine.pipeline import uhc_hash_multi

# k=2 independent hashes — collision probability (N/p)^2
# With p = 2^61-1: < 2^(-82) for 1 GB files (Corollary 5)
h_k = uhc_hash_multi(b"important data", bases=[131, 257])
# Returns: (hash_base_131, hash_base_257)
```

### Content-defined chunking for deduplication

```python
from uhc.chunking.cdc import cdc_chunk
from uhc.core.polynomial_hash import PolynomialHash

h = PolynomialHash(base=131)
data = open("large_file.bin", "rb").read()

# Split into variable-size chunks at content-determined boundaries
chunks = cdc_chunk(data, min_size=2048, avg_size=8192, max_size=65536)

# Hash each chunk — identical content always produces identical hashes
chunk_hashes = [h.hash(c) for c in chunks]

# Reconstruct whole-file hash from chunks via Theorem 1
running = 0
for chunk in chunks:
    running = h.hash_concat(running, len(chunk), h.hash(chunk))
assert running == h.hash(data)
```

### Lower-level: direct token extraction and CDH

```python
from uhc.core.deflate import deflate_extract_tokens
from uhc.core.gzip_parser import gzip_extract_tokens
from uhc.core.zstd_parser import zstd_extract_tokens
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod

# Extract LZ77 tokens from a DEFLATE stream
tokens = deflate_extract_tokens(compressed_deflate_bytes)

# Or from a gzip stream (strips RFC 1952 header, delegates to DEFLATE parser)
tokens = gzip_extract_tokens(gzip_bytes)

# Or from a Zstandard frame
tokens = zstd_extract_tokens(zstd_bytes)

# Compute hash via any of three CDH strategies
h_rope    = compressed_domain_hash(tokens, method=CDHMethod.ROPE)
h_sliding = compressed_domain_hash(tokens, method=CDHMethod.SLIDING_ROPE,
                                    d_max=32768, m_max=258)
h_prefix  = compressed_domain_hash(tokens, method=CDHMethod.PREFIX_ARRAY)

# All three produce identical results (Theorem 12)
assert h_rope == h_sliding == h_prefix
```

---

## Architecture

```
uhc/
├── cli.py                         # CLI: hash, verify, info, benchmark, chunks, inspect
├── core/
│   ├── polynomial_hash.py         # Mersenne arithmetic, PolynomialHash, Φ() (Defs 1-3, Thms 1-3)
│   ├── lz77.py                    # Literal/Reference tokens, encode/decode (Defs 4-5)
│   ├── rope.py                    # Hash rope: Leaf, Internal, RepeatNode, BB[2/7] (Defs 6-7, Thms 6-10)
│   ├── compressed_verifier.py     # CDH: prefix_array, rope, sliding_rope (Thms 11-12)
│   ├── multihash.py               # k-tuple multi-hash (Thm 21)
│   ├── deflate.py                 # DEFLATE parser / token extractor (Lemma 9)
│   ├── gzip_parser.py             # Gzip header parser, delegates to DEFLATE (RFC 1952)
│   ├── lz4_parser.py              # LZ4 block + frame parser (Lemma 10)
│   └── zstd_parser.py             # Zstandard frame parser (Lemma 11)
├── chunking/
│   └── cdc.py                     # Gear-based FastCDC chunking
└── engine/
    └── pipeline.py                # Unified public API
```

### Supported formats

| Format | Magic bytes | Parser | d_max | m_max | c_F |
|:-------|:------------|:-------|------:|------:|----:|
| DEFLATE | *(none)* | `deflate.py` | 32,768 | 258 | 23 |
| gzip | `1f 8b` | `gzip_parser.py` → `deflate.py` | 32,768 | 258 | 23 |
| LZ4 block | *(none)* | `lz4_parser.py` | 65,535 | ∞ | varies |
| LZ4 frame | `04 22 4d 18` | `lz4_parser.py` | 65,535 | ∞ | varies |
| Zstandard | `28 b5 2f fd` | `zstd_parser.py` | 2²⁷ | 131,074 | 44 |

c_F = log₂(d_max) + log₂(m_max) — the compression ratio above which CDH is faster than decompress-then-hash (Theorem 17).

---

## Mathematical Foundation

The complete mathematical framework (pre-print) is in the project knowledge file `compressed_domain_hashing_framework.md`:

- **10 definitions**, **14 lemmas**, **24 theorems**, **5 corollaries** — all with complete proofs
- Zero unresolved assumptions

### Key results

| Result | Statement |
|:-------|:---------|
| **Theorem 1** (Concatenation) | H(A ‖ B) = H(A)·x^{\|B\|} + H(B) |
| **Theorem 2** (Repetition) | H(S^q) = H(S)·Φ(q, x^d) |
| **Theorem 3** (Φ computation) | Φ(q, α) computable in O(log q) without modular inverse |
| **Theorem 4** (Overlapping decomposition) | Ref(d, l) with d < l decodes to P^q ‖ P\[0..r−1\] |
| **Theorem 12** (Main correctness) | CDH(τ) = H(T) for all valid LZ77 encodings τ of T |
| **Theorem 17** (Speedup) | CDH faster than DTH when compression ratio > c_F |
| **Theorem 20** (Collision bound) | Pr\[collision\] ≤ (N/p)^k with k independent bases |
| **Corollary 5** (Security) | p = 2¹²⁷−1, k = 2 → collision probability < 2⁻¹⁷⁴ for 1 TB |

### Collision resistance

| Configuration | Collision bound (1 TB file) |
|:-------------|:---------------------------|
| p = 2⁶¹−1, k = 1 | 2⁻²¹ |
| p = 2⁶¹−1, k = 2 | 2⁻⁴² |
| p = 2¹²⁷−1, k = 2 | **2⁻¹⁷⁴** (recommended) |

**Note:** Polynomial hashing is not cryptographically secure against adversaries who know the hash bases (Theorem 22c). For adversarial settings, compose with BLAKE3 (Theorem 23). CDH is designed for integrity against accidental corruption, deduplication, and verification protocols where the bases are secret.

---

## Development

```bash
git clone https://github.com/jemsbhai/uhc.git
cd uhc/code
pip install -e ".[dev,formats]"
python -m pytest tests/ -v
```

### Test suite

670+ tests across 18 test files covering:

- **Algebraic foundations:** polynomial hash, geometric accumulator Φ, Mersenne prime arithmetic
- **LZ77 encode/decode:** overlapping back-references, boundary cases, round-trip correctness
- **Hash rope:** concat, split, repeat, substr_hash, BB\[2/7\] balance invariants, RepeatNode splittability
- **CDH cross-validation:** three-way agreement (prefix_array = rope = sliding_rope) on all inputs
- **Format parsers:** DEFLATE (RFC 1951), gzip (RFC 1952), LZ4 (block + frame), Zstandard (RFC 8478)
- **Rigorous parser tests:** byte-level verification against reference decoders, edge cases, fuzzing
- **CDC chunking:** determinism, boundary stability, min/avg/max size constraints
- **Pipeline integration:** cross-format verification, multi-hash, API surface
- **CLI:** all 6 commands × multiple formats × text/JSON output × flags
- **Randomized property-based tests:** seeded for reproducibility

---

## Roadmap

### Done

- [x] Algebraic core (polynomial hash, geometric accumulator)
- [x] Hash rope data structure with RepeatNode (BB\[2/7\] balanced)
- [x] Compressed-domain hash verifier (three strategies, cross-validated)
- [x] k-tuple multi-hash (Theorem 21)
- [x] DEFLATE token extractor (Lemma 9)
- [x] Gzip header parser (RFC 1952) with DEFLATE delegation
- [x] LZ4 token extractor — block + frame (Lemma 10)
- [x] Zstandard token extractor (Lemma 11)
- [x] Content-defined chunking (Gear-based FastCDC)
- [x] Unified pipeline API
- [x] CLI with hash, verify, info, benchmark, chunks, inspect
- [x] Experiment infrastructure (timing, memory, sysinfo, plotting)

### Next

- [ ] Performance benchmarks (E1–E7) for ESA 2026 submission
- [ ] BLAKE3 Merkle wrapper for adversarial integrity (Theorem 23)
- [ ] MPHF index for chunk lookup
- [ ] C/C++ acceleration for inner loops

---

## Citation

If you use UHC in academic work, please cite:

```
@software{uhc2026,
  title  = {UHC: Unified Hash-Compression Engine},
  url    = {https://github.com/jemsbhai/uhc},
  year   = {2026},
}
```

## License

MIT
