# UHC - Unified Hash-Compression Engine

[![PyPI version](https://img.shields.io/pypi/v/uhc)](https://pypi.org/project/uhc/)
[![Python 3.10+](https://img.shields.io/pypi/pyversions/uhc)](https://pypi.org/project/uhc/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-810%20passing-brightgreen)]()

A Python framework for **compressed-domain hashing** (CDH) over LZ77 streams.

UHC computes the polynomial hash of uncompressed data by operating directly on compressed token streams, without ever materializing the decompressed bytes. It supports DEFLATE, gzip, ZIP, LZ4, and Zstandard formats, and produces results **mathematically identical** to hashing the decompressed data (Theorem 12).

---

## The Core Claim

**You can take two files, each compressed with a completely different scheme, and verify they contain identical content without decompressing either one.**

A DEFLATE archive and a Zstandard archive. A gzip file and an LZ4 frame. A ZIP entry and a raw stream. UHC computes a hash from each compressed representation independently, and if the hashes match, the underlying data is the same. No decompression needed.

This works because CDH is format-independent by construction: for any string T and any valid LZ77 encoding of T under any supported format, CDH produces exactly H(T). The hash depends only on the content, never on how it was compressed.

```python
import gzip, zstandard
from uhc.engine.pipeline import uhc_hash_compressed, Format

data = b"same content, different containers " * 500

gz_bytes  = gzip.compress(data)
zst_bytes = zstandard.ZstdCompressor().compress(data)

h_gz  = uhc_hash_compressed(gz_bytes,  Format.GZIP)
h_zst = uhc_hash_compressed(zst_bytes, Format.ZSTD)

assert h_gz == h_zst  # same content, verified without decompressing either file
```

This claim is backed by:
- **Mathematical proof**: Theorem 12, with 24 theorems, 14 lemmas, 5 corollaries, zero unresolved assumptions
- **810 passing tests**, including a full cross-format matrix: 6 formats x 4 data patterns x 4 sizes, all pairwise combinations, multi-hash, three CDH strategies, CLI integration
- **Collision bound**: with recommended parameters (p = 2^127 - 1, k = 2), probability of false match < 2^(-174) for 1 TB files

---

## Why?

Traditional integrity checking requires: read compressed, decompress, hash the raw bytes.

For a 1 TB file compressed to 100 GB, that is 1.1 TB of data movement: the compressed read plus the full decompression.

UHC reads only the 100 GB compressed stream and computes the hash algebraically from the LZ77 tokens. The speedup is proportional to the compression ratio (Theorem 17):

| Scenario | Decompress-then-hash | UHC CDH |
|:---------|:---------------------|:--------|
| 1 TB file, 10:1 compression | 1.1 TB I/O | 100 GB I/O |
| DEFLATE, CR > 23 | Baseline | **Faster** (CPU) |
| Zstandard, CR > 44 | Baseline | **Faster** (CPU) |
| LZ4, CR > 16 log N | Baseline | **Faster** (CPU) |

## How It Works

UHC exploits the algebraic structure of polynomial hash functions. When an LZ77 back-reference says "copy 1000 bytes from offset 5", those 1000 bytes form a repeating pattern of period 5. The hash of a repeated pattern P^q can be computed in O(log q) time using a geometric accumulator (Theorem 2), without materializing the bytes.

The core data structure is a **hash rope**, a balanced binary tree (BB[2/7]) augmented with hash metadata at every node. A dedicated **RepeatNode** encodes repetitions as mathematical metadata (repetition count + geometric accumulator hash), keeping the structure a strict tree and avoiding the DAG paradox of structural sharing.

Three CDH strategies are available, trading space for generality:

| Strategy | Space | Best for |
|:---------|:------|:---------|
| `PREFIX_ARRAY` | O(N) | Small files, debugging |
| `ROPE` | O(n log N) | General use, unbounded streams |
| `SLIDING_ROPE` | O(W) | Large files, bounded memory (W = d_max + m_max) |

All three produce identical results. This cross-validation is enforced by the test suite.

---

## Installation

```bash
pip install uhc
```

For optional format support (LZ4 compression, Zstandard compression, BLAKE3):

```bash
pip install uhc[formats]
```

**Requirements:** Python 3.10+. No required C dependencies. All parsers are pure Python.

---

## CLI Reference

UHC provides a command-line tool with six commands.

### `uhc hash` - Hash a file

```bash
# Hash a raw (uncompressed) file
uhc hash document.bin

# Hash a gzip file (auto-detected via magic bytes)
uhc hash archive.tar.gz

# Hash a DEFLATE stream with explicit format
uhc hash stream.deflate -f deflate

# Hash a Zstandard file
uhc hash data.zst -f zstd

# Hash a ZIP archive entry
uhc hash archive.zip -f zip

# Multi-hash for stronger collision resistance (k=2)
uhc hash archive.gz --bases 131 257

# Output in hexadecimal
uhc hash data.zst --hex

# JSON output for scripting
uhc hash archive.gz -o json

# Choose CDH strategy
uhc hash data.deflate -f deflate --method sliding_rope

# Hash from stdin
cat file.gz | uhc hash -

# Quiet mode: hash value only
uhc hash archive.gz -q

# Show elapsed time
uhc hash archive.gz --timing

# Verbose: show format, method, token count
uhc hash archive.gz -v
```

### `uhc verify` - Cross-format integrity verification

Verify that two files, possibly in different compression formats, contain identical content:

```bash
# Same format
uhc verify copy1.gz copy2.gz

# Cross-format: raw vs gzip
uhc verify original.bin archive.gz --format-a raw --format-b gzip

# Cross-format: DEFLATE vs Zstandard
uhc verify data.deflate data.zst --format-a deflate --format-b zstd

# Cross-format: DEFLATE vs LZ4
uhc verify data.deflate data.lz4 --format-a deflate --format-b lz4_frame

# Cross-format: ZIP vs gzip
uhc verify archive.zip backup.gz --format-a zip --format-b gzip

# Quiet mode: exit code only (0 = match, 1 = mismatch)
uhc verify a.gz b.zst --format-a gzip --format-b zstd -q
echo $?   # 0 if match

# JSON output
uhc verify a.gz b.gz -o json
```

### `uhc info` - File metadata and token statistics

```bash
# Compressed file info with token breakdown
uhc info archive.gz

# JSON output
uhc info data.zst -o json
```

### `uhc benchmark` - CDH vs decompress-then-hash timing

Measures CDH performance against the traditional decompress-then-hash approach, verifying Theorem 17:

```bash
uhc benchmark data.deflate -f deflate

# JSON output with custom trial count
uhc benchmark data.zst -f zstd --trials 10 -o json
```

**Note:** CDH becomes faster than DTH when the compression ratio exceeds the format constant c_F (23 for DEFLATE, 44 for Zstandard). The pure-Python implementation adds overhead; C-accelerated inner loops (planned) will shift the break-even point.

### `uhc chunks` - Content-defined chunking

```bash
# Show CDC chunk boundaries
uhc chunks largefile.bin

# Custom chunk sizes
uhc chunks data.bin --min-size 1024 --avg-size 4096 --max-size 16384

# JSON output
uhc chunks data.bin -o json
```

### `uhc inspect` - Dump LZ77 tokens

```bash
# Inspect a DEFLATE stream
uhc inspect data.deflate -f deflate

# Limit output
uhc inspect data.zst -f zstd -n 20

# JSON output
uhc inspect data.deflate -f deflate -o json
```

### Global flags

All commands support:

| Flag | Description |
|:-----|:------------|
| `--format`, `-f` | Input format: `raw`, `deflate`, `gzip`, `zip`, `lz4_block`, `lz4_frame`, `zstd`, `auto` |
| `--output`, `-o` | Output format: `text` (default), `json` |
| `--quiet`, `-q` | Minimal output |
| `--timing` | Show elapsed wall-clock time |
| `--verbose`, `-v` | Show detailed metadata |
| `--version` | Print version and exit |

Format auto-detection uses magic bytes:

| Magic bytes | Format |
|:------------|:-------|
| `1f 8b` | gzip |
| `50 4b 03 04` | ZIP |
| `04 22 4d 18` | LZ4 frame |
| `28 b5 2f fd` | Zstandard |
| *(none)* | Falls back to raw |

Raw DEFLATE streams have no magic bytes; use `--format deflate` explicitly.

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

data = b"the quick brown fox " * 1000
c = zlib.compressobj(6, zlib.DEFLATED, -15)
compressed = c.compress(data) + c.flush()

# Hash the decompressed content without decompressing
h = uhc_hash_compressed(compressed, Format.DEFLATE)

# Identical to hashing the raw data (Theorem 12)
assert h == uhc_hash(data)
```

### Cross-format verification

```python
import zlib, gzip, zstandard
from uhc.engine.pipeline import uhc_hash_compressed, uhc_verify, Format

data = b"verify across formats " * 100

c = zlib.compressobj(6, zlib.DEFLATED, -15)
deflate_bytes = c.compress(data) + c.flush()
gz_bytes = gzip.compress(data)
zst_bytes = zstandard.ZstdCompressor().compress(data)

# All three produce the same hash, despite different compression
h_def = uhc_hash_compressed(deflate_bytes, Format.DEFLATE)
h_gz  = uhc_hash_compressed(gz_bytes, Format.GZIP)
h_zst = uhc_hash_compressed(zst_bytes, Format.ZSTD)

assert h_def == h_gz == h_zst

# Or use the verify API directly
assert uhc_verify(deflate_bytes, gz_bytes, fmt_a=Format.DEFLATE, fmt_b=Format.GZIP)
```

### Hash a ZIP archive entry

```python
import io, zipfile
from uhc.core.zip_parser import zip_list_entries, zip_entry_extract_tokens
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod
from uhc.engine.pipeline import uhc_hash

data = b"zip entry content " * 200
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("doc.txt", data)
zip_bytes = buf.getvalue()

entries = zip_list_entries(zip_bytes)
tokens = zip_entry_extract_tokens(zip_bytes, entries[0])
h_zip = compressed_domain_hash(tokens, method=CDHMethod.ROPE)

assert h_zip == uhc_hash(data)  # matches raw hash
```

### Multi-hash for stronger collision resistance

```python
from uhc.engine.pipeline import uhc_hash_multi

# k=2 independent hashes, collision probability (N/p)^2
# With p = 2^61-1: < 2^(-82) for 1 GB files (Corollary 5)
h_k = uhc_hash_multi(b"important data", bases=[131, 257])
```

### Content-defined chunking for deduplication

```python
from uhc.chunking.cdc import cdc_chunk
from uhc.core.polynomial_hash import PolynomialHash

h = PolynomialHash(base=131)
data = open("large_file.bin", "rb").read()

chunks = cdc_chunk(data, min_size=2048, avg_size=8192, max_size=65536)
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
from uhc.core.zip_parser import zip_list_entries, zip_entry_extract_tokens
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod

# Extract LZ77 tokens from any format
tokens = deflate_extract_tokens(deflate_bytes)
tokens = gzip_extract_tokens(gzip_bytes)
tokens = zstd_extract_tokens(zstd_bytes)

entries = zip_list_entries(zip_bytes)
tokens = zip_entry_extract_tokens(zip_bytes, entries[0])

# Compute hash via any of three strategies
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
│   ├── polynomial_hash.py         # Mersenne arithmetic, PolynomialHash, Phi() (Defs 1-3, Thms 1-3)
│   ├── lz77.py                    # Literal/Reference tokens, encode/decode (Defs 4-5)
│   ├── rope.py                    # Hash rope: Leaf, Internal, RepeatNode, BB[2/7] (Defs 6-7, Thms 6-10)
│   ├── compressed_verifier.py     # CDH: prefix_array, rope, sliding_rope (Thms 11-12)
│   ├── multihash.py               # k-tuple multi-hash (Thm 21)
│   ├── deflate.py                 # DEFLATE parser / token extractor (Lemma 9)
│   ├── gzip_parser.py             # Gzip header parser, delegates to DEFLATE (RFC 1952)
│   ├── zip_parser.py              # ZIP archive parser, per-entry DEFLATE extraction
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
| gzip | `1f 8b` | `gzip_parser.py` | 32,768 | 258 | 23 |
| ZIP | `50 4b 03 04` | `zip_parser.py` | 32,768 | 258 | 23 |
| LZ4 block | *(none)* | `lz4_parser.py` | 65,535 | unbounded | varies |
| LZ4 frame | `04 22 4d 18` | `lz4_parser.py` | 65,535 | unbounded | varies |
| Zstandard | `28 b5 2f fd` | `zstd_parser.py` | 2^27 | 131,074 | 44 |

c_F = log2(d_max) + log2(m_max). CDH is faster than decompress-then-hash when the compression ratio exceeds c_F (Theorem 17).

---

## Mathematical Foundation

The complete mathematical framework is in the project knowledge file `compressed_domain_hashing_framework.md`:

- **10 definitions**, **14 lemmas**, **24 theorems**, **5 corollaries**, all with complete proofs
- Zero unresolved assumptions

### Key results

| Result | Statement |
|:-------|:---------|
| **Theorem 1** (Concatenation) | H(A \|\| B) = H(A) * x^{\|B\|} + H(B) |
| **Theorem 2** (Repetition) | H(S^q) = H(S) * Phi(q, x^d) |
| **Theorem 3** (Phi computation) | Phi(q, alpha) computable in O(log q) without modular inverse |
| **Theorem 4** (Overlapping decomposition) | Ref(d, l) with d < l decodes to P^q \|\| P[0..r-1] |
| **Theorem 12** (Main correctness) | CDH(tau) = H(T) for all valid LZ77 encodings tau of T |
| **Theorem 17** (Speedup) | CDH faster than DTH when compression ratio > c_F |
| **Theorem 20** (Collision bound) | Pr[collision] <= (N/p)^k with k independent bases |
| **Corollary 5** (Security) | p = 2^127 - 1, k = 2: collision probability < 2^(-174) for 1 TB |

### Collision resistance

| Configuration | Collision bound (1 TB file) |
|:-------------|:---------------------------|
| p = 2^61 - 1, k = 1 | 2^(-21) |
| p = 2^61 - 1, k = 2 | 2^(-42) |
| p = 2^127 - 1, k = 2 | **2^(-174)** (recommended) |

**Important:** polynomial hashing is not cryptographically secure against adversaries who know the hash bases (Theorem 22c). For adversarial settings, compose with BLAKE3 (Theorem 23). CDH is designed for integrity against accidental corruption, deduplication, and verification protocols where the bases are secret.

---

## Development

```bash
git clone https://github.com/jemsbhai/uhc.git
cd uhc/code
pip install -e ".[dev,formats]"
python -m pytest tests/ -v
```

### Test suite

810 tests covering:

- Algebraic foundations: polynomial hash, geometric accumulator Phi, Mersenne prime arithmetic
- LZ77 encode/decode: overlapping back-references, boundary cases, round-trip correctness
- Hash rope: concat, split, repeat, substr_hash, BB[2/7] balance invariants, RepeatNode splittability
- CDH cross-validation: three-way agreement (prefix_array = rope = sliding_rope) on all inputs
- Format parsers: DEFLATE (RFC 1951), gzip (RFC 1952), ZIP, LZ4 (block + frame), Zstandard (RFC 8878)
- Cross-format matrix: 6 formats x 4 data patterns x 4 sizes, all pairwise combinations verified to produce identical CDH, multi-hash (k=2), three CDH strategies, ZIP entry verification against every format
- CDC chunking: determinism, boundary stability, min/avg/max size constraints
- Pipeline integration: cross-format verification, multi-hash, API surface
- CLI: all 6 commands across multiple formats, text/JSON output, flags
- Randomized property-based tests with seeded RNG for reproducibility

---

## Roadmap

### Done

- [x] Algebraic core (polynomial hash, geometric accumulator)
- [x] Hash rope data structure with RepeatNode (BB[2/7] balanced)
- [x] Compressed-domain hash verifier (three strategies, cross-validated)
- [x] k-tuple multi-hash (Theorem 21)
- [x] DEFLATE token extractor (Lemma 9)
- [x] Gzip header parser (RFC 1952) with DEFLATE delegation
- [x] ZIP archive parser with per-entry token extraction
- [x] LZ4 token extractor, block + frame (Lemma 10)
- [x] Zstandard token extractor (Lemma 11)
- [x] Content-defined chunking (Gear-based FastCDC)
- [x] Unified pipeline API
- [x] CLI with hash, verify, info, benchmark, chunks, inspect
- [x] Cross-format verification matrix (810 tests, 6 formats, full pairwise coverage)
- [x] Experiment infrastructure (timing, memory, sysinfo, plotting)

### Next

- [ ] Performance benchmarks (E1-E7) for ESA 2026 submission
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
