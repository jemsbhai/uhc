# cdh-sort

> **RELEASE CONTAINMENT — EXPERIMENTAL / NOT PRODUCTION-SAFE.** This repository
> temporarily co-locates a Python package and a Rust research crate. Python
> polynomial-hash APIs remain probabilistic screening, not authentication;
> `uhc_verify` now uses strict native decoding and exact byte comparison. Rust
> LCP/comparison and radix sorting now make exact byte decisions and avoid
> recursive shared-prefix paths. The Rust verification modules remain
> scaffolds, resource bounds are not yet established, and neither package is
> production-qualified.

Experimental compressed-domain sorting research over LZ77 streams. Any
performance or correctness statement applies only to its stated model and
tested cases; it is not a release guarantee.

Public interface contracts, including exact verification, CLI exit codes, ZIP
rejection, CDH method selection, and checked rope access, are documented in
[README.python.md](README.python.md) and [README.rust.md](README.rust.md).

## Status

Pre-alpha — implementing the theoretical framework.

The Python distribution uses [README.python.md](README.python.md); the Rust
crate uses [README.rust.md](README.rust.md). See
[PROJECT_BOUNDARIES.md](PROJECT_BOUNDARIES.md) before building or packaging.
Adversarial test and fuzz reproduction commands are in
[ADVERSARIAL_TESTING.md](ADVERSARIAL_TESTING.md).
Cross-platform CI, package-content checks, and local quality commands are in
[QUALITY_GATES.md](QUALITY_GATES.md).

## Building

```powershell
cargo build --release
cargo test
```

## Architecture

See the companion theory documents for the full mathematical framework.
