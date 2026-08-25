# cdh-sort

> **RELEASE CONTAINMENT — EXPERIMENTAL / NOT PRODUCTION-SAFE.** `cd_lcp`,
> `cd_compare`, CD-Mergesort, and CD-Radix now make ordering decisions from
> exact rope bytes rather than polynomial-hash equality. Both MSD radix paths
> use bounded iterative work stacks. Rope construction now has explicit
> token/output/leaf/depth/arena budgets, but the `verify` modules are scaffolds and the
> implementation is not production-qualified.

Experimental compressed-domain sorting over LZ77 streams.

The crate explores sorting compressed string collections without first
materializing complete decompressed strings. Performance and correctness claims
remain research hypotheses unless a cited check establishes the exact tested
case.

## Status

Pre-alpha — implementing and validating the theoretical framework. Registry
publication is disabled during containment.

### UHC 02 compatibility note

`build::rope_builder::build_rope` now returns `Result<Node, BuildError>`.
Malformed public token streams report structured errors for zero fields,
format-limit violations, and references before the decoded prefix. Callers
must handle or explicitly unwrap this result.

### UHC 03 rope access contract

`byte_at::byte_at` now returns `Result<u8, RopeAccessError>` and reports empty
ropes, invalid node identifiers, and out-of-bounds positions without panicking.
Use `substr_hash_checked` and `split_checked` instead of calling the upstream
arena's unchecked range methods on public input. `validate_hasher` confirms the
arena prime/base contract before combining externally supplied hash metadata.
Nodes must originate from the same arena supplied to these functions; a numeric
node identifier cannot prove arena ownership when two arenas reuse an index.

### UHC 04 construction budgets

`build::rope_builder::build_rope_with_limits` accepts `BuildLimits`. Literal
leaves are capped at 4096 bytes by default, decoded bytes and token counts are
finite, and rope depth plus total arena nodes have explicit ceilings. Before a
reference or literal flush, the builder reserves a conservative node allowance
for persistent split/join paths; it returns `BuildError` before the configured
arena ceiling can be exceeded. `build_rope` remains the compatibility entry
point and applies finite defaults.

## Building

```powershell
cargo build --release
cargo test
```

In a repository checkout, deterministic exact sorting/LCP properties and
`cargo-fuzz` targets are documented in `ADVERSARIAL_TESTING.md`. Fuzz targets
and seed corpora are development inputs only and are excluded from the crate
package by the root manifest's explicit include list.

The Cargo manifest explicitly packages only Rust library sources, this README,
the shared license, and Cargo metadata. It excludes the co-located Python
project and all research artifacts. The incomplete `benches/` scaffold is
preserved locally but is neither a Cargo target nor a crate-package input.
