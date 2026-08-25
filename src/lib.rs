//! cdh-sort: Compressed-Domain Sorting over LZ77 Streams
//!
//! # Experimental safety warning
//!
//! This research crate is not production-qualified. `cd_lcp`, `cd_compare`,
//! CD-Mergesort, and CD-Radix now make exact byte decisions, and the MSD radix
//! paths use explicit work stacks. The `verify` modules remain scaffolds and
//! rope construction now has explicit resource budgets, but end-to-end sorting
//! and verification bounds have not yet been established, so the crate is not an
//! independent release or security gate.
//!
//! Built on the `hashrope` crate (crates.io) which provides:
//! - Mersenne-61 polynomial hashing
//! - BB[2/7] weight-balanced hash rope (Join, Split, Repeat, SubstrHash, Concat)
//! - Sliding window for streaming hash computation
//!
//! This crate adds:
//! - Checked ByteAt: O(log t) byte extraction without hashing, returning
//!   structured errors for invalid public positions
//! - CD-LCP / CD-Compare: compressed-domain string comparison
//! - CD-Radix and CD-LCP-Mergesort sorting algorithms
//! - Planned CD-Hybrid sorting (currently an unimplemented module stub)
//! - Synthetic token generators for experiments
//! - Baseline decompress-then-sort algorithms

pub mod build;
pub mod byte_at;
pub mod sort;
pub mod tokens;
pub mod verify;

#[cfg(test)]
mod adversarial_tests;
