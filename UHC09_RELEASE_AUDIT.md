# UHC 09 implementation release-candidate audit

This file defines the implementation-side decision record. It must be updated
with clean-checkout and hosted-CI evidence before any release decision. It does
not authorize a tag, upload, package publication, crate publication, merge, or
general release.

## Candidate identity and provenance

- Integration branch: `integration/uhc09-rc-audit`
- Base: `cc2f791fbada842cd389ec482d4c6c57c7d82abb`
- Logical UHC 01–08 commits already on the branch:
  `c41a4f8`, `1791b62`, `9556b9d`, and `6e58c07`
- Initial mixed-work preservation snapshot:
  `7fc476f146160f2afcd2550aded8f093f878702d`
- Byte-exact preservation branch tip:
  `4589749ad76d071effcb799ef1f6d3ba893afa68`
- Final candidate commit: **record after the UHC 09 audit commit exists**
- Python candidate version: `0.2.0rc1`
- Rust status: `0.1.0`, `publish = false`, outside the release candidate

The ambiguous preservation-snapshot `LICENSE` edit and incomplete
`benches/sort_benchmark.rs` scaffold are deliberately excluded from this
candidate and remain recoverable at the preservation commit. See
`PROJECT_BOUNDARIES.md`; no user work was deleted to create the candidate.

## Only defensible candidate scope

The candidate is Python-only and limited to:

- installation/metadata for one pure-Python wheel and one sdist;
- `uhc_verify_exact`, compatible `uhc_verify`, and `uhc verify` exact
  decoded-byte behavior;
- strict raw, DEFLATE, gzip, optional LZ4, and optional Zstandard decoding;
- supported parser subsets, malformed/trailing/ambiguous-input rejection,
  resource budgets, and documented CLI/API contracts.

Polynomial screening, polynomial chunk hashes, parser-reconstructed benchmark
agreement, compressed-domain performance, security screening, authentication,
sorting, and the Rust crate are excluded. Selecting `uhc hash` or `uhc chunks`
is an explicit research opt-in and both text and JSON output must warn that the
result is non-authoritative.

## Package-content contract

Fresh artifacts must be built into newly created external directories from the
exact clean candidate commit. Reusing any existing `0.1.6` wheel/sdist,
`uhc.egg-info`, `dist/`, or `target/package/` output is forbidden.

Expected Python artifacts:

- `uhc-0.2.0rc1-py3-none-any.whl`
- `uhc-0.2.0rc1.tar.gz`
- metadata name/version/summary/Requires-Python/SPDX license agree;
- `uhc/core/exact.py` and `uhc/core/resources.py` are present;
- wheel and sdist install independently and pass a raw-versus-DEFLATE exact
  verification smoke in isolated mode;
- no Rust, research, cache, or stale build input is present.

The separately inspected `cdh-sort-0.1.0.crate` must retain `publish = false`,
exclude Python/research/benchmark inputs, and contain Cargo VCS metadata for the
exact clean candidate commit. The checker also requires a clean source checkout
and byte-compares every material crate input with that commit because Cargo's
generated VCS metadata alone does not prove that packaging omitted dirty
changes. The crate is audit evidence only and must not be published.

## Evidence to record

| Gate | Commit/environment | Result | Durable output |
| --- | --- | --- | --- |
| Clean checkout/status | pending | pending | pending |
| Full Python tests | pending | pending | pending |
| Ruff/Mypy/coverage | pending | pending | pending |
| Rust tests/fmt/Clippy/docs | pending | pending | pending |
| Python/Rust fuzz-target compilation | pending | pending | pending |
| Wheel/sdist build, content check, install smokes | pending | pending | pending |
| Unpublished crate content/provenance check | pending | pending | pending |
| Fresh provenance-locked E1 | research evidence record | pending | pending |
| Atheris 60-second bounded runtime smoke | pending | pending | pending |
| Rust exact-sort 60-second bounded fuzz smoke | pending | pending | pending |
| Rust rope-builder 60-second bounded fuzz smoke | pending | pending | pending |
| Hosted Linux/Windows/macOS CI matrix | integration branch | pending | workflow URL/run IDs |

For each fuzz row, record seed, `max_len`, RSS cap, requested and observed
duration, final executed-input count, peak RSS, exit status, and crash/timeout
count. Short smokes do not replace long campaigns.

## Decision rule

Current decision: **NO RELEASE / AUDIT INCOMPLETE**.

The decision can become a narrowly scoped Python prerelease candidate only
after every implementation gate above passes from the same clean commit, every
fresh artifact validates and installs, the evidence locks verify, and the
dedicated hosted matrix completes successfully. Any blocker must remain
explicit; a ready-to-push branch is not equivalent to hosted-CI evidence.

UHC 10 may begin only after the completed UHC 09 record reports a clean,
evidence-preserving result and the final recommendation explicitly lifts the
gate. UHC 09 must not implement S2 or resume the paused UHC 01–08 automation.
