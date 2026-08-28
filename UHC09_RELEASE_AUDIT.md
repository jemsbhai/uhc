# UHC 09 implementation release-candidate audit

This file freezes the implementation-side audit scope and evidence anchors. The
cross-repository `UHC09_RELEASE_DECISION.md` in the research repository records
the final clean-checkout artifact hashes, local gates, hosted-CI run, and the
release/no-release decision against the exact commit containing this record.
Keeping mutable execution results out of this file prevents the audit record
from changing the commit that was tested. This file does not authorize a tag,
upload, package publication, crate publication, merge, or general release.

## Candidate identity and provenance

- Integration branch: `integration/uhc09-rc-audit`
- Base: `cc2f791fbada842cd389ec482d4c6c57c7d82abb`
- Logical UHC 01–08 commits already on the branch:
  `c41a4f8`, `1791b62`, `9556b9d`, and `6e58c07`
- Initial mixed-work preservation snapshot:
  `7fc476f146160f2afcd2550aded8f093f878702d`
- Byte-exact preservation branch tip:
  `4589749ad76d071effcb799ef1f6d3ba893afa68`
- Candidate implementation source anchor:
  `8bbdd6732c2a3187912bff981190caa92712d81a`
- Frozen research/evidence anchor:
  `95e4c9291bb79079f287d22dafe6aefdd649476c`
- Final audited branch tip: the documentation-only commit containing this
  record; its exact ID is pinned in the root decision report
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

## Frozen proportionate follow-up evidence

The root evidence lock versions source, run state, results, provenance, and
decision context together. The following evidence is already immutable at the
research anchor above:

| Evidence | Implementation commit | Result |
| --- | --- | --- |
| Bounded E1 profile | `83ca232` | 273 finite-input rows, zero mismatches, 36.46 seconds |
| Initial Atheris attempt | `83ca232` | exposed and preserved a native-Zstandard oracle defect |
| Second Atheris attempt | `07e2fd9` | exposed and preserved an uncaught reserved-DEFLATE-symbol parser defect |
| Final Atheris smoke | `8bbdd67` | 303,843 executions in 61 campaign seconds; no crash/timeout finding |
| Rust `exact_sort` smoke | `8bbdd67` | 238,327 executions in 61 campaign seconds; no crash/timeout finding |
| Rust `rope_builder` smoke | `8bbdd67` | 53,994 executions in 61 campaign seconds; no crash/timeout finding |

All runtime smokes used seed `20260824`, `max_len=4096`, and a 512 MiB RSS
cap. Their observed wall times and peak RSS, preserved reproducers, exact logs,
and exit statuses are in
`experiments/results/2026-08-28_032000_UHC09_fuzz_smoke` in the research
repository. These short smokes do not replace long campaigns and do not prove
correctness, security, or absence of defects.

The bounded E1 run is not the full/default E1 workload and cannot support a
claim of current full E1 reproducibility. The authoritative 62-row S1 run and
the failed 52-row S1 run remain separately locked as decision evidence and
failed non-decision evidence, respectively. S2 and E2-E16 remain unimplemented.

## Final clean-checkout gates

The root decision report must pin the exact implementation branch tip and
record all of the following without modifying that tip:

- clean checkout and source status;
- full Python tests, Ruff, Mypy, and coverage;
- Rust tests, rustfmt, Clippy, and rustdoc;
- Python harness and Rust fuzz-target compilation;
- fresh wheel/sdist/crate hashes, sizes, member inventories, metadata/content
  checks, and isolated Python artifact install smokes;
- evidence-lock verification;
- the hosted Linux/Windows/macOS workflow URL, run ID, and every job result.

## Decision rule

This record is not itself a release decision. The root decision can recognize
a narrowly scoped Python prerelease candidate only after every implementation
gate above passes from the same clean commit, every fresh artifact validates
and installs, the evidence locks verify, and the dedicated hosted matrix
completes successfully. Any blocker must remain explicit; a ready-to-push
branch is not equivalent to hosted-CI evidence.

UHC 10 may begin only after the completed UHC 09 record reports a clean,
evidence-preserving result and the final recommendation explicitly lifts the
gate. UHC 09 must not implement S2 or resume the paused UHC 01–08 automation.
