# Project and release boundaries

> **Containment status:** No artifact in this workspace is production-safe or
> approved for publication. Pre-existing `dist/` and `uhc.egg-info/` outputs in
> the original checkout are stale and must not be uploaded.

The implementation is intentionally contained in the nested `code/` Git
repository under the saved workspace root. UHC 09 uses additional Git
worktrees of that same repository; it does not turn the saved workspace root
or its research directories into implementation release inputs. The nested
repository currently co-locates two independently packaged projects because a
physical move would add risk without improving the release audit:

| Project | Manifest | Intended inputs | Release description |
| --- | --- | --- | --- |
| Python `uhc` `0.2.0rc1` | `pyproject.toml` | `uhc/`, Python tests, Python metadata | `README.python.md` |
| Rust `cdh-sort` `0.1.0` (`publish = false`) | `Cargo.toml` | `src/`, Cargo metadata | `README.rust.md` |

The Python `MANIFEST.in` and package-discovery rules exclude Rust, pre-existing
build artifacts/caches, and research paths; standard package metadata is
regenerated inside a source distribution. The Cargo `include` list and explicit
targets exclude Python, local build outputs, and research paths. The shared
`LICENSE` is intentionally present in both source packages.

## Preservation provenance and deliberate exclusions

Preservation commit `7fc476f146160f2afcd2550aded8f093f878702d` is the initial
durable mixed-work snapshot from which the logical UHC 01–08 integration
history was separated. The preservation branch's byte-exact tip is
`4589749ad76d071effcb799ef1f6d3ba893afa68`; it also records the original CRLF
source blobs needed to reproduce the authoritative S1 fingerprints. Two
unattributable user changes are deliberately absent from the
release-candidate branch but remain recoverable at that commit:

- the ambiguous `LICENSE` edit that removed `UHC Contributors` from the 2026
  copyright line; the candidate retains the prior tracked license text;
- `benches/sort_benchmark.rs`, an incomplete benchmark scaffold. It is not a
  declared Cargo target and must not enter a crate, but its source remains
  preserved at the snapshot commit.

Exclusion from the candidate is not deletion and does not assign authorship.

The saved workspace root one level above the implementation repository also
contains `experiments/`, `papers/`, `theory/`, and `usecases/`. Those are a
separate research/evidence boundary outside this Git repository; they are not
dependencies or release inputs for either implementation package.

A physical split into separately versioned Python, Rust, and research projects
is deferred. The preservation commit makes that future operation recoverable;
no release should infer a guarantee from this temporary directory layout.

The archive validator in `tools/check_package_contents.py` enforces these
boundaries against built wheels, Python source distributions, and Rust crates.
The CI workflow runs it on every proposed change, including an exact
clean-commit check for Cargo VCS provenance; it never publishes the resulting
artifacts. See `QUALITY_GATES.md` for the exact commands.
