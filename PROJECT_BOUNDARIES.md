# Project and release boundaries

> **Containment status:** No artifact in this workspace is production-safe or
> approved for publication. Pre-existing `dist/` and `uhc.egg-info/` outputs
> are stale and must not be uploaded.

This Git repository currently co-locates two independent implementation
projects because moving the untracked Rust work would risk losing user work:

| Project | Manifest | Intended inputs | Release description |
| --- | --- | --- | --- |
| Python `uhc` | `pyproject.toml` | `uhc/`, Python tests, Python metadata | `README.python.md` |
| Rust `cdh-sort` | `Cargo.toml` | `src/`, Cargo metadata | `README.rust.md` |

The Python `MANIFEST.in` and package-discovery rules exclude Rust, pre-existing
build artifacts/caches, and research paths; standard package metadata is
regenerated inside a source distribution. The Cargo `include` list and explicit
targets exclude Python, local build outputs, and research paths. The shared
`LICENSE` is intentionally present in both source packages.

`benches/sort_benchmark.rs` is an incomplete research scaffold. It remains in
place to preserve user work, while `autobenches = false` and the Cargo package
allowlist keep it out of builds and releases until it becomes a valid target.

The saved workspace root one level above this repository also contains
`experiments/`, `papers/`, `theory/`, and `usecases/`. Those are research
artifacts outside this Git repository; they are not dependencies or release
inputs for either implementation.

A physical split into separately versioned Python, Rust, and research projects
is deferred until the existing modified and untracked work is safely recorded.
No release should infer a guarantee from this temporary directory layout.

The archive validator in `tools/check_package_contents.py` enforces these
boundaries against built wheels, Python source distributions, and Rust crates.
The CI workflow runs it on every proposed change; it never publishes the
resulting artifacts. See `QUALITY_GATES.md` for the exact commands.
