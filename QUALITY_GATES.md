# CI, packaging, and quality gates

These gates apply to the experimental Python and Rust implementations only.
They prevent accidental package-boundary regressions; they do not authorize a
release or upgrade the project's pre-alpha safety status.

## Continuous-integration matrix

The GitHub Actions workflow in `.github/workflows/ci.yml` runs:

- the full Python suite with native format extras on Linux (Python 3.10 and
  3.13), Windows (3.12), and macOS (3.12);
- a Python 3.10 minimal-dependency job for the built-in raw DEFLATE/gzip core;
- Ruff, Mypy, and an 84% line-coverage floor for `uhc`. The coverage process
  excludes `test_cross_format.py` because coverage instrumentation multiplies
  its compression workload; every cross-format case still runs uninstrumented
  in each full-suite matrix job;
- wheel/sdist builds, metadata checks, and explicit archive-content checks;
- the Rust all-target/all-feature suite on Linux, Windows, and macOS;
- Rustfmt, warning-free Clippy, warning-free docs, and crate-content checks;
- compilation of both checked-in Rust fuzz targets. Long fuzz campaigns and
  Atheris remain explicit manual jobs documented in `ADVERSARIAL_TESTING.md`.

The root and `fuzz/` Cargo lockfiles are release/CI inputs. Rust commands use
`--locked`, so both lockfiles must remain present in a clean checkout.

No job publishes, uploads, tags, or releases an artifact.

## Local reproduction

From this Git repository:

```powershell
python -m pip install -e ".[dev,formats]"
python -m ruff check uhc tests tools
python -m mypy uhc
python -m pytest --ignore=tests/test_cross_format.py --cov=uhc --cov-report=term-missing:skip-covered

cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --locked --no-deps --all-features
```

Build artifacts into a clean directory and validate their contents before any
release decision:

```powershell
python -m build
python -m twine check dist/*
python tools/check_package_contents.py --wheel (Get-ChildItem dist/*.whl) --sdist (Get-ChildItem dist/*.tar.gz)

cargo package --locked
python tools/check_package_contents.py --crate (Get-ChildItem target/package/cdh-sort-*.crate)
```

The content checker fails if Python artifacts contain Rust/research inputs, if
the Rust crate contains Python/research inputs, or if either archive contains
local caches and build outputs. `PROJECT_BOUNDARIES.md` remains authoritative
for the intended package split.
