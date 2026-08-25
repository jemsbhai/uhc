# CI, packaging, and quality gates

These gates apply to the experimental Python and Rust implementations only.
They prevent accidental package-boundary regressions; they do not authorize a
release or upgrade either project's safety status.

## Continuous-integration matrix

The GitHub Actions workflow in `.github/workflows/ci.yml` runs:

- the full Python suite with native format extras on Linux (Python 3.10 and
  3.13), Windows (3.12), and macOS (3.12);
- a Python 3.10 minimal-dependency job that explicitly exercises exact raw,
  DEFLATE, and gzip verification, API/CLI contracts, parser behavior, and
  resource limits without LZ4, Zstandard, or BLAKE3;
- Ruff, Mypy, and an 84% line-coverage floor for `uhc`. The coverage process
  excludes `test_cross_format.py` because coverage instrumentation multiplies
  its compression workload; every cross-format case still runs uninstrumented
  in each full-suite matrix job;
- wheel/sdist builds in a fresh runner-temporary directory, exact-version and
  metadata/content checks, and isolated install/exact-verification smokes for
  both artifacts;
- the Rust all-target/all-feature suite on Linux, Windows, and macOS;
- Rustfmt, warning-free Clippy, warning-free docs, and an unpublished crate
  check that rejects a stale version, a dirty source checkout, any material
  archive input that differs from the expected commit, or a commit other than
  the checked-out Git SHA;
- compilation of the Python Atheris target and both checked-in Rust fuzz
  targets. Long fuzz campaigns and Atheris runtime smoke remain explicit
  manual jobs documented in `ADVERSARIAL_TESTING.md`.

The root and `fuzz/` Cargo lockfiles are release/CI inputs. Rust commands use
`--locked`, so both lockfiles must remain present in a clean checkout.

No job publishes, uploads, tags, or releases an artifact.

## Clean-checkout prerequisite

Run the release-candidate audit only from a dedicated clean checkout of the
candidate commit. Record the commit before testing and stop if any tracked or
untracked entry is present:

```powershell
$UhcCandidateCommit = (git rev-parse HEAD).Trim()
if (git status --porcelain=v1) {
    throw "release-candidate checkout is not clean"
}
```

Never reuse `dist/`, `target/package/`, or `uhc.egg-info/` from the saved
workspace. Create fresh external destinations for every audit run:

```powershell
$UhcGateRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("uhc-rc-" + [Guid]::NewGuid())
$UhcPythonDist = Join-Path $UhcGateRoot "python-dist"
$UhcCargoTarget = Join-Path $UhcGateRoot "cargo-target"
$UhcFuzzTarget = Join-Path $UhcGateRoot "fuzz-target"
New-Item -ItemType Directory -Path $UhcPythonDist, $UhcCargoTarget, $UhcFuzzTarget | Out-Null
```

## Complete local reproduction

Install the development requirements, then run both the complete suite and the
separate coverage gate:

```powershell
python -m pip install -e ".[dev,formats]"
python -m ruff check uhc tests tools
python -m mypy uhc
python -m pytest
python -m pytest --ignore=tests/test_cross_format.py --cov=uhc --cov-fail-under=84 --cov-report=term-missing:skip-covered
python -m py_compile fuzz/python/fuzz_native_differential.py
```

Run all Rust checks with build products outside the checkout, including both
fuzz binaries:

```powershell
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features --target-dir $UhcCargoTarget -- -D warnings
cargo test --locked --all-targets --all-features --target-dir $UhcCargoTarget
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --locked --no-deps --all-features --target-dir $UhcCargoTarget
Remove-Item Env:RUSTDOCFLAGS
cargo check --locked --manifest-path fuzz/Cargo.toml --bins --target-dir $UhcFuzzTarget
```

The environment-variable removal above only clears the temporary process
setting created by this command block; it does not delete a file or artifact.

## Fresh package builds and install smokes

Build the wheel and sdist into the external directory, require exactly one of
each, and validate version, metadata, core files, and project boundaries:

```powershell
python -m build --outdir $UhcPythonDist
$UhcWheel = @(Get-ChildItem -LiteralPath $UhcPythonDist -Filter "*.whl")
$UhcSdist = @(Get-ChildItem -LiteralPath $UhcPythonDist -Filter "*.tar.gz")
if ($UhcWheel.Count -ne 1 -or $UhcSdist.Count -ne 1) {
    throw "expected exactly one fresh wheel and one fresh sdist"
}
python -m twine check $UhcWheel[0].FullName $UhcSdist[0].FullName
python tools/check_package_contents.py --wheel $UhcWheel[0].FullName --sdist $UhcSdist[0].FullName
```

Install and smoke the wheel and sdist independently. Isolated mode prevents the
checkout from shadowing either installed artifact:

```powershell
$UhcWheelVenv = Join-Path $UhcGateRoot "wheel-venv"
$UhcSdistVenv = Join-Path $UhcGateRoot "sdist-venv"
python -m venv $UhcWheelVenv
python -m venv $UhcSdistVenv
$UhcWheelPython = Join-Path $UhcWheelVenv "Scripts/python.exe"
$UhcSdistPython = Join-Path $UhcSdistVenv "Scripts/python.exe"
& $UhcWheelPython -m pip install --no-deps $UhcWheel[0].FullName
& $UhcSdistPython -m pip install --no-deps $UhcSdist[0].FullName
$UhcSmoke = @'
import importlib.metadata as metadata
import zlib
import uhc
from uhc.engine.pipeline import Format, uhc_verify_exact
assert metadata.version("uhc") == "0.2.0rc1"
assert uhc.__version__ == "0.2.0rc1"
raw = b"clean artifact exact-verification smoke" * 8
encoder = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
encoded = encoder.compress(raw) + encoder.flush()
assert uhc_verify_exact(raw, encoded, fmt_a=Format.RAW, fmt_b=Format.DEFLATE)
'@
& $UhcWheelPython -I -c $UhcSmoke
& $UhcSdistPython -I -c $UhcSmoke
```

Finally package—but do not publish—the Rust crate into its external target and
bind the archive to the exact clean candidate commit:

```powershell
cargo package --locked --target-dir $UhcCargoTarget
$UhcCrate = @(Get-ChildItem -LiteralPath (Join-Path $UhcCargoTarget "package") -Filter "cdh-sort-*.crate")
if ($UhcCrate.Count -ne 1) {
    throw "expected exactly one fresh unpublished crate"
}
python tools/check_package_contents.py --crate $UhcCrate[0].FullName --expected-vcs-commit $UhcCandidateCommit --source-repository .
```

The checker requires Python `0.2.0rc1`, `uhc/core/exact.py`,
`uhc/core/resources.py`, matching wheel/sdist metadata, Rust `0.1.0` with
`publish = false`, and clean Cargo VCS metadata for the expected commit. It
also byte-compares every material crate input with that commit because Cargo's
generated VCS metadata does not itself prove the absence of dirty inputs. It
fails if Python artifacts contain Rust/research inputs, if the Rust crate
contains Python/research inputs, or if any archive contains local caches and
build outputs. `PROJECT_BOUNDARIES.md` remains authoritative for the intended
package split.
