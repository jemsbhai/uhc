# Adversarial verification suite

UHC 05 adds deterministic native differentials, Hypothesis/proptest
properties, permanent malformed and audit corpora, and runnable Python/Rust
fuzz targets. These checks increase evidence; they do not make this research
prototype production-safe.

## Install test dependencies

From this directory:

```powershell
python -m pip install -e ".[dev,formats]"
```

`hypothesis` is a required development dependency. `zstandard`, `lz4`, and
`blake3` remain optional format dependencies. Tests that require one of them
use an explicit pytest skip with the installation command in the reason.

## Deterministic regression and property runs

```powershell
python -m pytest tests/test_adversarial_differential.py tests/test_p0_correctness.py
$env:PROPTEST_CASES = "128"
$env:PROPTEST_RNG_SEED = "20260819"
cargo test --offline adversarial_tests -- --nocapture
```

The new Hypothesis properties use `derandomize=True`, disable the example
database, and print a replay blob if they fail. The Rust properties also pin
seed `20260819` in source; the environment variables above document an
equivalent seed for additional proptest runs.

Permanent minimized inputs live in [`tests/corpus`](tests/corpus). The audit
manifest is [`tests/corpus/audit/README.md`](tests/corpus/audit/README.md).
Future minimized failures should be added there rather than relying on an
untracked local property database.

## Rust fuzzing

Install `cargo-fuzz`, then run each checked-in target and corpus:

```powershell
cargo install cargo-fuzz
$UhcFuzzSeed = 20260824
$UhcFuzzSeconds = 60
$UhcFuzzMaxLen = 4096
$UhcFuzzRssMb = 512
$UhcFuzzLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("uhc-fuzz-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $UhcFuzzLogRoot | Out-Null
cargo fuzz run exact_sort fuzz/corpus/exact_sort -- -seed=$UhcFuzzSeed -max_len=$UhcFuzzMaxLen -rss_limit_mb=$UhcFuzzRssMb -max_total_time=$UhcFuzzSeconds -print_final_stats=1 2>&1 | Tee-Object -FilePath (Join-Path $UhcFuzzLogRoot "exact-sort.log")
if ($LASTEXITCODE -ne 0) { throw "exact_sort fuzz smoke failed" }
cargo fuzz run rope_builder fuzz/corpus/rope_builder -- -seed=$UhcFuzzSeed -max_len=$UhcFuzzMaxLen -rss_limit_mb=$UhcFuzzRssMb -max_total_time=$UhcFuzzSeconds -print_final_stats=1 2>&1 | Tee-Object -FilePath (Join-Path $UhcFuzzLogRoot "rope-builder.log")
if ($LASTEXITCODE -ne 0) { throw "rope_builder fuzz smoke failed" }
```

The `exact_sort` target compares CD-Mergesort, CD-Radix, native byte sorting,
CD-LCP, and native LCP. The `rope_builder` target generates valid overlapping
references and compares the bounded rope result with a direct decoder.
Crashes are written under ignored `fuzz/artifacts/`; minimize and promote each
confirmed failure into `tests/corpus/` or a focused Rust regression.

## Python native differential fuzzing

Atheris is intentionally not a package dependency because its platform/toolchain
support differs from the normal UHC test matrix. On a supported environment:

```powershell
python -m pip install atheris
$UhcFuzzSeed = 20260824
$UhcFuzzSeconds = 60
$UhcFuzzMaxLen = 4096
$UhcFuzzRssMb = 512
$UhcFuzzLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("uhc-atheris-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $UhcFuzzLogRoot | Out-Null
python fuzz/python/fuzz_native_differential.py fuzz/corpus/python_native -seed=$UhcFuzzSeed -max_len=$UhcFuzzMaxLen -rss_limit_mb=$UhcFuzzRssMb -max_total_time=$UhcFuzzSeconds -print_final_stats=1 2>&1 | Tee-Object -FilePath (Join-Path $UhcFuzzLogRoot "atheris-native-differential.log")
if ($LASTEXITCODE -ne 0) { throw "Atheris fuzz smoke failed" }
```

The target compares strict raw-DEFLATE, gzip, and optional Zstandard acceptance
and decoded bytes with their native bindings. For ZIP, UHC may reject native
features outside its documented stored/DEFLATE subset, but anything UHC accepts
must also be accepted with identical per-entry bytes by Python's `zipfile`.

The target itself rejects inputs above 4096 bytes, caps stream output and token
counts at 64 KiB, caps each ZIP entry at 32 KiB, caps aggregate ZIP output at
64 KiB, and caps non-directory ZIP entries at 32. Both native and project
decode paths enforce those bounds, so a compressed fuzz input cannot fall back
to the public 1 GiB defaults. The libFuzzer `-rss_limit_mb=512` is an additional
process guard, not the primary decoded-output limit.

## UHC 09 smoke evidence record

For each bounded smoke, preserve the complete `-print_final_stats=1` log and
record the candidate commit, operating system, Python/Rust/fuzzer versions,
corpus path and hash, seed (`20260824`), `max_len` (`4096`), RSS limit (512 MiB),
requested duration (60 seconds), observed wall duration, executed-input count,
peak RSS, exit status, crashes/timeouts, and artifact paths. The three log files
above provide the raw final-statistics evidence; summarize them in
`UHC09_RELEASE_AUDIT.md` rather than replacing them with an untraceable pass
statement.

These are intentionally short runtime smokes. A successful 60-second run only
shows that the harness executed under the stated bounds; it does not replace a
long fuzz campaign, establish absence of defects, or justify production use.
