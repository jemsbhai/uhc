"""Validate that Python and Rust packages respect the repository boundary."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


COMMON_FORBIDDEN_ROOTS = {
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "build",
    "dist",
    "experiments",
    "papers",
    "results",
    "target",
    "theory",
    "usecases",
}
COMMON_FORBIDDEN_PARTS = {".git", "__pycache__"}


def _safe_names(names: list[str]) -> set[str]:
    normalized: set[str] = set()
    for raw_name in names:
        name = raw_name.replace("\\", "/").removeprefix("./").rstrip("/")
        if not name:
            continue
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe archive member: {raw_name!r}")
        normalized.add(path.as_posix())
    return normalized


def _without_archive_root(names: set[str]) -> set[str]:
    roots = {PurePosixPath(name).parts[0] for name in names}
    if len(roots) != 1:
        return names
    return {
        PurePosixPath(*PurePosixPath(name).parts[1:]).as_posix()
        for name in names
        if len(PurePosixPath(name).parts) > 1
    }


def _assert_required(names: set[str], required: set[str], artifact: Path) -> None:
    missing = sorted(required - names)
    if missing:
        raise ValueError(f"{artifact.name} is missing required files: {missing}")


def _assert_clean(names: set[str], artifact: Path) -> None:
    offenders = sorted(
        name
        for name in names
        if (
            PurePosixPath(name).parts[0] in COMMON_FORBIDDEN_ROOTS
            or COMMON_FORBIDDEN_PARTS.intersection(PurePosixPath(name).parts)
        )
    )
    if offenders:
        raise ValueError(f"{artifact.name} contains build/research files: {offenders}")


def _wheel_names(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as archive:
        return _safe_names(archive.namelist())


def _tar_names(path: Path) -> set[str]:
    with tarfile.open(path, "r:*") as archive:
        return _safe_names(archive.getnames())


def check_wheel(path: Path) -> None:
    names = _wheel_names(path)
    _assert_clean(names, path)
    _assert_required(names, {"uhc/__init__.py"}, path)
    if not any(name.endswith(".dist-info/METADATA") for name in names):
        raise ValueError(f"{path.name} has no wheel metadata")
    forbidden_roots = {"benches", "fuzz", "src", "tests"}
    if any(PurePosixPath(name).parts[0] in forbidden_roots for name in names):
        raise ValueError(f"{path.name} contains non-wheel source trees")
    if any(name.endswith(".rs") or name in {"Cargo.toml", "Cargo.lock"} for name in names):
        raise ValueError(f"{path.name} contains Rust release inputs")
    print(f"validated wheel: {path} ({len(names)} members)")


def check_sdist(path: Path) -> None:
    names = _without_archive_root(_tar_names(path))
    _assert_clean(names, path)
    _assert_required(
        names,
        {
            "ADVERSARIAL_TESTING.md",
            "LICENSE",
            "MANIFEST.in",
            "README.python.md",
            "pyproject.toml",
            "tests/corpus/README.md",
            "uhc/__init__.py",
        },
        path,
    )
    forbidden_roots = {"benches", "fuzz", "src"}
    if any(PurePosixPath(name).parts[0] in forbidden_roots for name in names):
        raise ValueError(f"{path.name} contains Rust-only source trees")
    if {"Cargo.toml", "Cargo.lock", "README.rust.md"}.intersection(names):
        raise ValueError(f"{path.name} contains Rust release metadata")
    if any(name.endswith(".rs") for name in names):
        raise ValueError(f"{path.name} contains Rust source")
    print(f"validated sdist: {path} ({len(names)} members)")


def check_crate(path: Path) -> None:
    names = _without_archive_root(_tar_names(path))
    _assert_clean(names, path)
    _assert_required(
        names,
        {"Cargo.lock", "Cargo.toml", "LICENSE", "README.rust.md", "src/lib.rs"},
        path,
    )
    forbidden_roots = {"benches", "fuzz", "tests", "uhc"}
    if any(PurePosixPath(name).parts[0] in forbidden_roots for name in names):
        raise ValueError(f"{path.name} contains non-crate source trees")
    forbidden_files = {
        "ADVERSARIAL_TESTING.md",
        "MANIFEST.in",
        "README.python.md",
        "pyproject.toml",
    }
    if forbidden_files.intersection(names) or any(name.endswith(".py") for name in names):
        raise ValueError(f"{path.name} contains Python release inputs")
    print(f"validated crate: {path} ({len(names)} members)")


def _paths(values: list[str] | None) -> list[Path]:
    return [Path(value).resolve(strict=True) for value in values or []]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", nargs="+")
    parser.add_argument("--sdist", nargs="+")
    parser.add_argument("--crate", nargs="+")
    args = parser.parse_args()

    wheels = _paths(args.wheel)
    sdists = _paths(args.sdist)
    crates = _paths(args.crate)
    if not (wheels or sdists or crates):
        parser.error("provide at least one --wheel, --sdist, or --crate artifact")

    for path in wheels:
        check_wheel(path)
    for path in sdists:
        check_sdist(path)
    for path in crates:
        check_crate(path)


if __name__ == "__main__":
    main()
