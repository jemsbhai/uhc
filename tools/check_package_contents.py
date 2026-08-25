"""Validate release-candidate metadata, provenance, and package boundaries."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tarfile
import zipfile
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath


PYTHON_NAME = "uhc"
PYTHON_VERSION = "0.2.0rc1"
PYTHON_REQUIRES = ">=3.10"
PYTHON_SUMMARY = (
    "Exact cross-format byte verification with experimental compression parsers"
)
PYTHON_ARCHIVE_ROOT = f"{PYTHON_NAME}-{PYTHON_VERSION}"
PYTHON_DIST_INFO = f"{PYTHON_NAME}-{PYTHON_VERSION}.dist-info"

CRATE_NAME = "cdh-sort"
CRATE_VERSION = "0.1.0"
CRATE_ARCHIVE_ROOT = f"{CRATE_NAME}-{CRATE_VERSION}"

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
        normalized_name = path.as_posix()
        if normalized_name in normalized:
            raise ValueError(f"duplicate archive member: {normalized_name!r}")
        normalized.add(normalized_name)
    return normalized


def _without_archive_root(names: set[str]) -> set[str]:
    return {
        PurePosixPath(*PurePosixPath(name).parts[1:]).as_posix()
        for name in names
        if len(PurePosixPath(name).parts) > 1
    }


def _assert_archive_root(
    names: set[str], expected_root: str, artifact: Path
) -> None:
    roots = {PurePosixPath(name).parts[0] for name in names}
    if roots != {expected_root}:
        raise ValueError(
            f"{artifact.name} has archive roots {sorted(roots)!r}; "
            f"expected only {expected_root!r}"
        )


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
        members = archive.getmembers()
        unsupported = [
            member.name
            for member in members
            if not (member.isfile() or member.isdir())
        ]
        if unsupported:
            raise ValueError(
                f"{path.name} contains links or special members: {unsupported}"
            )
        return _safe_names([member.name for member in members])


def _wheel_bytes(path: Path, name: str) -> bytes:
    with zipfile.ZipFile(path) as archive:
        try:
            return archive.read(name)
        except KeyError as exc:
            raise ValueError(f"{path.name} is missing required file: {name}") from exc


def _tar_bytes(path: Path, root: str, name: str) -> bytes:
    member_name = f"{root}/{name}"
    with tarfile.open(path, "r:*") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise ValueError(
                f"{path.name} is missing required file: {name}"
            ) from exc
        extracted = archive.extractfile(member)
        if extracted is None:
            raise ValueError(f"{path.name} member is not a regular file: {name}")
        return extracted.read()


def _assert_python_metadata(payload: bytes, artifact: Path) -> None:
    metadata = BytesParser(policy=compat32).parsebytes(payload)
    expected = {
        "Name": PYTHON_NAME,
        "Version": PYTHON_VERSION,
        "Summary": PYTHON_SUMMARY,
        "Requires-Python": PYTHON_REQUIRES,
        "License-Expression": "MIT",
    }
    mismatches = {
        field: (metadata.get(field), value)
        for field, value in expected.items()
        if metadata.get(field) != value
    }
    if mismatches:
        raise ValueError(
            f"{artifact.name} has unexpected Python metadata: {mismatches}"
        )
    if "LICENSE" not in (metadata.get_all("License-File") or []):
        raise ValueError(f"{artifact.name} metadata does not record LICENSE")


def _assert_module_version(payload: bytes, artifact: Path) -> None:
    source = payload.decode("utf-8")
    match = re.search(
        r"^__version__\s*=\s*['\"]([^'\"]+)['\"]\s*$", source, re.MULTILINE
    )
    if match is None or match.group(1) != PYTHON_VERSION:
        actual = match.group(1) if match else None
        raise ValueError(
            f"{artifact.name} has uhc.__version__={actual!r}; "
            f"expected {PYTHON_VERSION!r}"
        )


def _toml_section(payload: bytes, section: str, artifact: Path) -> str:
    text = payload.decode("utf-8")
    match = re.search(
        rf"(?ms)^\[{re.escape(section)}\]\s*$\n(.*?)(?=^\[|\Z)", text
    )
    if match is None:
        raise ValueError(f"{artifact.name} metadata has no [{section}] section")
    return match.group(1)


def _assert_toml_literal(
    payload: bytes,
    section: str,
    field: str,
    expected_literal: str,
    artifact: Path,
) -> None:
    section_text = _toml_section(payload, section, artifact)
    match = re.search(
        rf"(?m)^\s*{re.escape(field)}\s*=\s*([^#\r\n]+?)\s*$", section_text
    )
    actual = match.group(1).strip() if match else None
    if actual != expected_literal:
        raise ValueError(
            f"{artifact.name} [{section}] {field}={actual!r}; "
            f"expected {expected_literal!r}"
        )


def _git_output(repository: Path, *args: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"").decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"cannot verify Git provenance in {repository}: {detail or exc}"
        ) from exc
    return completed.stdout


def _canonical_text(payload: bytes) -> bytes:
    """Normalize checkout line endings without hiding material source edits."""
    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _assert_crate_matches_commit(
    path: Path,
    names: set[str],
    repository: Path,
    expected_vcs_commit: str,
    path_in_vcs: str,
) -> None:
    head = _git_output(repository, "rev-parse", "HEAD").decode("ascii").strip()
    if head.lower() != expected_vcs_commit.lower():
        raise ValueError(
            f"crate source checkout is at {head!r}; "
            f"expected {expected_vcs_commit!r}"
        )
    status = _git_output(
        repository, "status", "--porcelain=v1", "--untracked-files=all"
    )
    if status:
        preview = status.decode("utf-8", errors="replace").splitlines()[:20]
        raise ValueError(
            f"crate source checkout is dirty; refusing provenance claim: {preview}"
        )

    source_map = {
        "Cargo.toml.orig": "Cargo.toml",
        "Cargo.lock": "Cargo.lock",
        "LICENSE": "LICENSE",
        "README.rust.md": "README.rust.md",
    }
    source_map.update(
        (name, name)
        for name in names
        if name.startswith("src/") and name.endswith(".rs")
    )
    prefix = path_in_vcs.strip("/")
    for archive_name, repository_name in source_map.items():
        git_path = f"{prefix}/{repository_name}" if prefix else repository_name
        committed = _git_output(
            repository, "show", f"{expected_vcs_commit}:{git_path}"
        )
        packaged = _tar_bytes(path, CRATE_ARCHIVE_ROOT, archive_name)
        if _canonical_text(packaged) != _canonical_text(committed):
            raise ValueError(
                f"{path.name} member {archive_name!r} does not match "
                f"clean commit {expected_vcs_commit}:{git_path}"
            )


def check_wheel(path: Path) -> None:
    expected_filename = f"{PYTHON_ARCHIVE_ROOT}-py3-none-any.whl"
    if path.name != expected_filename:
        raise ValueError(
            f"stale or unexpected wheel name {path.name!r}; "
            f"expected {expected_filename!r}"
        )

    names = _wheel_names(path)
    _assert_clean(names, path)
    _assert_required(
        names,
        {
            "uhc/__init__.py",
            "uhc/core/exact.py",
            "uhc/core/resources.py",
            f"{PYTHON_DIST_INFO}/METADATA",
            f"{PYTHON_DIST_INFO}/RECORD",
            f"{PYTHON_DIST_INFO}/WHEEL",
            f"{PYTHON_DIST_INFO}/entry_points.txt",
            f"{PYTHON_DIST_INFO}/licenses/LICENSE",
        },
        path,
    )
    dist_info_roots = {
        PurePosixPath(name).parts[0]
        for name in names
        if PurePosixPath(name).parts[0].endswith(".dist-info")
    }
    if dist_info_roots != {PYTHON_DIST_INFO}:
        raise ValueError(
            f"{path.name} has unexpected dist-info roots: {sorted(dist_info_roots)}"
        )
    _assert_python_metadata(
        _wheel_bytes(path, f"{PYTHON_DIST_INFO}/METADATA"), path
    )
    _assert_module_version(_wheel_bytes(path, "uhc/__init__.py"), path)

    wheel_metadata = BytesParser(policy=compat32).parsebytes(
        _wheel_bytes(path, f"{PYTHON_DIST_INFO}/WHEEL")
    )
    if wheel_metadata.get("Root-Is-Purelib") != "true":
        raise ValueError(f"{path.name} is not marked as a pure-Python wheel")
    if "py3-none-any" not in (wheel_metadata.get_all("Tag") or []):
        raise ValueError(f"{path.name} lacks the expected py3-none-any wheel tag")

    forbidden_roots = {"benches", "fuzz", "src", "tests"}
    if any(PurePosixPath(name).parts[0] in forbidden_roots for name in names):
        raise ValueError(f"{path.name} contains non-wheel source trees")
    if any(name.endswith(".rs") or name in {"Cargo.toml", "Cargo.lock"} for name in names):
        raise ValueError(f"{path.name} contains Rust release inputs")
    print(f"validated wheel: {path} ({len(names)} members)")


def check_sdist(path: Path) -> None:
    expected_filename = f"{PYTHON_ARCHIVE_ROOT}.tar.gz"
    if path.name != expected_filename:
        raise ValueError(
            f"stale or unexpected sdist name {path.name!r}; "
            f"expected {expected_filename!r}"
        )

    rooted_names = _tar_names(path)
    _assert_archive_root(rooted_names, PYTHON_ARCHIVE_ROOT, path)
    names = _without_archive_root(rooted_names)
    _assert_clean(names, path)
    _assert_required(
        names,
        {
            "ADVERSARIAL_TESTING.md",
            "LICENSE",
            "MANIFEST.in",
            "PKG-INFO",
            "README.python.md",
            "pyproject.toml",
            "tests/corpus/README.md",
            "uhc/__init__.py",
            "uhc.egg-info/PKG-INFO",
            "uhc.egg-info/SOURCES.txt",
            "uhc/core/exact.py",
            "uhc/core/resources.py",
        },
        path,
    )
    _assert_python_metadata(
        _tar_bytes(path, PYTHON_ARCHIVE_ROOT, "PKG-INFO"), path
    )
    _assert_python_metadata(
        _tar_bytes(path, PYTHON_ARCHIVE_ROOT, "uhc.egg-info/PKG-INFO"), path
    )
    _assert_module_version(
        _tar_bytes(path, PYTHON_ARCHIVE_ROOT, "uhc/__init__.py"), path
    )
    _assert_toml_literal(
        _tar_bytes(path, PYTHON_ARCHIVE_ROOT, "pyproject.toml"),
        "project",
        "version",
        f'"{PYTHON_VERSION}"',
        path,
    )
    egg_info_roots = {
        PurePosixPath(name).parts[0]
        for name in names
        if PurePosixPath(name).parts[0].endswith(".egg-info")
    }
    if egg_info_roots != {"uhc.egg-info"}:
        raise ValueError(
            f"{path.name} has stale or unexpected egg-info roots: "
            f"{sorted(egg_info_roots)}"
        )

    forbidden_roots = {"benches", "fuzz", "src"}
    if any(PurePosixPath(name).parts[0] in forbidden_roots for name in names):
        raise ValueError(f"{path.name} contains Rust-only source trees")
    if {"Cargo.toml", "Cargo.lock", "README.rust.md"}.intersection(names):
        raise ValueError(f"{path.name} contains Rust release metadata")
    if "tests/test_fuzz_target_limits.py" in names:
        raise ValueError(f"{path.name} contains a test for the excluded fuzz harness")
    if any(name.endswith(".rs") for name in names):
        raise ValueError(f"{path.name} contains Rust source")
    print(f"validated sdist: {path} ({len(names)} members)")


def check_crate(
    path: Path, expected_vcs_commit: str, source_repository: Path
) -> None:
    expected_filename = f"{CRATE_ARCHIVE_ROOT}.crate"
    if path.name != expected_filename:
        raise ValueError(
            f"stale or unexpected crate name {path.name!r}; "
            f"expected {expected_filename!r}"
        )

    rooted_names = _tar_names(path)
    _assert_archive_root(rooted_names, CRATE_ARCHIVE_ROOT, path)
    names = _without_archive_root(rooted_names)
    _assert_clean(names, path)
    _assert_required(
        names,
        {
            ".cargo_vcs_info.json",
            "Cargo.lock",
            "Cargo.toml",
            "Cargo.toml.orig",
            "LICENSE",
            "README.rust.md",
            "src/lib.rs",
        },
        path,
    )

    original_manifest = _tar_bytes(path, CRATE_ARCHIVE_ROOT, "Cargo.toml.orig")
    for field, value in (
        ("name", f'"{CRATE_NAME}"'),
        ("version", f'"{CRATE_VERSION}"'),
        ("publish", "false"),
    ):
        _assert_toml_literal(original_manifest, "package", field, value, path)

    vcs_payload = _tar_bytes(
        path, CRATE_ARCHIVE_ROOT, ".cargo_vcs_info.json"
    )
    try:
        vcs_info = json.loads(vcs_payload)
        git_info = vcs_info["git"]
        packaged_commit = git_info["sha1"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"{path.name} has invalid Cargo VCS provenance") from exc
    if not isinstance(packaged_commit, str) or re.fullmatch(
        r"[0-9a-fA-F]{40}", packaged_commit
    ) is None:
        raise ValueError(f"{path.name} has an invalid Cargo VCS commit")
    if git_info.get("dirty", False) is not False or vcs_info.get("dirty", False) is not False:
        raise ValueError(f"{path.name} was packaged from a dirty working tree")
    if packaged_commit.lower() != expected_vcs_commit.lower():
        raise ValueError(
            f"{path.name} was packaged from {packaged_commit!r}; "
            f"expected clean commit {expected_vcs_commit!r}"
        )
    path_in_vcs = vcs_info.get("path_in_vcs", "")
    if not isinstance(path_in_vcs, str):
        raise ValueError(f"{path.name} has invalid Cargo path_in_vcs provenance")
    _assert_crate_matches_commit(
        path,
        names,
        source_repository,
        expected_vcs_commit,
        path_in_vcs,
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
    print(
        f"validated unpublished crate: {path} ({len(names)} members, "
        f"clean commit {packaged_commit})"
    )


def _paths(values: list[str] | None) -> list[Path]:
    return [Path(value).resolve(strict=True) for value in values or []]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", nargs="+")
    parser.add_argument("--sdist", nargs="+")
    parser.add_argument("--crate", nargs="+")
    parser.add_argument(
        "--expected-vcs-commit",
        help="full clean Git commit expected in Cargo's .cargo_vcs_info.json",
    )
    parser.add_argument(
        "--source-repository",
        help="clean Git checkout whose committed crate inputs must match the archive",
    )
    args = parser.parse_args()

    wheels = _paths(args.wheel)
    sdists = _paths(args.sdist)
    crates = _paths(args.crate)
    if not (wheels or sdists or crates):
        parser.error("provide at least one --wheel, --sdist, or --crate artifact")
    if crates:
        if not args.expected_vcs_commit:
            parser.error("--expected-vcs-commit is required with --crate")
        if re.fullmatch(r"[0-9a-fA-F]{40}", args.expected_vcs_commit) is None:
            parser.error("--expected-vcs-commit must be a full 40-hex Git commit")
        if not args.source_repository:
            parser.error("--source-repository is required with --crate")

    for path in wheels:
        check_wheel(path)
    for path in sdists:
        check_sdist(path)
    for path in crates:
        check_crate(
            path,
            args.expected_vcs_commit,
            Path(args.source_repository).resolve(strict=True),
        )


if __name__ == "__main__":
    main()
