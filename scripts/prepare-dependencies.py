#!/usr/bin/env python3
"""Reconstruct immutable patched dependency sources from pinned crates.io archives."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


SCHEMA_VERSION = 1
RECEIPT_NAME = ".p11scope-prepared.json"
TREE_DOMAIN = b"p11scope-prepared-tree-v2\0"
RECIPE_DOMAIN = b"p11scope-prepared-recipe-v1\0"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_PATCH_BYTES = 16 * 1024 * 1024
NAME_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class PreparationError(Exception):
    """A deterministic refusal caused by invalid or inconsistent inputs."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(value: object, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PreparationError(f"invalid {field}: expected a non-empty POSIX relative path")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PreparationError(f"invalid {field}: path is not UTF-8") from error
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise PreparationError(f"invalid {field}: control character in path")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("/") or any(part in ("", ".", "..") for part in path.parts):
        raise PreparationError(f"invalid {field}: path must remain relative")
    return path


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_manifest(root: Path) -> dict:
    path = root / "third-party" / "sources.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreparationError(f"cannot read source manifest {path}: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise PreparationError("source manifest must use schema_version 1")
    if set(manifest) != {"schema_version", "workspace_manifests", "packages"}:
        raise PreparationError("source manifest has unknown or missing top-level fields")
    workspaces = manifest["workspace_manifests"]
    packages = manifest["packages"]
    if not isinstance(workspaces, list) or not workspaces or not isinstance(packages, list) or not packages:
        raise PreparationError("source manifest requires non-empty workspace_manifests and packages lists")
    for value in workspaces:
        _safe_relative(value, "workspace manifest")
    destinations = set()
    for record in packages:
        _validate_record(record)
        destination = output_name(record)
        if destination in destinations:
            raise PreparationError(f"duplicate package output {destination}")
        destinations.add(destination)
    return manifest


def _validate_record(record: object) -> None:
    fields = {"name", "version", "revision", "archive_sha256", "patches", "expected_tree_sha256", "applies_to"}
    if not isinstance(record, dict) or set(record) != fields:
        raise PreparationError("package record has unknown or missing fields")
    if not isinstance(record["name"], str) or not NAME_RE.fullmatch(record["name"]):
        raise PreparationError("invalid package name")
    if not isinstance(record["version"], str) or not VERSION_RE.fullmatch(record["version"]):
        raise PreparationError("invalid package version")
    if isinstance(record["revision"], bool) or not isinstance(record["revision"], int) or record["revision"] <= 0:
        raise PreparationError("package revision must be a positive integer")
    for field in ("archive_sha256", "expected_tree_sha256"):
        if not isinstance(record[field], str) or not SHA256_RE.fullmatch(record[field]):
            raise PreparationError(f"invalid {field}")
    if not isinstance(record["patches"], list) or not isinstance(record["applies_to"], list) or not record["applies_to"]:
        raise PreparationError("patches must be a list and applies_to a non-empty list")
    seen = set()
    for patch in record["patches"]:
        normalized = str(_safe_relative(patch, "patch path"))
        if normalized in seen:
            raise PreparationError(f"duplicate patch path {normalized}")
        expected_prefix = f"third-party/patches/{record['name']}-{record['version']}/"
        if not normalized.startswith(expected_prefix):
            raise PreparationError(f"patch path is outside {expected_prefix}")
        seen.add(normalized)
    for applies_to in record["applies_to"]:
        _safe_relative(applies_to, "applies_to path")


def output_name(record: dict) -> str:
    return f"{record['name']}-{record['version']}-p{record['revision']}"


def read_patch_bytes(root: Path, record: dict) -> list[tuple[str, bytes]]:
    result = []
    for relative in record["patches"]:
        path = root / relative
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_PATCH_BYTES:
                raise PreparationError(f"patch is not a bounded regular file: {relative}")
            content = path.read_bytes()
        except OSError as error:
            raise PreparationError(f"cannot read patch {relative}: {error}") from error
        result.append((relative, content))
    return result


def compute_recipe_identity(record: dict, patches: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256(RECIPE_DOMAIN)
    encoded = _canonical_json(record)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    for relative, content in patches:
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def compute_tree_digest(root: Path) -> str:
    """Return the prescribed v2 file tree digest, rejecting unsafe tree entries."""
    digest = hashlib.sha256(TREE_DOMAIN)
    files = []
    if not root.is_dir() or root.is_symlink():
        raise PreparationError(f"prepared tree is not a directory: {root}")
    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        if stat.S_IMODE(directory_path.lstat().st_mode) != 0o755:
            raise PreparationError(f"unsafe directory mode in prepared tree: {directory_path.relative_to(root)}")
        for name in directory_names:
            path = directory_path / name
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o755:
                raise PreparationError(f"unsafe directory entry in prepared tree: {path.relative_to(root)}")
        for name in file_names:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative, "tree path")
            metadata = path.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISREG(metadata.st_mode) or mode not in (0o644, 0o755):
                raise PreparationError(f"unsafe file entry in prepared tree: {relative}")
            if relative != RECEIPT_NAME:
                files.append((relative, mode, _sha256_file(path)))
    for relative, mode, content_digest in sorted(files, key=lambda item: item[0].encode("utf-8")):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{mode:04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(content_digest.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def normalize_tree_modes(root: Path) -> None:
    """Normalize Git's umask-dependent files while preserving executable intent."""
    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        if not stat.S_ISDIR(directory_path.lstat().st_mode):
            raise PreparationError(f"unsafe directory entry in prepared tree: {directory_path}")
        os.chmod(directory_path, 0o755)
        for name in directory_names:
            path = directory_path / name
            if not stat.S_ISDIR(path.lstat().st_mode):
                raise PreparationError(f"unsafe directory entry in prepared tree: {path}")
        for name in file_names:
            path = directory_path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise PreparationError(f"unsafe file entry in prepared tree: {path}")
            os.chmod(path, 0o755 if metadata.st_mode & 0o111 else 0o644)


def verify_prepared_tree(path: Path, record: dict, recipe_identity: str) -> None:
    """Verify receipt identity and every source byte/mode for a prepared package."""
    receipt_path = path / RECEIPT_NAME
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreparationError(f"missing or invalid prepared receipt for {output_name(record)}: {error}") from error
    expected_receipt = {
        "schema_version": 1,
        "package": record["name"],
        "version": record["version"],
        "revision": record["revision"],
        "recipe_sha256": recipe_identity,
        "tree_sha256": record["expected_tree_sha256"],
    }
    if receipt != expected_receipt:
        raise PreparationError(f"recipe identity mismatch for existing output {output_name(record)}")
    actual = compute_tree_digest(path)
    if actual != record["expected_tree_sha256"]:
        raise PreparationError(
            f"tree digest mismatch for {output_name(record)}: expected {record['expected_tree_sha256']}, got {actual}"
        )


def _archive_member_path(member_name: str, prefix: str) -> PurePosixPath | None:
    try:
        path = _safe_relative(member_name, "archive member")
    except PreparationError as error:
        raise PreparationError(f"unsafe archive member {member_name!r}: {error}") from error
    if not path.parts or path.parts[0] != prefix:
        raise PreparationError(f"unsafe archive member outside required root {prefix}: {member_name!r}")
    if len(path.parts) == 1:
        return None
    relative = PurePosixPath(*path.parts[1:])
    if ".git" in relative.parts:
        raise PreparationError(f"unsafe archive contains Git metadata: {member_name}")
    if relative.as_posix() == RECEIPT_NAME:
        raise PreparationError("unsafe archive contains reserved receipt")
    return relative


def _reject_git_metadata(root: Path) -> None:
    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        if ".git" in directory_names or ".git" in file_names:
            relative = (Path(directory) / ".git").relative_to(root)
            raise PreparationError(f"patch supplied Git metadata: {relative}")


def _isolated_git_environment(stage: Path) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({
        "GIT_CEILING_DIRECTORIES": str(stage.parent.resolve()),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    })
    return environment


def extract_archive(archive_path: Path, destination: Path, name: str, version: str) -> None:
    """Safely materialize one validated crates.io archive below destination."""
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PreparationError(f"archive exceeds {MAX_ARCHIVE_BYTES} byte limit")
    prefix = f"{name}-{version}"
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            validated = []
            seen = set()
            expanded = 0
            for entry_number, member in enumerate(archive, start=1):
                if entry_number > MAX_ARCHIVE_ENTRIES:
                    raise PreparationError(f"unsafe archive exceeds {MAX_ARCHIVE_ENTRIES} entry limit")
                relative = _archive_member_path(member.name, prefix)
                key = "." if relative is None else relative.as_posix()
                if key in seen:
                    raise PreparationError(f"unsafe archive has duplicate member {key}")
                seen.add(key)
                if member.sparse is not None or not (member.isdir() or member.isreg()):
                    raise PreparationError(f"unsafe archive member type for {member.name}")
                if relative is None and not member.isdir():
                    raise PreparationError(f"unsafe archive package root is not a directory: {member.name}")
                mode = member.mode & 0o7777
                wanted_mode = 0o755 if member.isdir() else mode
                if member.isdir():
                    if mode != 0o755:
                        raise PreparationError(f"unsafe archive directory mode for {member.name}: {mode:04o}")
                elif wanted_mode not in (0o644, 0o755) or member.mode != wanted_mode:
                    raise PreparationError(f"unsafe archive file mode for {member.name}: {member.mode:04o}")
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    raise PreparationError(f"unsafe archive exceeds {MAX_EXPANDED_BYTES} expanded-byte limit")
                validated.append((member, relative, wanted_mode))
            destination.mkdir(mode=0o755, parents=True)
            os.chmod(destination, 0o755)
            for member, relative, mode in validated:
                if relative is None:
                    continue
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    os.chmod(target, 0o755)
                    continue
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                parent = target.parent
                while parent != destination.parent and parent.is_relative_to(destination):
                    os.chmod(parent, 0o755)
                    if parent == destination:
                        break
                    parent = parent.parent
                source = archive.extractfile(member)
                if source is None:
                    raise PreparationError(f"unsafe archive cannot read {member.name}")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                os.chmod(target, mode)
    except (OSError, tarfile.TarError) as error:
        raise PreparationError(f"unsafe archive {archive_path}: {error}") from error


def _obtain_archive(root: Path, archive_dir: Path | None, record: dict, offline: bool, temporary: Path) -> Path:
    filename = f"{record['name']}-{record['version']}.crate"
    candidate = (archive_dir / filename) if archive_dir is not None else (root / "third-party" / "archives" / filename)
    if candidate.is_file():
        try:
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARCHIVE_BYTES:
                raise PreparationError(f"archive is not a bounded regular file: {candidate}")
            archive = temporary / filename
            shutil.copyfile(candidate, archive)
        except OSError as error:
            raise PreparationError(f"cannot copy archive {candidate}: {error}") from error
    elif offline:
        raise PreparationError(f"offline archive is missing: {candidate}")
    else:
        archive = temporary / filename
        url = f"https://static.crates.io/crates/{record['name']}/{filename}"
        try:
            with urllib.request.urlopen(url, timeout=30) as response, archive.open("xb") as output:
                total = 0
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_ARCHIVE_BYTES:
                        raise PreparationError(f"archive download exceeds {MAX_ARCHIVE_BYTES} byte limit")
                    output.write(block)
        except OSError as error:
            raise PreparationError(f"cannot download {url}: {error}") from error
    actual = _sha256_file(archive)
    if actual != record["archive_sha256"]:
        raise PreparationError(
            f"archive digest mismatch for {filename}: expected {record['archive_sha256']}, got {actual}"
        )
    return archive


def _receipt(record: dict, recipe_identity: str) -> dict:
    return {"schema_version": 1, "package": record["name"], "version": record["version"],
            "revision": record["revision"], "recipe_sha256": recipe_identity,
            "tree_sha256": record["expected_tree_sha256"]}


def prepare_package(root: Path, archive_dir: Path | None, record: dict, offline: bool, temporary: Path) -> None:
    patches = read_patch_bytes(root, record)
    recipe_identity = compute_recipe_identity(record, patches)
    output = root / "third-party" / "src" / output_name(record)
    if output.exists() or output.is_symlink():
        verify_prepared_tree(output, record, recipe_identity)
        return
    stage = Path(tempfile.mkdtemp(prefix=".prepare-dependencies-stage-", dir=root / "third-party"))
    try:
        tree = stage / "tree"
        archive = _obtain_archive(root, archive_dir, record, offline, temporary)
        extract_archive(archive, tree, record["name"], record["version"])
        _reject_git_metadata(tree)
        git_environment = _isolated_git_environment(stage)
        initialized = subprocess.run(
            ["git", "init", "--quiet", "--template="], cwd=stage, env=git_environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if initialized.returncode != 0:
            detail = (initialized.stdout + initialized.stderr).decode("utf-8", errors="replace").strip()
            raise PreparationError(f"cannot initialize private patch stage: {detail}")
        discovery = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=stage, env=git_environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        discovered_root = discovery.stdout.decode("utf-8", errors="replace").strip()
        if discovery.returncode != 0 or Path(discovered_root).resolve() != stage.resolve():
            raise PreparationError(f"private patch stage has unexpected Git root: {discovered_root}")
        for relative, content in patches:
            result = subprocess.run(
                ["git", "apply", "--verbose", "--whitespace=nowarn", "--directory=tree", "--"], cwd=stage,
                                    env=git_environment, input=content,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            detail = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
            if result.returncode != 0 or "Skipped patch" in detail:
                raise PreparationError(f"patch failed for {output_name(record)} at {relative}: {detail}")
            _reject_git_metadata(tree)
        if (tree / RECEIPT_NAME).exists() or (tree / RECEIPT_NAME).is_symlink():
            raise PreparationError(f"patch supplied reserved receipt for {output_name(record)}")
        normalize_tree_modes(tree)
        actual = compute_tree_digest(tree)
        if actual != record["expected_tree_sha256"]:
            raise PreparationError(
                f"tree digest mismatch for {output_name(record)}: expected {record['expected_tree_sha256']}, got {actual}"
            )
        receipt = tree / RECEIPT_NAME
        receipt.write_bytes(_canonical_json(_receipt(record, recipe_identity)) + b"\n")
        os.chmod(receipt, 0o644)
        output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(output.parent, 0o755)
        try:
            tree.rename(output)
        except FileExistsError:
            verify_prepared_tree(output, record, recipe_identity)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


@contextlib.contextmanager
def preparation_lock(root: Path):
    path = root / "third-party" / ".prepare-dependencies.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def run(root: Path, *, check: bool, offline: bool, archive_dir: Path | None) -> None:
    manifest = load_manifest(root)
    recipes = [(record, read_patch_bytes(root, record)) for record in manifest["packages"]]
    if check:
        for record, patches in recipes:
            verify_prepared_tree(root / "third-party/src" / output_name(record), record,
                                 compute_recipe_identity(record, patches))
        return
    with preparation_lock(root), tempfile.TemporaryDirectory(prefix="p11scope-dependency-archives-") as temporary:
        for record in manifest["packages"]:
            prepare_package(root, archive_dir, record, offline, Path(temporary))


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify prepared trees without changing them")
    parser.add_argument("--offline", action="store_true", help="forbid archive downloads")
    parser.add_argument("--archive-dir", type=Path, help="directory containing explicitly supplied .crate archives")
    options = parser.parse_args(arguments)
    if options.check and (options.offline or options.archive_dir is not None):
        parser.error("--check cannot be combined with preparation options")
    root = Path(__file__).resolve().parents[1]
    try:
        run(root, check=options.check, offline=options.offline, archive_dir=options.archive_dir)
    except PreparationError as error:
        print(f"prepare-dependencies: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
