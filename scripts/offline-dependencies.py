#!/usr/bin/env python3
"""Assemble and verify the finite offline dependency payload."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from urllib.parse import parse_qs, urlsplit, urlunsplit


SCHEMA_VERSION = 1
TREE_DOMAIN = b"p11scope-offline-dependency-tree-v1\0"
NIGHTLY_TOOLCHAIN = "nightly-2026-05-20"
CARGO_CHECKSUM_COMMENT = (
    "This file only protects against accidental modifications. It is not a security mechanism "
    "and does not protect against malicious changes."
)
RECIPE_RELATIVE = Path("third-party/offline-dependencies.json")
METADATA_ARGUMENTS = ("metadata", "--locked", "--offline", "--all-features",
                      "--format-version", "1", "--manifest-path")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
PAYLOAD_TOP = {"vendor", "archives", "provenance"}
SHARED_FILES = {"source.bundle", "LICENSE-MIT", "LICENSE-APACHE", "packages.json"}
NIGHTLY_FILES = {"sysroot-Cargo.toml", "Cargo.lock"}
SOURCE_EXPORT_V1_FIELDS = {"schema_version", "revision", "source_entries", "archives"}
SOURCE_EXPORT_V2_FIELDS = SOURCE_EXPORT_V1_FIELDS | {"offline_dependencies"}
OFFLINE_ASSOCIATION_FIELDS = {
    "payload_path", "recipe_path", "recipe_sha256", "payload_tree_sha256",
    "config_path", "config_sha256",
}


class OfflineDependencyError(Exception):
    """A deterministic refusal caused by invalid or inconsistent inputs."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise OfflineDependencyError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise OfflineDependencyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except OfflineDependencyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OfflineDependencyError(f"cannot read valid {label} {path}: {error}") from error


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise OfflineDependencyError(f"cannot load required helper {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError) as error:
        raise OfflineDependencyError(f"cannot load required helper {path}: {error}") from error
    finally:
        sys.dont_write_bytecode = previous
    return module


def _safe_relative(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise OfflineDependencyError(f"invalid {label}: expected POSIX relative path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise OfflineDependencyError(f"invalid {label}: control character in path")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in ("", ".", "..") for part in path.parts)):
        raise OfflineDependencyError(f"invalid {label}: path must remain relative")
    return path


def _regular(path: Path, label: str, *, executable: bool | None = None) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise OfflineDependencyError(f"missing {label}: {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise OfflineDependencyError(f"{label} is not a regular file: {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if executable is True and not mode & 0o111:
        raise OfflineDependencyError(f"{label} is not executable: {path}")
    return metadata


def _tool_identity(path: Path, label: str) -> dict:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise OfflineDependencyError(f"{label} path must be normalized and absolute")
    _regular(path, label, executable=True)
    if path.resolve() != path:
        raise OfflineDependencyError(f"{label} path must not contain symbolic links: {path}")
    metadata = path.stat()
    return {"path": str(path), "mode": stat.S_IMODE(metadata.st_mode),
            "size": metadata.st_size, "sha256": _sha256_file(path)}


def _external_target(root: Path, path: Path, label: str) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise OfflineDependencyError(f"{label} must be a normalized absolute path")
    try:
        path.relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise OfflineDependencyError(f"{label} must remain outside maintained source")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise OfflineDependencyError(f"{label} parent is unavailable: {error}") from error
    if parent != path.parent:
        raise OfflineDependencyError(f"{label} parent path contains a symbolic link")


def _absolute_directory(path: Path, label: str) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise OfflineDependencyError(f"{label} must be a normalized absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise OfflineDependencyError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or path.resolve() != path:
        raise OfflineDependencyError(f"{label} must be a real directory without symbolic links")


def _existing_lock_identity(metadata: os.stat_result, label: str) -> tuple[int, int]:
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid() or metadata.st_size != 0):
        raise OfflineDependencyError(f"{label} has unsafe type, mode, ownership, or content")
    return metadata.st_dev, metadata.st_ino


@contextlib.contextmanager
def _existing_preparation_lock(root: Path):
    """Lock the stable preparer lock without creating or following it."""
    path = root / "third-party/.prepare-dependencies.lock"
    descriptor = None
    try:
        named_before = path.lstat()
        identity = _existing_lock_identity(named_before, "prepared dependency lock")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        if _existing_lock_identity(os.fstat(descriptor), "opened prepared dependency lock") != identity:
            raise OfflineDependencyError("prepared dependency lock changed before open")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        named_locked = path.lstat()
        if _existing_lock_identity(named_locked, "locked prepared dependency lock") != identity:
            raise OfflineDependencyError("prepared dependency lock changed while locking")
        try:
            yield
        finally:
            named_after = path.lstat()
            if (_existing_lock_identity(os.fstat(descriptor), "opened prepared dependency lock") != identity
                    or _existing_lock_identity(named_after, "prepared dependency lock") != identity):
                raise OfflineDependencyError("prepared dependency lock changed during verification")
    except FileNotFoundError as error:
        raise OfflineDependencyError("prepared dependency lock is missing") from error
    except OSError as error:
        raise OfflineDependencyError(f"cannot inspect existing prepared dependency lock: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _entry_inventory(root: Path, *, payload_modes: bool) -> list[tuple[str, str, int, str]]:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise OfflineDependencyError(f"tree root is unavailable {root}: {error}") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise OfflineDependencyError(f"tree root is not a directory: {root}")
    root_mode = stat.S_IMODE(root_metadata.st_mode)
    allowed_root_modes = {0o755} if payload_modes else {0o755, 0o775}
    if root_mode not in allowed_root_modes:
        raise OfflineDependencyError(f"unsafe delivery mode for tree root: {root_mode:04o}")
    inventory = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        except OSError as error:
            raise OfflineDependencyError(f"cannot read tree directory {directory}: {error}") from error
        children = []
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative, "tree entry")
            try:
                metadata = path.lstat()
            except OSError as error:
                raise OfflineDependencyError(f"cannot inspect tree entry {relative}: {error}") from error
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode):
                raise OfflineDependencyError(f"unsafe symbolic link in tree: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                allowed = {0o755} if payload_modes else {0o755, 0o775}
                if mode not in allowed:
                    raise OfflineDependencyError(f"unsafe delivery mode for directory {relative}: {mode:04o}")
                inventory.append((relative, "directory", mode & 0o111, ""))
                children.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                if mode not in (0o644, 0o755):
                    raise OfflineDependencyError(f"unsafe delivery mode for file {relative}: {mode:04o}")
                inventory.append((relative, "file", mode & 0o111, _sha256_file(path)))
            else:
                raise OfflineDependencyError(f"unsafe tree entry type: {relative}")
        pending.extend(reversed(children))
    return sorted(inventory, key=lambda item: item[0].encode("utf-8"))


def tree_content_digest(root: Path, *, installed_rust_src: bool = False) -> str:
    """Hash all paths, types, executable bits and regular-file content."""
    digest = hashlib.sha256(TREE_DOMAIN)
    for relative, kind, executable_bits, content_digest in _entry_inventory(
            root, payload_modes=not installed_rust_src):
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(b"D" if kind == "directory" else b"F")
        digest.update(executable_bits.to_bytes(2, "big"))
        digest.update(bytes.fromhex(content_digest) if content_digest else b"")
    return digest.hexdigest()


def payload_inventory(root: Path) -> list[tuple[str, str, int, str]]:
    """Return the canonical, safety-checked payload inventory."""
    return _entry_inventory(root, payload_modes=True)


def _strict_manifest(root: Path, preparer) -> dict:
    path = root / "third-party/sources.json"
    strict = _read_json(path, "sources manifest")
    try:
        parsed = preparer.load_manifest(root)
    except preparer.PreparationError as error:
        raise OfflineDependencyError(f"sources manifest: {error}") from error
    if strict != parsed:
        raise OfflineDependencyError("sources manifest parsing disagreement")
    return parsed


def _package_recipes(root: Path, manifest: dict, preparer) -> dict:
    result = {}
    for record in manifest["packages"]:
        try:
            patches = preparer.read_patch_bytes(root, record)
            identity = preparer.compute_recipe_identity(record, patches)
        except preparer.PreparationError as error:
            raise OfflineDependencyError(f"package recipe {preparer.output_name(record)}: {error}") from error
        result[preparer.output_name(record)] = identity
    return dict(sorted(result.items()))


def _read_lock(path: Path, label: str) -> list[dict]:
    _regular(path, label)
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise OfflineDependencyError(f"cannot parse {label} {path}: {error}") from error
    packages = value.get("package")
    if not isinstance(packages, list):
        raise OfflineDependencyError(f"{label} has no package array")
    return packages


def _git_identity(source: str) -> dict:
    if not source.startswith("git+"):
        raise OfflineDependencyError(f"unsupported Git source identity: {source}")
    split = urlsplit(source[4:])
    query = parse_qs(split.query, strict_parsing=True)
    revision = split.fragment
    if set(query) != {"rev"} or query["rev"] != [revision] or not REVISION_RE.fullmatch(revision):
        raise OfflineDependencyError(f"unsupported Git source identity: {source}")
    url = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
    if not url:
        raise OfflineDependencyError(f"unsupported Git source identity: {source}")
    return {"url": url, "revision": revision}


def _locked_dependencies(lock_paths: list[Path]) -> tuple[dict, dict[str, dict]]:
    shared = None
    vendored = {}
    for lock in lock_paths:
        for package in _read_lock(lock, f"dependency lock {lock}"):
            name, version, source = package.get("name"), package.get("version"), package.get("source")
            if source is None:
                continue
            if not isinstance(name, str) or not isinstance(version, str) or not isinstance(source, str):
                raise OfflineDependencyError(f"malformed external package in {lock}")
            directory = f"{name}-{version}"
            if source.startswith("registry+"):
                checksum = package.get("checksum")
                if not isinstance(checksum, str) or not SHA256_RE.fullmatch(checksum):
                    raise OfflineDependencyError(f"registry package lacks checksum: {directory}")
                expected = {"name": name, "version": version, "kind": "registry", "checksum": checksum}
            elif source.startswith("git+"):
                identity = _git_identity(source)
                if shared is None:
                    shared = identity
                elif shared != identity:
                    raise OfflineDependencyError("dependency locks contain more than one shared Git identity")
                expected = {"name": name, "version": version, "kind": "git", "checksum": None}
            else:
                raise OfflineDependencyError(f"unsupported dependency source for {directory}: {source}")
            prior = vendored.setdefault(directory, expected)
            if prior != expected:
                raise OfflineDependencyError(f"conflicting vendored package identity: {directory}")
    if shared is None:
        raise OfflineDependencyError("dependency locks contain no shared Git revision")
    return shared, dict(sorted(vendored.items()))


def _isolated_git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    return environment


def _bundle_revision(path: Path) -> str:
    _regular(path, "shared Git bundle", executable=False)
    value = path.read_bytes()
    separator = value.find(b"\n\n")
    if separator < 0 or value[:separator].splitlines()[:1] not in ([b"# v2 git bundle"], [b"# v3 git bundle"]):
        raise OfflineDependencyError("shared Git bundle has an invalid header")
    pack = value[separator + 2:]
    if len(pack) < 32 or not pack.startswith(b"PACK") or hashlib.sha1(pack[:-20]).digest() != pack[-20:]:
        raise OfflineDependencyError("shared Git bundle pack checksum is invalid")
    environment = _isolated_git_environment()
    try:
        result = subprocess.run(["git", "bundle", "list-heads", str(path)],
                                env=environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
    except OSError as error:
        raise OfflineDependencyError(f"shared Git bundle identity check could not execute: {error}") from error
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
        raise OfflineDependencyError(f"shared Git bundle identity check failed: {detail}")
    heads = []
    for line in result.stdout.decode("utf-8", errors="strict").splitlines():
        fields = line.split(" ", 1)
        if len(fields) == 2 and REVISION_RE.fullmatch(fields[0]):
            heads.append(fields[0])
    if len(set(heads)) != 1:
        raise OfflineDependencyError("shared Git bundle must advertise exactly one revision")
    revision = heads[0]

    with tempfile.TemporaryDirectory(prefix="p11scope-bundle-verify-") as temporary:
        repository = Path(temporary) / "repository"
        (repository / "objects").mkdir(parents=True)
        (repository / "refs").mkdir()
        (repository / "HEAD").write_text("ref: refs/heads/unused\n", encoding="ascii")
        try:
            unpacked = subprocess.run(
                ["git", f"--git-dir={repository}", "bundle", "unbundle", str(path)],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            if unpacked.returncode != 0:
                detail = (unpacked.stdout + unpacked.stderr).decode(
                    "utf-8", errors="replace"
                ).strip()
                raise OfflineDependencyError(
                    f"shared Git bundle is incomplete or invalid: {detail}"
                )
            commit = subprocess.run(
                ["git", f"--git-dir={repository}", "cat-file", "-e", f"{revision}^{{commit}}"],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            connected = subprocess.run(
                ["git", f"--git-dir={repository}", "fsck", "--strict", "--no-dangling",
                 "--no-reflogs", revision],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        except OSError as error:
            raise OfflineDependencyError(
                f"shared Git bundle object validation could not execute: {error}"
            ) from error
    if commit.returncode != 0 or connected.returncode != 0:
        detail = (commit.stdout + commit.stderr + connected.stdout + connected.stderr).decode(
            "utf-8", errors="replace"
        ).strip()
        raise OfflineDependencyError(
            f"advertised revision is not a self-contained commit: {detail}"
        )
    return revision


def _rust_source(rustc: Path) -> tuple[Path, dict]:
    command = [str(rustc), "--print", "sysroot"]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as error:
        raise OfflineDependencyError(f"nightly sysroot query could not execute: {error}") from error
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
        raise OfflineDependencyError(f"nightly sysroot query failed with status {result.returncode}: {detail}")
    try:
        output = result.stdout.decode("utf-8").strip()
    except UnicodeError as error:
        raise OfflineDependencyError("nightly sysroot query returned non-UTF-8 output") from error
    if not output or "\n" in output or not Path(output).is_absolute():
        raise OfflineDependencyError("nightly sysroot query returned an invalid path")
    sysroot = Path(output).resolve(strict=True)
    rust = sysroot / "lib/rustlib/src/rust"
    manifest = rust / "library/sysroot/Cargo.toml"
    lock = rust / "library/Cargo.lock"
    _regular(manifest, "nightly sysroot manifest")
    _regular(lock, "nightly sysroot lock")
    identity = {
        "toolchain": NIGHTLY_TOOLCHAIN,
        "rust_src_tree_sha256": tree_content_digest(rust, installed_rust_src=True),
        "sysroot_manifest_sha256": _sha256_file(manifest),
        "sysroot_lock_sha256": _sha256_file(lock),
    }
    return rust, identity


def _workspace_identities(root: Path, manifest: dict) -> dict:
    result = {}
    for relative in manifest["workspace_manifests"]:
        path = root / relative
        lock = path.parent / "Cargo.lock"
        _regular(path, f"workspace manifest {relative}")
        _regular(lock, f"workspace lock {lock.relative_to(root)}")
        result[relative] = {"manifest_sha256": _sha256_file(path), "lock_sha256": _sha256_file(lock)}
    return result


def _validate_checksum_tree(package: Path, expected: dict) -> dict:
    checksum_path = package / ".cargo-checksum.json"
    checksum = _read_json(checksum_path, "Cargo vendor checksum")
    if (not isinstance(checksum, dict)
            or set(checksum) != {"$comment", "files", "package"}
            or checksum["$comment"] != CARGO_CHECKSUM_COMMENT):
        raise OfflineDependencyError(f"malformed Cargo vendor checksum: {checksum_path}")
    wanted_package = expected["checksum"] if expected["kind"] == "registry" else None
    if checksum["package"] != wanted_package or not isinstance(checksum["files"], dict):
        raise OfflineDependencyError(f"Cargo vendor package checksum mismatch: {package.name}")
    actual = {}
    for relative, kind, _executable, content_digest in _entry_inventory(package, payload_modes=True):
        if kind == "file" and relative != ".cargo-checksum.json":
            actual[relative] = content_digest
    for relative, value in checksum["files"].items():
        normalized = _safe_relative(relative, "Cargo checksum path").as_posix()
        if normalized != relative or not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise OfflineDependencyError(f"malformed Cargo checksum entry: {relative!r}")
    if checksum["files"] != actual:
        raise OfflineDependencyError(f"Cargo vendor file checksum mismatch: {package.name}")
    manifest_path = package / "Cargo.toml"
    try:
        cargo_manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        cargo_package = cargo_manifest["package"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise OfflineDependencyError(f"cannot parse vendored manifest {manifest_path}: {error}") from error
    if cargo_package.get("name") != expected["name"] or cargo_package.get("version") != expected["version"]:
        raise OfflineDependencyError(f"vendored manifest identity mismatch: {package.name}")
    return {"name": expected["name"], "version": expected["version"],
            "vendor_directory": package.name, "manifest_sha256": _sha256_file(manifest_path)}


def _validate_vendor(vendor: Path, expected: dict[str, dict]) -> list[dict]:
    try:
        entries = list(vendor.iterdir())
    except OSError as error:
        raise OfflineDependencyError(f"cannot read Cargo vendor directory: {error}") from error
    actual_names = {entry.name for entry in entries}
    if actual_names != set(expected):
        raise OfflineDependencyError(
            f"Cargo vendor package set mismatch: missing={sorted(set(expected) - actual_names)}, "
            f"extra={sorted(actual_names - set(expected))}"
        )
    shared_packages = []
    for name in sorted(expected, key=lambda value: value.encode("utf-8")):
        path = vendor / name
        try:
            metadata = path.lstat()
        except OSError as error:
            raise OfflineDependencyError(f"cannot inspect vendored package {name}: {error}") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o755:
            raise OfflineDependencyError(f"unsafe vendored package directory: {name}")
        record = _validate_checksum_tree(path, expected[name])
        if expected[name]["kind"] == "git":
            shared_packages.append(record)
    return shared_packages


def _shared_provenance(shared_dir: Path, shared: dict, packages: list[dict]) -> dict:
    expected = {"source.bundle", "LICENSE-MIT", "LICENSE-APACHE"}
    try:
        actual = {entry.name for entry in shared_dir.iterdir()}
    except OSError as error:
        raise OfflineDependencyError(f"cannot read supplied shared source: {error}") from error
    if actual != expected:
        raise OfflineDependencyError(f"shared source entries mismatch: expected={sorted(expected)}, got={sorted(actual)}")
    for name in expected:
        _regular(shared_dir / name, f"shared source {name}", executable=False)
    revision = _bundle_revision(shared_dir / "source.bundle")
    if revision != shared["revision"]:
        raise OfflineDependencyError(
            f"shared Git revision mismatch: expected {shared['revision']}, got {revision}"
        )
    return {
        "schema_version": 1,
        "source": {"url": shared["url"], "revision": revision,
                   "bundle_sha256": _sha256_file(shared_dir / "source.bundle")},
        "licenses": {name: _sha256_file(shared_dir / name)
                     for name in ("LICENSE-MIT", "LICENSE-APACHE")},
        "packages": sorted(packages, key=lambda item: (item["name"], item["version"])),
    }


def _required_archives(manifest: dict) -> dict[str, str]:
    return {f"{record['name']}-{record['version']}.crate": record["archive_sha256"]
            for record in manifest["packages"]}


def _copy_regular(source: Path, destination: Path) -> None:
    _regular(source, f"input file {source}")
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o644)


def _normalize_payload(root: Path) -> None:
    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        if not stat.S_ISDIR(directory_path.lstat().st_mode):
            raise OfflineDependencyError(f"unsafe payload directory entry: {directory_path}")
        os.chmod(directory_path, 0o755)
        for name in directory_names:
            path = directory_path / name
            if not stat.S_ISDIR(path.lstat().st_mode):
                raise OfflineDependencyError(f"unsafe symbolic link in payload: {path}")
        for name in file_names:
            path = directory_path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise OfflineDependencyError(f"unsafe payload file entry: {path}")
            os.chmod(path, 0o755 if metadata.st_mode & 0o111 else 0o644)


def _payload_structure(payload: Path, manifest: dict, expected_vendor: dict[str, dict],
                       expected_shared: dict) -> None:
    _entry_inventory(payload, payload_modes=True)
    actual_top = {path.name for path in payload.iterdir()}
    if actual_top != PAYLOAD_TOP:
        missing, extra = sorted(PAYLOAD_TOP - actual_top), sorted(actual_top - PAYLOAD_TOP)
        phrase = "missing payload entry" if missing else "unexpected payload entry"
        raise OfflineDependencyError(f"{phrase}: missing={missing}, extra={extra}")
    provenance = payload / "provenance"
    provenance_names = {path.name for path in provenance.iterdir()}
    if provenance_names != {"shared", "nightly"}:
        raise OfflineDependencyError(f"unexpected payload entry in provenance: {sorted(provenance_names)}")
    shared_dir, nightly_dir = provenance / "shared", provenance / "nightly"
    shared_names = {path.name for path in shared_dir.iterdir()}
    if shared_names != SHARED_FILES:
        missing, extra = sorted(SHARED_FILES - shared_names), sorted(shared_names - SHARED_FILES)
        phrase = "missing payload entry" if missing else "unexpected payload entry"
        raise OfflineDependencyError(f"{phrase} in shared provenance: missing={missing}, extra={extra}")
    nightly_names = {path.name for path in nightly_dir.iterdir()}
    if nightly_names != NIGHTLY_FILES:
        missing, extra = sorted(NIGHTLY_FILES - nightly_names), sorted(nightly_names - NIGHTLY_FILES)
        phrase = "missing payload entry" if missing else "unexpected payload entry"
        raise OfflineDependencyError(f"{phrase} in nightly provenance: missing={missing}, extra={extra}")
    archives = _required_archives(manifest)
    actual_archives = {path.name for path in (payload / "archives").iterdir()}
    if actual_archives != set(archives):
        raise OfflineDependencyError(
            f"archive set mismatch: missing={sorted(set(archives) - actual_archives)}, "
            f"extra={sorted(actual_archives - set(archives))}"
        )
    for name, expected in archives.items():
        path = payload / "archives" / name
        _regular(path, f"original archive {name}", executable=False)
        actual = _sha256_file(path)
        if actual != expected:
            raise OfflineDependencyError(f"original archive digest mismatch for {name}: expected {expected}, got {actual}")
    shared_packages = _validate_vendor(payload / "vendor", expected_vendor)
    actual_shared = _read_json(shared_dir / "packages.json", "shared provenance")
    revision = _bundle_revision(shared_dir / "source.bundle")
    if revision != expected_shared["source"]["revision"]:
        raise OfflineDependencyError("shared Git revision mismatch in payload")
    observed = {
        "schema_version": 1,
        "source": {"url": expected_shared["source"]["url"], "revision": revision,
                   "bundle_sha256": _sha256_file(shared_dir / "source.bundle")},
        "licenses": {name: _sha256_file(shared_dir / name)
                     for name in ("LICENSE-MIT", "LICENSE-APACHE")},
        "packages": shared_packages,
    }
    expected = dict(expected_shared)
    expected["packages"] = shared_packages
    if actual_shared != observed or expected != observed:
        raise OfflineDependencyError("shared package provenance mismatch")


def _verify_nightly_provenance(payload: Path, nightly: dict) -> None:
    directory = payload / "provenance/nightly"
    manifest = _sha256_file(directory / "sysroot-Cargo.toml")
    lock = _sha256_file(directory / "Cargo.lock")
    if manifest != nightly["sysroot_manifest_sha256"]:
        raise OfflineDependencyError("payload nightly sysroot manifest mismatch")
    if lock != nightly["sysroot_lock_sha256"]:
        raise OfflineDependencyError("payload nightly sysroot lock mismatch")


def _recipe_value(root: Path, manifest: dict, preparer, nightly: dict, shared: dict,
                  payload_digest: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "workspaces": _workspace_identities(root, manifest),
        "preparation": {
            "sources_manifest_sha256": _sha256_file(root / "third-party/sources.json"),
            "package_recipes": _package_recipes(root, manifest, preparer),
        },
        "nightly": nightly,
        "shared_git": shared,
        "payload_tree_sha256": payload_digest,
    }


def _validate_recipe(value: object, manifest: dict, preparer, root: Path) -> dict:
    top = {"schema_version", "workspaces", "preparation", "nightly", "shared_git",
           "payload_tree_sha256"}
    if (not isinstance(value, dict) or set(value) != top
            or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1):
        raise OfflineDependencyError("fixed recipe has unknown or missing top-level fields")
    expected_workspaces = set(manifest["workspace_manifests"])
    workspaces = value["workspaces"]
    if not isinstance(workspaces, dict) or set(workspaces) != expected_workspaces:
        raise OfflineDependencyError("fixed recipe workspace entries mismatch")
    for relative, record in workspaces.items():
        if not isinstance(record, dict) or set(record) != {"manifest_sha256", "lock_sha256"}:
            raise OfflineDependencyError(f"fixed recipe workspace fields mismatch: {relative}")
        if any(not isinstance(item, str) or not SHA256_RE.fullmatch(item) for item in record.values()):
            raise OfflineDependencyError(f"fixed recipe workspace digest invalid: {relative}")
    preparation = value["preparation"]
    if not isinstance(preparation, dict) or set(preparation) != {"sources_manifest_sha256", "package_recipes"}:
        raise OfflineDependencyError("fixed recipe preparation fields mismatch")
    package_recipes = preparation.get("package_recipes")
    expected_recipes = set(_package_recipes(root, manifest, preparer))
    if not isinstance(package_recipes, dict) or set(package_recipes) != expected_recipes:
        raise OfflineDependencyError("fixed recipe package recipe entries mismatch")
    digests = [preparation.get("sources_manifest_sha256"), value.get("payload_tree_sha256"),
               *package_recipes.values()]
    nightly = value["nightly"]
    if not isinstance(nightly, dict) or set(nightly) != {
            "toolchain", "rust_src_tree_sha256", "sysroot_manifest_sha256", "sysroot_lock_sha256"}:
        raise OfflineDependencyError("fixed recipe nightly fields mismatch")
    if nightly.get("toolchain") != NIGHTLY_TOOLCHAIN:
        raise OfflineDependencyError("fixed recipe nightly toolchain mismatch")
    digests.extend(nightly[field] for field in (
        "rust_src_tree_sha256", "sysroot_manifest_sha256", "sysroot_lock_sha256"))
    shared = value["shared_git"]
    if (not isinstance(shared, dict) or set(shared) != {"url", "revision"}
            or not isinstance(shared.get("url"), str)
            or not isinstance(shared.get("revision"), str)
            or not REVISION_RE.fullmatch(shared["revision"])):
        raise OfflineDependencyError("fixed recipe shared Git fields mismatch")
    if any(not isinstance(item, str) or not SHA256_RE.fullmatch(item) for item in digests):
        raise OfflineDependencyError("fixed recipe contains an invalid SHA-256 digest")
    return value


def check_fixed_recipe_inputs(root: Path, recipe: dict, manifest: dict, preparer) -> dict:
    """Bind maintained workspace and preparation bytes to one fixed recipe."""
    current = {
        "workspaces": _workspace_identities(root, manifest),
        "preparation": {
            "sources_manifest_sha256": _sha256_file(root / "third-party/sources.json"),
            "package_recipes": _package_recipes(root, manifest, preparer),
        },
    }
    if current["workspaces"] != recipe["workspaces"]:
        raise OfflineDependencyError("workspace lock or manifest input changed")
    if current["preparation"]["sources_manifest_sha256"] != recipe["preparation"]["sources_manifest_sha256"]:
        raise OfflineDependencyError("sources manifest input changed")
    if current["preparation"]["package_recipes"] != recipe["preparation"]["package_recipes"]:
        raise OfflineDependencyError("package recipe input changed")
    return current


def _check_current_inputs(root: Path, recipe: dict, manifest: dict, preparer,
                          nightly: dict, shared: dict) -> dict:
    fixed = check_fixed_recipe_inputs(root, recipe, manifest, preparer)
    if nightly != recipe["nightly"]:
        raise OfflineDependencyError("nightly source input changed")
    if shared != recipe["shared_git"]:
        raise OfflineDependencyError("shared Git revision in dependency locks changed")
    return {
        "schema_version": SCHEMA_VERSION,
        **fixed,
        "nightly": nightly,
        "shared_git": shared,
        "payload_tree_sha256": recipe["payload_tree_sha256"],
    }


def _run_metadata(root: Path, cargo: Path, rustc: Path, manifest: str) -> tuple[list[str], bytes]:
    argv = [str(cargo), *METADATA_ARGUMENTS, str(root / manifest)]
    environment = os.environ.copy()
    environment.update({"RUSTC": str(rustc), "CARGO_NET_OFFLINE": "true"})
    try:
        result = subprocess.run(argv, cwd=root, env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as error:
        raise OfflineDependencyError(f"Cargo metadata could not execute for {manifest}: {error}") from error
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
        raise OfflineDependencyError(f"Cargo metadata failed for {manifest} with status {result.returncode}: {detail}")
    return argv, result.stdout


def _write_new(path: Path, value: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(value)
    except OSError as error:
        raise OfflineDependencyError(f"cannot publish evidence {path}: {error}") from error


def _project_source_identity(root: Path) -> dict:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({"GIT_CEILING_DIRECTORIES": str(root.parent.resolve()),
                        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=root, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        head = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"], cwd=root, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
    except OSError as error:
        top = head = None
        git_error = str(error)
    else:
        git_error = "not a matching Git checkout"
    if top is not None and head is not None and top.returncode == 0 and head.returncode == 0:
        try:
            discovered = Path(top.stdout.decode("utf-8").strip()).resolve()
            revision = head.stdout.decode("ascii").strip()
        except (UnicodeError, OSError):
            discovered, revision = Path("/"), ""
        if discovered == root.resolve() and REVISION_RE.fullmatch(revision):
            return {"kind": "git", "revision": revision}
    manifest_path = root / ".p11scope-source-export.json"
    if manifest_path.is_file():
        value = _read_json(manifest_path, "source export manifest")
        if not isinstance(value, dict):
            raise OfflineDependencyError("source export manifest is malformed")
        schema = value.get("schema_version")
        if type(schema) is not int:
            raise OfflineDependencyError("source export manifest is malformed")
        expected_fields = SOURCE_EXPORT_V1_FIELDS if schema == 1 else (
            SOURCE_EXPORT_V2_FIELDS if schema == 2 else None
        )
        if (expected_fields is None or set(value) != expected_fields
                or not isinstance(value.get("revision"), str)
                or not REVISION_RE.fullmatch(value["revision"])
                or not isinstance(value.get("source_entries"), list)
                or not isinstance(value.get("archives"), list)):
            raise OfflineDependencyError("source export manifest is malformed")
        if schema == 2:
            association = value["offline_dependencies"]
            if (not isinstance(association, dict)
                    or set(association) != OFFLINE_ASSOCIATION_FIELDS
                    or any(not isinstance(item, str) for item in association.values())
                    or association["payload_path"] != "third-party/offline"
                    or association["recipe_path"] != "third-party/offline-dependencies.json"
                    or association["config_path"] != ".cargo/config.toml"
                    or any(not SHA256_RE.fullmatch(association[field]) for field in (
                        "recipe_sha256", "payload_tree_sha256", "config_sha256"
                    ))):
                raise OfflineDependencyError("source export manifest is malformed")
        return {"kind": "source-export", "revision": value["revision"],
                "manifest_sha256": _sha256_file(manifest_path)}
    raise OfflineDependencyError(
        f"cannot establish project source identity from Git or verified source export: {git_error}"
    )


def _evidence(prefix: Path, phase: str, values: dict[str, object]) -> None:
    for name in ("command", "tools", "inputs", "outcome"):
        _write_new(Path(f"{prefix}.{phase}.{name}.json"), _canonical_json(values[name]) + b"\n")


def _metadata_admission(root: Path, manifest: dict, checker, tools: dict,
                        temporary: Path) -> tuple[list[dict], dict]:
    commands, metadata_values = [], []
    for context, relative, tool in (
        ("root", "Cargo.toml", "stable"),
        ("bpf", "crates/ebpf/Cargo.toml", "bpf"),
    ):
        argv, output = _run_metadata(root, Path(tools[tool]["cargo"]["path"]),
                                     Path(tools[tool]["rustc"]["path"]), relative)
        path = temporary / f"{context}-metadata.json"
        path.write_bytes(output)
        commands.append({"context": context, "argv": argv, "cwd": str(root),
                         "environment": {"RUSTC": tools[tool]["rustc"]["path"],
                                         "CARGO_NET_OFFLINE": "true"}})
        metadata_values.append(f"{relative}={path}")
    try:
        details = checker.verify_details(root, root / "third-party/sources.json", metadata_values)
    except checker.MetadataError as error:
        raise OfflineDependencyError(f"prepared dependency metadata admission failed: {error}") from error
    return commands, details


def assemble(root: Path, options, preparer, checker) -> None:
    for path, label in ((options.output, "payload output"),
                        (options.candidate_recipe, "candidate recipe"),
                        (options.prefix, "evidence prefix")):
        _external_target(root, path, label)
    _absolute_directory(options.archive_dir, "archive directory")
    _absolute_directory(options.shared_source, "shared source directory")
    if os.path.lexists(options.output) or os.path.lexists(options.candidate_recipe):
        raise OfflineDependencyError("payload output and candidate recipe must not already exist")
    tools = {name: {
        "cargo": _tool_identity(getattr(options, f"{name}_cargo"), f"{name} Cargo"),
        "rustc": _tool_identity(getattr(options, f"{name}_rustc"), f"{name} rustc"),
    } for name in ("stable", "bpf")}
    project_source = _project_source_identity(root)
    manifest = _strict_manifest(root, preparer)
    workspace_before = _workspace_identities(root, manifest)
    preparation_before = {
        "sources_manifest_sha256": _sha256_file(root / "third-party/sources.json"),
        "package_recipes": _package_recipes(root, manifest, preparer),
    }
    try:
        preparer.run(root, check=False, offline=True, archive_dir=options.archive_dir)
    except preparer.PreparationError as error:
        raise OfflineDependencyError(f"original archives cannot reconstruct prepared trees: {error}") from error
    rust, nightly = _rust_source(Path(tools["bpf"]["rustc"]["path"]))
    lock_paths = [root / Path(workspace).parent / "Cargo.lock"
                  for workspace in manifest["workspace_manifests"]]
    lock_paths.append(rust / "library/Cargo.lock")
    shared, expected_vendor = _locked_dependencies(lock_paths)
    with tempfile.TemporaryDirectory(prefix="p11scope-offline-payload-") as temporary_name:
        temporary = Path(temporary_name)
        metadata_commands, admission = _metadata_admission(root, manifest, checker, tools, temporary)
        stage = Path(tempfile.mkdtemp(prefix=".offline-dependencies-", dir=options.output.parent))
        payload = stage / "payload"
        try:
            payload.mkdir(mode=0o755)
            archives = payload / "archives"
            shared_output = payload / "provenance/shared"
            nightly_output = payload / "provenance/nightly"
            archives.mkdir(mode=0o755)
            shared_output.mkdir(mode=0o755, parents=True)
            nightly_output.mkdir(mode=0o755, parents=True)
            vendor_argv = [tools["bpf"]["cargo"]["path"], "vendor", "--locked", "--offline",
                           "--versioned-dirs", "--manifest-path", str(root / "Cargo.toml"),
                           "--sync", str(root / "crates/ebpf/Cargo.toml"),
                           "--sync", str(rust / "library/sysroot/Cargo.toml"), str(payload / "vendor")]
            environment = os.environ.copy()
            environment.update({"RUSTC": tools["bpf"]["rustc"]["path"],
                                "CARGO_NET_OFFLINE": "true"})
            try:
                vendor_result = subprocess.run(vendor_argv, cwd=root, env=environment,
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            except OSError as error:
                raise OfflineDependencyError(f"Cargo vendor could not execute: {error}") from error
            if vendor_result.returncode != 0:
                detail = (vendor_result.stdout + vendor_result.stderr).decode("utf-8", errors="replace").strip()
                raise OfflineDependencyError(f"Cargo vendor failed with status {vendor_result.returncode}: {detail}")
            if _workspace_identities(root, manifest) != workspace_before:
                raise OfflineDependencyError("workspace lock or manifest changed during Cargo vendor")
            _normalize_payload(payload / "vendor")
            packages = _validate_vendor(payload / "vendor", expected_vendor)
            provenance = _shared_provenance(options.shared_source, shared, packages)
            for name in ("source.bundle", "LICENSE-MIT", "LICENSE-APACHE"):
                _copy_regular(options.shared_source / name, shared_output / name)
            (shared_output / "packages.json").write_bytes(_canonical_json(provenance) + b"\n")
            os.chmod(shared_output / "packages.json", 0o644)
            for name, expected in _required_archives(manifest).items():
                source = options.archive_dir / name
                _copy_regular(source, archives / name)
                actual = _sha256_file(archives / name)
                if actual != expected:
                    raise OfflineDependencyError(f"original archive digest mismatch for {name}")
            _copy_regular(rust / "library/sysroot/Cargo.toml", nightly_output / "sysroot-Cargo.toml")
            _copy_regular(rust / "library/Cargo.lock", nightly_output / "Cargo.lock")
            _normalize_payload(payload)
            final_commands, final_admission = _metadata_admission(
                root, manifest, checker, tools, temporary
            )
            if final_admission != admission:
                raise OfflineDependencyError("Cargo metadata selection changed during assembly")
            final_rust, final_nightly = _rust_source(Path(tools["bpf"]["rustc"]["path"]))
            if final_rust != rust or final_nightly != nightly:
                raise OfflineDependencyError("nightly source input changed during assembly")
            final_manifest = _strict_manifest(root, preparer)
            if final_manifest != manifest:
                raise OfflineDependencyError("sources manifest changed during assembly")
            preparation_final = {
                "sources_manifest_sha256": _sha256_file(root / "third-party/sources.json"),
                "package_recipes": _package_recipes(root, manifest, preparer),
            }
            if preparation_final != preparation_before:
                raise OfflineDependencyError("package recipe input changed during assembly")
            if _workspace_identities(root, manifest) != workspace_before:
                raise OfflineDependencyError("workspace lock or manifest changed during assembly")
            final_shared, final_vendor = _locked_dependencies(lock_paths)
            if final_shared != shared or final_vendor != expected_vendor:
                raise OfflineDependencyError("dependency lock inputs changed during assembly")
            try:
                preparer.run(root, check=True, offline=False, archive_dir=None)
            except preparer.PreparationError as error:
                raise OfflineDependencyError(f"package recipe input changed during assembly: {error}") from error
            _payload_structure(payload, manifest, expected_vendor, provenance)
            _verify_nightly_provenance(payload, nightly)
            payload_digest = tree_content_digest(payload)
            recipe = {
                "schema_version": SCHEMA_VERSION,
                "workspaces": workspace_before,
                "preparation": preparation_before,
                "nightly": nightly,
                "shared_git": shared,
                "payload_tree_sha256": payload_digest,
            }
            payload.rename(options.output)
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    try:
        _write_new(options.candidate_recipe, _canonical_json(recipe) + b"\n")
    except Exception:
        shutil.rmtree(options.output, ignore_errors=True)
        raise
    command_evidence = {"metadata_initial": metadata_commands,
                        "metadata_final": final_commands, "vendor": {
        "argv": vendor_argv, "cwd": str(root),
        "environment": {"RUSTC": tools["bpf"]["rustc"]["path"], "CARGO_NET_OFFLINE": "true"}}}
    inputs = {"workspaces": workspace_before, "preparation": recipe["preparation"],
              "nightly": nightly, "shared_git": shared,
              "archives": _required_archives(manifest),
              "admission_initial": admission, "admission_final": final_admission,
              "project_source": project_source}
    outcome = {"status": 0, "payload_tree_sha256": recipe["payload_tree_sha256"],
               "candidate_recipe_sha256": _sha256_file(options.candidate_recipe),
               "cargo_vendor_stdout_sha256": _sha256_bytes(vendor_result.stdout),
               "cargo_vendor_stderr_sha256": _sha256_bytes(vendor_result.stderr)}
    _evidence(options.prefix, "assemble", {"command": command_evidence, "tools": tools,
                                           "inputs": inputs, "outcome": outcome})


def verify(root: Path, options, preparer, *, reconstruct: bool = True) -> dict:
    _external_target(root, options.prefix, "evidence prefix")
    _absolute_directory(options.payload, "offline dependency payload")
    recipe_path = root / RECIPE_RELATIVE
    if not recipe_path.is_file():
        raise OfflineDependencyError(f"fixed recipe is missing: {recipe_path}")
    manifest = _strict_manifest(root, preparer)
    project_source = _project_source_identity(root)
    recipe_bytes = recipe_path.read_bytes()
    recipe = _validate_recipe(_read_json(recipe_path, "fixed recipe"), manifest, preparer, root)
    tool = _tool_identity(options.nightly_rustc, "nightly rustc")
    rust, nightly = _rust_source(options.nightly_rustc)
    inputs = _check_current_inputs(
        root, recipe, manifest, preparer, nightly, recipe["shared_git"]
    )
    lock_paths = [root / Path(workspace).parent / "Cargo.lock" for workspace in manifest["workspace_manifests"]]
    lock_paths.append(rust / "library/Cargo.lock")
    shared, expected_vendor = _locked_dependencies(lock_paths)
    if shared != recipe["shared_git"]:
        raise OfflineDependencyError("shared Git revision in dependency locks changed")
    _entry_inventory(options.payload, payload_modes=True)
    shared_dir = options.payload / "provenance/shared"
    try:
        shared_names = {path.name for path in shared_dir.iterdir()}
    except OSError as error:
        raise OfflineDependencyError(f"missing payload entry for shared provenance: {error}") from error
    if shared_names != SHARED_FILES:
        missing, extra = sorted(SHARED_FILES - shared_names), sorted(shared_names - SHARED_FILES)
        phrase = "missing payload entry" if missing else "unexpected payload entry"
        raise OfflineDependencyError(f"{phrase} in shared provenance: missing={missing}, extra={extra}")
    expected_shared = {
        "schema_version": 1,
        "source": {"url": shared["url"], "revision": shared["revision"],
                   "bundle_sha256": _sha256_file(shared_dir / "source.bundle")},
        "licenses": {name: _sha256_file(shared_dir / name)
                     for name in ("LICENSE-MIT", "LICENSE-APACHE")},
        "packages": [],
    }
    _payload_structure(options.payload, manifest, expected_vendor, expected_shared)
    _verify_nightly_provenance(options.payload, nightly)
    try:
        if reconstruct:
            preparer.run(root, check=False, offline=True,
                         archive_dir=options.payload / "archives")
        else:
            with _existing_preparation_lock(root):
                preparer.run(root, check=True, offline=False, archive_dir=None)
    except preparer.PreparationError as error:
        action = "original archives cannot reconstruct prepared trees" if reconstruct \
            else "existing prepared outputs failed read-only verification"
        raise OfflineDependencyError(f"{action}: {error}") from error
    final_rust, final_nightly = _rust_source(options.nightly_rustc)
    if final_rust != rust or final_nightly != nightly:
        raise OfflineDependencyError("nightly source input changed during verification")
    final_shared, final_vendor = _locked_dependencies(lock_paths)
    if final_shared != shared or final_vendor != expected_vendor:
        raise OfflineDependencyError("dependency lock inputs changed during verification")
    if _check_current_inputs(root, recipe, manifest, preparer, final_nightly, final_shared) != inputs:
        raise OfflineDependencyError("recipe inputs changed during verification")
    if recipe_path.read_bytes() != recipe_bytes:
        raise OfflineDependencyError("fixed recipe changed during verification")
    actual_digest = tree_content_digest(options.payload)
    if actual_digest != recipe["payload_tree_sha256"]:
        raise OfflineDependencyError(
            f"payload tree digest mismatch: expected {recipe['payload_tree_sha256']}, got {actual_digest}"
        )
    receipt = {"schema_version": 1, "recipe_sha256": _sha256_bytes(recipe_bytes),
               "observed_inputs": inputs, "payload": str(options.payload),
               "payload_tree_sha256": actual_digest, "project_source": project_source}
    values = {
        "command": {"operation": "verify", "payload": str(options.payload),
                    "nightly_rustc": str(options.nightly_rustc), "root": str(root)},
        "tools": {"nightly_rustc": tool},
        "inputs": inputs,
        "outcome": {"status": 0, "recipe_sha256": receipt["recipe_sha256"],
                    "payload_tree_sha256": actual_digest},
    }
    _evidence(options.prefix, "verify", values)
    _write_new(Path(f"{options.prefix}.verify.receipt.json"), _canonical_json(receipt) + b"\n")
    return receipt


def replacement_config(payload: Path, shared_git: dict, *, vendor_path: str | None = None) -> bytes:
    """Return the finite Cargo replacement configuration for one verified payload."""
    if (not isinstance(shared_git, dict) or set(shared_git) != {"url", "revision"}
            or not isinstance(shared_git["url"], str)
            or not isinstance(shared_git["revision"], str)
            or not REVISION_RE.fullmatch(shared_git["revision"])):
        raise OfflineDependencyError("invalid shared Git identity for replacement config")
    if vendor_path is None:
        if not payload.is_absolute() or Path(os.path.normpath(str(payload))) != payload:
            raise OfflineDependencyError("verified payload path must be normalized and absolute")
        directory = str(payload / "vendor")
    else:
        directory = _safe_relative(vendor_path, "relative vendor path").as_posix()
    for value, label in ((directory, "vendor directory"), (shared_git["url"], "shared Git URL")):
        if (any(character in value for character in ('"', "\n", "\r", "\\"))
                or any(ord(character) < 32 or ord(character) == 127 for character in value)):
            raise OfflineDependencyError(f"{label} cannot be represented safely")
    source = f"git+{shared_git['url']}?rev={shared_git['revision']}"
    return (
        "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n"
        f"[source.\"{source}\"]\ngit = \"{shared_git['url']}\"\n"
        f"rev = \"{shared_git['revision']}\"\nreplace-with = \"vendored-sources\"\n\n"
        f"[source.vendored-sources]\ndirectory = \"{directory}\"\n\n[net]\noffline = true\n"
    ).encode("utf-8")


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    assemble_parser = subparsers.add_parser("assemble")
    for option in ("output", "candidate-recipe", "archive-dir", "shared-source", "prefix",
                   "stable-cargo", "stable-rustc", "bpf-cargo", "bpf-rustc"):
        assemble_parser.add_argument(f"--{option}", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    for option in ("payload", "nightly-rustc", "prefix"):
        verify_parser.add_argument(f"--{option}", type=Path, required=True)
    verify_parser.add_argument("--check-prepared", action="store_true",
                               help="verify existing prepared outputs without reconstruction")
    options = parser.parse_args(arguments)
    root = Path(__file__).resolve().parents[1]
    preparer = _load_module(root / "scripts/prepare-dependencies.py", "p11scope_offline_preparer")
    checker = _load_module(root / "scripts/check-prepared-dependencies.py", "p11scope_offline_checker")
    try:
        if options.operation == "assemble":
            assemble(root, options, preparer, checker)
        else:
            verify(root, options, preparer, reconstruct=not options.check_prepared)
    except OfflineDependencyError as error:
        print(f"offline-dependencies: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
