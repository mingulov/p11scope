#!/usr/bin/env python3
"""Export committed source and pinned original crates for offline reconstruction."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
from types import SimpleNamespace
import subprocess
import sys
import tarfile
import tempfile


ARCHIVE_ROOT = "pkcs11-scope-source"
EXPORT_MANIFEST = ".p11scope-source-export.json"
SCHEMA_VERSION = 1
FULL_SCHEMA_VERSION = 2
OFFLINE_PAYLOAD_PATH = "third-party/offline"
OFFLINE_RECIPE_PATH = "third-party/offline-dependencies.json"
OFFLINE_CONFIG_PATH = ".cargo/config.toml"
OFFLINE_ASSOCIATION_FIELDS = {
    "payload_path", "recipe_path", "recipe_sha256", "payload_tree_sha256",
    "config_path", "config_sha256",
}
REFUSED_ENVIRONMENT = {
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET",
    "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER", "CC", "CFLAGS", "P11SCOPE_PRODUCT_BUILD_MODE",
    "P11SCOPE_PREPARED_STABLE_CARGO", "P11SCOPE_PREPARED_STABLE_RUSTC",
    "P11SCOPE_PREPARED_BPF_CARGO", "P11SCOPE_PREPARED_BPF_RUSTC",
    "P11SCOPE_SMALL_RING", "P11SCOPE_SMALL_STATE_MAPS",
}


def _refused_environment(name: str) -> bool:
    return (name in REFUSED_ENVIRONMENT or name.startswith("CARGO_SOURCE_")
            or name.startswith("CARGO_BUILD_") or name.startswith("CARGO_TARGET_")
            or name.startswith("CC_") or name.startswith("CFLAGS_")
            or name in {"HOST_CC", "TARGET_CC", "HOST_CFLAGS", "TARGET_CFLAGS"}
            or name.startswith("RUST")
            or name.startswith("P11SCOPE_PREPARED_")
            or name.startswith("P11SCOPE_SMALL_"))


class ExportError(Exception):
    """A deterministic refusal caused by unsafe or inconsistent export inputs."""


def _load_preparer(root: Path):
    path = root / "scripts/prepare-dependencies.py"
    spec = importlib.util.spec_from_file_location("p11scope_export_preparer", path)
    if spec is None or spec.loader is None:
        raise ExportError(f"cannot load dependency preparer {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError) as error:
        raise ExportError(f"cannot load dependency preparer {path}: {error}") from error
    finally:
        sys.dont_write_bytecode = previous
    return module


def _load_offline_helper(root: Path):
    path = root / "scripts/offline-dependencies.py"
    spec = importlib.util.spec_from_file_location("p11scope_export_offline", path)
    if spec is None or spec.loader is None:
        raise ExportError(f"cannot load offline dependency helper {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError) as error:
        raise ExportError(f"cannot load offline dependency helper {path}: {error}") from error
    finally:
        sys.dont_write_bytecode = previous
    return module


def _git_environment(root: Path) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({
        "GIT_CEILING_DIRECTORIES": str(root.parent.resolve()),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    })
    return environment


def _git(root: Path, environment: dict[str, str], *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", *arguments], cwd=root, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
        raise ExportError(f"Git {' '.join(arguments)} failed: {detail}")
    return result.stdout


def _repository_state(root: Path, environment: dict[str, str]) -> tuple[str, dict[str, tuple[str, str]]]:
    discovered = _git(root, environment, "rev-parse", "--show-toplevel").decode().strip()
    if Path(discovered).resolve() != root.resolve():
        raise ExportError(f"unexpected source repository root: {discovered}")
    revision = _git(root, environment, "rev-parse", "--verify", "HEAD").decode().strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise ExportError(f"invalid Git HEAD identity: {revision}")
    dirty = _git(root, environment, "status", "--porcelain=v1", "-z", "--untracked-files=normal")
    if dirty:
        names = [entry.decode("utf-8", errors="backslashreplace") for entry in dirty.split(b"\0") if entry]
        raise ExportError("source repository is not clean: " + ", ".join(names))
    raw = _git(root, environment, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    tracked = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, encoded_path = entry.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
            relative = encoded_path.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise ExportError("invalid tracked source entry") from error
        if kind != b"blob" or mode not in (b"100644", b"100755", b"120000"):
            raise ExportError(f"unsupported tracked source entry: {relative}")
        tracked[relative] = (mode.decode("ascii"), object_id.decode("ascii"))
    return revision, tracked


def _source_path(name: str) -> PurePosixPath:
    if not name or "\\" in name:
        raise ExportError(f"unsafe committed source path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ExportError(f"unsafe committed source path: {name!r}")
    if ".git" in path.parts:
        raise ExportError(f"committed source contains Git metadata: {name}")
    return path


def _required_inputs(manifest: dict) -> set[str]:
    required = {"scripts/export-source.py", "scripts/prepare-dependencies.py",
                "third-party/sources.json"}
    required.update(manifest["workspace_manifests"])
    for record in manifest["packages"]:
        required.update(record["patches"])
    return required


def _require_regular_inputs(tracked: dict[str, tuple[str, str]], required: set[str],
                            revision: str) -> None:
    for relative in sorted(required):
        entry = tracked.get(relative)
        if entry is None:
            raise ExportError(f"required export input is not committed at {revision}: {relative}")
        if entry[0] not in ("100644", "100755"):
            raise ExportError(
                f"required export input is not a committed regular file: {relative}"
            )


def _validate_output(root: Path, output: Path) -> Path:
    if not output.is_absolute():
        raise ExportError("output must be an absolute .tar.gz path")
    if not output.name.endswith(".tar.gz") or output.name == ".tar.gz":
        raise ExportError("output must have a non-empty .tar.gz name")
    normalized = Path(os.path.normpath(str(output)))
    if normalized != output:
        raise ExportError("output path is not normalized")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        raise ExportError(f"output parent is unavailable: {error}") from error
    if parent != output.parent:
        raise ExportError("output parent path contains a symbolic link")
    try:
        output.relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise ExportError("output must be outside the source repository")
    if os.path.lexists(output):
        raise ExportError(f"output already exists: {output}")
    return output


def _tar_info(name: str, mode: int, size: int = 0, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = mode
    info.size = 0 if directory else size
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.pax_headers = {}
    return info


def _add_bytes(output: tarfile.TarFile, name: str, content: bytes, mode: int = 0o644) -> None:
    output.addfile(_tar_info(name, mode, len(content)), io.BytesIO(content))


def _add_symlink(output: tarfile.TarFile, name: str, target: str) -> None:
    info = _tar_info(name, 0o777)
    info.type = tarfile.SYMTYPE
    info.size = 0
    info.linkname = target
    output.addfile(info)


def _git_blob_id(content: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(f"blob {len(content)}\0".encode("ascii"))
    digest.update(content)
    return digest.hexdigest()


def _validated_symlink_target(path: PurePosixPath, target: str,
                              tracked: dict[str, tuple[str, str]]) -> bytes:
    try:
        encoded = target.encode("utf-8")
    except UnicodeError as error:
        raise ExportError(f"unsafe committed symlink {path}: target is not UTF-8") from error
    if (not target or target.startswith("/") or "\\" in target
            or any(ord(character) < 32 or ord(character) == 127 for character in target)):
        raise ExportError(f"unsafe committed symlink {path}: invalid target {target!r}")
    directories = {
        parent.as_posix()
        for relative in tracked
        for parent in PurePosixPath(relative).parents
        if parent != PurePosixPath(".")
    }
    parts = list(path.parent.parts) if path.parent != PurePosixPath(".") else []
    target_parts = target.split("/")
    for index, part in enumerate(target_parts):
        if not part or part == ".":
            if not part:
                raise ExportError(f"unsafe committed symlink {path}: invalid target {target!r}")
            continue
        if part == "..":
            if not parts:
                raise ExportError(f"unsafe committed symlink {path}: target escapes archive root")
            parts.pop()
        else:
            traversed = "/".join([*parts, part])
            if index < len(target_parts) - 1 and traversed not in directories:
                raise ExportError(
                    f"unsafe committed symlink {path}: nonterminal target component is not a "
                    f"committed directory: {part!r}"
                )
            parts.append(part)
    resolved = "/".join(parts)
    target_entry = tracked.get(resolved)
    if target_entry is None or target_entry[0] not in ("100644", "100755"):
        raise ExportError(
            f"unsafe committed symlink {path}: target is not a direct committed regular file: "
            f"{target!r}"
        )
    return encoded


def _reject_generated_collisions(tracked: dict[str, tuple[str, str]],
                                 generated: list[str]) -> None:
    for destination in generated:
        for source in tracked:
            if source == destination:
                label = ("reserved export manifest" if destination == EXPORT_MANIFEST
                         else "embedded archive")
                raise ExportError(f"{label} collides with committed source: {destination}")
            if (source.startswith(destination + "/")
                    or destination.startswith(source + "/")):
                raise ExportError(
                    f"generated destination conflicts with committed source: "
                    f"{destination} and {source}"
                )


def _verified_payload_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ExportError(f"payload directory unavailable during streaming: {path}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o755:
        raise ExportError(f"payload directory mode or type changed during streaming: {path}")


def _verified_payload_bytes(path: Path, executable_bits: int, expected_digest: str) -> bytes:
    expected_mode = 0o755 if executable_bits else 0o644
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != expected_mode):
            raise ExportError(f"payload file mode or type changed during streaming: {path}")
        content = path.read_bytes()
        after = path.lstat()
    except ExportError:
        raise
    except OSError as error:
        raise ExportError(f"payload file unavailable during streaming: {path}: {error}") from error
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mode)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mode)
    if (identity_before != identity_after or not stat.S_ISREG(after.st_mode)
            or stat.S_IMODE(after.st_mode) != expected_mode):
        raise ExportError(f"payload file mode or identity changed during streaming: {path}")
    actual_digest = hashlib.sha256(content).hexdigest()
    if actual_digest != expected_digest:
        raise ExportError(
            f"payload file digest changed during streaming: {path}: "
            f"expected {expected_digest}, got {actual_digest}"
        )
    return content


def _build_archive(root: Path, revision: str, tracked: dict[str, tuple[str, str]],
                   originals: list[tuple[dict, Path]], destination: Path,
                   environment: dict[str, str], *, payload: Path | None = None,
                   payload_inventory: list[tuple[str, str, int, str]] | None = None,
                   config: bytes | None = None,
                   offline_association: dict[str, str] | None = None) -> None:
    source_tar = destination.parent / "committed-source.tar"
    with source_tar.open("xb") as stream:
        result = subprocess.run(
            ["git", "archive", "--format=tar", revision], cwd=root, env=environment,
            stdout=stream, stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        raise ExportError(
            "Git archive failed: " + result.stderr.decode("utf-8", errors="replace").strip()
        )

    source_entries = []
    archive_entries = []
    symlink_targets = {}
    payload_records = ({relative: (kind, executable_bits, digest)
                        for relative, kind, executable_bits, digest in payload_inventory}
                       if payload_inventory is not None else {})
    payload_archive_bytes = {}
    with source_tar.open("rb") as source_stream, tarfile.open(fileobj=source_stream, mode="r:") as source:
        members = source.getmembers()
        for member in members:
            path = _source_path(member.name.rstrip("/"))
            if not (member.isdir() or member.isreg() or member.issym()):
                raise ExportError(f"unsupported committed source entry: {member.name}")
            if member.isreg():
                stream = source.extractfile(member)
                if stream is None:
                    raise ExportError(f"cannot read committed source entry: {member.name}")
                with stream:
                    content = stream.read()
                expected = tracked.get(path.as_posix())
                if expected is None:
                    raise ExportError(
                        f"Git archive does not exactly match tracked source: {path.as_posix()}"
                    )
                expected_mode, expected_object = expected
                if expected_mode == "120000":
                    raise ExportError(f"Git archive type differs from committed symlink: {path}")
                archive_mode = "100755" if member.mode & 0o111 else "100644"
                expected_tar_mode = 0o775 if expected_mode == "100755" else 0o664
                if (archive_mode != expected_mode or member.mode != expected_tar_mode
                        or _git_blob_id(content) != expected_object):
                    raise ExportError(
                        f"Git archive differs from committed blob or mode: {path.as_posix()}"
                    )
                source_entries.append({
                    "path": path.as_posix(),
                    "kind": "file",
                    "mode": "0755" if expected_mode == "100755" else "0644",
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                })
            elif member.issym():
                expected = tracked.get(path.as_posix())
                if expected is None or expected[0] != "120000":
                    raise ExportError(f"Git archive type differs from committed source: {path}")
                target_bytes = _validated_symlink_target(path, member.linkname, tracked)
                if member.mode != 0o777 or _git_blob_id(target_bytes) != expected[1]:
                    raise ExportError(
                        f"Git archive differs from committed symlink blob or mode: {path}"
                    )
                symlink_targets[path.as_posix()] = member.linkname
                source_entries.append({
                    "path": path.as_posix(),
                    "kind": "symlink",
                    "mode": "120000",
                    "target": member.linkname,
                    "size": len(target_bytes),
                    "sha256": hashlib.sha256(target_bytes).hexdigest(),
                })
        archived_paths = {item["path"] for item in source_entries}
        tracked_paths = set(tracked)
        if archived_paths != tracked_paths:
            missing = sorted(tracked_paths - archived_paths)
            unexpected = sorted(archived_paths - tracked_paths)
            detail = missing[0] if missing else unexpected[0]
            raise ExportError(f"Git archive does not exactly match tracked source: {detail}")
        for record, path in originals:
            if payload is None:
                content = path.read_bytes()
            else:
                relative = path.relative_to(payload).as_posix()
                admitted = payload_records.get(relative)
                if admitted is None or admitted[0] != "file":
                    raise ExportError(f"payload archive is absent from retained inventory: {relative}")
                content = _verified_payload_bytes(path, admitted[1], admitted[2])
                payload_archive_bytes[relative] = content
            archive_entries.append({
                "path": (
                    f"{OFFLINE_PAYLOAD_PATH}/archives/{record['name']}-{record['version']}.crate"
                    if payload is not None else
                    f"third-party/archives/{record['name']}-{record['version']}.crate"
                ),
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            })

        export_manifest = {
            "schema_version": FULL_SCHEMA_VERSION if payload is not None else SCHEMA_VERSION,
            "revision": revision,
            "source_entries": sorted(source_entries, key=lambda item: item["path"].encode()),
            "archives": sorted(archive_entries, key=lambda item: item["path"].encode()),
        }
        if payload is not None:
            if config is None or offline_association is None or payload_inventory is None:
                raise ExportError("full export inputs are incomplete")
            export_manifest["offline_dependencies"] = offline_association
        manifest_bytes = (json.dumps(
            export_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ) + "\n").encode()

        with destination.open("xb") as raw_output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as output:
                    output.addfile(_tar_info(ARCHIVE_ROOT, 0o755, directory=True))
                    for member in members:
                        path = _source_path(member.name.rstrip("/"))
                        name = f"{ARCHIVE_ROOT}/{path.as_posix()}"
                        if member.isdir():
                            output.addfile(_tar_info(name, 0o755, directory=True))
                        elif member.isreg():
                            stream = source.extractfile(member)
                            if stream is None:
                                raise ExportError(f"cannot reread committed source entry: {member.name}")
                            with stream:
                                content = stream.read()
                            git_mode, git_object = tracked[path.as_posix()]
                            archive_mode = "100755" if member.mode & 0o111 else "100644"
                            expected_tar_mode = 0o775 if git_mode == "100755" else 0o664
                            if (archive_mode != git_mode or member.mode != expected_tar_mode
                                    or _git_blob_id(content) != git_object):
                                raise ExportError(
                                    "Git archive changed during committed source emission: "
                                    f"{path.as_posix()}"
                                )
                            _add_bytes(output, name, content,
                                       0o755 if git_mode == "100755" else 0o644)
                        else:
                            _add_symlink(output, name, symlink_targets[path.as_posix()])
                    known_directories = {member.name.rstrip("/") for member in members if member.isdir()}
                    generated_directories = (
                        ("third-party", OFFLINE_PAYLOAD_PATH, ".cargo")
                        if payload is not None else ("third-party", "third-party/archives")
                    )
                    for directory in generated_directories:
                        if directory not in known_directories:
                            if directory == OFFLINE_PAYLOAD_PATH:
                                assert payload is not None
                                _verified_payload_directory(payload)
                            output.addfile(_tar_info(f"{ARCHIVE_ROOT}/{directory}", 0o755, directory=True))
                    if payload is None:
                        ordered_originals = sorted(
                            originals,
                            key=lambda pair: (
                                f"third-party/archives/{pair[0]['name']}-{pair[0]['version']}.crate"
                            ).encode(),
                        )
                        for item, (_record, path) in zip(export_manifest["archives"], ordered_originals):
                            _add_bytes(output, f"{ARCHIVE_ROOT}/{item['path']}", path.read_bytes())
                    else:
                        for relative, kind, executable_bits, _digest in payload_inventory:
                            name = f"{ARCHIVE_ROOT}/{OFFLINE_PAYLOAD_PATH}/{relative}"
                            if kind == "directory":
                                _verified_payload_directory(payload / relative)
                                output.addfile(_tar_info(name, 0o755, directory=True))
                            else:
                                content = payload_archive_bytes.get(relative)
                                if content is None:
                                    content = _verified_payload_bytes(
                                        payload / relative, executable_bits, _digest
                                    )
                                _add_bytes(output, name, content,
                                           0o755 if executable_bits else 0o644)
                        _add_bytes(output, f"{ARCHIVE_ROOT}/{OFFLINE_CONFIG_PATH}", config)
                    _add_bytes(output, f"{ARCHIVE_ROOT}/{EXPORT_MANIFEST}", manifest_bytes)
    os.chmod(destination, 0o644)


def _verify_payload(helper, root: Path, payload: Path, nightly_rustc: Path,
                    prefix: Path, preparer) -> dict:
    try:
        return helper.verify(root, SimpleNamespace(
            payload=payload, nightly_rustc=nightly_rustc, prefix=prefix
        ), preparer)
    except helper.OfflineDependencyError as error:
        raise ExportError(f"offline dependency payload: {error}") from error


def _delivered_cargo_config_paths(root: Path) -> set[Path]:
    paths = set()
    current = root / "crates/ebpf"
    while True:
        paths.update((current / ".cargo/config", current / ".cargo/config.toml"))
        if current == root:
            return paths
        current = current.parent


def run(root: Path, output: Path, *, offline: bool, archive_dir: Path | None,
        offline_payload: Path | None = None, nightly_rustc: Path | None = None) -> None:
    root = root.resolve()
    output = _validate_output(root, output)
    environment = _git_environment(root)
    revision, tracked = _repository_state(root, environment)
    _require_regular_inputs(
        tracked,
        {"scripts/export-source.py", "scripts/prepare-dependencies.py",
         "third-party/sources.json"},
        revision,
    )
    full_mode = offline_payload is not None or nightly_rustc is not None
    if (offline_payload is None) != (nightly_rustc is None):
        raise ExportError("offline-payload and nightly-rustc must be supplied together")
    if full_mode and archive_dir is not None:
        raise ExportError("archive-dir is not accepted in full export mode")
    preparer = _load_preparer(root)
    try:
        manifest = preparer.load_manifest(root)
    except preparer.PreparationError as error:
        raise ExportError(str(error)) from error
    _require_regular_inputs(tracked, _required_inputs(manifest), revision)
    archive_targets = [
        (f"{OFFLINE_PAYLOAD_PATH}/archives/" if full_mode else "third-party/archives/")
        + f"{record['name']}-{record['version']}.crate"
        for record in manifest["packages"]
    ]
    if len(archive_targets) != len(set(archive_targets)):
        duplicate = next(path for path in archive_targets if archive_targets.count(path) > 1)
        raise ExportError(f"duplicate embedded archive destination: {duplicate}")
    if full_mode:
        _require_regular_inputs(tracked, {
            "scripts/offline-dependencies.py", "scripts/check-prepared-dependencies.py",
            OFFLINE_RECIPE_PATH,
        }, revision)
        _reject_generated_collisions(
            tracked, [EXPORT_MANIFEST, OFFLINE_PAYLOAD_PATH, OFFLINE_CONFIG_PATH]
        )
        delivered_configs = {
            path.relative_to(root).as_posix()
            for path in _delivered_cargo_config_paths(root)
        }
        competing = sorted(delivered_configs & set(tracked), key=os.fsencode)
        if competing:
            raise ExportError(f"competing Cargo configuration: {competing[0]}")
        _reject_generated_collisions(tracked, sorted(delivered_configs, key=os.fsencode))
    else:
        _reject_generated_collisions(tracked, [EXPORT_MANIFEST, *archive_targets])

    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.export-", dir=output.parent))
    try:
        originals = []
        staged_payload = None
        inventory = None
        config = None
        association = None
        helper = None
        if full_mode:
            assert offline_payload is not None and nightly_rustc is not None
            helper = _load_offline_helper(root)
            input_receipt = _verify_payload(
                helper, root, offline_payload, nightly_rustc, stage / "input", preparer
            )
            try:
                helper.payload_inventory(offline_payload)
                staged_payload = stage / "private-payload"
                shutil.copytree(offline_payload, staged_payload, symlinks=True)
            except (OSError, helper.OfflineDependencyError) as error:
                raise ExportError(f"cannot stage safe offline dependency payload: {error}") from error
            staged_receipt = _verify_payload(
                helper, root, staged_payload, nightly_rustc, stage / "staged", preparer
            )
            if staged_receipt["payload_tree_sha256"] != input_receipt["payload_tree_sha256"]:
                raise ExportError("offline dependency payload changed while staging")
            inventory = helper.payload_inventory(staged_payload)
            for record in manifest["packages"]:
                originals.append((
                    record,
                    staged_payload / "archives" / f"{record['name']}-{record['version']}.crate",
                ))
            recipe_bytes = (root / OFFLINE_RECIPE_PATH).read_bytes()
            recipe = helper._read_json(root / OFFLINE_RECIPE_PATH, "fixed recipe")
            config = helper.replacement_config(
                staged_payload, recipe["shared_git"],
                vendor_path=f"{OFFLINE_PAYLOAD_PATH}/vendor",
            )
            association = {
                "payload_path": OFFLINE_PAYLOAD_PATH,
                "recipe_path": OFFLINE_RECIPE_PATH,
                "recipe_sha256": hashlib.sha256(recipe_bytes).hexdigest(),
                "payload_tree_sha256": staged_receipt["payload_tree_sha256"],
                "config_path": OFFLINE_CONFIG_PATH,
                "config_sha256": hashlib.sha256(config).hexdigest(),
            }
        else:
            acquisition = stage / "originals"
            acquisition.mkdir(mode=0o700)
            try:
                for record in manifest["packages"]:
                    path = preparer._obtain_archive(
                        root, archive_dir, record, offline, acquisition
                    )
                    originals.append((record, path))
            except preparer.PreparationError as error:
                raise ExportError(str(error)) from error
        current_revision, current_tracked = _repository_state(root, environment)
        if current_revision != revision or current_tracked != tracked:
            raise ExportError("source repository identity changed during export")
        built = stage / "completed.tar.gz"
        try:
            _build_archive(
                root, revision, tracked, originals, built, environment,
                payload=staged_payload, payload_inventory=inventory, config=config,
                offline_association=association,
            )
        except OSError as error:
            raise ExportError(f"cannot stream source export: {error}") from error
        if full_mode:
            assert helper is not None and staged_payload is not None and nightly_rustc is not None
            final_receipt = _verify_payload(
                helper, root, staged_payload, nightly_rustc, stage / "final", preparer
            )
            if final_receipt["payload_tree_sha256"] != association["payload_tree_sha256"]:
                raise ExportError("offline dependency payload changed during archive streaming")
            final_revision, final_tracked = _repository_state(root, environment)
            if final_revision != revision or final_tracked != tracked:
                raise ExportError("source repository identity changed during export")
        try:
            os.link(built, output, follow_symlinks=False)
        except FileExistsError as error:
            raise ExportError(f"output already exists: {output}") from error
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _validate_absolute_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ExportError(f"{label} must be a normalized absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ExportError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or path.resolve() != path:
        raise ExportError(f"{label} must be a real directory without symbolic links")
    return path


def _validate_source_entries(root: Path, records: object,
                             admitted_generated: set[str] | None = None, *,
                             scan: bool = True) -> dict[str, dict]:
    if not isinstance(records, list):
        raise ExportError("source export manifest source_entries must be an array")
    expected = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("kind"), str):
            raise ExportError("source export manifest contains malformed source entry")
        kind = record["kind"]
        fields = {"path", "kind", "mode", "size", "sha256"}
        if kind == "symlink":
            fields.add("target")
        if (set(record) != fields or not isinstance(record.get("path"), str)
                or not isinstance(record.get("mode"), str)
                or type(record.get("size")) is not int or record["size"] < 0
                or not isinstance(record.get("sha256"), str)
                or len(record["sha256"]) != 64
                or any(character not in "0123456789abcdef" for character in record["sha256"])):
            raise ExportError("source export manifest contains malformed source entry")
        path = _source_path(record["path"])
        relative = path.as_posix()
        if (relative == EXPORT_MANIFEST or relative == OFFLINE_CONFIG_PATH
                or relative == OFFLINE_PAYLOAD_PATH
                or relative.startswith(OFFLINE_PAYLOAD_PATH + "/")):
            raise ExportError(f"generated payload/config must not be a source entry: {relative}")
        if relative in expected:
            raise ExportError(f"duplicate source export entry: {relative}")
        target = root / relative
        try:
            metadata = target.lstat()
        except OSError as error:
            raise ExportError(f"missing source export entry {relative}: {error}") from error
        if kind == "file":
            if not stat.S_ISREG(metadata.st_mode) or record["mode"] not in ("0644", "0755"):
                raise ExportError(f"source export entry type or mode mismatch: {relative}")
            mode = "0755" if stat.S_IMODE(metadata.st_mode) == 0o755 else "0644"
            if stat.S_IMODE(metadata.st_mode) not in (0o644, 0o755) or mode != record["mode"]:
                raise ExportError(f"source export entry type or mode mismatch: {relative}")
            content = target.read_bytes()
        elif kind == "symlink":
            if (not stat.S_ISLNK(metadata.st_mode) or record["mode"] != "120000"
                    or not isinstance(record.get("target"), str)):
                raise ExportError(f"source export entry type or mode mismatch: {relative}")
            link = os.readlink(target)
            if link != record["target"]:
                raise ExportError(f"source export symlink target mismatch: {relative}")
            content = link.encode("utf-8")
        else:
            raise ExportError(f"unsupported source export entry kind: {relative}")
        if (len(content) != record["size"]
                or hashlib.sha256(content).hexdigest() != record["sha256"]):
            raise ExportError(f"source export entry digest mismatch: {relative}")
        expected[relative] = record

    if not scan:
        return expected
    actual = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as error:
            raise ExportError(f"cannot scan extracted source {directory}: {error}") from error
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if relative == EXPORT_MANIFEST or relative == OFFLINE_CONFIG_PATH:
                continue
            if relative == OFFLINE_PAYLOAD_PATH:
                continue
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                actual.add(relative)
            else:
                raise ExportError(f"unsafe extracted source entry type: {relative}")
    admitted = admitted_generated or set()
    if actual != set(expected) | admitted:
        difference = sorted(actual ^ (set(expected) | admitted), key=os.fsencode)
        raise ExportError(f"source export entries do not exactly match extraction: {difference[0]}")
    tracked = {
        relative: (
            "120000" if record["kind"] == "symlink" else
            "100755" if record["mode"] == "0755" else "100644",
            "",
        )
        for relative, record in expected.items()
    }
    for relative, record in expected.items():
        if record["kind"] == "symlink":
            _validated_symlink_target(PurePosixPath(relative), record["target"], tracked)
    return expected


def _validate_prepared_state(root: Path, records: object, strict_manifest: dict,
                             preparer, mode: str) -> tuple[set[str], dict]:
    if mode not in {"forbid", "allow", "require"}:
        raise ExportError(f"unsupported prepared-state mode: {mode}")
    if not isinstance(records, list):
        raise ExportError("source export manifest source_entries must be an array")
    reserved = {"third-party/.prepare-dependencies.lock"}
    for record in records:
        if isinstance(record, dict) and isinstance(record.get("path"), str):
            relative = _source_path(record["path"]).as_posix()
            if relative == "third-party/src" or relative.startswith("third-party/src/") \
                    or relative in reserved:
                raise ExportError(f"prepared output collides with maintained source: {relative}")

    expected = {}
    try:
        for record in strict_manifest["packages"]:
            name = preparer.output_name(record)
            patches = preparer.read_patch_bytes(root, record)
            expected[name] = (record, preparer.compute_recipe_identity(record, patches))
    except preparer.PreparationError as error:
        raise ExportError(f"cannot derive prepared output identity: {error}") from error

    generated = set()
    custody = {"mode": mode, "root": None, "lock": None, "packages": {}}
    prepared_root = root / "third-party/src"
    if os.path.lexists(prepared_root):
        metadata = prepared_root.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o755
                or metadata.st_uid != os.getuid() or prepared_root.resolve() != prepared_root):
            raise ExportError("prepared output root has unsafe type, mode, ownership, or path")
        observed = {entry.name: entry for entry in os.scandir(prepared_root)}
        custody["root"] = {
            "device": metadata.st_dev, "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode), "mtime_ns": metadata.st_mtime_ns,
        }
    else:
        observed = {}
    unknown = sorted(set(observed) - set(expected), key=os.fsencode)
    if unknown:
        raise ExportError(f"unexpected prepared output: third-party/src/{unknown[0]}")
    if mode == "forbid" and os.path.lexists(prepared_root):
        raise ExportError("prepared output is forbidden")
    missing = sorted(set(expected) - set(observed), key=os.fsencode)
    if mode == "require" and missing:
        raise ExportError(f"required prepared output is missing: third-party/src/{missing[0]}")

    for name in sorted(observed, key=os.fsencode):
        path = prepared_root / name
        metadata = path.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o755
                or metadata.st_uid != os.getuid() or path.resolve() != path):
            raise ExportError(f"prepared output has unsafe type, mode, ownership, or path: {name}")
        record, recipe_identity = expected[name]
        try:
            inventory = preparer.verified_prepared_inventory(path, record, recipe_identity)
        except preparer.PreparationError as error:
            raise ExportError(f"prepared output {name}: {error}") from error
        entries = []
        for directory, directory_names, file_names in os.walk(path, followlinks=False):
            for entry_name in (*directory_names, *file_names):
                entry = Path(directory) / entry_name
                entry_metadata = entry.lstat()
                if entry_metadata.st_uid != os.getuid():
                    raise ExportError(f"prepared output has unsafe ownership: {entry.relative_to(root)}")
                entries.append({
                    "path": entry.relative_to(path).as_posix(),
                    "device": entry_metadata.st_dev, "inode": entry_metadata.st_ino,
                    "mode": stat.S_IMODE(entry_metadata.st_mode),
                    "size": entry_metadata.st_size, "mtime_ns": entry_metadata.st_mtime_ns,
                })
        for relative, _file_mode, _digest in inventory:
            generated.add(f"third-party/src/{name}/{relative}")
        encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")
        custody["packages"][name] = {
            "device": metadata.st_dev, "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode), "mtime_ns": metadata.st_mtime_ns,
            "inventory_sha256": hashlib.sha256(encoded).hexdigest(),
            "entries": sorted(entries, key=lambda entry: os.fsencode(entry["path"])),
        }

    lock = root / "third-party/.prepare-dependencies.lock"
    if os.path.lexists(lock):
        metadata = lock.lstat()
        if mode == "forbid":
            raise ExportError("prepared output is forbidden: third-party/.prepare-dependencies.lock")
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.getuid() or metadata.st_size != 0
                or lock.resolve() != lock):
            raise ExportError("prepared dependency lock has unsafe type, mode, ownership, or content")
        generated.add("third-party/.prepare-dependencies.lock")
        custody["lock"] = {"device": metadata.st_dev, "inode": metadata.st_ino,
                           "mode": stat.S_IMODE(metadata.st_mode),
                           "mtime_ns": metadata.st_mtime_ns}
    elif mode == "require":
        raise ExportError("required prepared output is missing: third-party/.prepare-dependencies.lock")
    if mode == "allow" and os.path.lexists(prepared_root) and custody["lock"] is None:
        raise ExportError("prepared output requires third-party/.prepare-dependencies.lock")
    return generated, custody


@contextlib.contextmanager
def _prepared_inspection_lock(root: Path):
    """Serialize inspection when the stable preparer lock already exists."""
    path = root / "third-party/.prepare-dependencies.lock"
    if not os.path.lexists(path):
        yield
        if os.path.lexists(path):
            raise ExportError("prepared state changed during unlocked inspection")
        return
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except OSError as error:
        raise ExportError(f"cannot lock prepared state for inspection: {error}") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _cargo_config_paths(root: Path, cargo_home: Path | None) -> set[Path]:
    paths = _delivered_cargo_config_paths(root)
    current = root.parent
    while True:
        paths.update((current / ".cargo/config", current / ".cargo/config.toml"))
        if current.parent == current:
            break
        current = current.parent
    if cargo_home is not None:
        paths.update((cargo_home / "config", cargo_home / "config.toml",
                      cargo_home / ".cargo/config", cargo_home / ".cargo/config.toml"))
    return paths


def validate_extracted(root: Path, cargo_home: Path | None = None, *,
                       prepared: str = "forbid") -> dict:
    """Validate one extracted schema-v2 source export without Git."""
    root = _validate_absolute_directory(root, "extracted source root")
    if cargo_home is not None:
        cargo_home = _validate_absolute_directory(cargo_home, "fresh Cargo home")
    inherited = sorted(key for key, value in os.environ.items()
                       if value and _refused_environment(key))
    if inherited:
        raise ExportError(f"refusing inherited build environment: {inherited[0]}")
    allowed_config = root / OFFLINE_CONFIG_PATH
    for path in sorted(_cargo_config_paths(root, cargo_home), key=lambda item: os.fsencode(str(item))):
        if os.path.lexists(path) and path != allowed_config:
            raise ExportError(f"competing Cargo configuration: {path}")

    helper = _load_offline_helper(root)
    preparer = _load_preparer(root)
    manifest_path = root / EXPORT_MANIFEST
    try:
        manifest_metadata = manifest_path.lstat()
    except OSError as error:
        raise ExportError(f"source export manifest is unavailable: {error}") from error
    if (not stat.S_ISREG(manifest_metadata.st_mode)
            or stat.S_IMODE(manifest_metadata.st_mode) != 0o644):
        raise ExportError("source export manifest has unsafe type or mode")
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"),
                              object_pairs_hook=helper._no_duplicate_keys)
    except helper.OfflineDependencyError as error:
        raise ExportError(str(error)) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ExportError(f"cannot read valid source export manifest {manifest_path}: {error}") from error
    top = {"schema_version", "revision", "source_entries", "archives",
           "offline_dependencies"}
    if (not isinstance(manifest, dict) or set(manifest) != top
            or type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != FULL_SCHEMA_VERSION
            or not isinstance(manifest.get("revision"), str)
            or len(manifest["revision"]) != 40
            or any(character not in "0123456789abcdef" for character in manifest["revision"])
            or not isinstance(manifest.get("archives"), list)):
        raise ExportError("source export manifest is not exact schema v2")
    association = manifest["offline_dependencies"]
    if (not isinstance(association, dict) or set(association) != OFFLINE_ASSOCIATION_FIELDS
            or any(not isinstance(value, str) for value in association.values())
            or association["payload_path"] != OFFLINE_PAYLOAD_PATH
            or association["recipe_path"] != OFFLINE_RECIPE_PATH
            or association["config_path"] != OFFLINE_CONFIG_PATH
            or any(len(association[field]) != 64
                   or any(character not in "0123456789abcdef" for character in association[field])
                   for field in ("recipe_sha256", "payload_tree_sha256", "config_sha256"))):
        raise ExportError("source export offline_dependencies association is malformed")

    source_records = _validate_source_entries(root, manifest["source_entries"], scan=False)
    recipe_path = root / OFFLINE_RECIPE_PATH
    config_path = root / OFFLINE_CONFIG_PATH
    payload = root / OFFLINE_PAYLOAD_PATH
    recipe_bytes = recipe_path.read_bytes()
    try:
        strict_manifest = helper._strict_manifest(root, preparer)
        recipe = helper._validate_recipe(
            json.loads(recipe_bytes.decode("utf-8"), object_pairs_hook=helper._no_duplicate_keys),
            strict_manifest, preparer, root
        )
        helper.check_fixed_recipe_inputs(root, recipe, strict_manifest, preparer)
        inventory = helper.payload_inventory(payload)
        payload_digest = helper.tree_content_digest(payload)
    except (helper.OfflineDependencyError, UnicodeError, json.JSONDecodeError) as error:
        raise ExportError(f"offline dependency payload: {error}") from error
    with _prepared_inspection_lock(root):
        admitted, prepared_state = _validate_prepared_state(
            root, manifest["source_entries"], strict_manifest, preparer, prepared
        )
    source_records = _validate_source_entries(root, manifest["source_entries"], admitted)
    if OFFLINE_RECIPE_PATH not in source_records:
        raise ExportError("fixed recipe is not bound as committed source")
    recipe_digest = hashlib.sha256(recipe_bytes).hexdigest()
    if (recipe_digest != association["recipe_sha256"]
            or source_records[OFFLINE_RECIPE_PATH]["sha256"] != association["recipe_sha256"]):
        raise ExportError("fixed recipe association digest mismatch")
    if (payload_digest != association["payload_tree_sha256"]
            or recipe["payload_tree_sha256"] != payload_digest):
        raise ExportError("offline dependency payload association digest mismatch")

    expected_archives = {}
    for record in strict_manifest["packages"]:
        relative = (f"{OFFLINE_PAYLOAD_PATH}/archives/"
                    f"{record['name']}-{record['version']}.crate")
        expected_archives[relative] = record["archive_sha256"]
    observed_archives = {}
    for record in manifest["archives"]:
        if (not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}
                or not isinstance(record["path"], str)
                or type(record["size"]) is not int or record["size"] < 0
                or not isinstance(record["sha256"], str)):
            raise ExportError("source export manifest contains malformed archive entry")
        path = _source_path(record["path"]).as_posix()
        if path in observed_archives:
            raise ExportError(f"duplicate source export archive entry: {path}")
        archive = root / path
        try:
            metadata = archive.lstat()
            content = archive.read_bytes()
        except OSError as error:
            raise ExportError(f"cannot read embedded archive {path}: {error}") from error
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o644
                or len(content) != record["size"]
                or hashlib.sha256(content).hexdigest() != record["sha256"]):
            raise ExportError(f"embedded archive entry mismatch: {path}")
        observed_archives[path] = record["sha256"]
    if observed_archives != expected_archives:
        raise ExportError("embedded archive set or digest mismatch")

    try:
        metadata = config_path.lstat()
    except OSError as error:
        raise ExportError(f"generated Cargo configuration is missing: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o644:
        raise ExportError("generated Cargo configuration has unsafe type or mode")
    config = config_path.read_bytes()
    try:
        expected_config = helper.replacement_config(
            payload, recipe["shared_git"], vendor_path=f"{OFFLINE_PAYLOAD_PATH}/vendor"
        )
    except helper.OfflineDependencyError as error:
        raise ExportError(str(error)) from error
    if (config != expected_config
            or hashlib.sha256(config).hexdigest() != association["config_sha256"]):
        raise ExportError("generated Cargo configuration custody mismatch")
    try:
        if manifest_path.read_bytes() != manifest_bytes or recipe_path.read_bytes() != recipe_bytes:
            raise ExportError("source identity changed during extracted validation")
        if config_path.read_bytes() != config:
            raise ExportError("generated Cargo configuration changed during validation")
        if (helper.payload_inventory(payload) != inventory
                or helper.tree_content_digest(payload) != payload_digest):
            raise ExportError("offline dependency payload changed during validation")
    except OSError as error:
        raise ExportError(f"bound input disappeared during validation: {error}") from error
    with _prepared_inspection_lock(root):
        final_admitted, final_prepared = _validate_prepared_state(
            root, manifest["source_entries"], strict_manifest, preparer, prepared
        )
    if final_admitted != admitted or final_prepared != prepared_state:
        raise ExportError("prepared state changed during extracted validation")
    _validate_source_entries(root, manifest["source_entries"], final_admitted)
    return {
        "identity": {
            "schema_version": FULL_SCHEMA_VERSION,
            "revision": manifest["revision"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "recipe_sha256": recipe_digest,
            "payload_tree_sha256": payload_digest,
            "config_sha256": hashlib.sha256(config).hexdigest(),
        },
        "prepared": prepared_state,
        "payload_inventory": inventory,
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--offline", action="store_true", help="forbid archive downloads")
    parser.add_argument("--archive-dir", type=Path,
                        help="directory containing explicitly supplied .crate archives")
    parser.add_argument("--offline-payload", type=Path,
                        help="verified complete offline dependency payload")
    parser.add_argument("--nightly-rustc", type=Path,
                        help="selected pinned nightly rustc used to verify the payload")
    parser.add_argument("--verify-extracted", type=Path,
                        help="validate an extracted full source export")
    parser.add_argument("--cargo-home", type=Path,
                        help="fresh Cargo home whose configuration custody is checked")
    parser.add_argument("--prepared", choices=("forbid", "allow", "require"),
                        help="admit recipe-owned prepared outputs while validating extraction")
    options = parser.parse_args(arguments)
    root = Path(__file__).resolve().parents[1]
    archive_dir = options.archive_dir.resolve() if options.archive_dir is not None else None
    try:
        if options.verify_extracted is not None:
            if options.cargo_home is None:
                raise ExportError("verify-extracted requires cargo-home")
            if (options.output is not None or options.offline or options.archive_dir is not None
                    or options.offline_payload is not None or options.nightly_rustc is not None):
                raise ExportError("verify-extracted cannot be combined with export arguments")
            validate_extracted(options.verify_extracted, options.cargo_home,
                               prepared=options.prepared or "forbid")
        else:
            if options.output is None:
                raise ExportError("output is required for source export")
            if options.cargo_home is not None:
                raise ExportError("cargo-home is only accepted with verify-extracted")
            if options.prepared is not None:
                raise ExportError("prepared is only accepted with verify-extracted")
            run(
                root, options.output, offline=options.offline, archive_dir=archive_dir,
                offline_payload=options.offline_payload, nightly_rustc=options.nightly_rustc,
            )
    except ExportError as error:
        print(f"export-source: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
