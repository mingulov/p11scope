#!/usr/bin/env python3
"""Export committed source and pinned original crates for offline reconstruction."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile


ARCHIVE_ROOT = "pkcs11-scope-source"
EXPORT_MANIFEST = ".p11scope-source-export.json"
SCHEMA_VERSION = 1


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


def _build_archive(root: Path, revision: str, tracked: dict[str, tuple[str, str]],
                   originals: list[tuple[dict, Path]], destination: Path,
                   environment: dict[str, str]) -> None:
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
            content = path.read_bytes()
            archive_entries.append({
                "path": f"third-party/archives/{record['name']}-{record['version']}.crate",
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            })

        export_manifest = {
            "schema_version": SCHEMA_VERSION,
            "revision": revision,
            "source_entries": sorted(source_entries, key=lambda item: item["path"].encode()),
            "archives": sorted(archive_entries, key=lambda item: item["path"].encode()),
        }
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
                            git_mode = tracked[path.as_posix()][0]
                            _add_bytes(output, name, content,
                                       0o755 if git_mode == "100755" else 0o644)
                        else:
                            _add_symlink(output, name, symlink_targets[path.as_posix()])
                    known_directories = {member.name.rstrip("/") for member in members if member.isdir()}
                    for directory in ("third-party", "third-party/archives"):
                        if directory not in known_directories:
                            output.addfile(_tar_info(f"{ARCHIVE_ROOT}/{directory}", 0o755, directory=True))
                    ordered_originals = sorted(
                        originals,
                        key=lambda pair: (
                            f"third-party/archives/{pair[0]['name']}-{pair[0]['version']}.crate"
                        ).encode(),
                    )
                    for item, (_record, path) in zip(export_manifest["archives"], ordered_originals):
                        _add_bytes(output, f"{ARCHIVE_ROOT}/{item['path']}", path.read_bytes())
                    _add_bytes(output, f"{ARCHIVE_ROOT}/{EXPORT_MANIFEST}", manifest_bytes)
    os.chmod(destination, 0o644)


def run(root: Path, output: Path, *, offline: bool, archive_dir: Path | None) -> None:
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
    preparer = _load_preparer(root)
    try:
        manifest = preparer.load_manifest(root)
    except preparer.PreparationError as error:
        raise ExportError(str(error)) from error
    _require_regular_inputs(tracked, _required_inputs(manifest), revision)
    archive_targets = [
        f"third-party/archives/{record['name']}-{record['version']}.crate"
        for record in manifest["packages"]
    ]
    if len(archive_targets) != len(set(archive_targets)):
        duplicate = next(path for path in archive_targets if archive_targets.count(path) > 1)
        raise ExportError(f"duplicate embedded archive destination: {duplicate}")
    _reject_generated_collisions(tracked, [EXPORT_MANIFEST, *archive_targets])

    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.export-", dir=output.parent))
    try:
        acquisition = stage / "originals"
        acquisition.mkdir(mode=0o700)
        originals = []
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
        _build_archive(root, revision, tracked, originals, built, environment)
        try:
            os.link(built, output, follow_symlinks=False)
        except FileExistsError as error:
            raise ExportError(f"output already exists: {output}") from error
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--offline", action="store_true", help="forbid archive downloads")
    parser.add_argument("--archive-dir", type=Path,
                        help="directory containing explicitly supplied .crate archives")
    options = parser.parse_args(arguments)
    root = Path(__file__).resolve().parents[1]
    archive_dir = options.archive_dir.resolve() if options.archive_dir is not None else None
    try:
        run(root, options.output, offline=options.offline, archive_dir=archive_dir)
    except ExportError as error:
        print(f"export-source: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
