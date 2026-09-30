#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package the tested official binaries without publishing private receipts."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
ARTIFACTS = ("p11scope", "p11scope-discover", "p11scope-discover-glibc", "p11scope-discover-musl")
LICENSES = ("LICENSE", "LICENSES/GPL-2.0-only.txt", "LICENSES/GPL-2.0-or-later.txt")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def regular(path: Path) -> bytes:
    """Read stable regular bytes; a symlink in any path component refuses."""
    if path.resolve(strict=True) != path.absolute():
        raise ValueError(f"symbolic link in input: {path.name}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"input must be regular: {path.name}")
        data = source.read()
        after = os.fstat(source.fileno())
        now = path.stat(follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(now):
            raise ValueError(f"input changed while read: {path.name}")
    return data


def relative_name(name: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or any(ord(c) < 32 for c in name):
        raise ValueError("invalid relative payload path")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(p in (".", "..") for p in path.parts):
        raise ValueError("unsafe relative payload path")
    return name


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes):
    return json.loads(data, object_pairs_hook=unique_object)


def git(root: Path, *args: str) -> bytes:
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    result = subprocess.run(["git", *args], cwd=root, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return result.stdout


def source_identity(root: Path):
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("source worktree must be clean")
    head = git(root, "rev-parse", "HEAD").decode().strip()
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    versions = []
    for name in ("Cargo.toml", "crates/discover/Cargo.toml"):
        # Both version fields are intentionally restricted to an ordinary release.
        text = git(root, "show", f"HEAD:{name}").decode()
        package = text.split("[package]", 1)[1].split("\n[", 1)[0]
        found = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', package, re.M)
        if not found:
            raise ValueError(f"invalid release version in {name}")
        versions.append(found[1])
    if versions[0] != versions[1]:
        raise ValueError("observer and helper versions differ")
    return head, tree, versions[0]


def receipt_facts(receipt: Path, head: str, tree: str):
    if regular(receipt / "status") != b"0\n":
        raise ValueError("receipt status is not successful")
    facts = {}
    for line in regular(receipt / "facts.log").decode().splitlines():
        key, separator, value = line.partition("\t")
        if not separator or not key or key in facts:
            raise ValueError("malformed or duplicate receipt fact")
        facts[key] = value
    if facts.get("head") != head or facts.get("tree") != tree:
        raise ValueError("receipt revision does not match the source")
    if facts.get("terminal_status") != "0" or facts.get("checker_status") != "0":
        raise ValueError("receipt terminal or checker status is not successful")
    value = facts.get("release_artifacts_sha256", "")
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("missing release artifact ledger digest")
    return facts


def artifacts(receipt: Path, expected: str):
    spec = importlib.util.spec_from_file_location("release_artifacts", Path(__file__).with_name("release-artifacts.py"))
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    ledger = receipt / "artifacts/release-artifacts.sha256"
    dist = receipt / "work/dist"
    hashes = verifier.verify(dist, ledger, expected)
    if set(hashes) != set(ARTIFACTS):
        raise ValueError("unexpected release artifact inventory")
    contents = {name: regular(dist / name) for name in ARTIFACTS}
    if any(digest(data) != hashes[name] for name, data in contents.items()):
        raise ValueError("release artifact digest changed during packaging")
    return hashes, contents


def validate_notice_contents(root: Path, manifest, payload):
    recipe_bytes = git(root, "show", "HEAD:third-party/licenses/sources.json")
    recipe = parse_json(recipe_bytes)
    if manifest.get("recipe_sha256") != digest(recipe_bytes):
        raise ValueError("notice recipe does not match committed source")
    for key in ("upstream_inputs", "musl", "native_runtime"):
        expected = recipe["files" if key == "upstream_inputs" else key]
        if manifest.get(key) != expected:
            raise ValueError(f"notice recipe provenance mismatch: {key}")
    required = {"licenses/upstream/" + name: item["sha256"]
                for name, item in recipe["files"].items()}
    for item in recipe["musl"]:
        required[f"licenses/musl-{item['version']}-source.tar.gz"] = item["sha256"]
    expected_tools = []
    for tool in recipe["toolchains"]:
        expected_tools.append({"name": tool["name"], "rustc_verbose_version": tool["rustc_verbose_version"]})
        required.update({item["payload"]: item["sha256"] for item in tool["files"]})
    if manifest.get("toolchains") != expected_tools:
        raise ValueError("notice toolchains do not match committed recipe")
    required["licenses/p11scope-GPL-3.0-or-later.txt"] = digest(git(root, "show", "HEAD:LICENSE"))
    for license_id in ("GPL-2.0-only", "GPL-2.0-or-later"):
        required[f"licenses/p11scope-{license_id}.txt"] = digest(git(root, "show", f"HEAD:LICENSES/{license_id}.txt"))
    for name, expected in required.items():
        if name not in payload or digest(payload[name]) != expected:
            raise ValueError(f"notice required payload missing or changed: {name}")
    graphs = manifest.get("graphs")
    if not isinstance(graphs, dict) or set(graphs) != {"host", "bpf"}:
        raise ValueError("notice graphs must include host and BPF workspaces")
    for graph in graphs.values():
        packages = graph.get("packages", [])
        identifiers = {package["id"] for package in packages}
        if not identifiers or len(identifiers) != len(packages):
            raise ValueError("notice graph package inventory is empty or duplicated")
        covered = set()
        for record in graph.get("notices", []):
            owners = set(record["packages"])
            if not owners or not owners <= identifiers:
                raise ValueError("notice graph contains invalid package ownership")
            covered.update(owners)
            if record["file"] not in payload or digest(payload[record["file"]]) != record["text_sha256"]:
                raise ValueError("notice graph text is missing or changed")
        if covered != identifiers:
            raise ValueError("notice graph coverage is incomplete")
        originals = graph.get("original_license_files", [])
        if not originals:
            raise ValueError("notice graph lacks original licensing files")
        for record in originals:
            if (record["package"] not in identifiers or record["file"] not in payload
                    or digest(payload[record["file"]]) != record["sha256"]):
                raise ValueError("notice original licensing file is missing or changed")


def notices_payload(root: Path, directory: Path, head: str, tree: str):
    manifest_bytes = regular(directory / "notices.json")
    manifest = parse_json(manifest_bytes)
    if (manifest.get("schema_version") != 1 or manifest.get("head") != head
            or manifest.get("tree") != tree or manifest.get("cargo_about_version") != "0.9.2"):
        raise ValueError("notice revision or generator identity mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict) or "NOTICES.md" not in files or "notices.json" in files:
        raise ValueError("invalid notice inventory")
    payload = {"notices.json": manifest_bytes}
    for name, expected in files.items():
        relative_name(name)
        data = regular(directory / name)
        if digest(data) != expected:
            raise ValueError(f"notice digest mismatch: {name}")
        payload[name] = data
    actual = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("notice inventory contains a symlink")
        if not path.is_dir():
            actual.add(path.relative_to(directory).as_posix())
    if actual != set(payload):
        raise ValueError("notice inventory differs from its manifest")
    validate_notice_contents(root, manifest, payload)
    return payload, digest(manifest_bytes)


def source_archive(root: Path, path: Path, head: str):
    """Validate every source byte against Git, never just a claimed revision."""
    data = regular(path)
    tracked = {}
    for item in git(root, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if item:
            metadata, name = item.split(b"\t", 1)
            mode, kind, blob = metadata.split()
            if kind != b"blob":
                raise ValueError("source contains a submodule")
            tracked[name.decode()] = (mode.decode(), blob.decode())
    members = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if member.name == "p11scope-source" and member.isdir():
                continue
            if not member.name.startswith("p11scope-source/"):
                raise ValueError("unexpected source archive root")
            name = relative_name(member.name[len("p11scope-source/"):].rstrip("/"))
            if name in members:
                raise ValueError("duplicate source archive member")
            if member.isdir():
                members[name] = None
                continue
            if member.isreg():
                content = archive.extractfile(member).read()
                mode = f"{member.mode:04o}"
                kind = "file"
            elif member.issym() and tracked.get(name, (None,))[0] == "120000":
                content = member.linkname.encode()
                mode, kind = "120000", "symlink"
            else:
                raise ValueError("unsafe source archive member type")
            members[name] = (mode, kind, content)
    files = {name: value for name, value in members.items() if value is not None}
    manifest_name = ".p11scope-source-export.json"
    if manifest_name not in files:
        raise ValueError("source export manifest is missing")
    manifest = parse_json(files[manifest_name][2])
    if manifest.get("schema_version") != 1 or manifest.get("revision") != head:
        raise ValueError("source archive revision or format mismatch (expected networked export v1)")
    records = manifest.get("source_entries", [])
    if len(records) != len(tracked) or {r["path"] for r in records} != set(tracked):
        raise ValueError("source manifest inventory differs from committed source")
    for record in records:
        name = record["path"]
        if name not in files:
            raise ValueError("source archive inventory is incomplete")
        mode, kind, content = files[name]
        if (record["mode"] != mode or record["kind"] != kind or record["size"] != len(content)
                or record["sha256"] != digest(content)):
            raise ValueError(f"source manifest digest or mode mismatch: {name}")
        git_mode, blob = tracked[name]
        expected_mode = "0755" if git_mode == "100755" else "120000" if git_mode == "120000" else "0644"
        git_blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if mode != expected_mode or git_blob != blob:
            raise ValueError(f"source bytes differ from committed Git blob: {name}")
    recipe = parse_json(git(root, "show", "HEAD:third-party/sources.json"))
    expected_archives = {}
    for item in recipe["packages"]:
        name = f"third-party/archives/{item['name']}-{item['version']}.crate"
        # Source recipe pins the upstream archive, independently of the export.
        expected_archives[name] = item["archive_sha256"]
    records = manifest.get("archives", [])
    if len(records) != len(expected_archives) or {r["path"] for r in records} != set(expected_archives):
        raise ValueError("source original archive inventory mismatch")
    for record in records:
        name = record["path"]
        if name not in files or files[name][1] != "file":
            raise ValueError("source original archive missing")
        content = files[name][2]
        if record["size"] != len(content) or record["sha256"] != digest(content) or digest(content) != expected_archives[name]:
            raise ValueError("source original archive checksum mismatch")
    if set(files) != set(tracked) | set(expected_archives) | {manifest_name}:
        raise ValueError("source archive inventory contains unlisted data")
    return data


def write_archive(path: Path, prefix: str, payload):
    with path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                for name, (data, mode) in sorted(payload.items()):
                    info = tarfile.TarInfo(f"{prefix}/{name}")
                    info.mode, info.size, info.mtime = mode, len(data), 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
    path.chmod(0o644)


def package(root: Path, receipt: Path, notices: Path, source: Path, output: Path):
    for path in (root, receipt, notices, source, output):
        if not path.is_absolute():
            raise ValueError("all paths must be absolute")
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists")
    parent = output.parent
    if parent.resolve(strict=True) != parent or not parent.is_dir():
        raise ValueError("output parent must be a canonical directory")
    if parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077:
        raise ValueError("output parent must be a private directory owned by the caller")
    if output.is_relative_to(root):
        raise ValueError("public output must be outside the source checkout")
    head, tree, version = source_identity(root)
    facts = receipt_facts(receipt, head, tree)
    hashes, binaries = artifacts(receipt, facts["release_artifacts_sha256"])
    notices_files, notices_hash = notices_payload(root, notices, head, tree)
    source_data = source_archive(root, source, head)
    source_name = f"p11scope-{version}-source.tar.gz"
    provenance = {
        "schema_version": 1, "version": version, "head": head, "tree": tree,
        "build_receipt_status": 0, "release_artifacts_sha256": facts["release_artifacts_sha256"],
        "artifacts": hashes, "notices_manifest_sha256": notices_hash,
        "source": {"file": source_name, "sha256": digest(source_data), "format": "networked-source-export-v1"},
        "p11scope_features": [], "rust": (root / ".release-rust-version").read_text(encoding="utf-8").strip(), "bpf_rust": "nightly-2026-05-20",
        "scope": "Safe-only official build. Consult the GitHub release notes for qualified kernels and lanes; system-wide tracing remains preview.",
    }
    public = encoded(provenance)
    common = {name: (regular(root / name), 0o644) for name in LICENSES}
    common.update({"notices/" + name: (data, 0o644) for name, data in notices_files.items()})
    common["RELEASE.json"] = (public, 0o644)
    # Recheck retained identities before emitting anything; final rereads below
    # also catch an input changed while the archives were written.
    if source_identity(root) != (head, tree, version):
        raise ValueError("source revision changed")
    output.mkdir(mode=0o700)
    try:
        builds = (
            (f"p11scope-{version}-x86_64-linux-musl", "p11scope", "p11scope"),
            (f"p11scope-discover-{version}-x86_64-linux-gnu", "p11scope-discover", "p11scope-discover-glibc"),
            (f"p11scope-discover-{version}-x86_64-linux-musl", "p11scope-discover", "p11scope-discover-musl"),
        )
        for prefix, installed_name, artifact in builds:
            payload = dict(common)
            payload[installed_name] = (binaries[artifact], 0o755)
            write_archive(output / f"{prefix}.tar.gz", prefix, payload)
        (output / source_name).write_bytes(source_data)
        (output / "RELEASE.json").write_bytes(public)
        sums = "".join(f"{digest(regular(path))}  {path.name}\n" for path in sorted(output.iterdir()))
        (output / "SHA256SUMS").write_text(sums)
        if receipt_facts(receipt, head, tree) != facts:
            raise ValueError("receipt changed during packaging")
        artifacts(receipt, facts["release_artifacts_sha256"])
        if notices_payload(root, notices, head, tree)[1] != notices_hash or regular(source) != source_data:
            raise ValueError("source or notices changed during packaging")
        if source_identity(root) != (head, tree, version):
            raise ValueError("source revision changed during packaging")
        for path in output.iterdir():
            path.chmod(0o644)
    except BaseException:
        shutil.rmtree(output)
        raise
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("receipt", "notices", "source", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = package(Path(__file__).resolve().parents[1], args.receipt, args.notices, args.source, args.output)
        print(f"Public release packages ready: v{result['version']} at {result['head']}")
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"package-release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
