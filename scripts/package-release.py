#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package the tested official binaries without publishing private receipts."""

from __future__ import annotations

import argparse
import datetime
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
import tempfile

sys.dont_write_bytecode = True
ARTIFACTS = ("p11scope", "p11scope-discover", "p11scope-discover-glibc", "p11scope-discover-musl")
LICENSES = ("LICENSE", "COPYRIGHT", "LICENSES/GPL-2.0-only.txt", "LICENSES/GPL-2.0-or-later.txt")
# The trusted build-release.sh receipt covers one official selection per capture mode.
OFFICIAL_P11SCOPE_FEATURES = {
    "full": (),
    "p0": ("stub-object-attributes",),
}
OFFICIAL_SCOPE = {
    "full": "FULL official build with object-attribute capture enabled. Live capture requires a Multi-capable Linux x86-64 host (normally 6.6+ or working backports), BTF and privileges; safe scoped Singles is available on eligible hosts. Offline/helper commands do not require live capability. `--system` selects whole-machine scope. Consult release notes for qualified lanes and known limitations.",
    "p0": "P0 official build with object-attribute capture disabled. Live capture requires a Multi-capable Linux x86-64 host (normally 6.6+ or working backports), BTF and privileges; safe scoped Singles is available on eligible hosts. Offline/helper commands do not require live capability. `--system` selects whole-machine scope. Consult release notes for qualified lanes and known limitations.",
}


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


# System packages reuse the exact tarball bytes (no second build). The
# observer is the static musl binary; the helper is the glibc binary
# because DEB/RPM target glibc distributions (Debian/Ubuntu, Fedora/RHEL)
# where a musl-dynamic helper would not execute without a musl loader.
# The musl helper stays tarball-only for musl systems (Alpine uses apk).
SYSTEM_PACKAGE_OBSERVER = "p11scope"
SYSTEM_PACKAGE_HELPER = "p11scope-discover-glibc"
SYSTEM_PACKAGE_MAINTAINER = "mingulov <mingulov@users.noreply.github.com>"
SYSTEM_PACKAGE_SUMMARY = "Non-interposing PKCS#11 observer on eBPF uprobes"
SYSTEM_PACKAGE_URL = "https://github.com/mingulov/p11scope"


def commit_epoch(root: Path) -> int:
    """Commit time as SOURCE_DATE_EPOCH for deterministic system packages."""
    out = git(root, "show", "-s", "--format=%ct", "HEAD").decode().strip()
    if not re.fullmatch(r"[0-9]+", out):
        raise ValueError("invalid commit timestamp")
    value = int(out)
    if value <= 0:
        raise ValueError("invalid commit timestamp")
    return value


def system_package_description(capture_mode: str, version: str) -> str:
    variant = ("FULL official build with object-attribute capture enabled"
               if capture_mode == "full" else
               "P0 official build with object-attribute capture disabled")
    return (f"{SYSTEM_PACKAGE_SUMMARY}.\n"
            f" This is the {variant} ({version}).\n"
            " .\n"
            " Installed files carry no file capabilities, set-id bits,\n"
            " services or maintainer scripts.\n"
            " See /usr/share/doc/p11scope/RELEASE.json for build provenance.")


def write_tree(base: Path, files, epoch: int):
    """Write sorted files with fixed modes, ownership-neutral mtimes."""
    for name, (data, mode) in sorted(files.items()):
        target = base / name
        if target.is_symlink() or target.exists():
            raise ValueError(f"system package staging collision: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(mode)
        os.utime(target, (epoch, epoch))
    for directory in sorted(base.rglob("*")):
        if directory.is_dir() and not directory.is_symlink():
            directory.chmod(0o755)
            os.utime(directory, (epoch, epoch))
    base.chmod(0o755)
    os.utime(base, (epoch, epoch))


def run_tool(arguments, epoch: int, what: str):
    environment = {k: v for k, v in os.environ.items()
                   if k not in ("SOURCE_DATE_EPOCH",)}
    environment["SOURCE_DATE_EPOCH"] = str(epoch)
    # LC_ALL=C for stable tool messages; PATH is the caller's.
    environment["LC_ALL"] = "C"
    result = subprocess.run(arguments, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace")[:500]
        raise ValueError(f"{what} failed with exit {result.returncode}: {detail}")


def build_deb(staging: Path, observer: bytes, helper: bytes, docs,
              version: str, capture_mode: str, epoch: int) -> bytes:
    dpkg_deb = shutil.which("dpkg-deb")
    if not dpkg_deb:
        raise ValueError("dpkg-deb is required to build the DEB package")
    root = staging / "deb"
    control = (f"Package: p11scope\nVersion: {version}\nSection: utils\n"
               f"Priority: optional\nArchitecture: amd64\n"
               f"Maintainer: {SYSTEM_PACKAGE_MAINTAINER}\n"
               f"Description: {system_package_description(capture_mode, version)}\n")
    files = {"DEBIAN/control": (control.encode(), 0o644),
             "usr/bin/p11scope": (observer, 0o755),
             "usr/bin/p11scope-discover": (helper, 0o755)}
    for name, (data, mode) in docs.items():
        files[f"usr/share/doc/p11scope/{name}"] = (data, mode)
    write_tree(root, files, epoch)
    output = staging / "p11scope.deb"
    run_tool([dpkg_deb, "--build", "--root-owner-group", str(root), str(output)],
             epoch, "dpkg-deb")
    return regular(output)


def build_rpm(staging: Path, observer: bytes, helper: bytes, docs,
              version: str, capture_mode: str, epoch: int) -> bytes:
    rpmbuild = shutil.which("rpmbuild")
    if not rpmbuild:
        raise ValueError("rpmbuild is required to build the RPM package")
    date = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    changelog_date = date.strftime("%a %b %d %Y")
    top = staging / "rpm"
    for name in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (top / name).mkdir(parents=True, exist_ok=True)
    buildroot = staging / "rpmbuild-root"
    files = {"usr/bin/p11scope": (observer, 0o755),
             "usr/bin/p11scope-discover": (helper, 0o755)}
    for name, (data, mode) in docs.items():
        files[f"usr/share/doc/p11scope/{name}"] = (data, mode)
    write_tree(buildroot, files, epoch)
    variant = ("FULL official build with object-attribute capture enabled"
               if capture_mode == "full" else
               "P0 official build with object-attribute capture disabled")
    doc_entries = "\n".join(f"/usr/share/doc/p11scope/{name}"
                            for name in sorted(docs))
    spec = (f"Name: p11scope\nVersion: {version}\nRelease: 1\n"
            f"Summary: {SYSTEM_PACKAGE_SUMMARY}\nLicense: GPL-3.0-or-later\n"
            f"URL: {SYSTEM_PACKAGE_URL}\nBuildArch: x86_64\n"
            "%global __os_install_post %{nil}\n"
            "%description\n"
            f"{SYSTEM_PACKAGE_SUMMARY}.\n"
            f"This is the {variant} ({version}).\n"
            "Installed files carry no file capabilities, set-id bits,\n"
            "services or maintainer scripts.\n"
            "See /usr/share/doc/p11scope/RELEASE.json for build provenance.\n"
            "%files\n/usr/bin/p11scope\n/usr/bin/p11scope-discover\n"
            "%dir /usr/share/doc/p11scope\n"
            f"{doc_entries}\n"
            "%changelog\n"
            f"* {changelog_date} {SYSTEM_PACKAGE_MAINTAINER} - {version}-1\n"
            f"- {variant}.\n")
    (top / "SPECS" / "p11scope.spec").write_text(spec)
    run_tool([rpmbuild, "-bb", "--define", f"_topdir {top}",
              "--define", "_buildhost reproducible",
              "--define", "use_source_date_epoch_as_buildtime 1",
              "--buildroot", str(buildroot), str(top / "SPECS" / "p11scope.spec")],
             epoch, "rpmbuild")
    found = sorted((top / "RPMS").rglob("*.rpm"))
    if len(found) != 1:
        raise ValueError("rpmbuild did not produce exactly one RPM")
    return regular(found[0])


def package(root: Path, receipt: Path, notices: Path, source: Path, output: Path,
            capture_mode: str = "full"):
    if capture_mode not in OFFICIAL_P11SCOPE_FEATURES:
        raise ValueError(f"unknown capture mode: {capture_mode}")
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
    if facts.get("capture_mode") != capture_mode:
        raise ValueError("receipt capture mode does not match --capture-mode")
    hashes, binaries = artifacts(receipt, facts["release_artifacts_sha256"])
    notices_files, notices_hash = notices_payload(root, notices, head, tree)
    source_data = source_archive(root, source, head)
    source_name = f"p11scope-{version}-source.tar.gz"
    pre_provenance = {
        "schema_version": 1, "version": version, "head": head, "tree": tree,
        "build_receipt_status": 0, "release_artifacts_sha256": facts["release_artifacts_sha256"],
        "artifacts": hashes, "notices_manifest_sha256": notices_hash,
        "source": {"file": source_name, "sha256": digest(source_data), "format": "networked-source-export-v1"},
        "p11scope_features": list(OFFICIAL_P11SCOPE_FEATURES[capture_mode]),
        "rust": (root / ".release-rust-version").read_text(encoding="utf-8").strip(), "bpf_rust": "nightly-2026-05-20",
        "scope": OFFICIAL_SCOPE[capture_mode],
    }
    # System packages embed the pre-package provenance (they cannot contain
    # their own hashes); the top-level and tarball RELEASE.json records the
    # final hashes below.
    pre_public = encoded(pre_provenance)
    licenses = {name: (regular(root / name), 0o644) for name in LICENSES}
    licenses.update({"notices/" + name: (data, 0o644) for name, data in notices_files.items()})
    system_docs = dict(licenses)
    system_docs["RELEASE.json"] = (pre_public, 0o644)
    epoch = commit_epoch(root)
    deb_name = f"p11scope_{version}_amd64.deb"
    rpm_name = f"p11scope-{version}-1.x86_64.rpm"
    with tempfile.TemporaryDirectory(prefix="p11scope-system-", dir=parent) as staging_name:
        staging = Path(staging_name)
        staging.chmod(0o700)
        deb_data = build_deb(staging, binaries[SYSTEM_PACKAGE_OBSERVER], binaries[SYSTEM_PACKAGE_HELPER],
                             system_docs, version, capture_mode, epoch)
        rpm_data = build_rpm(staging, binaries[SYSTEM_PACKAGE_OBSERVER], binaries[SYSTEM_PACKAGE_HELPER],
                             system_docs, version, capture_mode, epoch)
    provenance = dict(pre_provenance)
    provenance["packages"] = {
        "deb": {"file": deb_name, "sha256": digest(deb_data)},
        "rpm": {"file": rpm_name, "sha256": digest(rpm_data)},
    }
    public = encoded(provenance)
    common = dict(licenses)
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
        (output / deb_name).write_bytes(deb_data)
        (output / rpm_name).write_bytes(rpm_data)
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
    parser.add_argument("--capture-mode", choices=("full", "p0"), default="full")
    args = parser.parse_args()
    try:
        result = package(Path(__file__).resolve().parents[1], args.receipt, args.notices, args.source, args.output,
                         capture_mode=args.capture_mode)
        print(f"Public release packages ready: v{result['version']} at {result['head']}")
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"package-release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
