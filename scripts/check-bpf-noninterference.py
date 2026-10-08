#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare all bytes of the three default BPF objects from fresh snapshots.

Run an explicit --repeat-baseline diagnostic first, then compare distinct
baseline/candidate commits. Neither mode installs tools or uses target caches.
The baseline decision is reviewed separately from this same-environment check.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
COORDINATOR_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(COORDINATOR_DIRECTORY))
from _loader import load_path

OBJECT_NAMES = ("p11scope-ebpf", "p11scope-ebpf-inventory", "p11scope-ebpf-inventory-callers")
RELEASE_RUST = "1.98.1"
BPF_RUST = "nightly-2026-05-20"
BPF_LINKER = "0.10.4"
MAX_LOG_BYTES = 64 * 1024 * 1024


class CheckError(Exception):
    """A build or comparison has no trustworthy passing result."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_command(argv: list[str], cwd: Path, env: dict[str, str], evidence: Path,
                label: str, timeout: int = 120, stdout_path: Path | None = None) -> Path:
    """Retain output and stop the owned process group on timeout.

    Capture files have no byte cap. read_output limits text parsed later;
    failed stdout and retained stderr may grow until the process exits.
    """
    stdout_path = stdout_path or evidence / (label + ".stdout")
    stderr_path = evidence / (label + ".stderr")
    started = time.monotonic()
    status = None
    timed_out = False
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
            try:
                status = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    status = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    status = process.wait(timeout=10)
    finally:
        with (evidence / "commands.jsonl").open("a", encoding="utf-8") as record:
            record.write(json.dumps({"argv": argv, "cwd": str(cwd), "status": status,
                                     "timeout_seconds": timeout, "capture_byte_limit": None,
                                     "read_output_byte_limit": MAX_LOG_BYTES,
                                     "timed_out": timed_out, "elapsed_seconds": round(time.monotonic() - started, 3),
                                     "stdout": str(stdout_path), "stderr": str(stderr_path)}) + "\n")
    if timed_out or status != 0:
        raise CheckError(f"{label} failed (status={status}, timed_out={timed_out}); see {stderr_path}")
    return stdout_path


def read_output(path: Path, *, preserve_newlines: bool = False) -> str:
    if path.stat().st_size > MAX_LOG_BYTES:
        raise CheckError(f"command output exceeds {MAX_LOG_BYTES} bytes: {path}")
    with path.open(encoding="utf-8", newline="" if preserve_newlines else None) as source:
        return source.read()


def rustup_version_banner(help_output: str) -> str:
    # Admit a numeric release and an optional hexadecimal commit/date suffix.
    # Do not strip a malformed first line or recover a later matching banner.
    if any(not character.isprintable() and character not in "\n\t" for character in help_output):
        raise CheckError("invalid rustup version banner: unexpected control character")
    banner = help_output.split("\n", 1)[0]
    if re.fullmatch(r"rustup [0-9]+\.[0-9]+\.[0-9]+(?: \([0-9a-f]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\))?", banner) is None:
        raise CheckError("invalid rustup version banner")
    return banner


def validate_path(environment: dict[str, str]) -> None:
    if any(not entry or not Path(entry).is_absolute()
           for entry in environment.get("PATH", "").split(os.pathsep)):
        raise CheckError("PATH must contain only nonempty absolute directory entries")


def clean_environment(scratch: Path) -> dict[str, str]:
    environment = dict(os.environ)
    validate_path(environment)
    for key in list(environment):
        if (key.startswith(("CARGO_", "RUST", "P11SCOPE_", "CC_", "CFLAGS_", "CXX_"))
                and key != "RUSTUP_HOME") or key in {
                    "CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS", "HOST_CC", "TARGET_CC",
                    "HOST_CFLAGS", "TARGET_CFLAGS", "LLVM_PROFILE_FILE", "LLVM_PROFILE_FILE_NAME",
                }:
            del environment[key]
    cargo_home = scratch / "cargo-home"
    cargo_home.mkdir(mode=0o700)
    # Explicit paths override any inherited user configuration. The fresh
    # CARGO_HOME excludes global Cargo configuration and existing build caches.
    rustup_home = Path(environment.get("RUSTUP_HOME", str(Path.home() / ".rustup"))).resolve()
    environment.update({
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(scratch / "target"),
        "CARGO_BUILD_BUILD_DIR": str(scratch / "build"),
        "CARGO_INCREMENTAL": "0",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join([
            f"--remap-path-prefix={scratch / 'source'}=/p11scope",
            f"--remap-path-prefix={scratch}=/p11scope-build",
            f"--remap-path-prefix={cargo_home}=/cargo",
            f"--remap-path-prefix={rustup_home}=/rustup",
        ]),
        "TMPDIR": str(scratch / "tmp"),
        "LC_ALL": "C",
    })
    return environment


def tool_identity(cwd: Path, env: dict[str, str], evidence: Path, label: str) -> dict:
    """Record only the tools and packages that supply this build recipe."""
    records = {}
    # cargo.sh and the nested build both execute PATH cargo. Record that
    # dispatcher as well as rustup's selected channel-specific executables.
    for tool in ("cargo", "rustup", "clang-18", "bpf-linker", "llvm-readelf", "python3", "dpkg-query"):
        resolved = shutil.which(tool, path=env["PATH"])
        if resolved is None:
            raise CheckError(f"required tool is absent: {tool}")
        path = Path(resolved).resolve(strict=True)
        if not path.is_file():
            raise CheckError(f"tool is not a regular file: {path}")
        records[tool] = {"path": str(Path(resolved)), "realpath": str(path), "sha256": sha256(path)}
    for channel in (RELEASE_RUST, BPF_RUST):
        for tool in ("cargo", "rustc"):
            output = run_command(["rustup", "which", "--toolchain", channel, tool], cwd, env,
                                 evidence, f"{label}-which-{channel}-{tool}")
            path = Path(read_output(output).strip())
            if not path.is_absolute() or not path.is_file():
                raise CheckError(f"rustup returned an invalid {channel} {tool} path")
            version = run_command([str(path), "-vV" if tool == "rustc" else "--version"], cwd, env,
                                  evidence, f"{label}-version-{channel}-{tool}")
            records[f"{channel}-{tool}"] = {"path": str(path), "realpath": str(path.resolve()),
                                              "sha256": sha256(path), "version": read_output(version).strip()}
    for tool in ("rustup", "clang-18", "bpf-linker", "python3"):
        query = "--help" if tool == "rustup" else "--version"
        output = run_command([tool, query], cwd, env, evidence, f"{label}-version-{tool}")
        version = read_output(output, preserve_newlines=tool == "rustup")
        records[tool]["version"] = rustup_version_banner(version) if tool == "rustup" else version.strip()
    if records["bpf-linker"]["version"] != f"bpf-linker {BPF_LINKER}":
        raise CheckError(f"bpf-linker must be {BPF_LINKER}")
    resource = run_command(["clang-18", "-print-resource-dir"], cwd, env, evidence,
                           label + "-clang-resource")
    resource_dir = Path(read_output(resource).strip())
    if not resource_dir.is_absolute() or not resource_dir.is_dir():
        raise CheckError("clang returned an invalid resource directory")
    records["clang-18"]["resource_dir"] = str(resource_dir)
    packages = run_command(["dpkg-query", "-W", "-f=${Package}=${Version}\n",
                            "clang-18", "linux-libc-dev", "libc6-dev"], cwd, env,
                           evidence, label + "-packages")
    records["packages"] = read_output(packages).strip()
    if not records["packages"]:
        raise CheckError("empty compiler/header package receipt")
    write_json(evidence / (label + ".json"), records)
    return records


def extract_snapshot(archive_path: Path, source: Path) -> dict[str, str]:
    """Materialize only bounded ordinary files/directories from immutable Git blobs."""
    digests = {}
    total = 0
    with tarfile.open(archive_path, "r:") as archive:
        for count, member in enumerate(archive, 1):
            relative = PurePosixPath(member.name)
            if (count > 100_000 or relative.is_absolute() or not relative.parts
                    or any(part in ("", ".", "..", ".git") for part in relative.parts)
                    or "\\" in member.name or not (member.isfile() or member.isdir())):
                raise CheckError(f"unsafe snapshot archive entry: {member.name}")
            destination = source.joinpath(*relative.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if member.name in digests or member.size > 256 * 1024 * 1024 or total > 1024 * 1024 * 1024:
                raise CheckError("duplicate or oversized snapshot input")
            destination.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise CheckError(f"missing snapshot payload: {member.name}")
            with stream, destination.open("xb") as target:
                shutil.copyfileobj(stream, target)
            destination.chmod(0o755 if member.mode & 0o111 else 0o644)
            digests[member.name] = sha256(destination)
    if not digests:
        raise CheckError("empty source snapshot")
    return digests


def regular_object(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CheckError(f"missing object {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise CheckError(f"object must be a regular non-symlink file: {path}")
    if metadata.st_size == 0:
        raise CheckError(f"empty object: {path}")
    return metadata


def compare_objects(baseline: dict[str, Path], candidate: dict[str, Path]) -> None:
    identities = set()
    for side, objects in (("baseline", baseline), ("candidate", candidate)):
        if set(objects) != set(OBJECT_NAMES):
            raise CheckError(f"{side} must contain exactly the three default objects")
        for name in OBJECT_NAMES:
            metadata = regular_object(objects[name])
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in identities:
                raise CheckError(f"baseline/candidate object alias: {objects[name]}")
            identities.add(identity)
    for name in OBJECT_NAMES:
        # Compare whole bytes, including all debug/BTF/relocation sections.
        with baseline[name].open("rb") as left, candidate[name].open("rb") as right:
            while True:
                a, b = left.read(1024 * 1024), right.read(1024 * 1024)
                if a != b:
                    raise CheckError(f"default object differs: {name}")
                if not a:
                    break


def select_out_dir(messages: str, package_id: str, scratch: Path) -> Path:
    out_dirs = []
    finished = []
    for line in messages.splitlines():
        message = json.loads(line)
        if message.get("reason") == "build-script-executed" and message.get("package_id") == package_id:
            out_dirs.append(message["out_dir"])
        if message.get("reason") == "build-finished":
            finished.append(message.get("success"))
    if finished != [True] or len(out_dirs) != 1:
        raise CheckError("Cargo must report one successful build and one root-package OUT_DIR")
    path = Path(out_dirs[0])
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise CheckError("Cargo OUT_DIR must be an absolute non-symlink path")
    if not path.is_relative_to(scratch) or not path.is_dir():
        raise CheckError("Cargo OUT_DIR is outside the owned fresh build scratch")
    return path


def coordinator_identity() -> dict:
    directory = COORDINATOR_DIRECTORY
    return {name: {"path": str(directory / name), "sha256": sha256(directory / name)}
            for name in ("check-bpf-noninterference.py", "offline-dependencies.py", "_loader.py")}


def nightly_source(rustc: Path, cwd: Path, env: dict[str, str], evidence: Path, label: str) -> dict:
    output = run_command([str(rustc), "--print", "sysroot"], cwd, env, evidence, label)
    value = read_output(output).strip()
    sysroot = Path(value)
    if (not value or "\n" in value or not sysroot.is_absolute()
            or sysroot.resolve(strict=True) != sysroot or not sysroot.is_dir()):
        raise CheckError("selected nightly rustc returned an invalid sysroot path")
    manifest = sysroot / "lib/rustlib/src/rust/library/sysroot/Cargo.toml"
    lock = sysroot / "lib/rustlib/src/rust/library/Cargo.lock"
    try:
        for path in (manifest, lock):
            regular_object(path)
            if path.resolve(strict=True) != path:
                raise CheckError(f"nightly source contains a symbolic link: {path}")
    except (OSError, CheckError) as error:
        raise CheckError(f"selected nightly source is unavailable: {error}") from error
    return {"rustc": str(rustc), "sysroot": str(sysroot),
            "manifest": str(manifest), "manifest_sha256": sha256(manifest),
            "lock": str(lock), "lock_sha256": sha256(lock)}


@contextlib.contextmanager
def helper_environment(environment: dict[str, str]):
    """Use the same scrubbed inputs and owned temp directory inside finite helpers."""
    previous = dict(os.environ)
    previous_temporary = tempfile.tempdir
    try:
        os.environ.clear()
        os.environ.update(environment)
        tempfile.tempdir = environment["TMPDIR"]
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)
        tempfile.tempdir = previous_temporary


def copy_payload(helper, supplied: Path, owned: Path) -> None:
    """Copy only the validator's regular entries, with its admitted modes."""
    inventory = helper.payload_inventory(supplied)
    owned.mkdir(mode=0o755)
    owned.chmod(0o755)
    for relative, kind, executable, digest in inventory:
        destination = owned / relative
        if kind == "directory":
            destination.mkdir(parents=True, exist_ok=True, mode=0o755)
            destination.chmod(0o755)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            helper._copy_regular(supplied / relative, destination)
            destination.chmod(0o755 if executable else 0o644)
            if sha256(destination) != digest:
                raise CheckError(f"payload input changed during copy: {relative}")
    if helper.payload_inventory(owned) != inventory:
        raise CheckError("copied payload inventory changed")


def verify_home_configuration(home: Path, expected: bytes | None) -> None:
    """Admit only the exact generated replacement config in a private home."""
    for relative in ("config", "config.toml", "credentials", "credentials.toml"):
        path = home / relative
        if relative == "config.toml" and expected is not None:
            if not stat.S_ISREG(path.lstat().st_mode) or path.read_bytes() != expected:
                raise CheckError("generated Cargo configuration changed")
        elif os.path.lexists(path):
            raise CheckError(f"unreviewed private Cargo configuration: {path}")


def build_snapshot(repo: Path, revision: str, scratch: Path, evidence: Path, *,
                   offline_payload: Path | None = None) -> dict[str, Path]:
    if scratch.name != "scratch" or scratch.parent != evidence.parent or evidence.name not in {"baseline", "candidate"}:
        raise CheckError("snapshot paths must belong to one owned comparison directory")
    owner = json.loads((scratch.parent / "ownership.json").read_text(encoding="utf-8"))
    if owner != {"pid": os.getpid(), "repo": str(repo)}:
        raise CheckError("comparison scratch ownership mismatch")
    if scratch.exists():
        if scratch.is_symlink():
            raise CheckError("owned scratch was replaced by a symlink")
        shutil.rmtree(scratch)
    scratch.mkdir(mode=0o700)
    source = scratch / "source"
    source.mkdir()
    (scratch / "tmp").mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    env = clean_environment(scratch)
    coordinator = coordinator_identity()
    before = tool_identity(source, env, evidence, "tools-before")
    archive = run_command(["git", "-C", str(repo), "archive", "--format=tar", revision],
                          source, env, evidence, "git-archive", stdout_path=evidence / "source.tar")
    source_digests = extract_snapshot(archive, source)
    if (source / ".release-rust-version").read_text().strip() != RELEASE_RUST:
        raise CheckError("snapshot does not select the reviewed release Rust compiler")
    # Cargo also reads parent-directory configuration, independent of the
    # private CARGO_HOME. Refuse it rather than inheriting target/tool overrides.
    for directory in (source / "crates/ebpf", source / "crates", source, *source.parents):
        for filename in ("config", "config.toml"):
            config = directory / ".cargo" / filename
            if os.path.lexists(config):
                raise CheckError(f"unreviewed Cargo configuration override: {config}")
    tree = run_command(["git", "-C", str(repo), "rev-parse", revision + "^{tree}"],
                       source, env, evidence, "source-tree")
    nightly_rustc = Path(before[BPF_RUST + "-rustc"]["path"])
    nightly = nightly_source(nightly_rustc, source, env, evidence, "nightly-source-before")
    receipt = {"revision": revision, "tree": read_output(tree).strip(), "archive_sha256": sha256(archive),
               "lockfiles": {name: sha256(source / name) for name in ("Cargo.lock", "crates/ebpf/Cargo.lock")},
               "build_environment": {key: env[key] for key in ("CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR", "CARGO_ENCODED_RUSTFLAGS")},
               "tools": before, "coordinator": coordinator, "nightly_source": nightly,
               "acquisition_mode": "verified-payload" if offline_payload else "online"}
    write_json(evidence / "snapshot.json", receipt)
    configuration = None
    payload_receipts = None
    if offline_payload is None:
        run_command(["python3", "-I", "scripts/prepare-dependencies.py"], source, env,
                    evidence, "prepare-dependencies", timeout=600)
        verify_home_configuration(Path(env["CARGO_HOME"]), None)
        run_command(["./scripts/cargo.sh", "+" + RELEASE_RUST, "fetch", "--locked", "--manifest-path", "Cargo.toml"],
                    source, env, evidence, "fetch-root", timeout=900)
        run_command(["./scripts/cargo.sh", "+" + BPF_RUST, "fetch", "--locked", "--manifest-path", "crates/ebpf/Cargo.toml"],
                    source, env, evidence, "fetch-bpf", timeout=900)
        run_command(["./scripts/cargo.sh", "+" + BPF_RUST, "fetch", "--locked", "--manifest-path", nightly["manifest"]],
                    source, env, evidence, "fetch-sysroot", timeout=900)
    else:
        receipt["offline_payload_input"] = str(offline_payload)
        write_json(evidence / "snapshot.json", receipt)
        helper = load_path(COORDINATOR_DIRECTORY / "offline-dependencies.py")
        preparer = load_path(source / "scripts/prepare-dependencies.py")
        env.update(CARGO_NET_OFFLINE="true")
        try:
            with helper_environment(env):
                supplied, payload_tool = helper._verify_payload_contents(source, offline_payload, nightly_rustc, preparer)
                owned_payload = scratch / "offline-payload"
                copy_payload(helper, offline_payload, owned_payload)
                copied_receipt, _ = helper._verify_payload_contents(
                    source, owned_payload, nightly_rustc, preparer, reconstruct=False
                )
                configuration = helper.replacement_config(
                    owned_payload, copied_receipt["observed_inputs"]["shared_git"]
                )
        except helper.OfflineDependencyError as error:
            raise CheckError(f"offline payload refused: {error}") from error
        (Path(env["CARGO_HOME"]) / "config.toml").write_bytes(configuration)
        (evidence / "cargo-config.toml").write_bytes(configuration)
        payload_receipts = {"supplied": supplied, "copied": copied_receipt,
                            "nightly_rustc": payload_tool,
                            "config_path": str(Path(env["CARGO_HOME"]) / "config.toml"),
                            "config_sha256": sha256(evidence / "cargo-config.toml")}
        receipt["offline_payload"] = payload_receipts
        write_json(evidence / "snapshot.json", receipt)
        verify_home_configuration(Path(env["CARGO_HOME"]), configuration)
        run_command(["./scripts/cargo.sh", "+" + RELEASE_RUST, "fetch", "--locked", "--offline", "--manifest-path", "Cargo.toml"],
                    source, env, evidence, "fetch-root", timeout=900)
        run_command(["./scripts/cargo.sh", "+" + BPF_RUST, "fetch", "--locked", "--offline", "--manifest-path", "crates/ebpf/Cargo.toml"],
                    source, env, evidence, "fetch-bpf", timeout=900)
        run_command(["./scripts/cargo.sh", "+" + BPF_RUST, "fetch", "--locked", "--offline", "--manifest-path", nightly["manifest"]],
                    source, env, evidence, "fetch-sysroot", timeout=900)
    # build.rs invokes nested nightly Cargo: propagate offline there too.
    env["CARGO_NET_OFFLINE"] = "true"
    metadata_log = run_command(["./scripts/cargo.sh", "+" + RELEASE_RUST, "metadata", "--locked", "--offline",
                                "--no-deps", "--format-version", "1"], source, env, evidence, "metadata")
    metadata = json.loads(read_output(metadata_log))
    packages = [package for package in metadata["packages"]
                if package["name"] == "p11scope" and package["manifest_path"] == str(source / "Cargo.toml")]
    if len(packages) != 1 or metadata["workspace_root"] != str(source):
        raise CheckError("metadata must identify exactly the snapshot's root p11scope package")
    build_log = run_command(["./scripts/cargo.sh", "+" + RELEASE_RUST, "build", "--locked", "--offline", "--lib",
                             "--no-default-features", "--message-format=json"], source, env, evidence,
                            "build", timeout=1800)
    out_dir = select_out_dir(read_output(build_log), packages[0]["id"], scratch)
    identity_receipt = out_dir / "p11scope-identity-build-info.txt"
    if identity_receipt.exists():
        regular_object(identity_receipt)
        shutil.copyfile(identity_receipt, evidence / identity_receipt.name)
    objects = {}
    copied = evidence / "objects"
    copied.mkdir(mode=0o700)
    sections = []
    original_identities = set()
    for name in OBJECT_NAMES:
        original = out_dir / name
        metadata = regular_object(original)
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in original_identities:
            raise CheckError(f"root-package output object alias: {name}")
        original_identities.add(identity)
        destination = copied / name
        shutil.copyfile(original, destination)
        objects[name] = destination
        summary = run_command(["llvm-readelf", "--sections", "--wide", str(destination)],
                              source, env, evidence, "sections-" + name)
        sections.extend([name + "\n", read_output(summary)])
    (evidence / "sections.txt").write_text("\n".join(sections), encoding="utf-8")
    verify_home_configuration(Path(env["CARGO_HOME"]), configuration)
    if nightly_source(nightly_rustc, source, env, evidence, "nightly-source-after") != nightly:
        raise CheckError("selected nightly source changed during the snapshot build")
    if payload_receipts is not None:
        try:
            with helper_environment(env):
                for name, payload in (("supplied", offline_payload), ("copied", owned_payload)):
                    final, _ = helper._verify_payload_contents(
                        source, payload, nightly_rustc, preparer, reconstruct=False
                    )
                    if final != payload_receipts[name]:
                        raise CheckError(f"{name} offline payload receipt changed")
        except helper.OfflineDependencyError as error:
            raise CheckError(f"offline payload changed: {error}") from error
    for relative, digest in source_digests.items():
        if sha256(source / relative) != digest:
            raise CheckError(f"tracked snapshot input changed during build: {relative}")
    after = tool_identity(source, env, evidence, "tools-after")
    if before != after:
        raise CheckError("tool identity changed during the snapshot build")
    if coordinator_identity() != coordinator:
        raise CheckError("coordinator helper identity changed during the snapshot build")
    receipt.update({"out_dir": str(out_dir), "offline_nested_cargo": True,
                    "objects": {name: {"path": str(objects[name]), "original_path": str(out_dir / name),
                                       "sha256": sha256(objects[name]), "size": objects[name].stat().st_size}
                                for name in OBJECT_NAMES}})
    write_json(evidence / "snapshot.json", receipt)
    return objects


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--repeat-baseline", action="store_true")
    parser.add_argument("--baseline-offline-payload", type=Path)
    parser.add_argument("--candidate-offline-payload", type=Path)
    options = parser.parse_args()
    try:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise CheckError("the reviewed recipe requires Linux x86-64")
        validate_path(dict(os.environ))
        if (options.baseline_offline_payload is None) != (options.candidate_offline_payload is None):
            raise CheckError("both baseline and candidate offline payload paths are required")
        repo, work = options.repo, options.work
        if not repo.is_absolute() or repo.resolve(strict=True) != repo or not repo.is_dir():
            raise CheckError("repo must be an existing absolute non-symlink directory")
        if (not work.is_absolute() or work.parent.resolve(strict=True) != work.parent
                or Path(os.path.normpath(str(work))) != work or os.path.lexists(work)
                or work.is_relative_to(repo)):
            raise CheckError("work must be an absent absolute directory outside repo, with a non-symlink parent")
        for payload in (options.baseline_offline_payload, options.candidate_offline_payload):
            if payload is not None and (not payload.is_absolute() or payload.resolve(strict=True) != payload
                    or not payload.is_dir() or payload.is_relative_to(work) or work.is_relative_to(payload)):
                raise CheckError("offline payload must be an absolute real directory disjoint from owned work")
        work.mkdir(mode=0o700)
        write_json(work / "ownership.json", {"pid": os.getpid(), "repo": str(repo)})
        revisions = []
        for side, revision in (("baseline", options.baseline), ("candidate", options.candidate)):
            output = run_command(["git", "-C", str(repo), "rev-parse", "--verify", "--end-of-options", revision + "^{commit}"],
                                 repo, dict(os.environ), work, "resolve-" + side)
            resolved = read_output(output).strip()
            if len(resolved) != 40 or any(c not in "0123456789abcdef" for c in resolved):
                raise CheckError("Git did not resolve one full commit ID")
            revisions.append(resolved)
        baseline, candidate = revisions
        if (baseline == candidate) != options.repeat_baseline:
            raise CheckError("integration needs distinct commits; equal commits need explicit --repeat-baseline")
        scratch = work / "scratch"
        left = build_snapshot(repo, baseline, scratch, work / "baseline", offline_payload=options.baseline_offline_payload)
        right = build_snapshot(repo, candidate, scratch, work / "candidate", offline_payload=options.candidate_offline_payload)
        first = json.loads((work / "baseline/snapshot.json").read_text())["tools"]
        second = json.loads((work / "candidate/snapshot.json").read_text())["tools"]
        if first != second:
            raise CheckError("tool identity changed between baseline and candidate builds")
        if (json.loads((work / "baseline/snapshot.json").read_text())["coordinator"]
                != json.loads((work / "candidate/snapshot.json").read_text())["coordinator"]):
            raise CheckError("coordinator identity changed between snapshot builds")
        if (json.loads((work / "baseline/snapshot.json").read_text())["nightly_source"]
                != json.loads((work / "candidate/snapshot.json").read_text())["nightly_source"]):
            raise CheckError("selected nightly source changed between snapshot builds")
        compare_objects(left, right)
        write_json(work / "comparison.json", {"mode": "repeat-baseline" if options.repeat_baseline else "integration",
                                              "baseline": baseline, "candidate": candidate,
                                              "acquisition_mode": "verified-payload" if options.baseline_offline_payload else "online",
                                              "matched_objects": list(OBJECT_NAMES)})
        print(f"bpf-noninterference: {baseline} vs {candidate}: all three whole objects match")
        return 0
    except (CheckError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        print(f"bpf-noninterference: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
