#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Consume one completed same-source FULL package producer; never build.

Print only the absolute staged observer path on stdout. The caller owns the
private output parent. This consumes the existing public package format; it
does not produce the separate default/WIDE libtest fanout inputs.
"""

import argparse
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("package_release", ROOT / "scripts/package-release.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)
ARTIFACT = "release-preview-public-assets"
CI_WORKFLOW = ".github/workflows/ci.yml"
PACKAGE_WORKFLOW = ".github/workflows/package-preview.yml"
PACKAGE_GATES = {
    "validate": ("Validate accepted ordinary CI",),
    "package-full": ("Verify package checkout", "Build and assemble public package"),
}
DELIVERY_GATES = {
    "package-delivery / validate": PACKAGE_GATES["validate"],
    "package-delivery / package-full": PACKAGE_GATES["package-full"],
}
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def positive(value):
    return type(value) is int and value > 0


def api(endpoint):
    result = subprocess.run(["gh", "api", endpoint], check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60)
    require(len(result.stdout) <= 4 * 1024 * 1024, "API response exceeds bound")
    value = PACKAGE.parse_json(result.stdout)
    require(isinstance(value, dict), "API response must be an object")
    return value


def complete_list(document, key):
    rows = document.get(key)
    require(isinstance(rows, list) and type(document.get("total_count")) is int
            and len(rows) == document["total_count"] <= 100
            and all(isinstance(row, dict) for row in rows),
            "incomplete or excessive " + key + " listing")
    return rows


def check_run(run, repository, run_id, sha, tree, workflow):
    require(positive(run.get("id")) and run["id"] == run_id and run.get("head_sha") == sha,
            "preview run ID/source mismatch")
    path = workflow["path"]
    require(run.get("path") == path and positive(run.get("workflow_id"))
            and run["workflow_id"] == workflow["id"], "preview workflow identity mismatch")
    require(run.get("event") == "workflow_dispatch" and run.get("status") == "completed",
            "completed preview dispatch required")
    repo, head_repo = run.get("repository", {}), run.get("head_repository", {})
    require(isinstance(repo, dict) and isinstance(head_repo, dict)
            and repo.get("full_name") == repository and positive(repo.get("id"))
            and head_repo.get("full_name") == repository and head_repo.get("id") == repo["id"],
            "same-repository preview required")
    commit = run.get("head_commit")
    require(isinstance(commit, dict) and commit.get("id") == sha and commit.get("tree_id") == tree,
            "preview commit/tree mismatch")
    attempt = run.get("run_attempt")
    require(positive(attempt), "preview attempt missing")
    return attempt


def producer_checker():
    spec = importlib.util.spec_from_file_location("package_preview_ci", ROOT / "scripts/check-package-preview-ci.py")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    return checker


def package_gate(job, required_steps):
    # Reuse the accepted producer's execution/timestamp/step-shape contract;
    # its successful validate step binds ordinary and coverage CI to this SHA.
    checker = producer_checker()
    checker.check_gate(job)
    for name in required_steps:
        steps = [step for step in job["steps"] if step["name"] == name]
        require(len(steps) == 1 and steps[0]["conclusion"] == "success",
                "package producer gate step did not run: " + name)


def artifact_freshness(artifact, job):
    checker = producer_checker()
    started = checker.timestamp(job.get("started_at"))
    completed = checker.timestamp(job.get("completed_at"))
    created = checker.timestamp(artifact.get("created_at"))
    updated = checker.timestamp(artifact.get("updated_at"))
    require(started <= created <= completed,
            "artifact creation is outside the selected FULL producer job interval")
    # Updates cannot confer freshness on an artifact created by an old attempt.
    require(created <= updated, "artifact update precedes creation")


def producer_route(path, jobs):
    direct = set(PACKAGE_GATES) | {"package-p0"}
    nested = set(DELIVERY_GATES) | {"package-delivery / package-p0", "package-delivery"}
    known = direct | nested | {"release-preview"}
    # Lookalikes never authorize a route or hide an attempted producer behind
    # a different successful job. Only literal names below grant admission.
    for name in jobs:
        if any(token in name for token in ("package-delivery", "package-full", "package-p0")):
            require(name in known, "unrecognized package producer job name")
    if path == PACKAGE_WORKFLOW:
        require(not (nested | {"release-preview"}) & jobs.keys(),
                "conflicting standalone package producer route")
        return PACKAGE_GATES, "package-full"
    require(not direct & jobs.keys(), "foreign standalone package jobs in CI producer")

    def skipped(name):
        return jobs[name].get("status") == "completed" and jobs[name].get("conclusion") == "skipped"

    delivery = bool((nested - {"package-delivery"}) & jobs.keys())
    if "package-delivery" in jobs and not skipped("package-delivery"):
        delivery = True
    legacy = "release-preview" in jobs and not skipped("release-preview")
    require(not (delivery and legacy), "conflicting CI package producer routes")
    if delivery:
        return DELIVERY_GATES, "package-delivery / package-full"
    return None, "release-preview"


def select_artifact(repository, run_id, sha, tree):
    prefix = f"repos/{repository}/actions"
    run = api(f"{prefix}/runs/{run_id}")
    path = run.get("path")
    require(path in (CI_WORKFLOW, PACKAGE_WORKFLOW), "unrecognized package producer workflow")
    workflow = api(f"{prefix}/workflows/{path.rsplit('/', 1)[1]}")
    require(positive(workflow.get("id")) and workflow.get("path") == path,
            "invalid package producer workflow identity")
    attempt = check_run(run, repository, run_id, sha, tree, workflow)
    jobs = complete_list(api(f"{prefix}/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"), "jobs")
    by_name, identifiers = {}, set()
    for job in jobs:
        name, identifier = job.get("name"), job.get("id")
        require(isinstance(name, str) and name and name not in by_name
                and positive(identifier) and identifier not in identifiers, "duplicate/invalid preview job")
        # The endpoint binds the attempt. A missing optional run_attempt is
        # accepted, while a supplied contradiction (including bool) refuses.
        job_attempt = job.get("run_attempt", attempt)
        require(positive(job.get("run_id")) and job["run_id"] == run_id and job.get("head_sha") == sha
                and positive(job_attempt) and job_attempt == attempt, "stale preview job identity")
        by_name[name] = job
        identifiers.add(identifier)
    gates, producer = producer_route(path, by_name)
    conclusions = ("success", "failure") if gates is not None else ("success",)
    require(run.get("conclusion") in conclusions, "completed eligible preview dispatch required")
    required = tuple(gates) if gates is not None else (producer,)
    require(set(required) <= by_name.keys(), "required successful preview jobs missing")
    for name in required:
        job = by_name[name]
        require(job.get("status") == "completed" and job.get("conclusion") == "success",
                "matching successful preview job required: " + name)
        if gates is not None:
            package_gate(job, gates[name])
    artifacts = complete_list(api(f"{prefix}/runs/{run_id}/artifacts?per_page=100"), "artifacts")
    matches = [item for item in artifacts if item.get("name") == ARTIFACT]
    require(len(matches) == 1, "one exact FULL public artifact required")
    artifact = matches[0]
    require(positive(artifact.get("id")) and artifact.get("expired") is False,
            "artifact missing, invalid or expired")
    binding = artifact.get("workflow_run", {})
    require(isinstance(binding, dict) and binding.get("id") == run_id and binding.get("head_sha") == sha
            and binding.get("repository_id") == run["repository"]["id"]
            and binding.get("head_repository_id") == run["repository"]["id"], "artifact run/source mismatch")
    artifact_freshness(artifact, by_name[producer])
    require(positive(artifact.get("size_in_bytes")) and artifact["size_in_bytes"] <= MAX_ARCHIVE,
            "artifact archive size exceeds bound")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", "")) is not None,
            "artifact archive digest missing")
    return artifact, run, workflow


def static_elf(data):
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "ELF64 little-endian observer required")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    _, kind, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, _, _, _ = header
    require(kind in (2, 3) and machine == 62 and version == 1 and ehsize == 64,
            "Linux x86-64 executable required")
    require(phsize == 56 and 0 < phnum < 1024 and phoff >= 64
            and phoff + phsize * phnum <= len(data), "invalid ELF program headers")
    executable_entry = False
    for index in range(phnum):
        ptype, flags, offset, address, _, size, memsize, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize)
        require(offset + size <= len(data), "ELF segment exceeds file")
        require(ptype != 3, "static observer required; PT_INTERP present")
        if ptype == 1:
            require(size <= memsize, "invalid ELF load segment")
            executable_entry |= bool(flags & 1 and address <= entry < address + size)
        if ptype == 2:
            require(size % 16 == 0, "invalid ELF dynamic segment")
            for position in range(offset, offset + size, 16):
                tag, _ = struct.unpack_from("<qQ", data, position)
                require(tag != 1, "static observer required; DT_NEEDED present")
                if tag == 0:
                    break
    require(executable_entry, "ELF entry outside executable load segment")


def public_observer(path, sha, tree, version, rust, bpf_rust):
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(len(members) == 6, "exact six-file public artifact required")
        files = {}
        total = 0
        for member in members:
            name = PACKAGE.relative_name(member.filename)
            require(name not in files and "/" not in name and not member.is_dir()
                    and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG),
                    "unexpected/duplicate artifact ZIP path or type")
            total += member.file_size
            require(member.file_size <= MAX_FILE and total <= MAX_ARCHIVE,
                    "uncompressed artifact size exceeds bound")
            files[name] = archive.read(member)
    observer_prefix = f"p11scope-{version}-x86_64-linux-musl"
    observer_archive = observer_prefix + ".tar.gz"
    payloads = {"RELEASE.json", observer_archive, f"p11scope-{version}-source.tar.gz",
                f"p11scope-discover-{version}-x86_64-linux-gnu.tar.gz",
                f"p11scope-discover-{version}-x86_64-linux-musl.tar.gz"}
    require(set(files) == payloads | {"SHA256SUMS"}, "exact six-file public package required")
    checksums = {}
    for line in files["SHA256SUMS"].decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None and match[2] not in checksums, "invalid/duplicate checksum row")
        checksums[match[2]] = match[1]
    require(set(checksums) == payloads, "incomplete checksum ledger")
    require(all(PACKAGE.digest(files[name]) == expected for name, expected in checksums.items()),
            "public package checksum mismatch")
    release_bytes = files["RELEASE.json"]
    release = PACKAGE.parse_json(release_bytes)
    require(isinstance(release, dict), "RELEASE must be an object")
    require(type(release.get("schema_version")) is int and release["schema_version"] == 1 and release.get("head") == sha
            and release.get("tree") == tree and release.get("version") == version,
            "RELEASE source/tree/version mismatch")
    require(release.get("p11scope_features") == list(PACKAGE.OFFICIAL_P11SCOPE_FEATURES["full"])
            and type(release.get("build_receipt_status")) is int and release["build_receipt_status"] == 0
            and release.get("rust") == rust and release.get("bpf_rust") == bpf_rust,
            "RELEASE must name successful default FULL and pinned compilers")
    hashes = release.get("artifacts", {})
    require(isinstance(hashes, dict) and set(hashes) == set(PACKAGE.ARTIFACTS)
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in hashes.values()), "RELEASE binary hashes missing")
    seen, selected = set(), {}
    with tarfile.open(fileobj=io.BytesIO(files[observer_archive]), mode="r:gz") as archive:
        for index, member in enumerate(archive):
            name = PACKAGE.relative_name(member.name)
            require(index < 10000 and name not in seen and name.startswith(observer_prefix + "/")
                    and member.isfile() and member.mode & 0o7000 == 0,
                    "unsafe/duplicate observer archive path or type")
            seen.add(name)
            require(member.size <= MAX_FILE and member.offset_data + member.size <= MAX_ARCHIVE,
                    "observer archive size exceeds bound")
            leaf = name.removeprefix(observer_prefix + "/")
            if leaf in ("p11scope", "RELEASE.json"):
                require(member.mode == (0o755 if leaf == "p11scope" else 0o644),
                        "unexpected observer archive permissions")
                selected[leaf] = archive.extractfile(member).read()
    require(set(selected) == {"p11scope", "RELEASE.json"}
            and selected["RELEASE.json"] == release_bytes, "embedded RELEASE mismatch/missing observer")
    binary = selected["p11scope"]
    require(PACKAGE.digest(binary) == hashes["p11scope"], "observer hash differs from RELEASE")
    static_elf(binary)
    return binary, release_bytes


def download(args):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/(?!\.{1,2}$)[A-Za-z0-9_.-]+", args.repository) is not None,
            "invalid repository")
    require(re.fullmatch(r"[0-9a-f]{40}", args.sha) is not None and args.run_id > 0,
            "explicit source SHA and positive run ID required")
    require(PACKAGE.git(ROOT, "rev-parse", "HEAD").decode().strip() == args.sha,
            "checkout source differs from workflow SHA")
    tree = PACKAGE.git(ROOT, "rev-parse", "HEAD^{tree}").decode().strip()
    version = tomllib.loads(PACKAGE.git(ROOT, "show", "HEAD:Cargo.toml").decode())["package"]["version"]
    rust = PACKAGE.git(ROOT, "show", "HEAD:.release-rust-version").decode().strip()
    bpf_rust = tomllib.loads(PACKAGE.git(ROOT, "show", "HEAD:crates/ebpf/rust-toolchain.toml").decode())["toolchain"]["channel"]
    output = args.output
    parent = output.parent
    require(output.is_absolute() and parent.resolve(strict=True) == parent and parent.is_dir()
            and parent.stat().st_uid == os.getuid() and parent.stat().st_mode & 0o077 == 0,
            "absolute output with private owned canonical parent required")
    require(not output.exists() and not output.is_symlink(), "output already exists")
    artifact, run, workflow = select_artifact(args.repository, args.run_id, args.sha, tree)
    with tempfile.TemporaryDirectory(prefix="runtime-artifact-", dir=parent) as temporary:
        path = Path(temporary) / "artifact.zip"
        with path.open("xb") as stream:
            subprocess.run(["gh", "api", f"repos/{args.repository}/actions/artifacts/{artifact['id']}/zip"],
                           stdout=stream, stderr=subprocess.PIPE, check=True, timeout=180)
        require(path.stat().st_size == artifact["size_in_bytes"], "downloaded artifact size mismatch")
        require(PACKAGE.digest(path.read_bytes()) == artifact["digest"].removeprefix("sha256:"),
                "downloaded artifact digest mismatch")
        binary, release = public_observer(path, args.sha, tree, version, rust, bpf_rust)
        final_run = api(f"repos/{args.repository}/actions/runs/{args.run_id}")
        require(check_run(final_run, args.repository, args.run_id, args.sha, tree, workflow) == run["run_attempt"]
                and final_run["conclusion"] == run["conclusion"]
                and final_run["repository"]["id"] == run["repository"]["id"],
                "preview run changed while validating")
        require(PACKAGE.git(ROOT, "rev-parse", "HEAD").decode().strip() == args.sha
                and PACKAGE.git(ROOT, "rev-parse", "HEAD^{tree}").decode().strip() == tree,
                "checkout source changed while validating")
        output.mkdir(mode=0o700)
        try:
            (output / "p11scope").write_bytes(binary)
            (output / "p11scope").chmod(0o755)
            (output / "RELEASE.json").write_bytes(release)
        except BaseException:
            shutil.rmtree(output)
            raise
    return output / "p11scope"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(download(args))
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile,
            subprocess.SubprocessError) as error:
        print(f"runtime-observer: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
