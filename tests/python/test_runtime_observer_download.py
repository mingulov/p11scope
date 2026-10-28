#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the artifact consumer against an owned GitHub API transport stub."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/download-runtime-observer.py"
REPO = "mingulov/p11scope"
HEAD = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
TREE = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
RUST = (ROOT / ".release-rust-version").read_text().strip()
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def elf(*, machine=62, interpreter=False, needed=False):
    # One executable load segment; the negative adds a PT_INTERP segment.
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    count = 2 if interpreter or needed else 1
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, machine, 1, 0x400000,
                         64, 0, 0, 64, 56, count, 64, 0, 0)
    size = 64 + 56 * count + (16 if needed else 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, size, size, 4096)
    if interpreter:
        program += struct.pack("<IIQQQQQQ", 3, 4, 0, 0, 0, 8, 8, 1)
    elif needed:
        program += struct.pack("<IIQQQQQQ", 2, 4, size - 16, 0, 0, 16, 16, 8)
        program += struct.pack("<qQ", 1, 0)
    return header + program


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="runtime-download-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.base.chmod(0o700)
        self.tools = self.base / "tools"
        self.tools.mkdir()
        self.output = self.base / "observer"
        self.binary = elf()
        self.release = {"schema_version": 1, "version": VERSION, "head": HEAD,
                        "tree": TREE, "build_receipt_status": 0, "rust": RUST,
                        "bpf_rust": "nightly-2026-05-20", "p11scope_features": [],
                        "artifacts": {"p11scope": digest(self.binary),
                                      "p11scope-discover": "1" * 64,
                                      "p11scope-discover-glibc": "2" * 64,
                                      "p11scope-discover-musl": "3" * 64}}
        repository = {"id": 10, "full_name": REPO}
        self.run = {"id": 12, "run_attempt": 1, "path": ".github/workflows/ci.yml",
                    "head_sha": HEAD, "event": "workflow_dispatch", "status": "completed",
                    "conclusion": "success", "repository": repository,
                    "head_repository": copy.deepcopy(repository)}
        self.jobs = {"total_count": 2, "jobs": [
            {"id": 21, "run_id": 12, "run_attempt": 1, "head_sha": HEAD,
             "name": "release-preview", "status": "completed", "conclusion": "success"},
            {"id": 22, "run_id": 12, "run_attempt": 1, "head_sha": HEAD,
             "name": "lint", "status": "completed", "conclusion": "success"}]}
        self.artifact = {"id": 31, "name": "release-preview-public-assets", "expired": False,
                         "workflow_run": {"id": 12, "head_sha": HEAD,
                                          "repository_id": 10, "head_repository_id": 10}}
        self.extra_members = {}
        self.extra_zip = {}
        self.artifacts = [self.artifact]
        self.transport_tamper = False
        self.bad_checksum = False
        self.archive_release = None
        gh = self.tools / "gh"
        gh.write_text("#!" + sys.executable + "\n" + '''
import json, os, sys
from pathlib import Path
base = Path(os.environ["STUB_API"])
args = sys.argv[1:]
with (base / "calls").open("a") as out:
    out.write(json.dumps(args) + "\\n")
if args[:1] != ["api"]:
    sys.exit(90)
endpoint = args[1]
mapping = {
    "repos/mingulov/p11scope/actions/runs/12": "run.json",
    "repos/mingulov/p11scope/actions/runs/12/attempts/1/jobs?per_page=100": "jobs.json",
    "repos/mingulov/p11scope/actions/runs/12/artifacts?per_page=100": "artifacts.json",
    "repos/mingulov/p11scope/actions/artifacts/31/zip": "artifact.zip",
}
if endpoint not in mapping:
    sys.exit(91)
sys.stdout.buffer.write((base / mapping[endpoint]).read_bytes())
''')
        gh.chmod(0o755)

    def prepare(self):
        release = json.dumps(self.release, sort_keys=True).encode()
        prefix = f"p11scope-{VERSION}-x86_64-linux-musl"
        payload = {f"{prefix}/p11scope": self.binary,
                   f"{prefix}/RELEASE.json": self.archive_release or release,
                   f"{prefix}/LICENSE": b"license"} | self.extra_members
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            for name, data in payload.items():
                info = tarfile.TarInfo(name)
                info.mode = 0o755 if name.endswith("/p11scope") else 0o644
                if data is None:
                    info.type, info.linkname = tarfile.SYMTYPE, "/outside"
                    tar.addfile(info)
                else:
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
        assets = {"RELEASE.json": release, f"{prefix}.tar.gz": archive.getvalue(),
                  f"p11scope-discover-{VERSION}-x86_64-linux-gnu.tar.gz": b"glibc helper archive",
                  f"p11scope-discover-{VERSION}-x86_64-linux-musl.tar.gz": b"musl helper archive",
                  f"p11scope-{VERSION}-source.tar.gz": b"source export"}
        assets["SHA256SUMS"] = "".join(f"{digest(data)}  {name}\n"
                                        for name, data in sorted(assets.items())).encode()
        if self.bad_checksum:
            assets[f"{prefix}.tar.gz"] += b"tampered"
        with zipfile.ZipFile(self.base / "artifact.zip", "w") as zipped:
            for name, data in (assets | self.extra_zip).items():
                zipped.writestr(name, data)
        raw = (self.base / "artifact.zip").read_bytes()
        self.artifact.update(size_in_bytes=len(raw), digest="sha256:" + digest(raw))
        if self.transport_tamper:
            (self.base / "artifact.zip").write_bytes(raw[:-1] + b"!")
        for name, data in (("run", self.run), ("jobs", self.jobs),
                           ("artifacts", {"total_count": len(self.artifacts), "artifacts": self.artifacts})):
            (self.base / (name + ".json")).write_text(json.dumps(data))

    def invoke(self, *extra):
        self.prepare()
        env = os.environ | {"PATH": str(self.tools) + os.pathsep + os.environ["PATH"],
                            "STUB_API": str(self.base)}
        return subprocess.run([sys.executable, "-I", str(SCRIPT), "--repository", REPO,
                               "--run-id", "12", "--sha", HEAD, "--output", str(self.output),
                               *extra], cwd=ROOT, env=env, text=True, capture_output=True, timeout=15)

    def refused(self):
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("refusal:", result.stderr)
        self.assertFalse(self.output.exists(), "refused input left executable output")
        return result

    def test_exact_successful_full_artifact_stages_only_matching_static_observer(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.output / "p11scope"))
        self.assertEqual((self.output / "p11scope").read_bytes(), self.binary)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(os.access(self.output / "p11scope", os.X_OK))

    def test_run_repository_sha_workflow_event_and_success_are_required(self):
        for key, value in (("head_sha", "a" * 40), ("id", 13), ("status", "in_progress"),
                           ("conclusion", "failure"), ("path", ".github/workflows/other.yml"),
                           ("event", "pull_request"),
                           ("repository", {"id": 10, "full_name": "elsewhere/p11scope"}),
                           ("head_repository", {"id": 99, "full_name": REPO})):
            with self.subTest(key=key):
                saved = self.run[key]
                self.run[key] = value
                self.refused()
                self.run[key] = saved

    def test_preview_must_be_one_successful_job_on_exact_attempt(self):
        for key, value in (("conclusion", "skipped"), ("head_sha", "b" * 40),
                           ("run_id", 13), ("run_attempt", 2), ("name", "other")):
            with self.subTest(key=key):
                saved = self.jobs["jobs"][0][key]
                self.jobs["jobs"][0][key] = value
                self.refused()
                self.jobs["jobs"][0][key] = saved
        self.jobs["jobs"].append(copy.deepcopy(self.jobs["jobs"][0]))
        self.jobs["total_count"] = 3
        self.refused()

    def test_attempt_endpoint_accepts_documented_job_without_optional_attempt_field(self):
        self.jobs["jobs"][0].pop("run_attempt")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.base / "calls").read_text().splitlines()]
        self.assertIn(["api", "repos/mingulov/p11scope/actions/runs/12/attempts/1/jobs?per_page=100"], calls)

    def test_only_exact_unexpired_same_run_full_namespace_is_accepted(self):
        for key, value in (("name", "release-preview-public-assets-p0"), ("expired", True),
                           ("workflow_run", {"id": 13, "head_sha": HEAD,
                                             "repository_id": 10, "head_repository_id": 10})):
            with self.subTest(key=key):
                saved = self.artifact[key]
                self.artifact[key] = value
                self.refused()
                self.artifact[key] = saved

    def test_absent_duplicate_and_transport_tampered_artifact_are_refused(self):
        self.artifacts = []
        self.refused()
        self.artifacts = [self.artifact, self.artifact]
        self.refused()
        self.artifacts = [self.artifact]
        self.transport_tamper = True
        self.refused()

    def test_source_cli_and_output_parent_refuse_before_api_download(self):
        result = self.invoke("--sha", "f" * 40)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.base / "calls").exists())
        self.base.chmod(0o755)
        self.refused()
        self.assertFalse((self.base / "calls").exists())

    def test_release_revision_features_compiler_and_test_status_are_bound(self):
        for key, value in (("head", "c" * 40), ("tree", "d" * 40),
                           ("p11scope_features", ["stub-object-attributes"]),
                           ("rust", "1.88.0"), ("build_receipt_status", 1)):
            with self.subTest(key=key):
                saved = self.release[key]
                self.release[key] = value
                self.refused()
                self.release[key] = saved

    def test_checksum_and_embedded_release_mismatch_refuse_before_output(self):
        self.bad_checksum = True
        self.refused()
        self.bad_checksum = False
        self.archive_release = b'{}'
        self.refused()

    def test_malformed_dynamic_foreign_and_wrong_hash_observers_are_refused(self):
        for data in (b"#!/bin/sh\nexit 0\n", elf(machine=183), elf(interpreter=True), elf(needed=True),
                     elf()[:65]):
            with self.subTest(data=data[:20]):
                self.binary = data
                self.release["artifacts"]["p11scope"] = digest(data)
                self.refused()
        self.binary = elf()
        self.release["artifacts"]["p11scope"] = "e" * 64
        self.refused()

    def test_archive_traversal_symlinks_and_zip_extras_are_never_extracted(self):
        for name, data in (("../outside", b"owned"),
                           (f"p11scope-{VERSION}-x86_64-linux-musl/link", None)):
            with self.subTest(name=name):
                self.extra_members = {name: data}
                self.refused()
        self.extra_members = {}
        self.extra_zip = {"../outside": b"owned"}
        self.refused()
        self.assertFalse((self.base / "outside").exists())


if __name__ == "__main__":
    unittest.main()
