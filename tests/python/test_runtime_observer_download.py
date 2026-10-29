#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the artifact consumer against an owned GitHub API transport stub."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
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
        self.run = {"id": 12, "run_attempt": 1, "workflow_id": 71, "path": ".github/workflows/ci.yml",
                    "head_sha": HEAD, "event": "workflow_dispatch", "status": "completed",
                    "conclusion": "success", "repository": repository,
                    "head_repository": copy.deepcopy(repository),
                    "head_commit": {"id": HEAD, "tree_id": TREE}}
        self.run_after = None
        self.workflows = {"ci": {"id": 71, "path": ".github/workflows/ci.yml"},
                          "package-preview": {"id": 72, "path": ".github/workflows/package-preview.yml"}}
        self.jobs = {"total_count": 2, "jobs": [
            {"id": 21, "run_id": 12, "run_attempt": 1, "head_sha": HEAD,
             "name": "release-preview", "status": "completed", "conclusion": "success",
             "started_at": "2026-10-28T10:00:00Z", "completed_at": "2026-10-28T10:02:00Z"},
            {"id": 22, "run_id": 12, "run_attempt": 1, "head_sha": HEAD,
             "name": "lint", "status": "completed", "conclusion": "success"}]}
        self.artifact = {"id": 31, "name": "release-preview-public-assets", "expired": False,
                         "created_at": "2026-10-28T10:01:00Z", "updated_at": "2026-10-28T10:01:00Z",
                         "workflow_run": {"id": 12, "head_sha": HEAD,
                                          "repository_id": 10, "head_repository_id": 10}}
        self.extra_members = {}
        self.extra_zip = {}
        self.artifacts = [self.artifact]
        self.transport_tamper = False
        self.artifact_overrides = {}
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
    "repos/mingulov/p11scope/actions/workflows/ci.yml": "ci.json",
    "repos/mingulov/p11scope/actions/workflows/package-preview.yml": "package-preview.json",
    "repos/mingulov/p11scope/actions/runs/12/attempts/1/jobs?per_page=100": "jobs.json",
    "repos/mingulov/p11scope/actions/runs/12/attempts/2/jobs?per_page=100": "jobs.json",
    "repos/mingulov/p11scope/actions/runs/12/artifacts?per_page=100": "artifacts.json",
    "repos/mingulov/p11scope/actions/artifacts/31/zip": "artifact.zip",
}
if endpoint not in mapping:
    sys.exit(91)
name = mapping[endpoint]
if name == "run.json":
    counter = base / "run-reads"
    count = int(counter.read_text())
    counter.write_text(str(count + 1))
    if count and (base / "run-after.json").exists():
        name = "run-after.json"
sys.stdout.buffer.write((base / name).read_bytes())
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
        self.artifact.update(self.artifact_overrides)
        if self.transport_tamper:
            (self.base / "artifact.zip").write_bytes(raw[:-1] + b"!")
        for name, data in (("run", self.run), ("jobs", self.jobs),
                           ("artifacts", {"total_count": len(self.artifacts), "artifacts": self.artifacts})):
            (self.base / (name + ".json")).write_text(json.dumps(data))
        for name, data in self.workflows.items():
            (self.base / (name + ".json")).write_text(json.dumps(data))
        (self.base / "run-reads").write_text("0")
        (self.base / "calls").unlink(missing_ok=True)
        after = self.base / "run-after.json"
        if self.run_after is not None:
            after.write_text(json.dumps(self.run_after))
        else:
            after.unlink(missing_ok=True)

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

    def accepted(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.output / "p11scope"))
        self.assertEqual((self.output / "p11scope").read_bytes(), self.binary)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(os.access(self.output / "p11scope", os.X_OK))
        return result

    def package_preview(self, *, conclusion="success", p0="success"):
        self.run.update(workflow_id=72, path=".github/workflows/package-preview.yml", conclusion=conclusion)
        self.jobs = {"total_count": 2, "jobs": []}
        for identifier, name, gates in (
            (21, "validate", ("Validate accepted ordinary CI",)),
            (22, "package-full", ("Verify package checkout", "Build and assemble public package")),
        ):
            self.jobs["jobs"].append({
                "id": identifier, "run_id": 12, "run_attempt": 1, "head_sha": HEAD,
                "name": name, "status": "completed", "conclusion": "success",
                "started_at": "2026-10-28T10:00:00Z", "completed_at": "2026-10-28T10:02:00Z",
                "steps": [
                    {"name": step, "number": number, "status": "completed", "conclusion": "success"}
                    for number, step in enumerate(("Set up job", *gates, "Complete job"), 1)
                ],
            })
        if p0 is not None:
            self.jobs["jobs"].append({"id": 23, "run_id": 12, "run_attempt": 1, "head_sha": HEAD,
                                        "name": "package-p0", "status": "completed", "conclusion": p0})
            self.jobs["total_count"] += 1

    def test_exact_successful_full_artifact_stages_only_matching_static_observer(self):
        self.accepted()

    def package_delivery(self, *, conclusion="success", p0="success"):
        # Isolate vectors even when a prior negative unexpectedly staged output.
        if self.output.exists():
            shutil.rmtree(self.output)
        self.package_preview(conclusion=conclusion, p0=p0)
        self.run.update(workflow_id=71, path=".github/workflows/ci.yml")
        for job in self.jobs["jobs"]:
            job["name"] = "package-delivery / " + job["name"]
        self.jobs["jobs"].append({"id": 24, "run_id": 12, "run_attempt": 1, "head_sha": HEAD,
                                 "name": "release-preview", "status": "completed", "conclusion": "skipped"})
        self.jobs["total_count"] += 1

    def test_exact_nested_package_full_is_accepted_with_failed_or_missing_p0(self):
        for p0 in ("success", "failure", None):
            with self.subTest(p0=p0):
                self.package_delivery(conclusion="failure" if p0 == "failure" else "success", p0=p0)
                self.accepted()
                calls = (self.base / "calls").read_text()
                self.assertIn("workflows/ci.yml", calls)
                self.assertNotIn("workflows/package-preview.yml", calls)
                shutil.rmtree(self.output)

    def test_nested_producer_cannot_borrow_legacy_or_standalone_route(self):
        for other in ("release-preview", "validate", "package-full"):
            for nested_failure in (False, True):
                with self.subTest(other=other, nested_failure=nested_failure):
                    self.package_delivery()
                    if nested_failure:
                        self.jobs["jobs"][1]["conclusion"] = "failure"
                    if other == "release-preview":
                        job = self.jobs["jobs"][-1]
                        job.update(conclusion="success", started_at="2026-10-28T10:00:00Z",
                                   completed_at="2026-10-28T10:02:00Z")
                    else:
                        job = copy.deepcopy(self.jobs["jobs"][0 if other == "validate" else 1])
                        job.update(id=25, name=other, conclusion="success")
                        self.jobs["jobs"].append(job)
                        self.jobs["total_count"] += 1
                    self.refused()
                    self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_legacy_route_cannot_hide_attempted_delivery_lookalikes(self):
        for change in ("prefix", "suffix", "foreign-caller"):
            with self.subTest(change=change):
                self.package_delivery(p0=None)
                for job in self.jobs["jobs"][:2]:
                    if change == "prefix":
                        job["name"] = "foreign / " + job["name"]
                    elif change == "suffix":
                        job["name"] += " / foreign"
                    else:
                        job["name"] = job["name"].replace("package-delivery", "foreign")
                self.jobs["jobs"][-1].update(conclusion="success", started_at="2026-10-28T10:00:00Z",
                                               completed_at="2026-10-28T10:02:00Z")
                self.refused()
                self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_nested_route_requires_a_completed_skip_for_inactive_legacy(self):
        for status in ("queued", "in_progress", None):
            with self.subTest(status=status):
                self.package_delivery()
                self.jobs["jobs"][-1]["status"] = status
                self.refused()
                self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_nested_route_requires_exact_jobs_genuine_steps_and_original_attempt(self):
        for index in (0, 1):
            for change in ("missing", "failure", "skipped", "running", "no-steps", "skipped-gate",
                           "foreign-run", "foreign-sha", "old-attempt", "duplicate", "prefix", "suffix", "other-caller"):
                with self.subTest(index=index, change=change):
                    self.package_delivery()
                    job = self.jobs["jobs"][index]
                    if change == "missing":
                        self.jobs["jobs"].pop(index)
                        self.jobs["total_count"] -= 1
                    elif change in ("failure", "skipped"):
                        job["conclusion"] = change
                    elif change == "running":
                        job["status"] = "in_progress"
                    elif change == "no-steps":
                        job["steps"] = []
                    elif change == "skipped-gate":
                        job["steps"][1]["conclusion"] = "skipped"
                    elif change == "foreign-run":
                        job["run_id"] = 13
                    elif change == "foreign-sha":
                        job["head_sha"] = "a" * 40
                    elif change == "old-attempt":
                        job["run_attempt"] = 2
                    elif change == "duplicate":
                        self.jobs["jobs"].append(copy.deepcopy(job))
                        self.jobs["total_count"] += 1
                    elif change == "prefix":
                        job["name"] = "foreign / " + job["name"]
                    elif change == "suffix":
                        job["name"] += " / foreign"
                    else:
                        job["name"] = job["name"].replace("package-delivery", "foreign")
                    self.refused()
                    self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_all_routes_preserve_original_creation_despite_later_metadata_update(self):
        original_jobs = copy.deepcopy(self.jobs)
        original_run = copy.deepcopy(self.run)
        for route in ("legacy", "standalone", "nested"):
            for old_creation in (False, True):
                with self.subTest(route=route, old_creation=old_creation):
                    self.run = copy.deepcopy(original_run)
                    self.jobs = copy.deepcopy(original_jobs)
                    if route == "standalone":
                        self.package_preview()
                    elif route == "nested":
                        self.package_delivery()
                    self.artifact.update(created_at="2026-10-28T09:00:00Z" if old_creation else "2026-10-28T10:01:00Z",
                                         updated_at="2026-10-28T12:00:00Z")
                    if old_creation:
                        self.refused()
                        self.assertNotIn("/zip", (self.base / "calls").read_text())
                    else:
                        self.accepted()
                        shutil.rmtree(self.output)

    def test_nested_route_retains_full_payload_and_original_run_bindings(self):
        original_run, original_release = copy.deepcopy(self.run), copy.deepcopy(self.release)
        original_artifact = copy.deepcopy(self.artifact)
        for change in ("sha", "tree", "repository", "artifact-sha", "artifact-repository", "p0-namespace",
                       "p0-feature", "p0-only", "run-race"):
            with self.subTest(change=change):
                self.run = copy.deepcopy(original_run)
                self.release = copy.deepcopy(original_release)
                self.artifact = copy.deepcopy(original_artifact)
                self.artifacts = [self.artifact]
                self.run_after = None
                self.package_delivery()
                if change == "sha":
                    self.run["head_sha"] = "a" * 40
                elif change == "tree":
                    self.run["head_commit"]["tree_id"] = "a" * 40
                elif change == "repository":
                    self.run["head_repository"]["id"] = 99
                elif change == "artifact-sha":
                    self.artifact["workflow_run"]["head_sha"] = "a" * 40
                elif change == "artifact-repository":
                    self.artifact["workflow_run"]["repository_id"] = 99
                elif change == "p0-namespace":
                    self.artifact["name"] += "-p0"
                elif change == "p0-feature":
                    self.release["p11scope_features"] = ["p0-evidence"]
                elif change == "p0-only":
                    self.jobs["jobs"].pop(1)
                    self.jobs["total_count"] -= 1
                else:
                    self.run_after = copy.deepcopy(self.run)
                    self.run_after["run_attempt"] = 2
                self.refused()

    def test_nested_current_attempt_uses_its_own_full_upload_interval(self):
        for old_creation in (False, True):
            with self.subTest(old_creation=old_creation):
                self.package_delivery()
                self.second_attempt()
                self.artifact["updated_at"] = "2026-10-28T12:00:00Z"
                if old_creation:
                    self.artifact["created_at"] = "2026-10-28T10:01:00Z"
                    self.refused()
                    self.assertNotIn("/zip", (self.base / "calls").read_text())
                else:
                    self.accepted()
                    shutil.rmtree(self.output)

    def test_successful_package_full_is_accepted_independently_of_failed_p0(self):
        self.package_preview(conclusion="failure", p0="failure")
        self.accepted()
        calls = [json.loads(row) for row in (self.base / "calls").read_text().splitlines()]
        self.assertEqual([call[1] for call in calls], [
            "repos/mingulov/p11scope/actions/runs/12",
            "repos/mingulov/p11scope/actions/workflows/package-preview.yml",
            "repos/mingulov/p11scope/actions/runs/12/attempts/1/jobs?per_page=100",
            "repos/mingulov/p11scope/actions/runs/12/artifacts?per_page=100",
            "repos/mingulov/p11scope/actions/artifacts/31/zip",
            "repos/mingulov/p11scope/actions/runs/12",
        ], "package admission must retain its successful validate gate, without searching older CI")

    def test_successful_package_full_with_missing_p0_is_accepted(self):
        self.package_preview(p0=None)
        self.accepted()

    def test_successful_package_full_and_p0_are_accepted(self):
        self.package_preview()
        self.accepted()

    def second_attempt(self):
        self.run["run_attempt"] = 2
        for job in self.jobs["jobs"]:
            job["run_attempt"] = 2
            if job["name"] in ("release-preview", "validate", "package-full",
                               "package-delivery / validate", "package-delivery / package-full"):
                job.update(started_at="2026-10-28T11:00:00Z", completed_at="2026-10-28T11:02:00Z")
        self.artifact.update(created_at="2026-10-28T11:01:00Z", updated_at="2026-10-28T11:01:00Z")

    def test_package_current_attempt_refuses_prior_attempt_artifact_before_download(self):
        self.package_preview(conclusion="failure", p0="failure")
        self.second_attempt()
        # Same source/name/digest and freshly updated, but created by attempt 1.
        self.artifact["created_at"] = "2026-10-28T10:01:00Z"
        self.refused()
        self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_ci_current_attempt_refuses_prior_attempt_artifact_before_download(self):
        self.second_attempt()
        self.artifact["created_at"] = "2026-10-28T10:01:00Z"
        self.refused()
        self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_current_package_attempt_accepts_its_full_artifact_with_failed_p0(self):
        self.package_preview(conclusion="failure", p0="failure")
        self.second_attempt()
        self.accepted()

    def test_current_ci_attempt_accepts_its_own_artifact(self):
        self.second_attempt()
        self.accepted()

    def test_package_artifact_must_fall_inside_full_job_not_other_job_intervals(self):
        self.package_preview(conclusion="failure", p0="failure")
        self.jobs["jobs"][0].update(started_at="2026-10-28T09:00:00Z", completed_at="2026-10-28T12:00:00Z")
        self.jobs["jobs"][2].update(started_at="2026-10-28T09:00:00Z", completed_at="2026-10-28T12:00:00Z")
        self.artifact.update(created_at="2026-10-28T10:03:00Z", updated_at="2026-10-28T10:03:00Z")
        self.refused()
        self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_missing_malformed_and_inconsistent_freshness_timestamps_refuse_before_download(self):
        baseline_jobs = copy.deepcopy(self.jobs)
        baseline_artifact = copy.deepcopy(self.artifact)
        for package_route in (False, True):
            if package_route:
                self.package_preview(conclusion="failure", p0="failure")
            else:
                self.jobs = copy.deepcopy(baseline_jobs)
            selected_jobs = copy.deepcopy(self.jobs)
            producer_index = 1 if package_route else 0
            for owner, field, value in (
                ("artifact", "created_at", "missing"), ("artifact", "created_at", None),
                ("artifact", "created_at", "not-a-time"), ("artifact", "updated_at", "missing"),
                ("artifact", "updated_at", "2026-10-28T10:01:00+01:00"),
                ("artifact", "updated_at", "2026-10-28T09:59:00Z"),
                ("producer", "started_at", "missing"), ("producer", "started_at", "not-a-time"),
                ("producer", "completed_at", None), ("producer", "completed_at", "not-a-time"),
                ("producer", "completed_at", "2026-10-28T09:59:00Z"),
            ):
                with self.subTest(package_route=package_route, owner=owner, field=field, value=value):
                    self.jobs = copy.deepcopy(selected_jobs)
                    self.artifact = copy.deepcopy(baseline_artifact)
                    self.artifacts = [self.artifact]
                    target = self.artifact if owner == "artifact" else self.jobs["jobs"][producer_index]
                    if value == "missing":
                        target.pop(field)
                    else:
                        target[field] = value
                    self.refused()
                    self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_canonical_repository_rejects_path_segments_before_api_calls(self):
        for repository in ("../p11scope", "mingulov/..", "mingulov/.", "mingulov/repo/extra", ".owner/repo"):
            with self.subTest(repository=repository):
                result = self.invoke("--repository", repository)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.base / "calls").exists(), "invalid repository reached API")
                self.assertFalse(self.output.exists())

    def test_boolean_release_schema_version_is_not_version_one(self):
        self.release["schema_version"] = True
        self.refused()

    def test_run_rerun_or_source_race_refuses_after_validation_without_output(self):
        for key, value in (("run_attempt", 2), ("head_sha", "f" * 40),
                           ("status", "in_progress"), ("conclusion", "cancelled")):
            with self.subTest(key=key):
                self.run_after = copy.deepcopy(self.run)
                self.run_after[key] = value
                self.refused()
                calls = [json.loads(row) for row in (self.base / "calls").read_text().splitlines()]
                self.assertIn(["api", "repos/mingulov/p11scope/actions/artifacts/31/zip"], calls)

    def test_package_workflow_repository_commit_tree_and_terminal_identity_are_required(self):
        self.package_preview(conclusion="failure", p0="failure")
        baseline = copy.deepcopy(self.run)
        for mutation in (
            {"workflow_id": 71}, {"path": ".github/workflows/other.yml"},
            {"event": "push"}, {"status": "in_progress"}, {"status": "queued"},
            {"conclusion": "cancelled"}, {"conclusion": "timed_out"},
            {"repository": {"id": 10, "full_name": "elsewhere/p11scope"}},
            {"head_repository": {"id": 99, "full_name": REPO}},
            {"head_sha": "a" * 40}, {"head_commit": {"id": HEAD, "tree_id": "b" * 40}},
            {"head_commit": None}, {"run_attempt": True}, {"run_attempt": "1"},
        ):
            with self.subTest(mutation=mutation):
                self.run = baseline | mutation
                self.refused()
                self.assertNotIn("/zip", (self.base / "calls").read_text())
        self.run = baseline
        self.workflows["package-preview"]["id"] = 99
        self.refused()
        self.workflows["package-preview"] = {"id": 72, "path": ".github/workflows/other.yml"}
        self.refused()

    def test_package_validate_and_full_must_run_their_real_gates(self):
        self.package_preview(conclusion="failure", p0="failure")
        baseline = copy.deepcopy(self.jobs)
        for index in (0, 1):
            for change in ("missing", "failure", "skipped", "running", "no-steps", "setup-only",
                           "checkout-only", "skipped-gate", "wrong-run", "wrong-sha", "wrong-attempt", "bool-attempt"):
                with self.subTest(job=index, change=change):
                    self.jobs = copy.deepcopy(baseline)
                    job = self.jobs["jobs"][index]
                    if change == "missing":
                        self.jobs["jobs"].pop(index)
                        self.jobs["total_count"] -= 1
                    elif change in ("failure", "skipped"):
                        job["conclusion"] = change
                    elif change == "running":
                        job["status"] = "in_progress"
                    elif change == "no-steps":
                        job["steps"] = []
                    elif change == "setup-only":
                        job["steps"] = [job["steps"][0], job["steps"][-1]]
                    elif change == "checkout-only":
                        job["steps"] = [{"name": "Run actions/checkout@pinned", "number": 1,
                                         "status": "completed", "conclusion": "success"}]
                    elif change == "skipped-gate":
                        job["steps"][-2]["conclusion"] = "skipped"
                    elif change == "wrong-run":
                        job["run_id"] = 13
                    elif change == "wrong-sha":
                        job["head_sha"] = "f" * 40
                    else:
                        job["run_attempt"] = True if change == "bool-attempt" else 2
                    self.refused()
                    self.assertNotIn("/zip", (self.base / "calls").read_text())

    def test_package_missing_optional_job_attempt_is_accepted(self):
        self.package_preview(p0=None)
        for job in self.jobs["jobs"]:
            job.pop("run_attempt")
        self.accepted()

    def test_package_partial_duplicate_and_invalid_job_lists_refuse(self):
        self.package_preview(p0=None)
        baseline = copy.deepcopy(self.jobs)
        for change in ("partial", "duplicate-name", "duplicate-id", "invalid-row"):
            with self.subTest(change=change):
                self.jobs = copy.deepcopy(baseline)
                if change == "partial":
                    self.jobs["total_count"] += 1
                elif change == "duplicate-name":
                    self.jobs["jobs"].append(copy.deepcopy(self.jobs["jobs"][0]))
                    self.jobs["total_count"] += 1
                elif change == "duplicate-id":
                    self.jobs["jobs"][1]["id"] = self.jobs["jobs"][0]["id"]
                else:
                    self.jobs["jobs"][1] = None
                self.refused()

    def test_package_run_race_refuses_after_full_payload_checks(self):
        self.package_preview(conclusion="failure", p0="failure")
        for mutation in ({"run_attempt": 2}, {"conclusion": "success"},
                         {"workflow_id": 71}, {"head_commit": {"id": HEAD, "tree_id": "a" * 40}},
                         {"repository": {"id": 99, "full_name": REPO},
                          "head_repository": {"id": 99, "full_name": REPO}}):
            with self.subTest(mutation=mutation):
                self.run_after = self.run | mutation
                self.refused()
                self.assertIn("/zip", (self.base / "calls").read_text())

    def test_package_artifact_configuration_schema_and_digest_still_refuse(self):
        self.package_preview()
        self.artifact["name"] = "release-preview-public-assets-p0"
        self.refused()
        self.artifact["name"] = "release-preview-public-assets"
        for mutation in ({"p11scope_features": ["stub-object-attributes"]}, {"schema_version": True},
                         {"schema_version": "1"}, {"tree": "e" * 40}):
            with self.subTest(mutation=mutation):
                saved = copy.deepcopy(self.release)
                self.release.update(mutation)
                self.refused()
                self.release = saved
        self.artifact_overrides = {"digest": "sha256:" + "0" * 64}
        self.refused()

    def test_package_wrong_metadata_object_types_refuse_cleanly(self):
        self.package_preview()
        binding = self.artifact["workflow_run"]
        self.artifact["workflow_run"] = None
        self.refused()
        self.artifact["workflow_run"] = binding
        self.release["artifacts"] = list(self.release["artifacts"])
        self.refused()

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
