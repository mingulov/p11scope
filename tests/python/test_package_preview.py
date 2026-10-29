#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package-only orchestration at the real helper and extracted shell seams."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/check-package-preview-ci.py"
WORKFLOW = ROOT / ".github/workflows/package-preview.yml"
REPOSITORY = "example/p11scope"
RUN_ID = 42
WORKFLOW_ID = 71
ATTEMPT = 2
REQUIRED = (
    "dedupe", "lint", "audit", "tests", "bpf-noninterference", "scripts", "archive-log",
    "contracts-1", "contracts-2", "contracts-3", "contracts-4",
    "contracts-5", "contracts-6", "contracts-7", "contracts-8",
    "coverage (rest)", "coverage (contracts:1/6)", "coverage (contracts:2/6)",
    "coverage (contracts:3/6)", "coverage (contracts:4/6)",
    "coverage (contracts:5/6)", "coverage (contracts:6/6)", "coverage-report",
)


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def step(name, job="package"):
    return next(item for item in workflow()["jobs"][job]["steps"] if item.get("name") == name)


class PackagePreviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope-package-preview-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "source"
        self.repo.mkdir()
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.api = self.base / "api"
        self.api.mkdir()
        self.requests = self.base / "requests.jsonl"
        self.events = self.base / "children.jsonl"
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}", GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull, FAKE_API=str(self.api),
            FAKE_REQUESTS=str(self.requests), FAKE_EVENTS=str(self.events),
        )
        self.git("init", "-q")
        (self.repo / "tracked").write_text("exact source\n")
        self.git("add", "tracked")
        self.git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.tree = self.git("rev-parse", "HEAD^{tree}").strip()
        self.run = {
            "id": RUN_ID, "workflow_id": WORKFLOW_ID, "path": ".github/workflows/ci.yml",
            "status": "completed", "conclusion": "success", "head_sha": self.sha,
            "run_attempt": ATTEMPT, "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
            "head_commit": {"id": self.sha, "tree_id": self.tree},
        }
        self.jobs = [self.job(index, name) for index, name in enumerate(REQUIRED, 1)]
        (self.bin / "gh").write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
api = pathlib.Path(os.environ["FAKE_API"])
with open(os.environ["FAKE_REQUESTS"], "a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\\n")
path = sys.argv[-1]
if "/attempts/" in path:
    name = "jobs-" + path.rsplit("page=", 1)[1]
elif "/workflows/" in path:
    name = "workflow"
else:
    count = api / "run-count"
    number = int(count.read_text()) + 1 if count.exists() else 1
    count.write_text(str(number))
    name = "run-final" if number > 1 and (api / "run-final").exists() else "run"
if (api / (name + ".fail")).exists():
    sys.exit(29)
sys.stdout.write((api / name).read_text())
''')
        (self.bin / "gh").chmod(0o700)

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", *args],
                                       cwd=self.repo, env=self.env, text=True)

    def job(self, index, name):
        return {
            "id": index, "name": name, "run_id": RUN_ID, "run_attempt": ATTEMPT,
            "head_sha": self.sha, "status": "completed", "conclusion": "success",
            "started_at": "2026-10-29T00:00:00Z", "completed_at": "2026-10-29T00:01:00Z",
            "steps": [{"name": "Run actual gate", "number": 1,
                       "status": "completed", "conclusion": "success"}],
        }

    def write_api(self):
        (self.api / "workflow").write_text(json.dumps({"id": WORKFLOW_ID, "path": ".github/workflows/ci.yml"}))
        (self.api / "run").write_text(json.dumps(self.run))
        for index in range(0, max(1, len(self.jobs)), 100):
            (self.api / f"jobs-{index // 100 + 1}").write_text(json.dumps({
                "total_count": len(self.jobs), "jobs": self.jobs[index:index + 100],
            }))

    def validate(self, *extra):
        self.assertTrue(HELPER.is_file(), "the package CI validation helper is missing")
        self.write_api()
        return subprocess.run([
            sys.executable, "-I", str(HELPER), "--repository", REPOSITORY,
            "--sha", self.sha, "--accepted-ci-run-id", str(RUN_ID), *extra,
        ], cwd=self.repo, env=self.env, text=True, capture_output=True, timeout=10)

    def outputs(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return dict(line.split("=", 1) for line in result.stdout.splitlines())

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "", "a refusal must not publish job outputs")

    def test_success_pins_tree_attempt_and_both_independent_artifacts(self):
        output = self.outputs(self.validate())
        self.assertEqual(output["sha"], self.sha)
        self.assertEqual(output["tree"], self.tree)
        self.assertEqual(output["jobs"], "2")
        self.assertEqual(json.loads(output["matrix"]), {"include": [
            {"mode": "full", "artifact": "release-preview-public-assets", "public": "public"},
            {"mode": "p0", "artifact": "release-preview-public-assets-p0", "public": "public-p0"},
        ]})
        calls = [json.loads(line) for line in self.requests.read_text().splitlines()]
        self.assertEqual([call[-1] for call in calls], [
            f"repos/{REPOSITORY}/actions/workflows/ci.yml",
            f"repos/{REPOSITORY}/actions/runs/42",
            f"repos/{REPOSITORY}/actions/runs/42/attempts/2/jobs?per_page=100&page=1",
            f"repos/{REPOSITORY}/actions/runs/42",
        ])

    def test_selected_mode_and_canonical_jobs_are_published(self):
        for mode, jobs in (("full", "1"), ("p0", "16")):
            with self.subTest(mode=mode, jobs=jobs):
                output = self.outputs(self.validate("--capture-mode", mode, "--jobs", jobs))
                self.assertEqual(output["jobs"], jobs)
                self.assertEqual([item["mode"] for item in json.loads(output["matrix"])["include"]], [mode])

    def test_invalid_inputs_refuse_before_api_or_outputs(self):
        cases = [["--jobs", value] for value in ("", "0", "17", "01", "+2", "2\n", "2.0")]
        cases += [["--accepted-ci-run-id", value] for value in ("", "0", "-1", "01", "1\n")]
        cases += [["--capture-mode", "unknown"], ["--sha", "a" * 39],
                  ["--repository", "owner/repo?query=1"], ["--repository", "../repo"],
                  ["--repository", "owner/.."]]
        for options in cases:
            with self.subTest(options=options):
                self.assert_refused(self.validate(*options))
                self.assertFalse(self.requests.exists(), "invalid input reached the API")

    def test_dirty_or_wrong_checkout_refuses_before_api(self):
        (self.repo / "tracked").write_text("changed bytes\n")
        self.assert_refused(self.validate())
        self.assertFalse(self.requests.exists())
        self.git("checkout", "--", "tracked")
        self.assert_refused(self.validate("--sha", "a" * 40))
        self.assertFalse(self.requests.exists())
        (self.repo / "untracked").touch()
        self.assert_refused(self.validate())
        self.assertFalse(self.requests.exists())

    def test_wrong_run_workflow_repo_sha_tree_and_partial_run_refuse(self):
        baseline = copy.deepcopy(self.run)
        mutations = (
            {"id": 43}, {"workflow_id": 72}, {"path": ".github/workflows/other.yml"},
            {"status": "in_progress"}, {"conclusion": "failure"},
            {"repository": {"full_name": "other/p11scope"}},
            {"head_repository": {"full_name": "fork/p11scope"}},
            {"head_sha": "a" * 40}, {"head_commit": {"id": self.sha, "tree_id": "b" * 40}},
            {"run_attempt": 0}, {"run_attempt": True}, {"head_commit": None},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.run = {**baseline, **mutation}
                self.assert_refused(self.validate())

    def test_every_missing_failed_skipped_or_unexecuted_required_job_refuses(self):
        baseline = copy.deepcopy(self.jobs)
        for index, name in enumerate(REQUIRED):
            for change in ("missing", "skipped", "failure", "in_progress", "no-steps"):
                with self.subTest(name=name, change=change):
                    self.jobs = copy.deepcopy(baseline)
                    job = self.jobs[index]
                    if change == "missing":
                        self.jobs.pop(index)
                    elif change == "no-steps":
                        job["steps"] = []
                    elif change == "in_progress":
                        job["status"] = change
                    else:
                        job["conclusion"] = change
                    self.assert_refused(self.validate())

    def test_delivery_only_green_ci_cannot_qualify_as_ordinary_checks(self):
        self.jobs = [job for job in self.jobs if job["name"] == "dedupe"]
        for index, name in enumerate(("package-delivery / validate", "package-delivery / package-full"), 100):
            job = copy.deepcopy(self.jobs[0])
            job.update(id=index, name=name)
            self.jobs.append(job)
        self.assert_refused(self.validate())

    def test_stale_duplicate_and_invalid_job_or_gate_step_refuse(self):
        baseline = copy.deepcopy(self.jobs)
        mutations = (
            {"run_id": 41}, {"run_attempt": 1}, {"head_sha": "a" * 40},
            {"started_at": None}, {"completed_at": "invalid"},
            {"steps": [{"name": "Set up job", "number": 1, "status": "completed", "conclusion": "success"}]},
            {"steps": [{"name": "Run actual gate", "number": 1, "status": "completed", "conclusion": "skipped"}]},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.jobs = copy.deepcopy(baseline)
                self.jobs[0].update(mutation)
                self.assert_refused(self.validate())
        for duplicate in (dict(baseline[0]), {**baseline[0], "id": 500}):
            self.jobs = [*baseline, duplicate]
            self.assert_refused(self.validate())

    def test_jobs_are_paginated_without_deduping_or_losing_later_gates(self):
        self.jobs = [self.job(index, f"other-{index}") for index in range(100, 200)] + self.jobs
        output = self.outputs(self.validate())
        self.assertEqual(output["sha"], self.sha)
        self.assertIn("page=2", self.requests.read_text())
        self.jobs[-1]["conclusion"] = "failure"
        self.assert_refused(self.validate())

    def test_api_errors_malformed_incomplete_pages_and_attempt_race_refuse(self):
        self.assertTrue(HELPER.is_file(), "the package CI validation helper is missing")
        self.write_api()
        command = [sys.executable, "-I", str(HELPER), "--repository", REPOSITORY,
                   "--sha", self.sha, "--accepted-ci-run-id", "42"]
        for name, contents in (("run.fail", ""), ("run", "not json"),
                               ("run", '{"id": 42, "id": 42}'),
                               ("run", json.dumps({**self.run, "invalid": float("nan")})),
                               ("jobs-1", '{"total_count": 24, "jobs": []}'),
                               ("jobs-1", '{"total_count": true, "jobs": []}'),
                               ("workflow", '{"id": 71, "path": "other.yml"}')):
            with self.subTest(name=name, contents=contents):
                self.write_api()
                (self.api / name).write_text(contents)
                result = subprocess.run(command, cwd=self.repo, env=self.env, text=True,
                                        capture_output=True, timeout=10)
                self.assert_refused(result)
                (self.api / "run.fail").unlink(missing_ok=True)
        self.write_api()
        (self.api / "run-count").unlink(missing_ok=True)
        (self.api / "run-final").write_text(json.dumps({**self.run, "run_attempt": 3}))
        result = subprocess.run(command, cwd=self.repo, env=self.env, text=True,
                                capture_output=True, timeout=10)
        self.assert_refused(result)

    def test_real_validation_shell_emits_outputs_only_after_acceptance(self):
        self.assertTrue(WORKFLOW.is_file(), "the package-only workflow is missing")
        scripts = self.repo / "scripts"
        scripts.mkdir()
        shutil.copyfile(HELPER, scripts / HELPER.name)
        self.git("add", "scripts")
        self.git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture: validation helper")
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.tree = self.git("rev-parse", "HEAD^{tree}").strip()
        self.run.update(head_sha=self.sha, head_commit={"id": self.sha, "tree_id": self.tree})
        for job in self.jobs:
            job["head_sha"] = self.sha
        self.write_api()
        output = self.base / "github-output"
        env = {**self.env, "EXPECTED_REPOSITORY": REPOSITORY, "EXPECTED_SHA": self.sha,
               "ACCEPTED_CI_RUN_ID": "42", "CAPTURE_MODE": "p0", "BUILD_JOBS": "3",
               "GITHUB_OUTPUT": str(output)}
        command = ["bash", "--noprofile", "--norc", "-c", step("Validate accepted ordinary CI", "validate")["run"]]
        accepted = subprocess.run(command, cwd=self.repo, env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(values["jobs"], "3")
        self.assertEqual(json.loads(values["matrix"])["include"][0]["mode"], "p0")
        output.unlink()
        self.jobs[0]["conclusion"] = "skipped"
        self.write_api()
        refused = subprocess.run(command, cwd=self.repo, env=env, text=True, capture_output=True, timeout=10)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse(output.exists(), "failed validation published matrix outputs")

    def test_package_runner_rechecks_sha_tree_and_cleanliness_before_setup(self):
        self.assertTrue(WORKFLOW.is_file(), "the package-only workflow is missing")
        command = ["bash", "--noprofile", "--norc", "-c", step("Verify package checkout")["run"]]
        env = {**self.env, "EXPECTED_SHA": self.sha, "EXPECTED_TREE": self.tree}
        valid = subprocess.run(command, cwd=self.repo, env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        for mutation in ({"EXPECTED_SHA": "a" * 40}, {"EXPECTED_TREE": "b" * 40}):
            invalid = subprocess.run(command, cwd=self.repo, env={**env, **mutation},
                                     text=True, capture_output=True, timeout=10)
            self.assertNotEqual(invalid.returncode, 0)
        (self.repo / "untracked").touch()
        dirty = subprocess.run(command, cwd=self.repo, env=env, text=True, capture_output=True, timeout=10)
        self.assertNotEqual(dirty.returncode, 0)
        steps = workflow()["jobs"]["package"]["steps"]
        self.assertEqual(steps[1]["name"], "Verify package checkout")

    def prepare_package_children(self):
        scripts = self.repo / "scripts"
        scripts.mkdir()
        stub = '''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["FAKE_EVENTS"], "a") as log:
    log.write(json.dumps([name, args]) + "\\n")
def value(option):
    return args[args.index(option) + 1]
if name == "build-release.sh":
    mode = value("--capture-mode")
    if os.environ.get("FAIL_CHILD") == "builder" or mode == os.environ.get("FAIL_MODE"):
        sys.exit(37)
    receipt = pathlib.Path(args[-1])
    receipt.mkdir()
    (receipt / "status").write_text("1\\n" if os.environ.get("FAIL_CHILD") == "receipt" else "0\\n")
    (receipt / "facts.log").write_text(mode + " " + value("--jobs"))
    (receipt / "private.log").write_text("private capture material")
elif name == "export-source.py":
    if os.environ.get("FAIL_CHILD") == "source": sys.exit(39)
    pathlib.Path(value("--output")).write_bytes(b"genuine-source-stand-in")
elif name == "release-notices.py":
    if os.environ.get("FAIL_CHILD") == "notices": sys.exit(41)
    pathlib.Path(value("--output")).mkdir()
else:
    if os.environ.get("FAIL_CHILD") == "package": sys.exit(43)
    receipt = pathlib.Path(value("--receipt"))
    if (receipt / "status").read_text() != "0\\n": sys.exit(45)
    if (receipt / "facts.log").read_text().split()[0] != value("--capture-mode"): sys.exit(47)
    if not pathlib.Path(value("--source")).is_file(): sys.exit(49)
    if not pathlib.Path(value("--notices")).is_dir(): sys.exit(51)
    output = pathlib.Path(value("--output"))
    output.mkdir()
    (output / "RELEASE.json").write_text("public package")
'''
        for name in ("build-release.sh", "export-source.py", "release-notices.py", "package-release.py"):
            (scripts / name).write_text(stub)
            (scripts / name).chmod(0o700)

    def assemble(self, mode, *, jobs="2", failure="", fail_mode=""):
        self.assertTrue(WORKFLOW.is_file(), "the package-only workflow is missing")
        runner = self.base / (mode + "-" + (failure or fail_mode or "success"))
        runner.mkdir()
        public = "public" if mode == "full" else "public-p0"
        env = {**self.env, "RUNNER_TEMP": str(runner), "CAPTURE_MODE": mode,
               "BUILD_JOBS": jobs, "PUBLIC_DIRECTORY": public,
               "FAIL_CHILD": failure, "FAIL_MODE": fail_mode}
        result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c",
                                 step("Build and assemble public package")["run"]],
                                cwd=self.repo, env=env, text=True, capture_output=True, timeout=10)
        return result, runner / "release-evidence" / public

    def test_real_assembly_passes_mode_jobs_and_exact_source_receipt_arguments(self):
        self.prepare_package_children()
        for mode, jobs in (("full", "2"), ("p0", "16")):
            with self.subTest(mode=mode):
                self.events.unlink(missing_ok=True)
                result, public = self.assemble(mode, jobs=jobs)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([p.name for p in public.iterdir()], ["RELEASE.json"])
                calls = [json.loads(line) for line in self.events.read_text().splitlines()]
                self.assertEqual([call[0] for call in calls], ["build-release.sh", "export-source.py",
                                                            "release-notices.py", "package-release.py"])
                evidence = public.parent
                self.assertEqual(calls[0][1], ["--capture-mode", mode, "--jobs", jobs, str(evidence / "receipt")])
                self.assertEqual(calls[1][1], ["--output", str(evidence / "source.tar.gz")])
                self.assertEqual(calls[2][1], ["--cargo-about", str(evidence.parent / "release-tools/cargo-about"),
                                             "--musl-archive", str(evidence.parent / "release-tools/musl-1.2.5.tar.gz"),
                                             "--output", str(evidence / "notices")])
                self.assertEqual(calls[3][1], ["--capture-mode", mode, "--receipt", str(evidence / "receipt"),
                                             "--notices", str(evidence / "notices"), "--source", str(evidence / "source.tar.gz"),
                                             "--output", str(public)])

    def test_builder_source_notices_package_or_receipt_failure_blocks_that_upload(self):
        self.prepare_package_children()
        for failure, status in (("builder", 37), ("source", 39), ("notices", 41), ("package", 43), ("receipt", 45)):
            with self.subTest(failure=failure):
                result, public = self.assemble("full", failure=failure)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertFalse(public.exists())

    def test_full_package_is_uploadable_while_p0_fails(self):
        self.prepare_package_children()
        full_result, full_public = self.assemble("full", fail_mode="p0")
        p0_result, p0_public = self.assemble("p0", fail_mode="p0")
        self.assertEqual(full_result.returncode, 0, full_result.stderr)
        self.assertTrue((full_public / "RELEASE.json").is_file())
        self.assertEqual(p0_result.returncode, 37)
        self.assertFalse(p0_public.exists())
        package = workflow()["jobs"]["package"]
        self.assertEqual(package["needs"], "validate")
        self.assertIs(package["strategy"]["fail-fast"], False)
        upload = next(item for item in package["steps"] if item.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertNotIn("if", upload, "each successful matrix member uploads immediately")
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/release-evidence/${{ matrix.public }}/")
        self.assertEqual(upload["with"]["name"], "${{ matrix.artifact }}")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")

    def test_workflow_is_manual_only_pinned_read_only_and_has_no_duplicate_gates(self):
        self.assertTrue(WORKFLOW.is_file(), "the package-only workflow is missing")
        document = workflow()
        trigger = document.get("on", document.get(True))
        self.assertEqual(set(trigger), {"workflow_dispatch"})
        inputs = trigger["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs), {"accepted_ci_run_id", "capture_mode", "jobs"})
        self.assertTrue(inputs["accepted_ci_run_id"]["required"])
        self.assertEqual(inputs["capture_mode"]["options"], ["full", "p0", "both"])
        self.assertEqual(inputs["capture_mode"]["default"], "both")
        self.assertEqual(str(inputs["jobs"]["default"]), "2")
        self.assertEqual(document["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(set(document["jobs"]), {"validate", "package"})
        standard = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        ordinary = set(standard["jobs"]) - {"contracts", "coverage", "privileged-e2e", "release-preview", "quarantine"}
        ordinary.update(f"contracts-{index}" for index in standard["jobs"]["contracts"]["strategy"]["matrix"]["shard"])
        ordinary.update(f"coverage ({partition})" for partition in standard["jobs"]["coverage"]["strategy"]["matrix"]["partition"])
        self.assertEqual(ordinary, set(REQUIRED), "new CI gates must update the acceptance helper and its controls")
        pins = {item["uses"] for job in standard["jobs"].values() for item in job["steps"] if "uses" in item}
        for job in document["jobs"].values():
            self.assertEqual(job["runs-on"], "ubuntu-26.04")
            self.assertEqual(job["steps"][0]["with"]["fetch-depth"], 0)
            for item in job["steps"]:
                if "uses" in item:
                    self.assertIn(item["uses"], pins)


if __name__ == "__main__":
    unittest.main()
