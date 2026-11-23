#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the CI gate record (scripts/ci/gate-record.py).

The gate judges one workflow run against the select job's selection
document and writes a p11scope/ci-gate/v1 record. These tests drive the
real script against a stubbed Actions API: green runs pass with every
skipped cell named, quick passes are labelled quick-green, and any
failed, cancelled, required-but-not-run, unexpected or unknown job
fails the gate. Matrix grouping, rerun dedup, pagination and delivery
children are pinned with fixtures.

Run: python3 -I tests/python/test_ci_gate_record.py -v
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = ROOT / "scripts" / "ci" / "gate-record.py"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = load("gate_record", GATE_PATH)
SELECT = load("select_cells", ROOT / "scripts" / "ci" / "select-cells.py")

REPOSITORY = "example/p11scope"
RUN_ID = 42
SHA = "c" * 40

GH_STUB = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs
base = Path(os.environ["FAKE_API"])
with (base / "calls").open("a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\\n")
if (base / "fail").exists():
    sys.exit(29)
endpoint = sys.argv[-1]
query = parse_qs(urlparse(endpoint).query)
page = int(query.get("page", ["1"])[0])
jobs = json.loads((base / "jobs.json").read_text())
sys.stdout.write(json.dumps({
    "total_count": len(jobs), "jobs": jobs[(page - 1) * 100:page * 100]}))
"""


class GateRecordTests(unittest.TestCase):
    maxDiff = 8192

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gate-record-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.api = self.base / "api"
        self.api.mkdir()
        self.bin = self.base / "bin"
        self.bin.mkdir()
        (self.bin / "gh").write_text(GH_STUB)
        (self.bin / "gh").chmod(0o700)
        self.record = self.base / "gate.json"
        self.summary = self.base / "summary.md"
        self.env = {key: value for key, value in os.environ.items()}
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}",
            FAKE_API=str(self.api),
            GITHUB_REPOSITORY=REPOSITORY,
            GITHUB_RUN_ID=str(RUN_ID),
            GITHUB_SHA=SHA,
            GITHUB_STEP_SUMMARY=str(self.summary))

    def selection(self, workflow, event="push", ref="refs/heads/dev/v0.8.0",
                  classes=("known",), tier_input="full", **kwargs):
        arguments = {"delivery_task": "checks", "dedupe_run": True,
                     "release_preview": False, "privileged_e2e": False,
                     "pkcs11_full": False}
        arguments.update(kwargs)
        document, _ = SELECT.build_selection(
            workflow, event, ref, SHA, tier_input, set(classes),
            "dev/v0.8.0", **arguments)
        return document

    def job(self, index, name, conclusion="success", status="completed",
            sha=SHA, run_id=RUN_ID):
        return {"id": index, "name": name, "run_id": run_id,
                "head_sha": sha, "status": status, "conclusion": conclusion}

    def fixture(self, selection, verdicts=()):
        """API job list for a selection: selected jobs succeed and every
        other job skips, unless verdicts maps the job id to another
        conclusion ('missing' omits it). Matrix jobs list per-child
        entries; contracts lists its explicit shard names."""
        entries = []
        for job_id, entry in selection["jobs"].items():
            if job_id == "gate":
                entries.append(self.job(len(entries) + 1, "gate",
                                        conclusion=None, status="in_progress"))
                continue
            verdict = dict(verdicts).get(
                job_id, "success" if entry["state"] == "selected"
                else "skipped")
            if verdict == "missing":
                continue
            names = entry.get("names")
            count = entry.get("children")
            if names is not None:
                for name in names:
                    entries.append(self.job(len(entries) + 1, name, verdict))
            elif count is not None:
                for num in range(count):
                    entries.append(self.job(len(entries) + 1,
                                            f"{job_id} (cell-{num})",
                                            verdict))
            else:
                entries.append(self.job(len(entries) + 1, job_id, verdict))
        return entries

    def run_gate(self, workflow, selection, entries, fail_api=False):
        (self.api / "jobs.json").write_text(json.dumps(entries))
        if fail_api:
            (self.api / "fail").touch()
        env = {**self.env, "P11SCOPE_CI_WORKFLOW": workflow,
               "GATE_SELECTION": json.dumps(selection)}
        result = subprocess.run(
            [sys.executable, "-I", str(GATE_PATH), "--record",
             str(self.record)],
            env=env, text=True, capture_output=True, timeout=60)
        record = json.loads(self.record.read_text(encoding="utf-8")) \
            if self.record.is_file() else None
        summary = self.summary.read_text(encoding="utf-8") \
            if self.summary.is_file() else ""
        return result, record, summary

    def test_full_ci_run_passes(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success"})
        result, record, summary = self.run_gate("ci", selection, entries)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["schema"], "p11scope/ci-gate/v1")
        self.assertEqual(record["workflow"], "ci")
        self.assertEqual(record["sha"], SHA)
        self.assertEqual(record["tier"], "full")
        self.assertEqual(record["verdict"], "pass")
        self.assertEqual(record["label"], "full-green")
        self.assertEqual(record["unknown_jobs"], [])
        for job_id, entry in record["jobs"].items():
            with self.subTest(job=job_id):
                state = selection["jobs"][job_id]["state"]
                if state == "selected":
                    self.assertEqual(entry["status"], "passed")
                elif job_id == "archive-log":
                    # Conditional and ran: archiving a green matrix.
                    self.assertEqual(entry["status"], "passed")
                else:
                    self.assertEqual(entry["status"], "not-selected")
        self.assertEqual(record["jobs"]["quarantine"]["status"],
                         "not-selected")
        self.assertNotIn("gate", record["jobs"])
        self.assertIn("## gate (ci full)", summary)
        self.assertIn("verdict: pass (full-green)", summary)
        self.assertIn("- quarantine: not-selected", summary)

    def test_quick_run_is_labelled_quick_green(self):
        selection = self.selection("privileged-tests", ref="refs/heads/test/x")
        entries = self.fixture(selection)
        result, record, summary = self.run_gate(
            "privileged-tests", selection, entries)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["tier"], "quick")
        self.assertEqual(record["verdict"], "pass")
        self.assertEqual(record["label"], "quick-green")
        self.assertEqual(record["jobs"]["public-cli"]["status"], "passed")
        self.assertEqual(len(record["jobs"]["public-cli"]["children"]), 3)
        self.assertIn("verdict: pass (quick-green)", summary)

    def test_summary_names_every_skipped_cell(self):
        selection = self.selection("privileged-tests", ref="refs/heads/test/x")
        entries = self.fixture(selection)
        result, record, summary = self.run_gate(
            "privileged-tests", selection, entries)
        self.assertEqual(result.returncode, 0, result.stderr)
        skipped = {job_id for job_id, entry in record["jobs"].items()
                   if entry["status"] == "not-selected"}
        self.assertTrue(skipped)
        for job_id in sorted(skipped):
            reason = record["jobs"][job_id]["reason"]
            self.assertTrue(reason)
            self.assertIn(f"- {job_id}: not-selected ({reason})", summary)
        self.assertIn("- browser-cells: not-selected (not in the quick tier)",
                      summary)

    def test_failed_and_cancelled_jobs_fail(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success",
                                           "tests": "failure"})
        result, record, summary = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["verdict"], "fail")
        self.assertEqual(record["label"], "red")
        self.assertEqual(record["jobs"]["tests"]["status"], "failed")
        self.assertIn("- tests: failed (failed: tests)", summary)
        entries = self.fixture(selection, {"archive-log": "success",
                                           "lint": "cancelled"})
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["jobs"]["lint"]["status"], "cancelled")

    def test_selected_but_skipped_or_missing_is_required_not_run(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success",
                                           "coverage": "skipped"})
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["jobs"]["coverage"]["status"], "failed")
        self.assertIn("required but not run",
                      record["jobs"]["coverage"]["detail"])
        entries = self.fixture(selection, {"archive-log": "success",
                                           "audit": "missing"})
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required but not run",
                      record["jobs"]["audit"]["detail"])

    def test_child_count_mismatch_fails(self):
        selection = self.selection("privileged-tests", ref="refs/heads/test/x")
        entries = self.fixture(selection)
        dropped = [entry for entry in entries
                   if entry["name"] != "public-cli (cell-2)"]
        self.assertEqual(len(dropped), len(entries) - 1)
        result, record, _ = self.run_gate(
            "privileged-tests", selection, dropped)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["jobs"]["public-cli"]["status"], "failed")
        self.assertIn("ran 2 children, expected 3",
                      record["jobs"]["public-cli"]["detail"])

    def test_contracts_shards_are_named_exactly(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success"})
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["jobs"]["contracts"]["status"], "passed")
        dropped = [entry for entry in entries
                   if entry["name"] != "contracts-8"]
        result, record, _ = self.run_gate("ci", selection, dropped)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required but not run",
                      record["jobs"]["contracts"]["detail"])

    def test_conditional_failure_fails(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success",
                                           "quarantine": "failure"})
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["jobs"]["quarantine"]["status"], "failed")

    def test_deselected_but_ran_fails(self):
        selection = self.selection("privileged-tests", ref="refs/heads/test/x")
        entries = self.fixture(selection,
                               {"browser-cells": "success"})
        result, record, _ = self.run_gate(
            "privileged-tests", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["jobs"]["browser-cells"]["status"], "failed")
        self.assertIn("ran though not selected",
                      record["jobs"]["browser-cells"]["detail"])

    def test_unknown_job_fails(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success"})
        entries.append(self.job(len(entries) + 1, "mystery-job"))
        result, record, summary = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["unknown_jobs"], ["mystery-job"])
        self.assertIn("- mystery-job: unknown job (not in the selection)",
                      summary)

    def test_rerun_judges_the_latest_attempt(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success",
                                           "lint": "missing"})
        entries.append(self.job(500, "lint", "failure"))
        entries.append(self.job(501, "lint", "success"))
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["jobs"]["lint"]["status"], "passed")
        entries = self.fixture(selection, {"archive-log": "success",
                                           "lint": "missing"})
        entries.append(self.job(500, "lint", "success"))
        entries.append(self.job(501, "lint", "failure"))
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record["jobs"]["lint"]["status"], "failed")

    def test_delivery_children_pass_when_selected(self):
        selection = self.selection("ci", event="workflow_dispatch",
                                   ref="refs/heads/main",
                                   delivery_task="packages")
        entries = self.fixture(selection)
        entries.append(self.job(len(entries) + 1,
                                "package-delivery / validate"))
        entries.append(self.job(len(entries) + 1,
                                "package-delivery / package-full"))
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["jobs"]["package-delivery"]["status"],
                         "passed")

    def test_delivery_children_fail_when_unselected(self):
        selection = self.selection("ci", event="workflow_dispatch",
                                   ref="refs/heads/main",
                                   delivery_task="packages")
        entries = self.fixture(selection)
        entries.append(self.job(len(entries) + 1,
                                "docker-delivery / image"))
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ran though not selected",
                      record["jobs"]["docker-delivery"]["detail"])

    def test_job_prefixes_match_exactly(self):
        # public-cli must not swallow public-cli-ia32: the matrix rule
        # requires the " (" separator.
        selection = self.selection("privileged-tests", ref="refs/heads/test/x")
        entries = self.fixture(selection)
        result, record, _ = self.run_gate(
            "privileged-tests", selection, entries)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["jobs"]["public-cli"]["status"], "passed")
        self.assertEqual(record["jobs"]["public-cli-ia32"]["status"],
                         "passed")

    def test_selection_mismatches_fail_without_a_record(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success"})
        for mutate in ("schema", "workflow", "sha", "empty"):
            with self.subTest(mutate=mutate):
                broken = dict(selection)
                if mutate == "schema":
                    broken["schema"] = "p11scope/ci-selection/v0"
                elif mutate == "workflow":
                    broken["workflow"] = "privileged-tests"
                elif mutate == "sha":
                    broken["sha"] = "d" * 40
                else:
                    broken = {}
                self.record.unlink(missing_ok=True)
                self.summary.unlink(missing_ok=True)
                result, record, summary = self.run_gate(
                    "ci", broken, entries)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(record)
                self.assertEqual(summary, "")

    def test_api_error_and_stale_identity_fail(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success"})
        result, record, _ = self.run_gate("ci", selection, entries,
                                          fail_api=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(record)
        entries[0]["head_sha"] = "d" * 40
        result, record, _ = self.run_gate("ci", selection, entries)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(record)

    def test_jobs_are_paginated(self):
        selection = self.selection("ci")
        entries = self.fixture(selection, {"archive-log": "success"})
        entries.extend(self.job(1000 + number, f"padding-{number}")
                       for number in range(90))
        self.assertGreater(len(entries), 100)
        (self.api / "jobs.json").write_text(json.dumps(entries))
        env = {**self.env, "PATH": f"{self.bin}:{self.env['PATH']}",
               "FAKE_API": str(self.api)}
        script = ("import importlib.util; "
                  "spec = importlib.util.spec_from_file_location("
                  "'gate_record', %r); "
                  "module = importlib.util.module_from_spec(spec); "
                  "spec.loader.exec_module(module); "
                  "jobs = module.fetch_jobs(%r, %d, %r); "
                  "print(len(jobs))" % (
                      str(ROOT / "scripts" / "ci" / "gate-record.py"),
                      REPOSITORY, RUN_ID, SHA))
        result = subprocess.run([sys.executable, "-I", "-c", script],
                                env=env, text=True, capture_output=True,
                                timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(len(entries)))
        calls = (self.api / "calls").read_text(
            encoding="utf-8").splitlines()
        self.assertTrue(any("page=2" in call for call in calls))

    def test_labels(self):
        self.assertEqual(GATE.label_for("quick", "pass"), "quick-green")
        self.assertEqual(GATE.label_for("full", "pass"), "full-green")
        self.assertEqual(GATE.label_for("integration", "pass"),
                         "integration-green")
        self.assertEqual(GATE.label_for("schedule", "pass"), "schedule")
        self.assertEqual(GATE.label_for("quick", "fail"), "red")
        self.assertEqual(GATE.label_for("full", "fail"), "red")


if __name__ == "__main__":
    unittest.main()
