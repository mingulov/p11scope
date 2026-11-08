#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Contract for the generic cell-script template.

scripts/ci/run-cell-script.sh runs one scripts/ci/<name>.sh cell script and
validates its results.jsonl with scripts/ci/check-cell-results.py. The
checker requires every row well formed, no qualified row failing, and the
expected-failure set exactly equal to the declared list. Exit 77 from a
cell script (prerequisite missing) always fails the job.

Run: python3 -I tests/python/test_cell_results.py -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "ci" / "check-cell-results.py"
RUNNER = ROOT / "scripts" / "ci" / "run-cell-script.sh"
WRAPPER = ROOT / "scripts" / "ci" / "public-cli-host.sh"


def run_checker(rows, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "results.jsonl"
        if rows is not None:
            with path.open("w", encoding="utf-8") as file:
                for row in rows:
                    if isinstance(row, str):
                        file.write(row + "\n")
                    else:
                        file.write(json.dumps(row) + "\n")
        result = subprocess.run(
            [sys.executable, "-I", str(CHECKER), str(path), *extra],
            capture_output=True, text=True, timeout=30)
        return result


def row(cell, passed, qualification="qualified", detail="ok"):
    return {"cell": cell, "pass": passed,
            "qualification": qualification, "detail": detail}


class CheckCellResultsTests(unittest.TestCase):
    def test_qualified_pass_accepted(self):
        result = run_checker([row("a", True), row("b", True, "owned-provider-counts")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_cli_qualified_kinds_accepted(self):
        result = run_checker([row("run-prearm", True, "prearm-exactness", "held [] with 3/3 ledger"),
                              row("system", True, "owned-provider-counts-with-runner-noise",
                                  "counts match; disclosed runner noise")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_66_discovery_gap_qualification_accepted(self):
        result = run_checker([row("select-endpoint-system", True,
                                  "owned-provider-counts-with-66-discovery-gap",
                                  "counts match; disclosed 6.6 discovery gap")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_qualified_failure_fails(self):
        result = run_checker([row("a", True), row("b", False, "command-contract")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed qualified cell b", result.stderr)

    def test_failed_qualification_fails(self):
        result = run_checker([row("a", False, "failed", "boom")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed qualified cell a", result.stderr)

    def test_nonqualifying_smoke_allowed(self):
        result = run_checker([row("a", True), row("smoke", False, "nonqualifying", "smoke")],
                             "--allow-nonqualifying", "smoke")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SMOKE smoke", result.stdout)

    def test_nonqualifying_pass_allowed(self):
        result = run_checker([row("smoke", True, "nonqualifying", "smoke passed")],
                             "--allow-nonqualifying", "smoke")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonqualifying_without_allow_list_fails(self):
        result = run_checker([row("smoke", False, "nonqualifying", "smoke")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nonqualifying cell not in allow list: smoke", result.stderr)

    def test_unknown_qualification_fails(self):
        result = run_checker([row("a", True, "skipped", "x")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown qualification", result.stderr)

    def test_require_cells_must_be_present(self):
        result = run_checker([row("a", True)], "--require", "a", "--require", "b")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing required cells: b", result.stderr)
        result = run_checker([row("a", True), row("b", True)], "--require", "a", "--require", "b")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_require_duplicate_names_fail(self):
        result = run_checker([row("a", True)], "--require", "a", "--require", "a")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate --require names", result.stderr)

    def test_allow_nonqualifying_must_match_exactly(self):
        result = run_checker([row("a", True)], "--allow-nonqualifying", "smoke")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing nonqualifying", result.stderr)

    def test_expected_failures_must_match_declared_list(self):
        rows = [row("a", True), row("known", False, "expected-failure", "bug 1")]
        result = run_checker(rows, "--expected-failure", "known")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("EXPECTED-FAIL known", result.stdout)

    def test_undeclared_expected_failure_fails(self):
        rows = [row("known", False, "expected-failure", "bug 1")]
        result = run_checker(rows)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("undeclared expected failures: known", result.stderr)

    def test_missing_expected_failure_fails(self):
        result = run_checker([row("a", True)], "--expected-failure", "known")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing expected failures: known", result.stderr)

    def test_unexpected_pass_of_expected_failure_fails(self):
        rows = [row("known", True, "expected-failure", "fixed?")]
        result = run_checker(rows, "--expected-failure", "known")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected pass for expected failure known", result.stderr)

    def test_malformed_rows_fail(self):
        cases = [
            ["not json"],
            [json.dumps({"cell": "a", "pass": True})],
            [json.dumps({"cell": "a", "pass": True, "qualification": "qualified",
                         "detail": "ok", "extra": 1})],
            [json.dumps({"cell": "", "pass": True, "qualification": "qualified", "detail": "x"})],
            [json.dumps({"cell": "a", "pass": 1, "qualification": "qualified", "detail": "x"})],
            [json.dumps({"cell": "a", "pass": True, "qualification": "", "detail": "x"})],
            [json.dumps({"cell": "a", "pass": True, "qualification": "qualified", "detail": 1})],
        ]
        for case in cases:
            with self.subTest(case=case):
                result = run_checker(case)
                self.assertNotEqual(result.returncode, 0, case)

    def test_duplicate_cells_fail(self):
        result = run_checker([row("a", True), row("a", True)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate cell a", result.stderr)

    def test_empty_and_missing_files_fail(self):
        result = run_checker([])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no result rows", result.stderr)
        result = run_checker(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing results file", result.stderr)

    def test_duplicate_expected_names_fail(self):
        rows = [row("known", False, "expected-failure", "bug")]
        result = run_checker(rows, "--expected-failure", "known", "--expected-failure", "known")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate --expected-failure names", result.stderr)

    def test_allow_nonqualifying_restricts_smoke(self):
        rows = [row("smoke", False, "nonqualifying", "smoke"),
                row("other", False, "nonqualifying", "hidden failure")]
        result = run_checker(rows, "--allow-nonqualifying", "smoke")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nonqualifying cell not in allow list: other", result.stderr)
        result = run_checker([row("smoke", False, "nonqualifying", "smoke")],
                             "--allow-nonqualifying", "smoke")
        self.assertEqual(result.returncode, 0, result.stderr)


class RunCellScriptContractTests(unittest.TestCase):
    def setUp(self):
        self.text = RUNNER.read_text(encoding="utf-8")

    def test_runner_validates_with_the_checker(self):
        self.assertIn("scripts/ci/check-cell-results.py", self.text)
        self.assertIn("--expected-failure", self.text)
        self.assertIn("--allow-nonqualifying", self.text)
        self.assertIn("--require", self.text)

    def test_exit_77_always_fails(self):
        self.assertIn("77", self.text)
        self.assertIn("never a pass in CI", self.text)

    def test_runner_requires_root_and_a_bare_name(self):
        self.assertIn('must run as root', self.text)
        self.assertIn('scripts/ci/$NAME.sh', self.text)
        self.assertIn('without path', self.text)

    def test_runner_rejects_bad_arguments_unprivileged(self):
        result = subprocess.run(
            ["bash", str(RUNNER)], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage:", result.stderr)
        result = subprocess.run(
            ["bash", str(RUNNER), "no-such-cell", "/bin/true", "/tmp"],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no executable cell script", result.stderr)


class PublicCliHostWrapperTests(unittest.TestCase):
    def setUp(self):
        self.text = WRAPPER.read_text(encoding="utf-8")

    def test_wrapper_calls_the_existing_public_cli_lane(self):
        self.assertIn("scripts/qualify-public-cli.sh", self.text)
        self.assertIn("results.jsonl", self.text)

    def test_wrapper_lists_its_apt_prerequisites(self):
        self.assertIn("Apt prerequisites:", self.text)
        for package in ("gcc", "softhsm2"):
            self.assertIn(package, self.text)

    def test_missing_prerequisite_exits_77(self):
        self.assertIn("exit 77", self.text)
        self.assertIn("missing prerequisite", self.text)

    def test_smoke_exit_is_accepted_when_results_exist(self):
        self.assertIn('"$rc" -eq 2', self.text)


if __name__ == "__main__":
    unittest.main()
