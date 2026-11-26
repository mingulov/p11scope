#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the generic cell-script template.

scripts/ci/run-cell-script.sh runs one scripts/ci/<name>.sh cell script and
validates its results.jsonl with scripts/ci/check-cell-results.py. The
checker requires every row well formed, no qualified row failing, and the
expected-failure set exactly equal to the declared list (intermittent
failures may land as either a pass or a known-signature failure). Exit 77 from a
cell script (prerequisite missing) always fails the job.

Run: python3 -I tests/python/test_cell_results.py -v
"""

import json
import shutil
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


def row(cell, passed, qualification="qualified", detail="ok", proof=None):
    row = {"cell": cell, "pass": passed,
           "qualification": qualification, "detail": detail}
    if proof is not None:
        row["proof"] = proof
    return row


def edge_proof(total=64017, callers=1):
    return {"edge_total": total, "caller_count": callers}


def info_proof(manufacturer="SoftHSM", major=2, minor=6, tokens=2,
               mechanisms=140, slots=2):
    return {"manufacturer": manufacturer, "library_major": major,
            "library_minor": minor, "token_rows": tokens,
            "mechanism_rows": mechanisms, "slots": slots}


class CheckCellResultsTests(unittest.TestCase):
    def test_qualified_pass_accepted(self):
        result = run_checker([row("a", True), row("b", True, "owned-provider-counts")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_cli_qualified_kinds_accepted(self):
        result = run_checker([row("doctor", True, "command-contract", "rc=0"),
                              row("names-pid", True, "semantic-names",
                                  "six independent physical targets carry expected semantic names"),
                              row("verdict-pid", True, "verdict-consistency",
                                  "clean owned target verdict is consistent"),
                              row("run-prearm", True, "prearm-exactness", "held [] with 3/3 ledger"),
                              row("system", True, "owned-provider-counts-with-runner-noise",
                                  "counts match; disclosed runner noise"),
                              row("mt-system", True, "owned-provider-counts-with-ambient-gap",
                                  "counts match; disclosed honest ambient gap")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_owned_edge_usage_counts_accepted_with_proof(self):
        # The verdict decides over the typed proof record; the
        # detail sentence is human prose and is never parsed (its
        # content is deliberately unrelated here).
        result = run_checker([
            row("inventory-mt-pid", True, "owned-edge-usage-counts",
                "human detail, ignored by the verdict",
                proof=edge_proof(64017, 1)),
            row("inventory-mt-system", True, "owned-edge-usage-counts",
                "human detail, ignored by the verdict",
                proof=edge_proof(64065, 5)),
        ])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_owned_edge_usage_counts_rejects_bad_proof(self):
        cases = [
            None,
            "not-an-object",
            {},
            {"edge_total": 64017},
            {"edge_total": 64017, "caller_count": 1, "extra": 0},
            {"edge_total": 0, "caller_count": 1},
            {"edge_total": 64017, "caller_count": 0},
            {"edge_total": -1, "caller_count": 1},
            {"edge_total": True, "caller_count": 1},
            {"edge_total": "64017", "caller_count": 1},
        ]
        for proof in cases:
            with self.subTest(proof=proof):
                result = run_checker([row("inventory-mt-pid", True,
                                          "owned-edge-usage-counts",
                                          "human detail", proof=proof)])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("owned-edge-usage-counts proof", result.stderr)
                self.assertNotIn("inventory-mt-pid", result.stdout)

    def test_provider_info_exact_accepted_with_proof(self):
        # The verdict decides over the typed proof record; the
        # detail sentence is human prose and is never parsed (its
        # content is deliberately unrelated here).
        result = run_checker([
            row("inventory-provider-info-pid", True, "provider-info-exact",
                "human detail, ignored by the verdict",
                proof=info_proof()),
        ])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_provider_info_exact_rejects_bad_proof(self):
        good = info_proof()
        cases = [
            None,
            "not-an-object",
            {},
            dict(good, token_rows=0),
            dict(good, mechanism_rows=0),
            dict(good, slots=0),
            dict(good, token_rows=-1),
            dict(good, token_rows=True),
            dict(good, token_rows="2"),
            dict(good, manufacturer=""),
            dict(good, manufacturer=7),
            dict(good, library_major=256),
            dict(good, library_minor=-1),
            dict(good, extra=0),
            {key: value for key, value in good.items() if key != "slots"},
        ]
        for proof in cases:
            with self.subTest(proof=proof):
                result = run_checker([row("inventory-provider-info-pid", True,
                                          "provider-info-exact",
                                          "human detail", proof=proof)])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("provider-info-exact proof", result.stderr)
                self.assertNotIn("inventory-provider-info-pid", result.stdout)

    def test_proof_on_other_qualifications_refused(self):
        # Only the two exact-proof qualifications may carry proof;
        # any other row with a proof key is schema-invalid.
        result = run_checker([row("a", True, "qualified", "ok",
                                  proof=info_proof())])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("want no proof", result.stderr)

    def test_provider_info_exact_failure_rejected(self):
        result = run_checker([
            row("inventory-provider-info-pid", False, "provider-info-exact",
                "human detail, ignored by the verdict",
                proof=info_proof()),
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed qualified cell inventory-provider-info-pid", result.stderr)

    def test_owned_edge_usage_counts_failure_rejected(self):
        result = run_checker([
            row("inventory-mt-pid", False, "owned-edge-usage-counts",
                "human detail, ignored by the verdict",
                proof=edge_proof()),
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed qualified cell inventory-mt-pid", result.stderr)

    def test_66_discovery_gap_qualification_accepted(self):
        result = run_checker([row("select-endpoint-system", True,
                                  "owned-provider-counts-with-66-discovery-gap",
                                  "counts match; disclosed 6.6 discovery gap")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exit_ambient_gap_qualification_rejected(self):
        # The oracle no longer emits the exit-ambient label (an exit
        # excuse requires proof the process exited, and the ambiguous
        # mid-flight row fails closed): the checker's closed set
        # rejects it, like the retired burst label below.
        result = run_checker([row("counter-counts-system", True,
                                  "owned-provider-counts-with-exit-ambient-gap",
                                  "counts match; disclosed honest ambient exits: "
                                  "mid_flight_exits=3; discovery_skips=2")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown qualification", result.stderr)

    def test_ambient_burst_qualification_rejected(self):
        # The oracle no longer emits the burst label (evidence-only
        # census since the pdg-harden holdouts): the checker's closed
        # set rejects it until the v0.8 re-arm.
        result = run_checker([row("system", True,
                                  "owned-provider-counts-with-ambient-burst",
                                  "counts match; disclosed ambient burst")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown qualification", result.stderr)

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

    def test_intermittent_failure_accepts_either_outcome(self):
        for outcome in (row("flaky", True),
                        row("flaky", False, "expected-failure", "bug 1: signature")):
            result = run_checker([row("a", True), outcome],
                                 "--intermittent-failure", "flaky=task/fix",
                                 "--require", "a")
            self.assertEqual(result.returncode, 0, (outcome, result.stderr))

    def test_intermittent_failure_never_masks_a_failure(self):
        for outcome, message in (
                (row("flaky", False, "failed", "rc=101 other"), "failed qualified cell flaky"),
                (row("flaky", True, "expected-failure", "UNEXPECTED PASS"),
                 "unexpected pass for expected failure flaky")):
            result = run_checker([outcome], "--intermittent-failure", "flaky=task/fix")
            self.assertNotEqual(result.returncode, 0, outcome)
            self.assertIn(message, result.stderr)

    def test_intermittent_failure_row_must_appear(self):
        result = run_checker([row("a", True)], "--intermittent-failure", "flaky=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing intermittent cells: flaky", result.stderr)

    def test_intermittent_failure_names_are_exclusive(self):
        rows = [row("flaky", False, "expected-failure", "bug")]
        result = run_checker(rows, "--intermittent-failure", "flaky=task/fix",
                             "--expected-failure", "flaky")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cells declared both expected and intermittent: flaky", result.stderr)
        result = run_checker(rows, "--intermittent-failure", "flaky=task/fix",
                             "--intermittent-failure", "flaky=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate --intermittent-failure declaration: flaky=task/fix",
                      result.stderr)

    def test_intermittent_failure_needs_a_named_lane(self):
        for value in ("flaky", "flaky=", "=task/fix", "flaky=bad lane",
                      "flaky=../escape"):
            result = run_checker([row("flaky", True)],
                                 "--intermittent-failure", value)
            with self.subTest(value=value):
                self.assertNotEqual(result.returncode, 0, value)
                self.assertIn("intermittent cell needs a named lane", result.stderr)

    def test_intermittent_failure_accepts_two_lanes_for_one_cell(self):
        outcome = row("flaky", False, "expected-failure", "bug 1: signature")
        result = run_checker([row("a", True), outcome],
                             "--intermittent-failure", "flaky=task/one",
                             "--intermittent-failure", "flaky=task/two")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("flaky=task/one+task/two", result.stdout)

    def test_malformed_rows_fail(self):
        # Each malformed shape is refused with its exact typed
        # error, never a bare nonzero exit or a traceback.
        cases = [
            (["not json"], "invalid JSON"),
            ([json.dumps(["a", True])], "row is not an object"),
            ([json.dumps("a")], "row is not an object"),
            ([json.dumps(42)], "row is not an object"),
            ([json.dumps({"cell": "a", "pass": True})],
             "row must have exactly cell/pass/qualification/detail"),
            ([json.dumps({"cell": "a", "pass": True, "qualification": "qualified",
                          "detail": "ok", "extra": 1})],
             "row must have exactly cell/pass/qualification/detail"),
            ([json.dumps({"cell": "", "pass": True, "qualification": "qualified", "detail": "x"})],
             "cell must be a nonempty string"),
            ([json.dumps({"cell": 1, "pass": True, "qualification": "qualified", "detail": "x"})],
             "cell must be a nonempty string"),
            ([json.dumps({"cell": None, "pass": True, "qualification": "qualified", "detail": "x"})],
             "cell must be a nonempty string"),
            ([json.dumps({"cell": "a", "pass": 1, "qualification": "qualified", "detail": "x"})],
             "pass must be a boolean"),
            ([json.dumps({"cell": "a", "pass": True, "qualification": "", "detail": "x"})],
             "qualification must be a nonempty string"),
            ([json.dumps({"cell": "a", "pass": True, "qualification": 1, "detail": "x"})],
             "qualification must be a nonempty string"),
            ([json.dumps({"cell": "a", "pass": True, "qualification": "qualified", "detail": 1})],
             "detail must be a string"),
        ]
        for case, message in cases:
            with self.subTest(case=case):
                result = run_checker(case)
                self.assertNotEqual(result.returncode, 0, case)
                self.assertIn(message, result.stderr, case)

    def test_duplicate_cells_fail(self):
        result = run_checker([row("a", True), row("a", True)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate cell a", result.stderr)

    def test_proof_null_is_refused_everywhere(self):
        # An explicit JSON null is a present proof, never absence:
        # refused on plain qualifications and on exact-proof ones
        # alike (null is not an object).
        plain = dict(row("a", True, "qualified", "ok"))
        plain["proof"] = None
        result = run_checker([plain], "--require", "a")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("want no proof", result.stderr)
        self.assertNotIn("PASS a", result.stdout)
        exact = dict(
            row(
                "inventory-provider-info-pid",
                True,
                "provider-info-exact",
                "human detail",
                proof=info_proof(),
            )
        )
        exact["proof"] = None
        result = run_checker([exact])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an object", result.stderr)

    def test_duplicate_scalar_keys_refused(self):
        # The lossy-collapse repro: the first boolean must not be
        # silently replaced before the typed verdict is judged.
        line = (
            '{"cell":"a","pass":false,"pass":true,'
            '"qualification":"qualified","detail":"ok"}'
        )
        result = run_checker([line], "--require", "a")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate key", result.stderr)
        self.assertNotIn("PASS a", result.stdout)

    def test_duplicate_proof_keys_refused(self):
        proof = (
            '{"edge_total": 1, "edge_total": 2, "caller_count": 1}'
        )
        line = (
            '{"cell":"inventory-mt-pid","pass":true,'
            '"qualification":"owned-edge-usage-counts",'
            '"detail":"human detail","proof":' + proof + "}"
        )
        result = run_checker([line])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate key", result.stderr)

    def test_checker_leaves_no_bytecode_beside_shared_validator(self):
        # A gate must not mutate the tree it validates: importing
        # the shared row validator must not drop __pycache__ next
        # to the staged scripts.
        cache = CHECKER.parent / "__pycache__"
        shutil.rmtree(cache, ignore_errors=True)
        result = run_checker([row("a", True)], "--require", "a")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(cache.exists())

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
