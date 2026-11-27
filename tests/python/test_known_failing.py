#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract tests for the typed known-failing ledger gate."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-known-failing.py"
SHA = "a" * 40


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def row(**changes):
    value = {
        "path": "tests/python/test_sample.py",
        "test": "Sample.test_x",
        "cell": "X",
        "issues": ["KI-01"],
        "target": "0.7.3",
        "runner": "python-suite",
        "signature": {"cell": "X", "branch": "B"},
        "lane": "lane-x",
        "mode": "always",
        "reason": "provider branch rejects the owned fixture",
        "last_green_sha": SHA,
    }
    value.update(changes)
    return value


def result_doc(entries=(), runner="python-suite", host="github", complete=True, selection=None):
    if selection is None:
        selection = [
            {"path": item["path"], "test": item["test"], "invocation": item.get("invocation", [])}
            for item in entries
        ]
    results = []
    for item in entries:
        results.append({
            "path": item["path"], "test": item["test"], "invocation": item.get("invocation", []),
            "state": item.get("state", "failed"), "signature": item.get("signature", {"cell": "X", "branch": "B"}),
        })
    return {
        "schema": "p11scope/known-failing-results/v1",
        "runner": runner,
        "host": host,
        "complete": complete,
        "selection": selection,
        "results": results,
    }


class Fixture:
    def __init__(self, test_case):
        self.temp = tempfile.TemporaryDirectory(prefix="known-failing-test-")
        test_case.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/typed-python-suite.py", self.root / "scripts/typed-python-suite.py")
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / ".github/workflows/main.yml").write_text("jobs: {}\n", encoding="utf-8")
        (self.root / "docs").mkdir()
        (self.root / "docs/known-limitations.md").write_text("# Known limitations\n", encoding="utf-8")
        (self.root / "tests").mkdir(exist_ok=True)
        write_json(self.root / "tests/ignored-tests.json", {"schema": "p11scope/ignored-tests/v1", "sites": []})
        (self.root / "scripts/run-python-suites.py").write_text("RUN = []\nDRIVEN = []\nEXCLUDED = {}\n", encoding="utf-8")
        (self.root / "scripts/run-privileged-lib-tests.sh").write_text(
            "EXPECTED_FAILURE_TESTS=(\n"
            "discovery::engine::tests::exit_loader_balanced_benign_transaction_needs_no_terminal_truncation\n"
            "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64\n"
            "inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64\n"
            ")\n"
            "KNOWN_FAILING_TYPED_TESTS=(\n"
            ")\n", encoding="utf-8")
        write_json(self.root / "tests/known-failing.json", {"schema": "p11scope/known-failing/v1", "rows": []})

    def registry(self, issues=(("KI-01", True),)):
        entries = ",".join('{"id":"%s","test":%s}' % (issue, str(test).lower()) for issue, test in issues)
        headings = "\n".join(f"### {issue}\nplain explanation\n" for issue, _test in issues)
        (self.root / "docs/known-limitations.md").write_text(
            "# Known limitations\n\n## Known limitations in 0.7.2\n\n"
            "<!-- p11scope-known-issues-v1\n"
            '{"schema":"p11scope/known-issues/v1","issues":[' + entries + "]}\n"
            "-->\n" + headings,
            encoding="utf-8")

    def release_doc(self):
        path = self.root / "docs/releases/v0.7.2.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# p11scope v0.7.2\n", encoding="utf-8")

    def python_suite(self):
        suite = self.root / "tests/python/test_sample.py"
        suite.parent.mkdir(parents=True, exist_ok=True)
        suite.write_text(
            "import unittest\n"
            "class Sample(unittest.TestCase):\n"
            "    def test_x(self): pass\n"
            "    def test_control(self): pass\n"
            "if __name__ == '__main__': unittest.main()\n", encoding="utf-8")
        (self.root / "scripts/run-python-suites.py").write_text(
            "RUN = [('test_sample.py', [])]\nDRIVEN = []\nEXCLUDED = {}\n", encoding="utf-8")

    def shell_cell(self, declarations=True, repeated=False, runner_name="cells.sh", declared="mt-exact"):
        script = self.root / "scripts/ci" / runner_name
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(
            "#!/bin/sh\nif [ \"$1\" = --list-cells ]; then echo mt-exact; exit 0; fi\nexit 0\n", encoding="utf-8")
        script.chmod(0o755)
        declaration = f" \\n            --expected-failure {declared}" if declarations else ""
        invocation = (
            "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\"" + declaration + " \\n"
            "            --known-failing-results \"$out/kf.json\" \\n"
            f"            --known-failing-runner cell:scripts/ci/{runner_name} \\n"
            "            --known-failing-host github\n"
        )
        body = invocation + (invocation if repeated else "")
        (self.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n" + body,
            encoding="utf-8")

    def rows(self, rows):
        write_json(self.root / "tests/known-failing.json", {"schema": "p11scope/known-failing/v1", "rows": rows})

    def run_checker(self, *extra):
        return subprocess.run([sys.executable, "-I", str(CHECKER), "--root", str(self.root), *extra],
                              capture_output=True, text=True, timeout=45)

    def results_file(self, value):
        path = self.root / "results.json"
        write_json(path, value)
        return path


def fixture(case):
    return Fixture(case)


class StaticValidationTests(unittest.TestCase):
    def assert_bad_row(self, bad_row, needle):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([bad_row])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn(needle, result.stderr)

    def test_empty_preregistry_ledger_passes(self):
        f = fixture(self)
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pre-registry empty-list window", result.stdout)

    def test_valid_python_row_passes_executable_discovery(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row()])
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_released_tree_without_registry_is_refused(self):
        f = fixture(self)
        f.release_doc()
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("the 0.7.2 release needs the typed known-issue registry", result.stderr)

    def test_released_tree_with_all_test_false_registry_and_no_rows_passes(self):
        f = fixture(self)
        f.registry((("KI-01", False), ("KI-02", False)))
        f.release_doc()
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 rows, typed issue registry", result.stdout)

    def test_released_tree_with_test_true_issue_and_no_rows_is_refused(self):
        f = fixture(self)
        f.registry((("KI-01", True),))
        f.release_doc()
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test=yes issues without rows: KI-01", result.stderr)

    def test_released_tree_with_rows_and_registry_passes(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row()])
        f.release_doc()
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fedora_host_limited_rows_are_refused_without_a_host_judge(self):
        for hosts in (["fedora"], ["fedora-sm1"], ["github", "fedora-sm1"]):
            with self.subTest(hosts=hosts):
                f = fixture(self)
                f.registry()
                f.python_suite()
                f.rows([row(hosts=hosts)])
                result = f.run_checker()
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn("no CI judge", result.stderr)

    def test_github_and_vng_hosts_are_accepted(self):
        for hosts in (["github"], ["github", "vng"]):
            with self.subTest(hosts=hosts):
                f = fixture(self)
                f.registry()
                f.python_suite()
                f.rows([row(hosts=hosts)])
                result = f.run_checker()
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_python_suite_row_without_github_has_no_judge(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row(hosts=["vng"])])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no CI judge", result.stderr)
        self.assertIn("python-suite rows without github", result.stderr)

    def test_wrong_vocabulary_runner_is_refused(self):
        for runner in ("bogus-runner", "host-matrix"):
            with self.subTest(runner=runner):
                f = fixture(self)
                f.registry()
                f.python_suite()
                f.rows([row(runner=runner)])
                result = f.run_checker()
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn("runner is not in the closed runner vocabulary", result.stderr)

    def test_python_suite_judge_host_pins_ci_typed_host(self):
        # The checker hardcodes github as the only python-suite judge host;
        # this pins the CI leg it must move with.
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertEqual(text.count("P11SCOPE_KNOWN_FAILING_HOST:"), 1)
        self.assertIn("P11SCOPE_KNOWN_FAILING_HOST: github", text)

    def test_row_expires_once_its_target_release_exists(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row(target="0.7.3")])
        target_doc = f.root / "docs/releases/v0.7.3.md"
        target_doc.parent.mkdir(parents=True, exist_ok=True)
        target_doc.write_text("# p11scope v0.7.3\n", encoding="utf-8")
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rows expire at their target release", result.stderr)
        target_doc.unlink()
        (f.root / "docs/releases/v9.9.9.md").write_text("# unrelated\n", encoding="utf-8")
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signature_cell_must_equal_the_row_cell(self):
        self.assert_bad_row(row(signature={"cell": "OTHER", "branch": "B"}), "signature cell must equal")

    def test_nonstring_signature_branch_is_refused_typed(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row(signature={"cell": "X", "branch": []})])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("signature branch must be a typed token string", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_undecodable_suite_registry_fails_registration_typed(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        (f.root / "scripts/run-python-suites.py").write_bytes(b"RUN = [\xff\n")
        f.rows([row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("suite invocation is not registered in scripts/run-python-suites.py", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_undecodable_privileged_runner_is_typed_refusal(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        (f.root / "scripts/run-privileged-lib-tests.sh").write_bytes(b"#!/bin/sh\n\xff\n")
        f.rows([row(runner="privileged-lib")])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("privileged-lib runner declaration cannot be read", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_privileged_runner_is_typed_refusal(self):
        checker = load_script(CHECKER, "known_failing_checker_runner_absent")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            problems = checker.validate_privileged_runner(
                root, [{"runner": "privileged-lib", "test": "x"}])
            self.assertTrue(any("scripts/run-privileged-lib-tests.sh is missing" in problem
                                for problem in problems))

    def test_missing_suite_registry_fails_registration_typed(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        (f.root / "scripts/run-python-suites.py").unlink()
        f.rows([row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("suite invocation is not registered in scripts/run-python-suites.py", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_privileged_lib_rows_are_refused_until_coverage_counts_xfail(self):
        self.assert_bad_row(row(runner="privileged-lib"), "refused until")

    def test_lane_doc_ki_block_parses_as_the_typed_registry(self):
        text = (ROOT / "docs/testing/known-failing.md").read_text(encoding="utf-8")
        self.assertEqual(1, text.count("```markdown"))
        start = text.index("```markdown\n") + len("```markdown\n")
        block = text[start:text.index("```", start)]
        self.assertIn("<!-- p11scope-known-issues-v1", block)
        f = fixture(self)
        (f.root / "docs/known-limitations.md").write_text(
            "# Known limitations\n\n" + block, encoding="utf-8")
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("typed issue registry", result.stdout)
        f.python_suite()
        f.rows([row(issues=["KI-01"])])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not marked test=yes", result.stderr)

    def test_typed_provenance_is_required(self):
        for field in ("cell", "issues", "reason", "last_green_sha"):
            with self.subTest(field=field):
                bad = row()
                del bad[field]
                self.assert_bad_row(bad, "missing required fields")

    def test_issue_is_a_list_and_duplicate_issues_fail(self):
        bad = row(issues="KI-01")
        self.assert_bad_row(bad, "issues must be a nonempty unique list")
        self.assert_bad_row(row(issues=["KI-01", "KI-01"]), "issues must be a nonempty unique list")

    def test_two_issue_row_passes(self):
        f = fixture(self)
        f.registry((("KI-01", True), ("KI-02", True)))
        f.python_suite()
        f.rows([row(issues=["KI-01", "KI-02"])])
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signature_accepts_typed_values_only(self):
        self.assert_bad_row(row(signature={"message": "lost track of the object"}), "free-text/log matching")
        self.assert_bad_row(row(signature={"branch": "lost track of the object"}), "stable typed token")
        self.assert_bad_row(row(signature={}), "nonempty object")
        # Nested typed values are valid when every leaf is enum-like.
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row(signature={"cell": "X", "branch": "typed_branch", "nested": {"branches": ["A", "B"], "count": 2, "exact": True}})])
        self.assertEqual(f.run_checker().returncode, 0)

    def test_sha_and_plain_reason_are_validated(self):
        self.assert_bad_row(row(last_green_sha="abc123"), "40-hex")
        self.assert_bad_row(row(reason="bad\nlog text"), "printable plain text")

    def test_unknown_and_not_testyes_issues_fail(self):
        self.assert_bad_row(row(issues=["KI-09"]), "not a named known issue")
        f = fixture(self)
        f.registry((("KI-01", False),))
        f.python_suite()
        f.rows([row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not marked test=yes", result.stderr)

    def test_every_testyes_issue_needs_a_row(self):
        f = fixture(self)
        f.registry((("KI-01", True), ("KI-02", True)))
        f.python_suite()
        f.rows([row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test=yes issues without rows: KI-02", result.stderr)

    def test_executable_discovery_rejects_lexically_present_missing_test(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row(test="Sample.test_missing")])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("executable discovery did not find exact test id", result.stderr)

    def test_suite_registration_is_exact(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        (f.root / "scripts/run-python-suites.py").write_text("RUN = []\nDRIVEN = []\nEXCLUDED = {}\n")
        f.rows([row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("suite invocation is not registered", result.stderr)

    def test_duplicate_composite_rows_fail(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        first = row()
        second = row(issues=["KI-01"])
        f.rows([first, second])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate row", result.stderr)


class CellDeclarationTests(unittest.TestCase):
    def cell_row(self, runner="cell:scripts/ci/cells.sh"):
        return row(path="scripts/ci/cells.sh", test="mt-exact", cell="mt-exact", runner=runner,
                   signature={"cell": "mt-exact", "branch": "B"})

    def test_valid_cell_row_matches_per_runner_declaration(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        f.rows([self.cell_row()])
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_row_needs_no_per_runner_declaration(self):
        f = fixture(self)
        f.registry()
        f.shell_cell(declarations=False)
        (f.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n"
            "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
            "--require other-cell"
            " --known-failing-results \"$out/kf.json\""
            " --known-failing-runner cell:scripts/ci/cells.sh"
            " --known-failing-host github\n",
            encoding="utf-8")
        f.rows([self.cell_row()])
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("has no per-runner declaration", result.stderr)

    def test_undeclared_declaration_fails_despite_a_row(self):
        f = fixture(self)
        f.registry()
        f.shell_cell(declared="other-cell")
        f.rows([self.cell_row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("undeclared expected cells: other-cell", result.stderr)

    def test_cell_must_equal_test_for_cell_runners(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        bad = self.cell_row()
        bad["cell"] = "OTHER"
        bad["signature"] = {"cell": "OTHER", "branch": "B"}
        f.rows([bad])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cell must equal", result.stderr)

    def test_repeated_declarations_compare_require_file_exactly(self):
        f = fixture(self)
        f.shell_cell(declarations=False)
        self.repeated_workflow(f, "--require-file /tmp/inventory-a.txt", "--require-file /tmp/inventory-a.txt")
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.repeated_workflow(f, "--require-file /tmp/inventory-a.txt", "--require-file /tmp/inventory-b.txt")
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repeated declarations for one runner/results stream differ", result.stderr)

    def test_require_file_alone_is_a_nonempty_selection(self):
        f = fixture(self)
        f.shell_cell(declarations=False)
        (f.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n"
            "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
            "--require-file /tmp/dynamic-selection.txt"
            " --known-failing-results \"$out/kf.json\""
            " --known-failing-runner cell:scripts/ci/cells.sh"
            " --known-failing-host github\n",
            encoding="utf-8")
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_undeclared_extra_declaration_fails(self):
        f = fixture(self)
        f.registry()
        f.shell_cell(declared="unlisted-cell")
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("undeclared expected cells", result.stderr)

    def test_runner_script_must_exist(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        (f.root / "scripts/ci/cells.sh").unlink()
        f.rows([self.cell_row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cell runner script does not exist", result.stderr)

    def test_every_checker_invocation_needs_typed_result_wiring(self):
        f = fixture(self)
        f.registry()
        (f.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n"
            "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" --require x\n",
            encoding="utf-8")
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not emit typed known-failing results", result.stderr)

    def test_cell_row_without_workflow_invocation_has_no_judge(self):
        f = fixture(self)
        f.registry()
        f.shell_cell(declarations=False)
        (f.root / ".github/workflows/main.yml").write_text("jobs: {}\n", encoding="utf-8")
        f.rows([self.cell_row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no CI judge", result.stderr)
        self.assertIn("same --known-failing-runner", result.stderr)

    def test_cell_row_with_incompatible_host_has_no_judge(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        bad = self.cell_row()
        bad["hosts"] = ["vng"]
        f.rows([bad])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no CI judge", result.stderr)

    def test_cell_row_with_kf_host_wildcard_is_judged(self):
        for host in ("$kf_host", "${kf_host}"):
            with self.subTest(host=host):
                f = fixture(self)
                f.registry()
                f.shell_cell(declarations=False)
                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
                    "--require mt-exact"
                    " --known-failing-results \"$out/kf.json\""
                    " --known-failing-runner cell:scripts/ci/cells.sh"
                    f" --known-failing-host \"{host}\"\n",
                    encoding="utf-8")
                good = self.cell_row()
                good["hosts"] = ["vng"]
                f.rows([good])
                result = f.run_checker()
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_cell_row_with_wrong_existing_runner_has_no_judge(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        other = f.root / "scripts/ci/other.sh"
        other.write_text(
            "#!/bin/sh\nif [ \"$1\" = --list-cells ]; then echo mt-exact; exit 0; fi\nexit 0\n",
            encoding="utf-8")
        other.chmod(0o755)
        f.rows([row(path="scripts/ci/other.sh", test="mt-exact", cell="mt-exact",
                    runner="cell:scripts/ci/other.sh",
                    signature={"cell": "mt-exact", "branch": "B"})])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no CI judge", result.stderr)
        self.assertIn("same --known-failing-runner", result.stderr)

    def test_cell_row_with_bogus_stream_host_has_no_judge(self):
        for host in ("bogus-host", "$other"):
            with self.subTest(host=host):
                f = fixture(self)
                f.registry()
                f.shell_cell(declarations=False)
                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
                    "--require mt-exact"
                    " --known-failing-results \"$out/kf.json\""
                    " --known-failing-runner cell:scripts/ci/cells.sh"
                    f" --known-failing-host {host}\n",
                    encoding="utf-8")
                f.rows([self.cell_row()])
                result = f.run_checker()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("has no CI judge", result.stderr)

    def test_cell_rs_row_without_ignored_entry_is_refused(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        (f.root / "tests/run_tree.rs").write_text("// fixture\n", encoding="utf-8")
        f.rows([row(path="tests/run_tree.rs", test="mt-exact", cell="mt-exact",
                    runner="cell:scripts/ci/cells.sh",
                    signature={"cell": "mt-exact", "branch": "B"})])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ignored-tests missing cell=known-failing rows: tests/run_tree.rs:mt-exact",
                      result.stderr)

    def test_cell_row_path_must_equal_runner_script(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        script = f.root / "scripts/ci/other.sh"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o755)
        bad = row(path="tests/python/test_sample.py", test="mt-exact", cell="mt-exact",
                  runner="cell:scripts/ci/other.sh",
                  signature={"cell": "mt-exact", "branch": "B"})
        f.rows([bad])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must equal the runner script", result.stderr)
        self.assertIn("has no CI judge", result.stderr)

    def test_cell_rs_path_exception_skips_runner_script_equality(self):
        checker = load_script(CHECKER, "known_failing_checker_rs_exception")
        good = row(path="tests/run_tree.rs", test="mt-exact", cell="mt-exact",
                   runner="cell:scripts/ci/run-run-tree.sh",
                   signature={"cell": "mt-exact", "branch": "B"})
        problems, _ = checker.validate_row(good, 1)
        self.assertFalse([p for p in problems if "must equal the runner script" in p],
                         problems)
        bad = row(path="tests/python/test_sample.py", test="mt-exact", cell="mt-exact",
                  runner="cell:scripts/ci/run-run-tree.sh",
                  signature={"cell": "mt-exact", "branch": "B"})
        problems, _ = checker.validate_row(bad, 1)
        self.assertTrue(any("must equal the runner script" in p for p in problems),
                        problems)


    def repeated_workflow(self, f, first_option, second_option):
        def invocation(option):
            return (
                "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
                + option
                + " --known-failing-results \"$out/kf.json\""
                + " --known-failing-runner cell:scripts/ci/cells.sh"
                + " --known-failing-host github\n"
            )
        (f.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n" + invocation(first_option) + invocation(second_option),
            encoding="utf-8")

    def test_repeated_declarations_compare_required_and_nonqualifying_exactly(self):
        for option in ("--require alpha", "--allow-nonqualifying smoke"):
            with self.subTest(option=option):
                f = fixture(self)
                f.shell_cell(declarations=False)
                self.repeated_workflow(f, option, option)
                result = f.run_checker()
                self.assertEqual(result.returncode, 0, result.stderr)
                changed = option.replace("alpha", "beta").replace("smoke", "other-smoke")
                self.repeated_workflow(f, option, changed)
                result = f.run_checker()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("repeated declarations for one runner/results stream differ", result.stderr)


class RowActivationTests(unittest.TestCase):
    def test_hosted_rows_and_registry_pass_static_together(self):
        # d.3 row 2 shape (python-suite, two issues) plus d.3 row 11
        # shape (intermittent cell, vng host judged via the "$kf_host"
        # matrix host), written with a KI block into a temp copy. The
        # real d.3 rows 2 and 11 do not ship: row 2's test file is
        # absent from the tree and row 11's legacy intermittent
        # failure carries no branch (see report).
        f = fixture(self)
        f.registry((("KI-02", True), ("KI-03", True), ("KI-13", True)))
        f.python_suite()
        f.shell_cell(declarations=False)
        (f.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n"
            "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
            "--intermittent-failure mt-exact"
            " --known-failing-results \"$out/kf.json\""
            " --known-failing-runner cell:scripts/ci/cells.sh"
            " --known-failing-host \"$kf_host\"\n",
            encoding="utf-8")
        python_row = row(test="Sample.test_x", issues=["KI-02", "KI-03"])
        cell_row = row(path="scripts/ci/cells.sh", test="mt-exact", cell="mt-exact",
                       issues=["KI-13"], runner="cell:scripts/ci/cells.sh",
                       mode="intermittent", hosts=["vng"],
                       signature={"cell": "mt-exact", "branch": "known_gap"})
        f.rows([python_row, cell_row])
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)


class ResultDocumentTests(unittest.TestCase):
    def make_f(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row()])
        return f

    def assert_bad_results(self, document, needle):
        f = self.make_f()
        path = f.results_file(document)
        result = f.run_checker("--results", str(path))
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn(needle, result.stderr)

    def test_correct_typed_result_passes(self):
        f = self.make_f()
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x"}])
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 expected failures", result.stdout)

    def test_omitting_a_failing_result_cannot_turn_red_green(self):
        self.assert_bad_results(result_doc([], selection=[]), "selection must be a nonempty")
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x"}])
        doc["results"] = []
        self.assert_bad_results(doc, "selected tests without terminal results")

    def test_completeness_record_must_be_true(self):
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x"}], complete=False)
        self.assert_bad_results(doc, "complete must be true")

    def test_results_outside_selection_fail(self):
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x"}])
        doc["selection"] = []
        self.assert_bad_results(doc, "selection must be a nonempty")
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x"}])
        doc["results"].append({"path": "tests/python/test_sample.py", "test": "Other.test", "invocation": [],
                                "state": "passed", "signature": None})
        self.assert_bad_results(doc, "terminal results outside the selection")

    def test_duplicate_terminal_keys_fail_closed(self):
        item = {"path": "tests/python/test_sample.py", "test": "Sample.test_x"}
        doc = result_doc([item, item])
        self.assert_bad_results(doc, "duplicate result")

    def test_signature_mismatch_and_exact_type_equality(self):
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "signature": {"cell": "X", "branch": "C"}}])
        self.assert_bad_results(doc, "failure signature mismatch")
        row_signature = {"cell": "X", "branch": "B", "count": 1}
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "signature": {"cell": "X", "branch": "B", "count": True}}])
        f = self.make_f()
        f.rows([row(signature=row_signature)])
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failure signature mismatch", result.stderr)
        doc["results"][0]["signature"]["count"] = 1
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signed_zero_is_distinct_in_exact_json_equality(self):
        f = self.make_f()
        f.rows([row(signature={"cell": "X", "branch": "B", "zero": 0.0})])
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "signature": {"cell": "X", "branch": "B", "zero": -0.0}}])
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failure signature mismatch", result.stderr)

    def test_stale_always_row_and_intermittent_pass(self):
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "state": "passed", "signature": None}])
        self.assert_bad_results(doc, "stale row")
        f = self.make_f()
        f.rows([row(mode="intermittent")])
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 intermittent passes", result.stdout)

    def test_unlisted_failure_fails_but_closed_legacy_exemption_is_scoped(self):
        f = fixture(self)
        doc = result_doc([{"path": "scripts/qualify-public-cli.sh", "test": "mt-exact"}],
                         runner="cell:scripts/qualify-public-cli.sh")
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failing test not listed", result.stderr)
        doc = result_doc([{"path": "scripts/qualify-public-cli.sh", "test": "profile-cgroup"}],
                         runner="cell:scripts/qualify-public-cli.sh")
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_host_filter_selects_exact_hosts(self):
        f = fixture(self)
        f.registry()
        f.shell_cell(declarations=False)
        (f.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n"
            "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
            "--require mt-exact"
            " --known-failing-results \"$out/kf.json\""
            " --known-failing-runner cell:scripts/ci/cells.sh"
            " --known-failing-host \"$kf_host\"\n",
            encoding="utf-8")
        f.rows([row(path="scripts/ci/cells.sh", test="mt-exact", cell="mt-exact",
                    runner="cell:scripts/ci/cells.sh", hosts=["vng"],
                    signature={"cell": "mt-exact", "branch": "B"})])
        doc = result_doc([{"path": "scripts/ci/cells.sh", "test": "mt-exact",
                           "state": "passed", "signature": None}],
                         runner="cell:scripts/ci/cells.sh", host="github")
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_result_signature_is_typed_only(self):
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "signature": {"detail": "a raw log line"}}])
        self.assert_bad_results(doc, "free-text/log matching")

    def test_nonstring_result_state_is_refused_typed(self):
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x"}])
        doc["results"][0]["state"] = []
        f = self.make_f()
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("state is not in the closed terminal-state vocabulary", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_bogus_results_host_is_refused(self):
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x"}],
                         host="mars")
        self.assert_bad_results(doc, "host must be one of")

    def test_unhashable_result_keys_stay_typed(self):
        for side in ("selection", "results"):
            with self.subTest(side=side):
                good = {"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                        "invocation": []}
                bad = {"path": [], "test": "Sample.test_x", "invocation": []}
                selection = [bad if side == "selection" else good]
                result_row = dict(bad if side == "results" else good)
                result_row.update({"state": "failed",
                                   "signature": {"cell": "X", "branch": "B"}})
                doc = {"schema": "p11scope/known-failing-results/v1",
                       "runner": "python-suite", "host": "github", "complete": True,
                       "selection": selection, "results": [result_row]}
                f = self.make_f()
                result = f.run_checker("--results", str(f.results_file(doc)))
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn("path must be a clean repository-relative POSIX path", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_row_whose_cell_the_stream_never_selects_stays_red(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        f.rows([row(path="scripts/ci/cells.sh", test="mt-exact", cell="mt-exact",
                    runner="cell:scripts/ci/cells.sh",
                    signature={"cell": "mt-exact", "branch": "B"})])
        doc = result_doc([{"path": "scripts/ci/cells.sh", "test": "other-cell",
                           "state": "passed", "signature": None}],
                         runner="cell:scripts/ci/cells.sh")
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("listed row has no selected terminal result: mt-exact", result.stderr)

    def test_results_mode_skips_executable_discovery(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row(test="Sample.test_missing")])
        static = f.run_checker()
        self.assertNotEqual(static.returncode, 0)
        self.assertIn("executable discovery did not find exact test id", static.stderr)
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_missing"}])
        judged = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(judged.returncode, 0, judged.stderr)
        self.assertIn("1 expected failures", judged.stdout)

    def test_results_summary_prints_neutral_counts(self):
        f = fixture(self)
        doc = result_doc([
            {"path": "tests/python/test_sample.py", "test": "Sample.test_a",
             "state": "skipped", "signature": {"branch": "host_prerequisite"}},
            {"path": "tests/python/test_sample.py", "test": "Sample.test_b",
             "state": "not_applicable", "signature": {"qualification": "nonqualifying"}},
            {"path": "tests/python/test_sample.py", "test": "Sample.test_c",
             "state": "passed", "signature": None},
        ])
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 skipped, 1 not_applicable", result.stdout)


class FallbackBranchTests(unittest.TestCase):
    def test_generic_fallback_branch_rows_are_refused(self):
        # The exact unittest fallback shape first: any AssertionError would
        # otherwise match the named issue.
        cases = [("failed", {"branch": "failed", "exception": "AssertionError", "oracle": "unittest"})]
        cases += [(branch, {"branch": branch, "oracle": "unittest"})
                  for branch in ("error", "skipped", "unexpected_success", "not_run",
                                 "passed", "not_applicable", "class_skip", "module_skip")]
        for branch, signature in cases:
            with self.subTest(branch=branch):
                f = fixture(self)
                f.registry()
                f.python_suite()
                f.rows([row(signature=signature)])
                result = f.run_checker()
                self.assertNotEqual(result.returncode, 0, branch)
                self.assertIn("generic producer state or scope token", result.stderr)

    def test_custom_signature_row_judges_its_named_failure(self):
        body = (
            "import unittest\n"
            "class TypedFailure(AssertionError):\n"
            "    def __init__(self):\n"
            "        super().__init__('raw prose that must not be copied')\n"
            "        self.p11scope_signature = {'cell': 'X', 'branch': 'sign_not_attributed'}\n"
            "class Sample(unittest.TestCase):\n"
            "    def test_x(self): raise TypedFailure()\n"
            "if __name__ == '__main__': unittest.main()\n")
        f = fixture(self)
        f.registry()
        f.python_suite()
        (f.root / "tests/python/test_sample.py").write_text(body, encoding="utf-8")
        custom = {"cell": "X", "branch": "sign_not_attributed"}
        f.rows([row(signature=custom)])
        static = f.run_checker()
        self.assertEqual(static.returncode, 0, static.stderr)
        fragment = f.root / "fragment.json"
        run = subprocess.run(
            [sys.executable, "-I", "scripts/typed-python-suite.py",
             "tests/python/test_sample.py", str(fragment)],
            cwd=f.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 1, run.stderr)
        runner = load_script(ROOT / "scripts/run-python-suites.py", "python_suite_runner_b2_green")
        merged = f.root / "merged.json"
        runner.merge_typed_fragments([(fragment, "test_sample.py", [])], merged, "github")
        judged = f.run_checker("--results", str(merged))
        self.assertEqual(judged.returncode, 0, judged.stderr)
        self.assertIn("1 expected failures", judged.stdout)


class StaticWiringTests(unittest.TestCase):
    STATIC_RUN = "python3 -I scripts/check-known-failing.py"
    SUITES_RUN = "python3 -I scripts/run-python-suites.py"

    def scripts_run_steps(self):
        import yaml
        document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        steps = document["jobs"]["scripts"]["steps"]
        return [step for step in steps
                if isinstance(step, dict) and isinstance(step.get("run"), str)]

    def test_scripts_job_runs_static_checker_before_suites(self):
        steps = self.scripts_run_steps()
        runs = [step["run"] for step in steps]
        static = [index for index, run in enumerate(runs) if run.strip() == self.STATIC_RUN]
        suites = [index for index, run in enumerate(runs) if run.strip() == self.SUITES_RUN]
        self.assertEqual(len(static), 1,
                         f"scripts job must run the static checker exactly once, found {len(static)}")
        self.assertEqual(len(suites), 1,
                         f"scripts job must run the suite driver exactly once, found {len(suites)}")
        self.assertLess(static[0], suites[0],
                        "static ledger check must precede typed judgment")
        self.assertEqual(set(steps[static[0]]), {"run"},
                         "static checker step must carry no guard keys (an if: could disable it)")


class StrictNullAdmissionTests(unittest.TestCase):
    SCALARS = ("null", "0", "[]", "true")

    def test_missing_static_registry_follows_row_policy(self):
        checker = load_script(CHECKER, "known_failing_checker_registry_absent")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tests").mkdir()
            self.assertEqual(checker.validate_ignored_known_failing(root, []), [])
            problems = checker.validate_ignored_known_failing(root, [{"path": "tests/x.rs"}])
            self.assertTrue(any("missing ignored-test registry" in problem for problem in problems))

    def test_invalid_json_documents_are_typed_refusals(self):
        f = fixture(self)
        target = f.root / "bad-known-failing.json"
        target.write_text("{oops\n", encoding="utf-8")
        result = f.run_checker("--list", str(target))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid JSON", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        g = fixture(self)
        target = g.root / "results.json"
        target.write_text("{oops\n", encoding="utf-8")
        result = g.run_checker("--results", str(target))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid JSON", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_documents_are_typed_refusals(self):
        f = fixture(self)
        result = f.run_checker("--results", str(f.root / "absent.json"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        g = fixture(self)
        (g.root / "tests/known-failing.json").unlink()
        result = g.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing known-failing list", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        h = fixture(self)
        shutil.rmtree(h.root / ".github/workflows")
        result = h.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing workflow directory", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_limitations_means_no_registry(self):
        f = fixture(self)
        (f.root / "docs/known-limitations.md").unlink()
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_static_registry_follows_row_policy(self):
        checker = load_script(CHECKER, "known_failing_checker_registry_absent")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tests").mkdir()
            self.assertEqual(checker.validate_ignored_known_failing(root, []), [])
            problems = checker.validate_ignored_known_failing(root, [{"path": "tests/x.rs"}])
            self.assertTrue(any("missing ignored-test registry" in problem for problem in problems))

    def test_undecodable_documents_are_typed_refusals(self):
        cases = (
            ("null-known-failing.json", b'{"rows": [\xff]}\n', ["--list"], "cannot read known-failing list"),
            ("docs/known-limitations.md", b'# Known limitations\n\xff\n', [], "known-issue registry: cannot read"),
            ("results.json", b'{"results": [\xff]}\n', ["--results"], "cannot read"),
            (".github/workflows/main.yml", b'jobs:\n  test: \xff\n', [], "cannot parse workflow"),
            (".github/workflows/bad.yml", b'jobs:\n  test: [unclosed\n', [], "cannot parse workflow"),
        )
        for name, content, flag, needle in cases:
            with self.subTest(name=name):
                f = fixture(self)
                target = f.root / name
                target.write_bytes(content)
                result = f.run_checker(*flag, str(target)) if flag else f.run_checker()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(needle, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_null_and_scalar_lists_are_rejected(self):
        for text in self.SCALARS:
            with self.subTest(text=text):
                f = fixture(self)
                target = f.root / "null-known-failing.json"
                target.write_text(text + "\n", encoding="utf-8")
                result = f.run_checker("--list", str(target))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("top level must be an object", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_null_and_scalar_registry_is_rejected(self):
        for text in self.SCALARS:
            with self.subTest(text=text):
                f = fixture(self)
                (f.root / "docs/known-limitations.md").write_text(
                    "# Known limitations\n\n## Known limitations in 0.7.2\n\n"
                    "<!-- p11scope-known-issues-v1\n" + text + "\n-->\n",
                    encoding="utf-8")
                result = f.run_checker()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("top level must have exactly schema and issues", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_null_and_scalar_ignored_registry_is_rejected(self):
        for text in self.SCALARS:
            with self.subTest(text=text):
                f = fixture(self)
                (f.root / "tests/ignored-tests.json").write_text(text + "\n", encoding="utf-8")
                result = f.run_checker()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must be an object with a sites list", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_null_and_scalar_result_documents_are_rejected(self):
        for text in self.SCALARS:
            with self.subTest(text=text):
                f = fixture(self)
                target = f.root / "results.json"
                target.write_text(text + "\n", encoding="utf-8")
                result = f.run_checker("--results", str(target))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("top level must have exactly schema/runner/host/complete/selection/results",
                              result.stderr)
                self.assertNotIn("Traceback", result.stderr)


class RegistryReadStateTests(unittest.TestCase):
    def load_checker(self, label):
        return load_script(ROOT / "scripts/check-known-failing.py", f"checker_read_state_{label}")

    def test_missing_registry_raises_for_caller_policy(self):
        checker = self.load_checker("missing")
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "absent.json"
            with self.assertRaises(FileNotFoundError):
                checker.load_ignored_registry(missing)

    def test_unreadable_registry_is_typed_problem(self):
        checker = self.load_checker("unreadable")
        with tempfile.TemporaryDirectory() as temporary:
            blocked = Path(temporary) / "ignored-tests.json"
            blocked.mkdir()
            files, problems = checker.load_ignored_registry(blocked)
            self.assertEqual(files, {})
            self.assertTrue(problems)
            self.assertIn("cannot read ignored-test registry", problems[0])

    def test_undecodable_registry_is_typed_problem(self):
        checker = self.load_checker("undecodable")
        with tempfile.TemporaryDirectory() as temporary:
            bad = Path(temporary) / "ignored-tests.json"
            bad.write_bytes(b'{"sites": [\xff]}\n')
            files, problems = checker.load_ignored_registry(bad)
            self.assertEqual(files, {})
            self.assertTrue(problems)

    def test_rejection_preserves_parse_detail(self):
        checker = self.load_checker("detail")
        with tempfile.TemporaryDirectory() as temporary:
            dup = Path(temporary) / "ignored-tests.json"
            dup.write_text('{"schema": "p11scope/ignored-tests/v1", "sites": ['
                           '{"file": "a.rs", "path": "X", "file": "b.rs"}]}\n',
                           encoding="utf-8")
            files, problems = checker.load_ignored_registry(dup)
            self.assertEqual(files, {})
            self.assertIn("duplicate", problems[0])


class ProducerTests(unittest.TestCase):
    def test_typed_python_wrapper_records_outer_selection_and_terminal_states(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            suite = temp / "test_sample.py"
            fragment = temp / "fragment.json"
            suite.write_text(
                "import unittest\n"
                "class Sample(unittest.TestCase):\n"
                "    def test_pass(self): pass\n"
                "    def test_fail(self): self.fail('typed failure')\n"
                "if __name__ == '__main__': unittest.main()\n")
            result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/typed-python-suite.py"),
                                     str(suite), str(fragment)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            data = json.loads(fragment.read_text())
            self.assertEqual(data["schema"], "p11scope/python-suite-fragment/v1")
            self.assertTrue(data["complete"])
            self.assertEqual(len(data["selection"]), 2)
            states = {item["test"]: item for item in data["results"]}
            self.assertEqual(states["Sample.test_pass"]["state"], "passed")
            self.assertEqual(states["Sample.test_pass"]["signature"], None)
            self.assertEqual(states["Sample.test_fail"]["state"], "failed")
            self.assertEqual(states["Sample.test_fail"]["signature"]["oracle"], "unittest")
            self.assertNotIn("typed failure", json.dumps(states["Sample.test_fail"]["signature"]))

    def test_privileged_lib_converter_exactness_and_closed_tokens(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            test_name = "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64"
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            output = temp / "out.json"
            selection.write_text(test_name + "\n")
            verdicts.write_text(test_name + "\tXFAIL\n")
            converter = ROOT / "scripts/ci/privileged-lib-results.py"
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data["runner"], "privileged-lib")
            self.assertEqual(len(data["selection"]), 1)
            self.assertEqual(data["results"][0]["signature"], {"oracle": "runner-xfail", "verdict": "XFAIL"})
            verdicts.write_text("")
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("one-to-one", result.stderr)


def load_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RustDiscoveryTests(unittest.TestCase):
    def test_libtest_terse_parser_matches_exact_real_id(self):
        checker = load_script(CHECKER, "known_failing_checker_under_test")
        rust_row = row(path="tests/inventory_command.rs", test="inventory::privileged_tests::example_cell",
                       runner="privileged-lib")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".release-rust-version").write_text("1.99.1\n", encoding="utf-8")
            (root / "scripts").mkdir()
            (root / "scripts/cargo.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "scripts/cargo.sh").chmod(0o755)
            artifact = {"reason": "compiler-artifact", "executable": "/tmp/libtest", "target": {"test": True}}

            def fake_run(command, **kwargs):
                del kwargs
                if command[0].endswith("cargo.sh"):
                    return subprocess.CompletedProcess(command, 0, json.dumps(artifact) + "\n", "")
                if command[:3] == ["/tmp/libtest", "--list", "--format"]:
                    return subprocess.CompletedProcess(command, 0, "inventory::privileged_tests::example_cell: test\n", "")
                raise AssertionError(command)

            with mock.patch.object(checker.subprocess, "run", side_effect=fake_run):
                self.assertTrue(checker.cargo_list_probe(root, rust_row))
                missing = dict(rust_row, test="inventory::privileged_tests::example_cell:")
                self.assertFalse(checker.cargo_list_probe(root, missing))

    def test_undecodable_toolchain_file_fails_probe_closed(self):
        checker = load_script(CHECKER, "known_failing_checker_toolchain")
        rust_row = row(path="tests/inventory_command.rs", test="inventory::privileged_tests::example_cell",
                       runner="privileged-lib")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".release-rust-version").write_bytes(b"1.99.1\xff\n")
            self.assertFalse(checker.cargo_list_probe(root, rust_row))

    def test_missing_toolchain_file_fails_probe_closed(self):
        checker = load_script(CHECKER, "known_failing_checker_toolchain_absent")
        rust_row = row(path="tests/inventory_command.rs", test="inventory::privileged_tests::example_cell",
                       runner="privileged-lib")
        with tempfile.TemporaryDirectory() as temporary:
            self.assertFalse(checker.cargo_list_probe(Path(temporary), rust_row))


class ScopedLegacyDeclarationTests(unittest.TestCase):
    def workflow_with_declaration(self, f, runner, option, cell):
        (f.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n"
            "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" \\\n"
            f"            {option} {cell} \\\n"
            "            --known-failing-results \"$out/kf.json\" \\\n"
            f"            --known-failing-runner {runner} \\\n"
            "            --known-failing-host github\n",
            encoding="utf-8")

    def test_public_cli_expected_names_do_not_exempt_run_tree(self):
        f = fixture(self)
        self.workflow_with_declaration(f, "cell:scripts/ci/run-run-tree.sh", "--expected-failure", "profile-cgroup")
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("undeclared expected cells: profile-cgroup", result.stderr)

    def test_run_tree_intermittent_names_do_not_exempt_public_cli(self):
        f = fixture(self)
        cell = "privileged_run_tree_arming_exhaustion_still_stages_and_counts"
        self.workflow_with_declaration(f, "cell:scripts/qualify-public-cli.sh", "--intermittent-failure", cell)
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("undeclared intermittent cells", result.stderr)


class PythonProducerProcessTests(unittest.TestCase):
    def write_suite(self, temp, body):
        suite = temp / "test_sample.py"
        suite.write_text(body, encoding="utf-8")
        return suite

    def test_custom_typed_exception_signature_is_exact_and_message_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            suite = self.write_suite(temp,
                "import unittest\n"
                "class TypedFailure(AssertionError):\n"
                "    def __init__(self):\n"
                "        super().__init__('raw prose that must not be copied')\n"
                "        self.p11scope_signature = {'cell': 'X', 'branch': 'sign_not_attributed'}\n"
                "class Sample(unittest.TestCase):\n"
                "    def test_fail(self): raise TypedFailure()\n"
                "if __name__ == '__main__': unittest.main()\n")
            fragment = temp / "fragment.json"
            result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/typed-python-suite.py"),
                                     str(suite), str(fragment)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            data = json.loads(fragment.read_text())
            self.assertEqual(data["results"][0]["signature"], {"cell": "X", "branch": "sign_not_attributed"})

    def test_teardown_module_error_is_a_typed_suite_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            suite = self.write_suite(temp,
                "import unittest\n"
                "class Sample(unittest.TestCase):\n"
                "    def test_pass(self): pass\n"
                "def tearDownModule(): raise AssertionError('module teardown failed')\n"
                "if __name__ == '__main__': unittest.main()\n")
            fragment = temp / "fragment.json"
            result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/typed-python-suite.py"),
                                     str(suite), str(fragment)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            data = json.loads(fragment.read_text())
            self.assertIn("suite_events", data)
            self.assertEqual(data["suite_events"][0]["event"], "tearDownModule")
            self.assertEqual(data["suite_events"][0]["state"], "error")
            self.assertNotIn("module teardown failed", json.dumps(data["suite_events"]))

    def test_merge_adds_process_integrity_rows_and_detects_unexplained_exit(self):
        runner = load_script(ROOT / "scripts/run-python-suites.py", "python_suite_runner_under_test")
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            fragment = temp / "fragment.json"
            write_json(fragment, {
                "schema": "p11scope/python-suite-fragment/v1",
                "path": "tests/python/test_sample.py",
                "invocation": [],
                "process_exit": 1,
                "complete": True,
                "selection": [{"test": "Sample.test_pass"}],
                "results": [{"test": "Sample.test_pass", "state": "passed", "signature": None}],
                "suite_events": [],
            })
            output = temp / "merged.json"
            problems = runner.merge_typed_fragments([(fragment, "test_sample.py", [])], output, "github")
            data = json.loads(output.read_text())
            rows = {(item["test"]): item for item in data["results"]}
            self.assertIn("<suite-process>", rows)
            self.assertEqual(rows["<suite-process>"]["state"], "failed")
            self.assertIn((str(fragment), "test_sample.py", []), problems)

    def test_merge_makes_module_events_unlisted_failures_not_passes(self):
        runner = load_script(ROOT / "scripts/run-python-suites.py", "python_suite_runner_module_events")
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            fragment = temp / "fragment.json"
            write_json(fragment, {
                "schema": "p11scope/python-suite-fragment/v1",
                "path": "tests/python/test_sample.py",
                "invocation": [],
                "process_exit": 1,
                "complete": True,
                "selection": [{"test": "Sample.test_pass"}],
                "results": [{"test": "Sample.test_pass", "state": "passed", "signature": None}],
                "suite_events": [{"event": "tearDownModule", "state": "error",
                                   "signature": {"branch": "error", "oracle": "unittest", "exception": "AssertionError"}}],
            })
            output = temp / "merged.json"
            runner.merge_typed_fragments([(fragment, "test_sample.py", [])], output, "github")
            data = json.loads(output.read_text())
            rows = {item["test"]: item for item in data["results"]}
            self.assertEqual(rows["<suite-events>"]["state"], "failed")
            self.assertEqual(rows["<suite-process>"]["state"], "passed")


class WorkflowScanTests(unittest.TestCase):
    def workflow_with_run_block(self, f, body):
        (f.root / ".github/workflows/main.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: |\n" + body,
            encoding="utf-8")

    def test_unparsable_step_mentioning_checker_is_reported(self):
        for mention in ("scripts/ci/check-cell-results.py", "scripts/ci/run-cell-script.sh"):
            with self.subTest(mention=mention):
                f = fixture(self)
                self.workflow_with_run_block(
                    f, f"          python3 -I {mention} \"$out/results.jsonl --require x\n")
                result = f.run_checker()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unparsable step mentions a cell checker", result.stderr)

    def test_unparsable_step_without_checker_stays_silent(self):
        f = fixture(self)
        self.workflow_with_run_block(f, "          echo \"oops --require x\n")
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workflow_invocation_count_is_pinned(self):
        checker = load_script(CHECKER, "known_failing_checker_scan_count")
        invocations, problems = checker.workflow_invocations(ROOT)
        self.assertEqual(problems, [])
        self.assertEqual(len(invocations), 14)


class ShutdownCrashTests(unittest.TestCase):
    CRASH_BODY = (
        "import atexit\nimport os\nimport signal\nimport unittest\n"
        "class Crash(unittest.TestCase):\n"
        "    def test_ok(self): pass\n"
        "atexit.register(lambda: os.kill(os.getpid(), signal.SIGSEGV))\n"
        "if __name__ == '__main__': unittest.main()\n")

    def test_atexit_crash_fails_typed_run(self):
        f = fixture(self)
        shutil.copy2(ROOT / "scripts/run-python-suites.py",
                     f.root / "scripts/run-python-suites.py")
        shutil.copy2(ROOT / "scripts/check-known-failing.py",
                     f.root / "scripts/check-known-failing.py")
        suite = f.root / "tests/python/test_crash_atexit.py"
        suite.parent.mkdir(parents=True, exist_ok=True)
        suite.write_text(self.CRASH_BODY, encoding="utf-8")
        runner = load_script(f.root / "scripts/run-python-suites.py",
                             "python_suite_runner_shutdown_crash")
        runner.RUN = [("test_crash_atexit.py", [])]
        merged = f.root / "merged.json"
        env = {"P11SCOPE_KNOWN_FAILING_RESULTS": str(merged),
               "P11SCOPE_KNOWN_FAILING_HOST": "github"}
        with mock.patch.dict(os.environ, env):
            failed = runner.run_suites(set())
        self.assertTrue(failed, "an atexit crash must fail the typed run")
        document = json.loads(merged.read_text(encoding="utf-8"))
        rows = {item["test"]: item for item in document["results"]}
        self.assertEqual(rows["<suite-process>"]["state"], "failed")
        self.assertEqual(rows["<suite-process>"]["signature"]["branch"],
                         "process_exit_inconsistent")


class FragmentAdmissionTests(unittest.TestCase):
    TEMPLATE = (
        '{"schema": "p11scope/python-suite-fragment/v1", '
        '"path": "tests/python/test_sample.py", "invocation": [], '
        '"process_exit": %s, "complete": true, '
        '"selection": [{"test": "Sample.test_x"}], '
        '"results": [{"test": "Sample.test_x", "state": "failed", '
        '"signature": {"cell": "X", "branch": "B"}}], "suite_events": []}\n')

    def merge_text(self, text):
        runner = load_script(ROOT / "scripts/run-python-suites.py",
                             "python_suite_runner_admission")
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            fragment = temp / "fragment.json"
            fragment.write_text(text, encoding="utf-8")
            output = temp / "merged.json"
            problems = runner.merge_typed_fragments(
                [(fragment, "test_sample.py", [], 1)], output, "github")
            document = json.loads(output.read_text(encoding="utf-8"))
            rows = {item["test"]: item for item in document["results"]}
            return problems, rows["<suite-process>"]

    def test_boolean_process_exit_is_fragment_invalid(self):
        problems, process = self.merge_text(self.TEMPLATE % "true")
        self.assertTrue(problems)
        self.assertEqual(process["state"], "failed")
        self.assertEqual(process["signature"]["branch"], "fragment_invalid")

    def test_duplicate_fragment_keys_are_fragment_invalid(self):
        text = self.TEMPLATE % "1"
        text = text.replace('{"schema":', '{"process_exit": 0, "schema":', 1)
        problems, process = self.merge_text(text)
        self.assertTrue(problems)
        self.assertEqual(process["state"], "failed")
        self.assertEqual(process["signature"]["branch"], "fragment_invalid")

    def test_wellformed_failure_merges_clean(self):
        problems, process = self.merge_text(self.TEMPLATE % "1")
        self.assertEqual(problems, [])
        self.assertEqual(process["state"], "passed")

    def test_null_and_scalar_fragments_are_fragment_invalid(self):
        for text in ("null", "0", "[]", "true", "{oops"):
            with self.subTest(text=text):
                runner = load_script(ROOT / "scripts/run-python-suites.py",
                                     "python_suite_runner_null_doc")
                with tempfile.TemporaryDirectory() as temporary:
                    temp = Path(temporary)
                    fragment = temp / "fragment.json"
                    fragment.write_text(text + "\n", encoding="utf-8")
                    output = temp / "merged.json"
                    problems = runner.merge_typed_fragments(
                        [(fragment, "test_sample.py", [], 0)], output, "github")
                    document = json.loads(output.read_text(encoding="utf-8"))
                    rows = {item["test"]: item for item in document["results"]}
                    self.assertTrue(problems)
                    self.assertEqual(rows["<suite-process>"]["state"], "failed")
                    self.assertEqual(rows["<suite-process>"]["signature"]["branch"],
                                     "fragment_invalid")

    def test_missing_fragment_is_fragment_invalid(self):
        runner = load_script(ROOT / "scripts/run-python-suites.py",
                             "python_suite_runner_absent_fragment")
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            output = temp / "merged.json"
            problems = runner.merge_typed_fragments(
                [(temp / "absent.json", "test_sample.py", [], 1)], output, "github")
            document = json.loads(output.read_text(encoding="utf-8"))
            rows = {item["test"]: item for item in document["results"]}
            self.assertTrue(problems)
            self.assertEqual(rows["<suite-process>"]["state"], "failed")
            self.assertEqual(rows["<suite-process>"]["signature"]["branch"],
                             "fragment_invalid")

    def test_undecodable_fragment_is_fragment_invalid(self):
        runner = load_script(ROOT / "scripts/run-python-suites.py",
                             "python_suite_runner_undecodable")
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            fragment = temp / "fragment.json"
            fragment.write_bytes(b'{"process_exit": \xff}\n')
            output = temp / "merged.json"
            problems = runner.merge_typed_fragments(
                [(fragment, "test_sample.py", [], 1)], output, "github")
            document = json.loads(output.read_text(encoding="utf-8"))
            rows = {item["test"]: item for item in document["results"]}
            self.assertTrue(problems)
            self.assertEqual(rows["<suite-process>"]["state"], "failed")
            self.assertEqual(rows["<suite-process>"]["signature"]["branch"],
                             "fragment_invalid")

    def test_nonstring_suite_event_state_is_fragment_invalid(self):
        for literal in ("[]", "{}", "1", "null", "true"):
            with self.subTest(literal=literal):
                problems, rows = self.merge_event_text(literal, 0)
                self.assertTrue(problems)
                self.assertEqual(rows["<suite-process>"]["state"], "failed")
                self.assertEqual(rows["<suite-process>"]["signature"]["branch"],
                                 "fragment_invalid")

    EVENT_TEMPLATE = (
        '{"schema": "p11scope/python-suite-fragment/v1", '
        '"path": "tests/python/test_sample.py", "invocation": [], '
        '"process_exit": %d, "complete": true, '
        '"selection": [{"test": "Sample.test_pass"}], '
        '"results": [{"test": "Sample.test_pass", "state": "passed", "signature": null}], '
        '"suite_events": [{"event": "tearDownModule", "state": %s, '
        '"signature": {"branch": "error", "oracle": "unittest", '
        '"exception": "AssertionError"}}]}\n')

    def merge_event_text(self, state_literal, process_exit):
        runner = load_script(ROOT / "scripts/run-python-suites.py",
                             "python_suite_runner_event_vocab")
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            fragment = temp / "fragment.json"
            fragment.write_text(self.EVENT_TEMPLATE % (process_exit, state_literal),
                                encoding="utf-8")
            output = temp / "merged.json"
            problems = runner.merge_typed_fragments(
                [(fragment, "test_sample.py", [], process_exit)], output, "github")
            document = json.loads(output.read_text(encoding="utf-8"))
            return problems, {item["test"]: item for item in document["results"]}

    def test_unknown_suite_event_state_is_fragment_invalid(self):
        for state in ("eror", "not_a_state"):
            with self.subTest(state=state):
                problems, rows = self.merge_event_text(f'"{state}"', 0)
                self.assertTrue(problems)
                self.assertEqual(rows["<suite-process>"]["state"], "failed")
                self.assertEqual(rows["<suite-process>"]["signature"]["branch"],
                                 "fragment_invalid")

    def test_known_suite_event_error_stays_typed_failure(self):
        problems, rows = self.merge_event_text('"error"', 1)
        self.assertEqual(problems, [])
        self.assertEqual(rows["<suite-events>"]["state"], "failed")
        self.assertEqual(rows["<suite-events>"]["signature"]["events"][0]["event"],
                         "tearDownModule")


class TypedEnvironmentTests(unittest.TestCase):
    BODY = ("import unittest\nclass Sample(unittest.TestCase):\n"
            "    def test_x(self): pass\n"
            "if __name__ == '__main__': unittest.main()\n")

    def run_tiny_suite(self, env):
        f = fixture(self)
        shutil.copy2(ROOT / "scripts/run-python-suites.py",
                     f.root / "scripts/run-python-suites.py")
        shutil.copy2(ROOT / "scripts/check-known-failing.py",
                     f.root / "scripts/check-known-failing.py")
        suite = f.root / "tests/python/test_sample.py"
        suite.parent.mkdir(parents=True, exist_ok=True)
        suite.write_text(self.BODY, encoding="utf-8")
        runner = load_script(f.root / "scripts/run-python-suites.py",
                             "python_suite_runner_typed_env")
        runner.RUN = [("test_sample.py", [])]
        merged = f.root / "merged.json"
        full_env = {"PATH": os.environ.get("PATH", "")}
        full_env.update(env)
        if "P11SCOPE_KNOWN_FAILING_RESULTS" in full_env:
            full_env["P11SCOPE_KNOWN_FAILING_RESULTS"] = str(merged)
        with mock.patch.dict(os.environ, full_env, clear=True):
            return runner.run_suites(set())

    def test_partial_typed_environment_fails_typed(self):
        failed = self.run_tiny_suite({"P11SCOPE_KNOWN_FAILING_RESULTS": "x"})
        self.assertIn("typed-result configuration", " ".join(failed))

    def test_missing_typed_environment_runs_untyped(self):
        self.assertEqual(self.run_tiny_suite({}), [])


class CliUsageTests(unittest.TestCase):
    def test_checker_usage_error_is_typed(self):
        result = subprocess.run([sys.executable, "-I", str(CHECKER), "--bogus-flag"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_runner_unknown_suite_is_typed(self):
        runner = load_script(ROOT / "scripts/run-python-suites.py", "python_suite_runner_cli")
        self.assertEqual(runner.main(["no-such-suite.py"]), 2)

    def test_wrapper_usage_error_is_typed(self):
        wrapper = load_script(ROOT / "scripts/typed-python-suite.py", "typed_python_suite_cli")
        self.assertEqual(wrapper.main([]), 2)

    def test_privileged_converter_usage_error_is_typed(self):
        converter = ROOT / "scripts/ci/privileged-lib-results.py"
        result = subprocess.run([sys.executable, "-I", str(converter)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage: privileged-lib-results.py", result.stderr)


class WrapperFileTests(unittest.TestCase):
    def run_wrapper(self, temp, suite_arg):
        fragment = temp / "fragment.json"
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "scripts/typed-python-suite.py"),
             str(suite_arg), str(fragment)],
            capture_output=True, text=True)
        return result, fragment

    def test_missing_suite_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            result, fragment = self.run_wrapper(temp, temp / "absent.py")
            self.assertNotEqual(result.returncode, 0)
            document = json.loads(fragment.read_text(encoding="utf-8"))
            self.assertFalse(document["complete"])

    def test_syntax_broken_suite_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            suite = temp / "test_broken.py"
            suite.write_text("def broken(:\n", encoding="utf-8")
            result, fragment = self.run_wrapper(temp, suite)
            self.assertNotEqual(result.returncode, 0)
            document = json.loads(fragment.read_text(encoding="utf-8"))
            self.assertFalse(document["complete"])

    def test_empty_suite_completes_false(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            suite = temp / "test_empty.py"
            suite.write_text("", encoding="utf-8")
            _result, fragment = self.run_wrapper(temp, suite)
            document = json.loads(fragment.read_text(encoding="utf-8"))
            self.assertFalse(document["complete"])


class DriverReadTests(unittest.TestCase):
    def test_unreadable_driver_reports_typed(self):
        runner = load_script(ROOT / "scripts/run-python-suites.py", "python_suite_runner_driver")
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            (temp / "driver").mkdir()
            (temp / "driver/bad.py").write_bytes(b"x = \xff\n")
            read = runner.read_driver(temp)
            self.assertIsNone(read("driver/bad.py"))
            self.assertIsNone(read("driver/absent.py"))
            problems = runner.registry_problems(set(), [], {"x.py": "driver/bad.py"}, {}, read)
            self.assertTrue(any("does not exist" in problem for problem in problems))


class ScopeSkipTests(unittest.TestCase):
    CLASS_SKIP_BODY = (
        "import unittest\n"
        "class Skipped(unittest.TestCase):\n"
        "    @classmethod\n"
        "    def setUpClass(cls): raise unittest.SkipTest('no gcc-m32 on this host')\n"
        "    def test_a(self): pass\n"
        "    def test_b(self): pass\n"
        "class Lively(unittest.TestCase):\n"
        "    def test_c(self): pass\n"
        "if __name__ == '__main__': unittest.main()\n")
    MODULE_SKIP_BODY = (
        "import unittest\n"
        "def setUpModule(): raise unittest.SkipTest('no pkcs11.h on this host')\n"
        "class Probe(unittest.TestCase):\n"
        "    def test_a(self): pass\n"
        "    def test_b(self): pass\n"
        "if __name__ == '__main__': unittest.main()\n")
    CLASS_ERROR_BODY = (
        "import unittest\n"
        "class Probe(unittest.TestCase):\n"
        "    @classmethod\n"
        "    def setUpClass(cls): raise RuntimeError('fixture exploded')\n"
        "    def test_a(self): pass\n"
        "if __name__ == '__main__': unittest.main()\n")

    def run_scope_suite(self, body):
        f = fixture(self)
        suite = f.root / "tests/python/test_sample.py"
        suite.parent.mkdir(parents=True, exist_ok=True)
        suite.write_text(body, encoding="utf-8")
        fragment = f.root / "fragment.json"
        run = subprocess.run(
            [sys.executable, "-I", "scripts/typed-python-suite.py",
             "tests/python/test_sample.py", str(fragment)],
            cwd=f.root, capture_output=True, text=True, timeout=60)
        data = json.loads(fragment.read_text(encoding="utf-8"))
        return f, run, data, fragment

    def merge_and_judge(self, f, fragment, module_name):
        runner = load_script(ROOT / "scripts/run-python-suites.py", module_name)
        merged = f.root / "merged.json"
        runner.merge_typed_fragments([(fragment, "test_sample.py", [])], merged, "github")
        document = json.loads(merged.read_text(encoding="utf-8"))
        judged = f.run_checker("--results", str(merged))
        return document, judged

    def test_setupclass_skip_marks_its_scope_skipped_and_stays_green(self):
        f, run, data, fragment = self.run_scope_suite(self.CLASS_SKIP_BODY)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(data["complete"])
        states = {item["test"]: item for item in data["results"]}
        self.assertEqual(states["Skipped.test_a"]["state"], "skipped")
        self.assertEqual(states["Skipped.test_a"]["signature"], {"branch": "class_skip", "oracle": "unittest"})
        self.assertEqual(states["Skipped.test_b"]["state"], "skipped")
        self.assertEqual(states["Skipped.test_b"]["signature"], {"branch": "class_skip", "oracle": "unittest"})
        self.assertEqual(states["Lively.test_c"]["state"], "passed")
        self.assertNotIn("gcc-m32", json.dumps(data))
        document, judged = self.merge_and_judge(f, fragment, "python_suite_runner_class_skip")
        self.assertTrue(document["complete"])
        rows = {item["test"]: item for item in document["results"]}
        self.assertEqual(rows["<suite-process>"]["state"], "passed")
        self.assertEqual(rows["<suite-events>"]["state"], "passed")
        self.assertEqual(judged.returncode, 0, judged.stderr)
        self.assertIn("results ok", judged.stdout)

    def test_setupmodule_skip_marks_all_skipped_and_stays_green(self):
        f, run, data, fragment = self.run_scope_suite(self.MODULE_SKIP_BODY)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(data["complete"])
        states = {item["test"]: item for item in data["results"]}
        self.assertEqual(set(states), {"Probe.test_a", "Probe.test_b"})
        for item in states.values():
            self.assertEqual(item["state"], "skipped")
            self.assertEqual(item["signature"], {"branch": "module_skip", "oracle": "unittest"})
        self.assertNotIn("pkcs11.h", json.dumps(data))
        document, judged = self.merge_and_judge(f, fragment, "python_suite_runner_module_skip")
        self.assertTrue(document["complete"])
        self.assertEqual(judged.returncode, 0, judged.stderr)

    def test_setupclass_error_stays_red(self):
        f, run, data, fragment = self.run_scope_suite(self.CLASS_ERROR_BODY)
        self.assertEqual(run.returncode, 1)
        self.assertFalse(data["complete"])
        states = {item["test"]: item for item in data["results"]}
        self.assertEqual(states["Probe.test_a"]["state"], "not_run")
        self.assertNotIn("class_skip", json.dumps(data))
        self.assertEqual(data["suite_events"][0]["state"], "error")
        document, judged = self.merge_and_judge(f, fragment, "python_suite_runner_class_error")
        self.assertFalse(document["complete"])
        self.assertNotEqual(judged.returncode, 0)
        self.assertIn("complete must be true", judged.stderr)

    def test_module_skip_is_scoped_to_the_skipped_module(self):
        f = fixture(self)
        helper = f.root / "tests/python/helper_mod.py"
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text(
            "import unittest\n"
            "def setUpModule(): raise unittest.SkipTest('no helper')\n"
            "class Helper(unittest.TestCase):\n"
            "    def test_h(self): pass\n",
            encoding="utf-8")
        suite = f.root / "tests/python/test_sample.py"
        suite.write_text(
            "import unittest\nimport helper_mod\n"
            "class Broken(unittest.TestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls): raise RuntimeError('boom')\n"
            "    def test_a(self): pass\n"
            "def load_tests(loader, tests, ignore):\n"
            "    suite = unittest.TestSuite()\n"
            "    suite.addTests(loader.loadTestsFromModule(helper_mod))\n"
            "    suite.addTests(loader.loadTestsFromTestCase(Broken))\n"
            "    return suite\n"
            "if __name__ == '__main__': unittest.main()\n",
            encoding="utf-8")
        fragment = f.root / "fragment.json"
        run = subprocess.run(
            [sys.executable, "-I", "scripts/typed-python-suite.py",
             "tests/python/test_sample.py", str(fragment)],
            cwd=f.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 1, run.stderr)
        data = json.loads(fragment.read_text(encoding="utf-8"))
        self.assertFalse(data["complete"])
        states = {item["test"]: item for item in data["results"]}
        self.assertEqual(states["Helper.test_h"]["state"], "skipped")
        self.assertEqual(states["Helper.test_h"]["signature"],
                         {"branch": "module_skip", "oracle": "unittest"})
        self.assertEqual(states["Broken.test_a"]["state"], "not_run")
        events = {event["event"]: event for event in data["suite_events"]}
        self.assertIn("setUpModule", events)
        self.assertIn("setUpClass", events)
        self.assertNotIn("Broken)", json.dumps(data))
        document, judged = self.merge_and_judge(f, fragment, "python_suite_runner_module_scope")
        self.assertFalse(document["complete"])
        self.assertNotEqual(judged.returncode, 0)
        self.assertIn("complete must be true", judged.stderr)

    def test_class_skip_is_scoped_to_its_qualified_class(self):
        f = fixture(self)
        helper = f.root / "tests/python/helper_mod.py"
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text(
            "import unittest\n"
            "class Broken(unittest.TestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls): raise unittest.SkipTest('no helper')\n"
            "    def test_h(self): pass\n",
            encoding="utf-8")
        suite = f.root / "tests/python/test_sample.py"
        suite.write_text(
            "import unittest\nimport helper_mod\n"
            "class Broken(unittest.TestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls): raise RuntimeError('boom')\n"
            "    def test_a(self): pass\n"
            "def load_tests(loader, tests, ignore):\n"
            "    suite = unittest.TestSuite()\n"
            "    suite.addTests(loader.loadTestsFromTestCase(helper_mod.Broken))\n"
            "    suite.addTests(loader.loadTestsFromTestCase(Broken))\n"
            "    return suite\n"
            "if __name__ == '__main__': unittest.main()\n",
            encoding="utf-8")
        fragment = f.root / "fragment.json"
        run = subprocess.run(
            [sys.executable, "-I", "scripts/typed-python-suite.py",
             "tests/python/test_sample.py", str(fragment)],
            cwd=f.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 1, run.stderr)
        data = json.loads(fragment.read_text(encoding="utf-8"))
        self.assertFalse(data["complete"])
        states = {item["test"]: item for item in data["results"]}
        self.assertEqual(states["Broken.test_h"]["state"], "skipped")
        self.assertEqual(states["Broken.test_h"]["signature"],
                         {"branch": "class_skip", "oracle": "unittest"})
        self.assertEqual(states["Broken.test_a"]["state"], "not_run")
        document, judged = self.merge_and_judge(f, fragment, "python_suite_runner_class_scope")
        self.assertFalse(document["complete"])
        self.assertNotEqual(judged.returncode, 0)
        self.assertIn("complete must be true", judged.stderr)

    def test_teardownclass_error_is_a_typed_failure(self):
        body = (
            "import unittest\n"
            "class Broken(unittest.TestCase):\n"
            "    def test_a(self): pass\n"
            "    @classmethod\n"
            "    def tearDownClass(cls): raise RuntimeError('teardown boom')\n"
            "if __name__ == '__main__': unittest.main()\n")
        f, run, data, fragment = self.run_scope_suite(body)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertTrue(data["complete"])
        self.assertEqual(data["results"][0]["state"], "passed")
        self.assertEqual(data["suite_events"][0]["event"], "tearDownClass")
        self.assertEqual(data["suite_events"][0]["state"], "error")
        self.assertNotIn("Broken)", json.dumps(data))
        document, judged = self.merge_and_judge(f, fragment, "python_suite_runner_teardown_class")
        self.assertTrue(document["complete"])
        rows = {item["test"]: item for item in document["results"]}
        self.assertEqual(rows["<suite-events>"]["state"], "failed")
        self.assertEqual(rows["<suite-events>"]["signature"]["events"][0]["event"], "tearDownClass")
        self.assertNotEqual(judged.returncode, 0)
        self.assertIn("failing test not listed: <suite-events>", judged.stderr)
        self.assertNotIn("stable typed token", judged.stderr)


class NeutralTerminalStateTests(unittest.TestCase):
    def test_unlisted_skip_is_not_a_failure_or_a_pass(self):
        f = fixture(self)
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "state": "skipped", "signature": {"branch": "host_prerequisite"}}])
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 intermittent passes", result.stdout)

    def test_listed_skip_is_not_terminal_failure_evidence(self):
        f = fixture(self)
        f.registry()
        f.python_suite()
        f.rows([row()])
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "state": "skipped", "signature": {"branch": "host_prerequisite"}}])
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("listed row was not executed", result.stderr)

    def test_not_applicable_is_neutral_but_never_a_pass(self):
        f = fixture(self)
        doc = result_doc([{"path": "scripts/ci/cells.sh", "test": "smoke",
                           "state": "not_applicable", "signature": {"qualification": "nonqualifying"}}],
                         runner="cell:scripts/ci/cells.sh")
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 intermittent passes", result.stdout)


class PrivilegedTypedBranchTests(unittest.TestCase):
    def test_converter_maps_promoted_curated_test_outside_ignored_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            test_name = "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64"
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            output = temp / "out.json"
            selection.write_text(test_name + "\n")
            verdicts.write_text(test_name + "\tPASS\n")
            converter = ROOT / "scripts/ci/privileged-lib-results.py"
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data["selection"][0]["path"], "src/attach/inventory/activation/privileged_tests.rs")

    def test_converter_uses_sidecar_typed_signature_for_failed_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            test_name = "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64"
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            sidecar = temp / "sidecar.json"
            output = temp / "out.json"
            selection.write_text(test_name + "\n")
            write_json(sidecar, {"cell": "X", "branch": "exactly_one_module"})
            verdicts.write_text(test_name + "\tFAIL\t" + str(sidecar) + "\n")
            converter = ROOT / "scripts/ci/privileged-lib-results.py"
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data["results"][0]["signature"], {"cell": "X", "branch": "exactly_one_module"})

    def test_converter_refuses_malformed_sidecar_typed_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            test_name = "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64"
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            sidecar = temp / "sidecar.json"
            output = temp / "out.json"
            selection.write_text(test_name + "\n")
            sidecar.write_text('{"branch":"raw prose with spaces"}\n', encoding="utf-8")
            verdicts.write_text(test_name + "\tFAIL\t" + str(sidecar) + "\n")
            converter = ROOT / "scripts/ci/privileged-lib-results.py"
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("typed signature", result.stderr)

    def test_converter_refuses_duplicate_key_sidecar(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            test_name = "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64"
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            sidecar = temp / "sidecar.json"
            output = temp / "out.json"
            selection.write_text(test_name + "\n")
            sidecar.write_text('{"cell":"X","branch":"x","branch":"y"}\n', encoding="utf-8")
            verdicts.write_text(test_name + "\tFAIL\t" + str(sidecar) + "\n")
            converter = ROOT / "scripts/ci/privileged-lib-results.py"
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing or invalid JSON", result.stderr)

    def test_converter_rejects_null_and_scalar_sidecars_typed(self):
        for content in ("null\n", '"s"\n', "true\n"):
            with self.subTest(content=content):
                with tempfile.TemporaryDirectory() as temporary:
                    temp = Path(temporary)
                    test_name = "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64"
                    selection = temp / "selection.txt"
                    verdicts = temp / "verdicts.tsv"
                    sidecar = temp / "sidecar.json"
                    output = temp / "out.json"
                    selection.write_text(test_name + "\n")
                    sidecar.write_text(content, encoding="utf-8")
                    verdicts.write_text(test_name + "\tFAIL\t" + str(sidecar) + "\n")
                    converter = ROOT / "scripts/ci/privileged-lib-results.py"
                    result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("not a typed signature", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_converter_rejects_null_and_scalar_registry_typed(self):
        for content in ("null\n", "0\n", "[]\n", '"s"\n', "true\n", "{oops\n"):
            with self.subTest(content=content):
                with tempfile.TemporaryDirectory() as temporary:
                    temp = Path(temporary)
                    (temp / "scripts/ci").mkdir(parents=True)
                    (temp / "tests").mkdir()
                    shutil.copy2(ROOT / "scripts/ci/privileged-lib-results.py",
                                 temp / "scripts/ci/privileged-lib-results.py")
                    shutil.copy2(ROOT / "scripts/check-known-failing.py",
                                 temp / "scripts/check-known-failing.py")
                    (temp / "tests/ignored-tests.json").write_text(content, encoding="utf-8")
                    selection = temp / "selection.txt"
                    verdicts = temp / "verdicts.tsv"
                    output = temp / "out.json"
                    selection.write_text("X\n")
                    verdicts.write_text("X\tPASS\n")
                    converter = temp / "scripts/ci/privileged-lib-results.py"
                    result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("cannot read ignored-test registry", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_converter_rejects_nonlist_sites_typed(self):
        for content in ('{"schema": "p11scope/ignored-tests/v1", "sites": null}\n',
                        '{"schema": "p11scope/ignored-tests/v1", "sites": 0}\n'):
            with self.subTest(content=content):
                with tempfile.TemporaryDirectory() as temporary:
                    temp = Path(temporary)
                    (temp / "scripts/ci").mkdir(parents=True)
                    (temp / "tests").mkdir()
                    shutil.copy2(ROOT / "scripts/ci/privileged-lib-results.py",
                                 temp / "scripts/ci/privileged-lib-results.py")
                    shutil.copy2(ROOT / "scripts/check-known-failing.py",
                                 temp / "scripts/check-known-failing.py")
                    (temp / "tests/ignored-tests.json").write_text(content, encoding="utf-8")
                    selection = temp / "selection.txt"
                    verdicts = temp / "verdicts.tsv"
                    output = temp / "out.json"
                    selection.write_text("X\n")
                    verdicts.write_text("X\tPASS\n")
                    converter = temp / "scripts/ci/privileged-lib-results.py"
                    result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must be an object with a sites list", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_converter_fails_loud_on_missing_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            (temp / "scripts/ci").mkdir(parents=True)
            (temp / "tests").mkdir()
            shutil.copy2(ROOT / "scripts/ci/privileged-lib-results.py",
                         temp / "scripts/ci/privileged-lib-results.py")
            shutil.copy2(ROOT / "scripts/check-known-failing.py",
                         temp / "scripts/check-known-failing.py")
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            output = temp / "out.json"
            selection.write_text("X\n")
            verdicts.write_text("X\tPASS\n")
            converter = temp / "scripts/ci/privileged-lib-results.py"
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot read ignored-test registry", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(output.exists())

    def test_converter_rejects_undecodable_inputs_typed(self):
        cases = (("verdicts", "cannot read structured records"),
                 ("sidecar", "missing or invalid JSON"))
        for name, needle in cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temporary:
                    temp = Path(temporary)
                    test_name = "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64"
                    selection = temp / "selection.txt"
                    verdicts = temp / "verdicts.tsv"
                    sidecar = temp / "sidecar.json"
                    output = temp / "out.json"
                    selection.write_text(test_name + "\n")
                    if name == "verdicts":
                        verdicts.write_bytes(f"{test_name}\tFAIL\t{sidecar}\n".encode() + b"\xff")
                    else:
                        verdicts.write_text(test_name + "\tFAIL\t" + str(sidecar) + "\n")
                    sidecar.write_bytes(b'{"branch": "\xff"}\n' if name == "sidecar"
                                        else b'{"cell": "X", "branch": "B"}\n')
                    converter = ROOT / "scripts/ci/privileged-lib-results.py"
                    result = subprocess.run([sys.executable, "-I", str(converter), str(selection),
                                             str(verdicts), str(output), "github"],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(needle, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_converter_rejects_bad_host_and_shapes_typed(self):
        converter = ROOT / "scripts/ci/privileged-lib-results.py"
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            output = temp / "out.json"
            selection.write_text("X\n")
            verdicts.write_text("X\tPASS\n")
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection),
                                     str(verdicts), str(output), "mars"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown host", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            verdicts.write_text("X\n")
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection),
                                     str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("malformed verdict line", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            selection.write_text("")
            verdicts.write_text("")
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection),
                                     str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("selection is empty or duplicated", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_converter_rejects_verdict_shape_violations_typed(self):
        converter = ROOT / "scripts/ci/privileged-lib-results.py"
        name = "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64"
        cases = (
            ("bad-verdict", f"{name}\tMAYBE\n", "verdict outside the closed"),
            ("sidecar-on-pass", f"{name}\tPASS\t/tmp/x.json\n", "passing verdict carries"),
            ("unmapped", ("NoSuchTestXYZ123\tPASS\n", "NoSuchTestXYZ123\n"),
             "no unambiguous Rust source path"),
        )
        for label, payload, needle in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as temporary:
                    temp = Path(temporary)
                    selection = temp / "selection.txt"
                    verdicts = temp / "verdicts.tsv"
                    output = temp / "out.json"
                    if label == "unmapped":
                        verdicts.write_text(payload[0])
                        selection.write_text(payload[1])
                    else:
                        selection.write_text(name + "\n")
                        verdicts.write_text(payload)
                    result = subprocess.run([sys.executable, "-I", str(converter), str(selection),
                                             str(verdicts), str(output), "github"],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(needle, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_converter_missing_selection_is_typed(self):
        converter = ROOT / "scripts/ci/privileged-lib-results.py"
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            verdicts = temp / "verdicts.tsv"
            output = temp / "out.json"
            verdicts.write_text("X\tPASS\n")
            result = subprocess.run([sys.executable, "-I", str(converter), str(temp / "absent.txt"),
                                     str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot read structured records", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_converter_maps_healthy_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            (temp / "scripts/ci").mkdir(parents=True)
            (temp / "tests").mkdir()
            shutil.copy2(ROOT / "scripts/ci/privileged-lib-results.py",
                         temp / "scripts/ci/privileged-lib-results.py")
            shutil.copy2(ROOT / "scripts/check-known-failing.py",
                         temp / "scripts/check-known-failing.py")
            (temp / "tests/ignored-tests.json").write_text(
                '{"schema": "p11scope/ignored-tests/v1", "sites": ['
                '{"file": "src/b.rs", "path": "X"}]}\n',
                encoding="utf-8")
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            output = temp / "out.json"
            selection.write_text("X\n")
            verdicts.write_text("X\tPASS\n")
            converter = temp / "scripts/ci/privileged-lib-results.py"
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["results"][0]["path"], "src/b.rs")

    def test_token_index_skips_undecodable_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            (temp / "scripts/ci").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/ci/privileged-lib-results.py",
                         temp / "scripts/ci/privileged-lib-results.py")
            shutil.copy2(ROOT / "scripts/check-ignored-tests.py",
                         temp / "scripts/check-ignored-tests.py")
            (temp / "src").mkdir()
            (temp / "src/bad.rs").write_bytes(b"fn broken_\xff() {}\n")
            (temp / "src/good.rs").write_text("fn ExampleToken() {}\n", encoding="utf-8")
            module = load_script(temp / "scripts/ci/privileged-lib-results.py",
                                 "privileged_token_index_decode")
            index = module.rust_token_index()
            self.assertEqual(index.get("ExampleToken"), {"src/good.rs"})

    def test_converter_refuses_duplicate_key_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            (temp / "scripts/ci").mkdir(parents=True)
            (temp / "tests").mkdir()
            shutil.copy2(ROOT / "scripts/ci/privileged-lib-results.py",
                         temp / "scripts/ci/privileged-lib-results.py")
            shutil.copy2(ROOT / "scripts/check-known-failing.py",
                         temp / "scripts/check-known-failing.py")
            (temp / "tests/ignored-tests.json").write_text(
                '{"schema": "p11scope/ignored-tests/v1", "sites": ['
                '{"file": "src/a.rs", "path": "X", "file": "src/b.rs"}]}\n',
                encoding="utf-8")
            test_name = "X"
            selection = temp / "selection.txt"
            verdicts = temp / "verdicts.tsv"
            output = temp / "out.json"
            selection.write_text(test_name + "\n")
            verdicts.write_text(test_name + "\tPASS\n")
            converter = temp / "scripts/ci/privileged-lib-results.py"
            result = subprocess.run([sys.executable, "-I", str(converter), str(selection), str(verdicts), str(output), "github"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot read ignored-test registry", result.stderr)


class ProducerMutationSweepTests(unittest.TestCase):
    def record(self, results, name, original_ok, mutant_ok):
        if original_ok and not mutant_ok:
            results["killed"] += 1
        else:
            results["failures"].append(f"{name}(original={original_ok},mutant={mutant_ok})")

    def mutate_source(self, path, old, new):
        source = path.read_text(encoding="utf-8")
        self.assertIn(old, source)
        return source.replace(old, new, 1)

    def python_suite_fragment(self, script_source, suite_body, temp):
        suite = temp / "test_probe.py"
        fragment = temp / "fragment.json"
        script = temp / "typed-python-suite.py"
        suite.write_text(suite_body, encoding="utf-8")
        script.write_text(script_source, encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", str(script), str(suite), str(fragment)],
                                capture_output=True, text=True)
        if not fragment.exists():
            return None, result
        return json.loads(fragment.read_text()), result

    def test_producer_and_discovery_mutation_sweep(self):
        results = {"killed": 0, "failures": []}

        # Python process integrity: accepting every exit code erases the
        # pass-then-nonzero-exit proof.
        runner_source = (ROOT / "scripts/run-python-suites.py").read_text(encoding="utf-8")
        runner_mutant = self.mutate_source(ROOT / "scripts/run-python-suites.py",
                                           "and ((process_exit == 1) == failure_present)", "and True")
        for label, source in (("original", runner_source), ("mutant", runner_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "run-python-suites.py"
                script.write_text(source, encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-known-failing.py", temp / "check-known-failing.py")
                module = load_script(script, f"runner_{label}")
                fragment = temp / "fragment.json"
                write_json(fragment, {
                    "schema": "p11scope/python-suite-fragment/v1",
                    "path": "tests/python/test_sample.py", "invocation": [], "process_exit": 1,
                    "complete": True,
                    "selection": [{"test": "Sample.test_pass"}],
                    "results": [{"test": "Sample.test_pass", "state": "passed", "signature": None}],
                    "suite_events": [],
                })
                output = temp / "merged.json"
                problems = module.merge_typed_fragments([(fragment, "test_sample.py", [])], output, "github")
                rows = {row_["test"]: row_ for row_ in json.loads(output.read_text())["results"]}
                ok = bool(problems) and rows["<suite-process>"]["state"] == "failed"
                if label == "original":
                    original_ok = ok
                else:
                    mutant_ok = ok
        self.record(results, "python-process-exit", original_ok, mutant_ok)

        # Outer-observed exit must equal the fragment's self-report: a
        # teardown crash never reaches the fragment, so dropping the
        # equality reopens the green-on-crash hole.
        crash_mutant = self.mutate_source(ROOT / "scripts/run-python-suites.py",
                                          "and observed_returncode == process_exit", "and True")
        for label, source in (("original", runner_source), ("mutant", crash_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "run-python-suites.py"
                script.write_text(source, encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-known-failing.py", temp / "check-known-failing.py")
                module = load_script(script, f"runner_crash_{label}")
                fragment = temp / "fragment.json"
                write_json(fragment, {
                    "schema": "p11scope/python-suite-fragment/v1",
                    "path": "tests/python/test_sample.py", "invocation": [], "process_exit": 0,
                    "complete": True,
                    "selection": [{"test": "Sample.test_pass"}],
                    "results": [{"test": "Sample.test_pass", "state": "passed", "signature": None}],
                    "suite_events": [],
                })
                output = temp / "merged.json"
                problems = module.merge_typed_fragments([(fragment, "test_sample.py", [], 139)], output, "github")
                rows = {row_["test"]: row_ for row_ in json.loads(output.read_text())["results"]}
                ok = bool(problems) and rows["<suite-process>"]["state"] == "failed"
                if label == "original":
                    original_ok = ok
                else:
                    mutant_ok = ok
        self.record(results, "python-outer-exit", original_ok, mutant_ok)

        # Fragment admission is exact-typed: a boolean process_exit must not
        # pass as the integer 1 via isinstance.
        bool_mutant = self.mutate_source(ROOT / "scripts/run-python-suites.py",
                                         "and type(fragment.get(\"process_exit\")) is int",
                                         "and isinstance(fragment.get(\"process_exit\"), int)")
        for label, source in (("original", runner_source), ("mutant", bool_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "run-python-suites.py"
                script.write_text(source, encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-known-failing.py", temp / "check-known-failing.py")
                module = load_script(script, f"runner_bool_{label}")
                fragment = temp / "fragment.json"
                write_json(fragment, {
                    "schema": "p11scope/python-suite-fragment/v1",
                    "path": "tests/python/test_sample.py", "invocation": [], "process_exit": True,
                    "complete": True,
                    "selection": [{"test": "Sample.test_x"}],
                    "results": [{"test": "Sample.test_x", "state": "failed",
                                 "signature": {"cell": "X", "branch": "B"}}],
                    "suite_events": [],
                })
                output = temp / "merged.json"
                problems = module.merge_typed_fragments([(fragment, "test_sample.py", [], 1)], output, "github")
                rows = {row_["test"]: row_ for row_ in json.loads(output.read_text())["results"]}
                ok = bool(problems) and rows["<suite-process>"]["state"] == "failed"
                if label == "original":
                    original_ok = ok
                else:
                    mutant_ok = ok
        self.record(results, "python-fragment-bool-exit", original_ok, mutant_ok)

        # Fragment admission rejects duplicate keys: plain json.loads keeps
        # the last one and would launder a contradictory process_exit.
        dup_mutant = self.mutate_source(ROOT / "scripts/run-python-suites.py",
                                        "fragment, _load_problems = checker.strict_json(text, str(fragment_path))",
                                        "fragment = json.loads(text)")
        for label, source in (("original", runner_source), ("mutant", dup_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "run-python-suites.py"
                script.write_text(source, encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-known-failing.py", temp / "check-known-failing.py")
                module = load_script(script, f"runner_dup_{label}")
                fragment = temp / "fragment.json"
                fragment.write_text(
                    '{"schema": "p11scope/python-suite-fragment/v1", '
                    '"path": "tests/python/test_sample.py", "invocation": [], '
                    '"process_exit": 0, "process_exit": 1, "complete": true, '
                    '"selection": [{"test": "Sample.test_x"}], '
                    '"results": [{"test": "Sample.test_x", "state": "failed", '
                    '"signature": {"cell": "X", "branch": "B"}}], "suite_events": []}\n',
                    encoding="utf-8")
                output = temp / "merged.json"
                problems = module.merge_typed_fragments([(fragment, "test_sample.py", [], 1)], output, "github")
                rows = {row_["test"]: row_ for row_ in json.loads(output.read_text())["results"]}
                ok = bool(problems) and rows["<suite-process>"]["state"] == "failed"
                if label == "original":
                    original_ok = ok
                else:
                    mutant_ok = ok
        self.record(results, "python-fragment-dup-keys", original_ok, mutant_ok)

        # Every merge admission clause is killed individually: each mutant
        # drops exactly one exactness or invalid-marking clause, and its
        # malformed input merges clean only under the mutant.
        clause_cases = [
            ("python-event-state-closed",
             'and event.get("state") in SUITE_EVENT_STATES', "and True",
             [{"test": "Sample.test_pass"}],
             [{"test": "Sample.test_pass", "state": "passed", "signature": None}],
             [{"event": "tearDownModule", "state": "eror",
               "signature": {"branch": "error"}}],
             0),
            ("python-event-signature-shape",
             'and (event.get("signature") is None\n'
             '                         or type(event.get("signature")) is dict)):',
             "and True):",
             [{"test": "Sample.test_pass"}],
             [{"test": "Sample.test_pass", "state": "passed", "signature": None}],
             [{"event": "tearDownModule", "state": "error", "signature": "oops"}],
             1),
            ("python-event-keys",
             'set(event) == {"event", "state", "signature"}', "True",
             [{"test": "Sample.test_pass"}],
             [{"test": "Sample.test_pass", "state": "passed", "signature": None}],
             [{"event": "tearDownModule", "state": "error",
               "signature": {"branch": "error"}, "extra": 1}],
             1),
            ("python-event-invalid",
             'if event["state"] in event_failure_states:\n'
             "                    failure_present = True\n"
             "            else:\n"
             "                invalid = True",
             'if event["state"] in event_failure_states:\n'
             "                    failure_present = True\n"
             "            else:",
             [{"test": "Sample.test_pass"}],
             [{"test": "Sample.test_pass", "state": "passed", "signature": None}],
             [{"broken": 1}],
             0),
            ("python-selection-keys",
             'set(item) == {"test"}', "True",
             [{"test": "Sample.test_x", "extra": 1}],
             [{"test": "Sample.test_x", "state": "failed",
               "signature": {"cell": "X", "branch": "B"}}],
             [],
             1),
            ("python-selection-invalid",
             'selection.append({"path": suite_path, "test": item["test"], "invocation": invocation})\n'
             "            else:\n"
             "                invalid = True",
             'selection.append({"path": suite_path, "test": item["test"], "invocation": invocation})\n'
             "            else:",
             [{"broken": 1}],
             [{"test": "Sample.test_x", "state": "failed",
               "signature": {"cell": "X", "branch": "B"}}],
             [],
             1),
            ("python-result-keys",
             'set(item) != {"test", "state", "signature"}', "False",
             [{"test": "Sample.test_x"}],
             [{"test": "Sample.test_x", "state": "failed",
               "signature": {"cell": "X", "branch": "B"}, "extra": 1}],
             [],
             1),
            ("python-result-invalid",
             "                invalid = True\n"
             "                complete = False\n"
             "                continue",
             "                complete = False\n"
             "                continue",
             [{"test": "Sample.test_x"}],
             [{"broken": 1}],
             [],
             0),
        ]
        for index, (name, old, new, selection, outcome, events, exit_code) in enumerate(clause_cases):
            self.assertIn(old, runner_source, name)
            mutant_source = runner_source.replace(old, new, 1)
            clause_outcomes = {}
            for label, source in (("original", runner_source), ("mutant", mutant_source)):
                with tempfile.TemporaryDirectory() as temporary:
                    temp = Path(temporary)
                    script = temp / "run-python-suites.py"
                    script.write_text(source, encoding="utf-8")
                    shutil.copy2(ROOT / "scripts/check-known-failing.py",
                                 temp / "check-known-failing.py")
                    module = load_script(script, f"runner_clause_{index}_{label}")
                    fragment = temp / "fragment.json"
                    write_json(fragment, {
                        "schema": "p11scope/python-suite-fragment/v1",
                        "path": "tests/python/test_sample.py", "invocation": [],
                        "process_exit": exit_code, "complete": True,
                        "selection": selection, "results": outcome,
                        "suite_events": events,
                    })
                    output = temp / "merged.json"
                    problems = module.merge_typed_fragments(
                        [(fragment, "test_sample.py", [], exit_code)], output, "github")
                    rows = {row_["test"]: row_ for row_ in json.loads(output.read_text())["results"]}
                    clause_outcomes[label] = (
                        bool(problems) and rows["<suite-process>"]["state"] == "failed")
            self.record(results, name, clause_outcomes["original"], clause_outcomes["mutant"])

        # Suite-event states must be exact strings before set membership:
        # unhashable states are typed fragment_invalid, never a crash.
        state_str_mutant = self.mutate_source(ROOT / "scripts/run-python-suites.py",
                                              'and type(event.get("state")) is str\n'
                                              '                    and event.get("state") in SUITE_EVENT_STATES',
                                              'and event.get("state") in SUITE_EVENT_STATES')
        outcomes = {}
        for label, source in (("original", runner_source), ("mutant", state_str_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "run-python-suites.py"
                script.write_text(source, encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-known-failing.py",
                             temp / "check-known-failing.py")
                module = load_script(script, f"runner_state_str_{label}")
                fragment = temp / "fragment.json"
                write_json(fragment, {
                    "schema": "p11scope/python-suite-fragment/v1",
                    "path": "tests/python/test_sample.py", "invocation": [],
                    "process_exit": 0, "complete": True,
                    "selection": [{"test": "Sample.test_pass"}],
                    "results": [{"test": "Sample.test_pass", "state": "passed",
                                 "signature": None}],
                    "suite_events": [{"event": "tearDownModule", "state": [],
                                      "signature": {"branch": "error"}}],
                })
                output = temp / "merged.json"
                try:
                    problems = module.merge_typed_fragments(
                        [(fragment, "test_sample.py", [], 0)], output, "github")
                    rows = {row_["test"]: row_ for row_ in json.loads(output.read_text())["results"]}
                    ok = bool(problems) and rows["<suite-process>"]["state"] == "failed"
                except TypeError:
                    ok = False
                if label == "original":
                    original_ok = ok
                else:
                    mutant_ok = ok
        self.record(results, "python-event-state-str", original_ok, mutant_ok)

        # Python module terminal events must reach the typed fragment.
        typed_source = (ROOT / "scripts/typed-python-suite.py").read_text(encoding="utf-8")
        typed_mutant = self.mutate_source(ROOT / "scripts/typed-python-suite.py",
                                          '"suite_events": RECORDER.suite_events,', '"suite_events": [],')
        teardown_body = ("import unittest\nclass Sample(unittest.TestCase):\n def test_pass(self): pass\n"
                         "def tearDownModule(): raise AssertionError('x')\nunittest.main()\n")
        outcomes = {}
        for label, source in (("original", typed_source), ("mutant", typed_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                data, _run = self.python_suite_fragment(source, teardown_body, Path(temporary))
                outcomes[label] = bool(data and data.get("suite_events"))
        self.record(results, "python-suite-events", outcomes["original"], outcomes["mutant"])

        # A unittest-owned typed exception signature must not be degraded to
        # broad oracle/exception-type tokens.
        typed_mutant = self.mutate_source(ROOT / "scripts/typed-python-suite.py",
                                          "if custom is not None:", "if False:")
        custom_body = ("import unittest\nclass TypedFailure(AssertionError):\n"
                       " def __init__(self):\n  super().__init__('x')\n"
                       "  self.p11scope_signature={'cell':'X','branch':'exact_branch'}\n"
                       "class Sample(unittest.TestCase):\n def test_fail(self): raise TypedFailure()\nunittest.main()\n")
        outcomes = {}
        for label, source in (("original", typed_source), ("mutant", typed_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                data, _run = self.python_suite_fragment(source, custom_body, Path(temporary))
                signature = data["results"][0]["signature"] if data and data.get("results") else None
                outcomes[label] = signature == {"cell": "X", "branch": "exact_branch"}
        self.record(results, "python-custom-signature", outcomes["original"], outcomes["mutant"])

        # Cell nonqualifying rows are honest not_applicable evidence, never passes.
        cell_source = (ROOT / "scripts/ci/check-cell-results.py").read_text(encoding="utf-8")
        cell_mutant = self.mutate_source(ROOT / "scripts/ci/check-cell-results.py",
                                         'state = "not_applicable"', 'state = "passed"')
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", cell_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                (temp / "scripts/qualify-public-cli.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                rows_path = temp / "results.jsonl"
                rows_path.write_text(json.dumps({"cell": "smoke", "pass": False, "detail": "smoke",
                                                 "qualification": "nonqualifying"}) + "\n", encoding="utf-8")
                output = temp / "typed.json"
                run = subprocess.run([sys.executable, "-I", str(script), str(rows_path),
                                      "--allow-nonqualifying", "smoke", "--known-failing-results", str(output),
                                      "--known-failing-runner", "cell:scripts/qualify-public-cli.sh",
                                      "--known-failing-host", "github"], capture_output=True, text=True)
                state = None
                if output.exists():
                    state = json.loads(output.read_text())["results"][0]["state"]
                outcomes[label] = state == "not_applicable"
        self.record(results, "cell-nonqualifying-state", outcomes["original"], outcomes["mutant"])

        # A failed cell's exact branch sidecar must not be degraded to the
        # broad cell/qualification pair.
        cell_mutant = self.mutate_source(ROOT / "scripts/ci/check-cell-results.py",
            'signature = sidecar if sidecar is not None else {"cell": cell, "qualification": qualification}',
            'signature = {"cell": cell, "qualification": qualification}')
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", cell_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                (temp / "scripts/qualify-public-cli.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                rows_path = temp / "results.jsonl"
                rows_path.write_text(json.dumps({"cell": "a", "pass": False, "detail": "d", "qualification": "qualified"}) + "\n", encoding="utf-8")
                signature = {"cell": "a", "branch": "sign_not_attributed"}
                (temp / "a.typed-failure.json").write_text(json.dumps(signature) + "\n", encoding="utf-8")
                output = temp / "typed.json"
                subprocess.run([sys.executable, "-I", str(script), str(rows_path), "--require", "a",
                                "--known-failing-results", str(output), "--known-failing-runner",
                                "cell:scripts/qualify-public-cli.sh", "--known-failing-host", "github"],
                               capture_output=True, text=True)
                emitted = json.loads(output.read_text())["results"][0]["signature"] if output.exists() else None
                outcomes[label] = emitted == signature
        self.record(results, "cell-branch-sidecar", outcomes["original"], outcomes["mutant"])

        # Cell rows are admitted strictly: duplicate keys must fail the
        # row instead of collapsing (a failed cell rewritten as a pass).
        cell_mutant = self.mutate_source(ROOT / "scripts/ci/check-cell-results.py",
                                         "row, row_problems = checker.strict_json(line, f\"line {number}\")",
                                         "row, row_problems = json.loads(line), []")
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", cell_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                (temp / "scripts/qualify-public-cli.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                rows_path = temp / "results.jsonl"
                rows_path.write_text('{"cell":"a","pass":false,"pass":true,'
                                     '"qualification":"qualified","detail":"d"}\n', encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(script), str(rows_path), "--require", "a"],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode != 0
        self.record(results, "cell-row-dup-keys", outcomes["original"], outcomes["mutant"])

        # Cell sidecars are admitted strictly: contradictory duplicate
        # branches must fail instead of collapsing to one.
        cell_mutant = self.mutate_source(ROOT / "scripts/ci/check-cell-results.py",
                                         "value, _load_problems = checker.strict_json(text, str(path))",
                                         "value = json.loads(text)")
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", cell_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                (temp / "scripts/qualify-public-cli.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                rows_path = temp / "results.jsonl"
                rows_path.write_text(json.dumps({"cell": "a", "pass": False, "detail": "d",
                                                 "qualification": "qualified"}) + "\n", encoding="utf-8")
                (temp / "a.typed-failure.json").write_text(
                    '{"cell":"a","branch":"x","branch":"y"}\n', encoding="utf-8")
                output = temp / "typed.json"
                run = subprocess.run([sys.executable, "-I", str(script), str(rows_path), "--require", "a",
                                      "--known-failing-results", str(output),
                                      "--known-failing-runner", "cell:scripts/qualify-public-cli.sh",
                                      "--known-failing-host", "github"],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode != 0 and not output.exists()
        self.record(results, "cell-sidecar-dup-keys", outcomes["original"], outcomes["mutant"])

        # The shared registry loader rejects duplicate keys: restoring
        # plain loads collapses them back into one mapping.
        helper_source = (ROOT / "scripts/check-known-failing.py").read_text(encoding="utf-8")
        helper_mutant = self.mutate_source(
            ROOT / "scripts/check-known-failing.py",
            "    registry, load_problems = strict_json(text, str(path))",
            "    registry, load_problems = json.loads(text), []")
        outcomes = {}
        for label, source in (("original", helper_source), ("mutant", helper_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "check-known-failing.py"
                script.write_text(source, encoding="utf-8")
                registry = temp / "ignored-tests.json"
                registry.write_text(
                    '{"schema": "p11scope/ignored-tests/v1", "sites": ['
                    '{"file": "a.rs", "path": "X", "file": "b.rs"}]}\n', encoding="utf-8")
                module = load_script(script, f"registry_helper_{label}")
                _files, problems = module.load_ignored_registry(registry)
                outcomes[label] = problems != []
        self.record(results, "ignored-registry-dup-keys", outcomes["original"], outcomes["mutant"])

        # The shared registry loader requires an object with a sites list:
        # dropping the shape guard crashes on null or non-list sites.
        shape_mutant = self.mutate_source(
            ROOT / "scripts/check-known-failing.py",
            "    if load_problems or type(registry) is not dict or type(registry.get(\"sites\")) is not list:",
            "    if load_problems:")
        outcomes = {}
        for label, source in (("original", helper_source), ("mutant", shape_mutant)):
            label_ok = True
            for index, content in enumerate(("null\n",
                                            '{"schema": "p11scope/ignored-tests/v1", "sites": null}\n',
                                            '{"schema": "p11scope/ignored-tests/v1", "sites": 0}\n')):
                with tempfile.TemporaryDirectory() as temporary:
                    temp = Path(temporary)
                    script = temp / "check-known-failing.py"
                    script.write_text(source, encoding="utf-8")
                    registry = temp / "ignored-tests.json"
                    registry.write_text(content, encoding="utf-8")
                    module = load_script(script, f"registry_shape_{index}_{label}")
                    try:
                        _files, problems = module.load_ignored_registry(registry)
                    except (AttributeError, TypeError):
                        label_ok = False
                        break
                    label_ok = label_ok and problems != []
            outcomes[label] = label_ok
        self.record(results, "ignored-registry-shape", outcomes["original"], outcomes["mutant"])

        # The cell emitter surfaces registry problems instead of mapping
        # on: dropping the propagation silently falls back to runner paths.
        propagate_mutant = self.mutate_source(ROOT / "scripts/ci/check-cell-results.py",
                                              "    test_files, registry_problems = ignored_test_files()\n"
                                              "    if registry_problems:\n"
                                              "        return \"; \".join(registry_problems)",
                                              "    test_files, registry_problems = ignored_test_files()")
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", propagate_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                (temp / "scripts/qualify-public-cli.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                (temp / "tests").mkdir()
                (temp / "tests/ignored-tests.json").write_text("null\n", encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                rows_path = temp / "results.jsonl"
                rows_path.write_text(json.dumps({"cell": "a", "pass": True, "detail": "d",
                                                 "qualification": "qualified"}) + "\n", encoding="utf-8")
                output = temp / "typed.json"
                run = subprocess.run([sys.executable, "-I", str(script), str(rows_path), "--require", "a",
                                      "--known-failing-results", str(output),
                                      "--known-failing-runner", "cell:scripts/qualify-public-cli.sh",
                                      "--known-failing-host", "github"],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode != 0 and not output.exists()
        self.record(results, "cell-emit-registry-propagate", outcomes["original"], outcomes["mutant"])

        # A null cell row must be a typed row-shape refusal: restoring the
        # None-sentinel check silently skips it and greens the run.
        row_null_mutant = self.mutate_source(ROOT / "scripts/ci/check-cell-results.py",
                                             "if row is checker.PARSE_FAILED:",
                                             "if row is None:")
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", row_null_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                (temp / "scripts/qualify-public-cli.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                rows_path = temp / "results.jsonl"
                rows_path.write_text(json.dumps({"cell": "good", "pass": True, "detail": "d",
                                                 "qualification": "qualified"}) + "\nnull\n", encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(script), str(rows_path), "--require", "good"],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode != 0
        self.record(results, "cell-row-null", outcomes["original"], outcomes["mutant"])

        # Privileged sidecars must drive the failed-row signature and remain
        # strictly typed.
        privileged_source = (ROOT / "scripts/ci/privileged-lib-results.py").read_text(encoding="utf-8")
        privileged_mutants = {
            "privileged-sidecar-ignored": self.mutate_source(
                ROOT / "scripts/ci/privileged-lib-results.py", "if len(parts) == 3:", "if False:"),
            "privileged-invalid-sidecar-accepted": self.mutate_source(
                ROOT / "scripts/ci/privileged-lib-results.py", "    if problems:\n", "    if False:\n"),
        }

        def privileged_behavior(source, sidecar_text):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "tests").mkdir()
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                shutil.copy2(ROOT / "tests/ignored-tests.json", temp / "tests/ignored-tests.json")
                script = temp / "scripts/ci/privileged-lib-results.py"
                script.write_text(source, encoding="utf-8")
                name = "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64"
                selection = temp / "selection.txt"; verdicts = temp / "verdicts.tsv"
                sidecar = temp / "sidecar.json"; output = temp / "out.json"
                selection.write_text(name + "\n", encoding="utf-8")
                sidecar.write_text(sidecar_text, encoding="utf-8")
                verdicts.write_text(name + "\tFAIL\t" + str(sidecar) + "\n", encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(script), str(selection), str(verdicts), str(output), "github"],
                                     capture_output=True, text=True)
                return run, (json.loads(output.read_text()) if output.exists() else None)

        valid_sidecar = '{"cell":"X","branch":"exactly_one_module"}\n'
        original_run, original_doc = privileged_behavior(privileged_source, valid_sidecar)
        mutant_run, mutant_doc = privileged_behavior(privileged_mutants["privileged-sidecar-ignored"], valid_sidecar)
        original_ok = (original_run.returncode == 0 and original_doc["results"][0]["signature"] ==
                       {"cell": "X", "branch": "exactly_one_module"})
        mutant_ok = (mutant_run.returncode == 0 and mutant_doc["results"][0]["signature"] ==
                     {"cell": "X", "branch": "exactly_one_module"})
        self.record(results, "privileged-sidecar-ignored", original_ok, mutant_ok)

        invalid_sidecar = '{"branch":"raw prose with spaces"}\n'
        original_run, _doc = privileged_behavior(privileged_source, invalid_sidecar)
        mutant_run, mutant_doc = privileged_behavior(privileged_mutants["privileged-invalid-sidecar-accepted"], invalid_sidecar)
        original_ok = original_run.returncode != 0
        mutant_ok = mutant_run.returncode != 0 or mutant_doc is None
        self.record(results, "privileged-invalid-sidecar-accepted", original_ok, mutant_ok)

        # Privileged sidecars are admitted strictly: contradictory duplicate
        # branches must fail instead of collapsing to one.
        dup_sidecar = '{"cell":"X","branch":"x","branch":"y"}\n'
        sidecar_mutant = self.mutate_source(
            ROOT / "scripts/ci/privileged-lib-results.py",
            "value, _load_problems = checker.strict_json(text, str(path))",
            "value = json.loads(text)")
        original_run, _doc = privileged_behavior(privileged_source, dup_sidecar)
        mutant_run, _doc = privileged_behavior(sidecar_mutant, dup_sidecar)
        self.record(results, "privileged-sidecar-dup-keys",
                    original_run.returncode != 0, mutant_run.returncode != 0)

        # The privileged registry read is strict: a duplicate-key registry
        # fails instead of collapsing to one mapping.
        propagate_mutant = self.mutate_source(
            ROOT / "scripts/ci/privileged-lib-results.py",
            "    if registry_problems:\n"
            "        print(f\"privileged-lib-results: cannot read ignored-test registry: {'; '.join(registry_problems)}\", file=sys.stderr)\n"
            "        return 1",
            "    if False:\n"
            "        print(f\"privileged-lib-results: cannot read ignored-test registry: {'; '.join(registry_problems)}\", file=sys.stderr)\n"
            "        return 1")
        outcomes = {}
        for label, source in (("original", privileged_source), ("mutant", propagate_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "tests").mkdir()
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-ignored-tests.py", temp / "scripts/check-ignored-tests.py")
                (temp / "tests/ignored-tests.json").write_text("null\n", encoding="utf-8")
                os.symlink(ROOT / "src", temp / "src")
                script = temp / "scripts/ci/privileged-lib-results.py"
                script.write_text(source, encoding="utf-8")
                name = "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64"
                selection = temp / "selection.txt"; verdicts = temp / "verdicts.tsv"; output = temp / "out.json"
                selection.write_text(name + "\n", encoding="utf-8")
                verdicts.write_text(name + "\tPASS\n", encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(script), str(selection), str(verdicts), str(output), "github"],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode != 0
        self.record(results, "privileged-registry-propagate", outcomes["original"], outcomes["mutant"])

        # The shared loader lets missing files raise so each caller applies
        # its own missing-file policy visibly; swallowing the raise back
        # into an empty mapping hides absence from the loud consumer.
        missing_mutant = self.mutate_source(
            ROOT / "scripts/check-known-failing.py",
            "    except FileNotFoundError:\n        raise",
            "    except FileNotFoundError:\n        return {}, []")
        outcomes = {}
        for label, source in (("original", helper_source), ("mutant", missing_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "check-known-failing.py"
                script.write_text(source, encoding="utf-8")
                module = load_script(script, f"registry_missing_{label}")
                try:
                    module.load_ignored_registry(temp / "absent.json")
                    outcomes[label] = False
                except FileNotFoundError:
                    outcomes[label] = True
        self.record(results, "ignored-registry-missing", outcomes["original"], outcomes["mutant"])

        # Unreadable registries are typed problems, not silent empty maps.
        unreadable_mutant = self.mutate_source(
            ROOT / "scripts/check-known-failing.py",
            "    except (OSError, UnicodeDecodeError) as exc:\n"
            "        return {}, [f\"{path}: cannot read ignored-test registry: {exc}\"]",
            "    except OSError:\n"
            "        return {}, []")
        outcomes = {}
        for label, source in (("original", helper_source), ("mutant", unreadable_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "check-known-failing.py"
                script.write_text(source, encoding="utf-8")
                blocked = temp / "ignored-tests.json"
                blocked.mkdir()
                module = load_script(script, f"registry_unreadable_{label}")
                _files, problems = module.load_ignored_registry(blocked)
                outcomes[label] = problems != []
        self.record(results, "ignored-registry-unreadable", outcomes["original"], outcomes["mutant"])

        # Undecodable registries are typed problems, never tracebacks.
        undecodable_mutant = self.mutate_source(
            ROOT / "scripts/check-known-failing.py",
            "    except (OSError, UnicodeDecodeError) as exc:\n"
            "        return {}, [f\"{path}: cannot read ignored-test registry: {exc}\"]",
            "    except OSError as exc:\n"
            "        return {}, [f\"{path}: cannot read ignored-test registry: {exc}\"]")
        outcomes = {}
        for label, source in (("original", helper_source), ("mutant", undecodable_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "check-known-failing.py"
                script.write_text(source, encoding="utf-8")
                bad = temp / "ignored-tests.json"
                bad.write_bytes(b'{"sites": [\xff]}\n')
                module = load_script(script, f"registry_undecodable_{label}")
                try:
                    _files, problems = module.load_ignored_registry(bad)
                except UnicodeDecodeError:
                    outcomes[label] = False
                else:
                    outcomes[label] = problems != []
        self.record(results, "ignored-registry-undecodable", outcomes["original"], outcomes["mutant"])

        # The cell fallback on a missing registry is deliberate and pinned:
        # re-raising instead breaks registry-less runner-path operation.
        fallback_mutant = self.mutate_source(
            ROOT / "scripts/ci/check-cell-results.py",
            "    except FileNotFoundError:\n"
            "        # Registry-less trees keep the runner-path fallback; every other\n"
            "        # read failure is a typed problem the caller must surface.\n"
            "        return {}, []",
            "    except FileNotFoundError:\n"
            "        raise")
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", fallback_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                module = load_script(script, f"cell_fallback_{label}")
                try:
                    outcomes[label] = module.ignored_test_files() == ({}, [])
                except FileNotFoundError:
                    outcomes[label] = False
        self.record(results, "cell-missing-fallback", outcomes["original"], outcomes["mutant"])

        # The privileged converter fails loud on a missing registry: falling
        # back silently would let the token index green the run instead.
        priv_missing_mutant = self.mutate_source(
            ROOT / "scripts/ci/privileged-lib-results.py",
            "    try:\n"
            "        files, registry_problems = checker_module().load_ignored_registry(ROOT / \"tests/ignored-tests.json\")\n"
            "    except FileNotFoundError as error:\n"
            "        print(f\"privileged-lib-results: cannot read ignored-test registry: {error}\", file=sys.stderr)\n"
            "        return 1",
            "    try:\n"
            "        files, registry_problems = checker_module().load_ignored_registry(ROOT / \"tests/ignored-tests.json\")\n"
            "    except FileNotFoundError:\n"
            "        files, registry_problems = {}, []")
        outcomes = {}
        for label, source in (("original", privileged_source), ("mutant", priv_missing_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-ignored-tests.py", temp / "scripts/check-ignored-tests.py")
                os.symlink(ROOT / "src", temp / "src")
                script = temp / "scripts/ci/privileged-lib-results.py"
                script.write_text(source, encoding="utf-8")
                name = "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64"
                selection = temp / "selection.txt"; verdicts = temp / "verdicts.tsv"; output = temp / "out.json"
                selection.write_text(name + "\n", encoding="utf-8")
                verdicts.write_text(name + "\tPASS\n", encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(script), str(selection), str(verdicts), str(output), "github"],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode != 0
        self.record(results, "privileged-missing-loud", outcomes["original"], outcomes["mutant"])

        # An undecodable fragment is fragment_invalid, never a traceback.
        fragment_decode_mutant = self.mutate_source(
            ROOT / "scripts/run-python-suites.py",
            "        except (OSError, UnicodeDecodeError):\n"
            "            fragment = None",
            "        except OSError:\n"
            "            fragment = None")
        outcomes = {}
        for label, source in (("original", runner_source), ("mutant", fragment_decode_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "run-python-suites.py"
                script.write_text(source, encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-known-failing.py", temp / "check-known-failing.py")
                module = load_script(script, f"runner_fragment_decode_{label}")
                fragment = temp / "fragment.json"
                fragment.write_bytes(b'{"process_exit": \xff}\n')
                output = temp / "merged.json"
                try:
                    problems = module.merge_typed_fragments(
                        [(fragment, "test_sample.py", [], 1)], output, "github")
                    rows = {row_["test"]: row_ for row_ in json.loads(output.read_text())["results"]}
                    outcomes[label] = bool(problems) and rows["<suite-process>"]["state"] == "failed"
                except UnicodeDecodeError:
                    outcomes[label] = False
        self.record(results, "merge-fragment-decode", outcomes["original"], outcomes["mutant"])

        # An undecodable toolchain file fails discovery closed, never a traceback.
        toolchain_mutant = self.mutate_source(
            ROOT / "scripts/check-known-failing.py",
            "        toolchain = toolchain_file.read_text(encoding=\"utf-8\").strip()\n"
            "    except (OSError, UnicodeDecodeError):\n"
            "        return False",
            "        toolchain = toolchain_file.read_text(encoding=\"utf-8\").strip()\n"
            "    except OSError:\n"
            "        return False")
        outcomes = {}
        for label, source in (("original", helper_source), ("mutant", toolchain_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "check-known-failing.py"
                script.write_text(source, encoding="utf-8")
                (temp / ".release-rust-version").write_bytes(b"1.99.1\xff\n")
                module = load_script(script, f"checker_toolchain_{label}")
                try:
                    outcomes[label] = module.cargo_list_probe(temp, {"path": "tests/x.rs"}) is False
                except UnicodeDecodeError:
                    outcomes[label] = False
        self.record(results, "toolchain-decode", outcomes["original"], outcomes["mutant"])

        # An undecodable suite registry fails registration closed, never a traceback.
        registry_exec_mutant = self.mutate_source(
            ROOT / "scripts/check-known-failing.py",
            "    except (OSError, SyntaxError, UnicodeDecodeError):",
            "    except (OSError, SyntaxError):")
        outcomes = {}
        for label, source in (("original", helper_source), ("mutant", registry_exec_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "check-known-failing.py"
                script.write_text(source, encoding="utf-8")
                (temp / "scripts").mkdir()
                (temp / "scripts/run-python-suites.py").write_bytes(b"RUN = [\xff\n")
                module = load_script(script, f"checker_registry_exec_{label}")
                probe_row = {"path": "tests/python/test_sample.py", "runner": "python-suite"}
                try:
                    outcomes[label] = module.python_suite_registered(temp, probe_row) is False
                except UnicodeDecodeError:
                    outcomes[label] = False
        self.record(results, "registry-exec-decode", outcomes["original"], outcomes["mutant"])

        # An undecodable drift driver reads as missing, never a traceback.
        driver_mutant = self.mutate_source(
            ROOT / "scripts/run-python-suites.py",
            "        except (FileNotFoundError, OSError, UnicodeDecodeError):",
            "        except FileNotFoundError:")
        outcomes = {}
        for label, source in (("original", runner_source), ("mutant", driver_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "run-python-suites.py"
                script.write_text(source, encoding="utf-8")
                (temp / "driver").mkdir()
                (temp / "driver/bad.py").write_bytes(b"x = \xff\n")
                module = load_script(script, f"runner_driver_{label}")
                try:
                    outcomes[label] = module.read_driver(temp)("driver/bad.py") is None
                except UnicodeDecodeError:
                    outcomes[label] = False
        self.record(results, "driver-decode", outcomes["original"], outcomes["mutant"])

        # Promoted curated tests outside the ignored registry are mapped by
        # the Rust-source fallback; disabling it recreates the shard failure.
        fallback_mutant = privileged_source.replace("if len(candidates) == 1:", "if False:", 1)
        outcomes = {}
        for label, source in (("original", privileged_source), ("mutant", fallback_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "tests").mkdir()
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                shutil.copy2(ROOT / "scripts/check-ignored-tests.py", temp / "scripts/check-ignored-tests.py")
                shutil.copy2(ROOT / "tests/ignored-tests.json", temp / "tests/ignored-tests.json")
                os.symlink(ROOT / "src", temp / "src")
                script = temp / "scripts/ci/privileged-lib-results.py"
                script.write_text(source, encoding="utf-8")
                name = "attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64"
                selection = temp / "selection.txt"; verdicts = temp / "verdicts.tsv"; output = temp / "out.json"
                selection.write_text(name + "\n", encoding="utf-8")
                verdicts.write_text(name + "\tPASS\n", encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(script), str(selection), str(verdicts), str(output), "github"],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode == 0
        self.record(results, "privileged-promoted-source-fallback", outcomes["original"], outcomes["mutant"])

        # Rust terse-list parsing and the pinned cargo wrapper are executable
        # discovery controls, not incidental implementation details.
        checker_source = CHECKER.read_text(encoding="utf-8")
        rust_mutants = {
            "rust-terse-parser": checker_source.replace('line[: -len(": test")].strip()', 'line[:-5].strip()', 1),
            "rust-cargo-wrapper": checker_source.replace('str(cargo_wrapper), f"+{toolchain}"', '"cargo", f"+{toolchain}"', 1),
        }

        def rust_probe_ok(source):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                script = temp / "check-known-failing.py"
                script.write_text(source, encoding="utf-8")
                try:
                    module = load_script(script, "checker_mutant")
                except Exception:
                    return False
                root = temp / "root"; (root / "scripts").mkdir(parents=True)
                (root / ".release-rust-version").write_text("1.99.1\n", encoding="utf-8")
                wrapper = root / "scripts/cargo.sh"
                wrapper.write_text("#!/bin/sh\n", encoding="utf-8"); wrapper.chmod(0o755)
                artifact = {"reason": "compiler-artifact", "executable": "/tmp/libtest", "target": {"test": True}}
                def fake_run(command, **kwargs):
                    del kwargs
                    if command[0].endswith("cargo.sh"):
                        return subprocess.CompletedProcess(command, 0, json.dumps(artifact) + "\n", "")
                    if command[:3] == ["/tmp/libtest", "--list", "--format"]:
                        return subprocess.CompletedProcess(command, 0, "inventory::privileged_tests::example_cell: test\n", "")
                    raise AssertionError(command)
                rust_row = row(path="tests/inventory_command.rs", test="inventory::privileged_tests::example_cell",
                               runner="privileged-lib")
                try:
                    with mock.patch.object(module.subprocess, "run", side_effect=fake_run):
                        return module.cargo_list_probe(root, rust_row)
                except Exception:
                    return False

        for name, mutant in rust_mutants.items():
            self.record(results, name, rust_probe_ok(checker_source), rust_probe_ok(mutant))

        # Legacy declaration exemptions are runner-scoped statically as well as
        # at result-evaluation time.
        legacy_mutant = checker_source.replace(
            "legacy_always = set(LEGACY_CELL_EXPECTED) if runner == PUBLIC_CLI_RUNNER else set()",
            "legacy_always = set(LEGACY_CELL_EXPECTED)", 1)
        outcomes = {}
        for label, source in (("original", checker_source), ("mutant", legacy_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                checker = temp / "check-known-failing.py"
                checker.write_text(source, encoding="utf-8")
                f = fixture(self)
                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" \\\n"
                    "            --expected-failure profile-cgroup \\\n"
                    "            --known-failing-results \"$out/kf.json\" \\\n"
                    "            --known-failing-runner cell:scripts/ci/run-run-tree.sh \\\n"
                    "            --known-failing-host github\n", encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(checker), "--root", str(f.root)],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode != 0
        self.record(results, "legacy-declaration-scope", outcomes["original"], outcomes["mutant"])

        # --require is presence evidence and may overlap an outcome class;
        # only outcome classes themselves are mutually exclusive.
        cell_order_mutant = cell_source.replace(
            "        for cell in selection_order:\n            if cell in selected_seen:\n                continue\n",
            "        for cell in selection_order:\n            if cell in selected_seen:\n                problems.append(f\"typed selection overlap: {cell}\")\n                continue\n",
            1)
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", cell_order_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                (temp / "scripts/qualify-public-cli.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                (temp / "tests").mkdir()
                (temp / "tests/known-failing.json").write_text('{"schema":"p11scope/known-failing/v1","rows":[]}\n', encoding="utf-8")
                (temp / ".github/workflows").mkdir(parents=True)
                (temp / ".github/workflows/main.yml").write_text("jobs: {}\n", encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                rows_path = temp / "results.jsonl"
                rows_path.write_text(json.dumps({"cell": "smoke", "pass": False, "detail": "smoke",
                                                 "qualification": "nonqualifying"}) + "\n", encoding="utf-8")
                output = temp / "typed.json"
                run = subprocess.run([sys.executable, "-I", str(script), str(rows_path),
                                      "--require", "smoke", "--allow-nonqualifying", "smoke",
                                      "--known-failing-results", str(output),
                                      "--known-failing-runner", "cell:scripts/qualify-public-cli.sh",
                                      "--known-failing-host", "github"], capture_output=True, text=True)
                outcomes[label] = run.returncode == 0
        self.record(results, "cell-require-orthogonal-selection", outcomes["original"], outcomes["mutant"])

        # Repeated declarations for one runner/results stream compare every
        # selection category, not only the two legacy outcome lists.
        repeated_mutant = checker_source.replace(
            'for key in ("expected", "intermittent", "required", "nonqualifying", "require_file")):',
            'for key in ("expected", "intermittent")):', 1)

        def repeated_declaration_refused(source):
            with tempfile.TemporaryDirectory() as temporary:
                checker = Path(temporary) / "check-known-failing.py"
                checker.write_text(source, encoding="utf-8")
                f = fixture(self)
                f.shell_cell(declarations=False)

                def invocation(option):
                    return (
                        "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
                        + option
                        + " --known-failing-results \"$out/kf.json\""
                        + " --known-failing-runner cell:scripts/ci/cells.sh"
                        + " --known-failing-host github\n"
                    )

                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    + invocation("--require alpha") + invocation("--require beta"), encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(checker), "--root", str(f.root)],
                                     capture_output=True, text=True)
                return run.returncode != 0

        self.record(results, "workflow-repeated-selection-categories",
                    repeated_declaration_refused(checker_source), repeated_declaration_refused(repeated_mutant))

        # The workflow parser preserves the provider matrix shell array
        # expansion point; dropping it loses the suite=no nonqualifying row.
        array_mutant = checker_source.replace(
            '            option_sequence.append(("array-expansion", array_match.group(1)))',
            '            pass', 1)
        outcomes = {}
        for label, source in (("original", checker_source), ("mutant", array_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                script = Path(temporary) / "check-known-failing.py"
                script.write_text(source, encoding="utf-8")
                module = load_script(script, f"workflow_parser_{label}")
                invocations, scan_problems = module.workflow_invocations(ROOT)
                provider = [item for item in invocations if item["job"] == "pkcs11-check-providers"]
                outcomes[label] = (not scan_problems and len(provider) == 1 and
                                   ("array-expansion", "allow_extra") in provider[0]["option_sequence"])
        self.record(results, "workflow-array-expansion-loss", outcomes["original"], outcomes["mutant"])

        # Dynamic require-file inventory is consumed into the typed
        # selection; dropping it recreates the vng paranoid-bonus failure.
        require_file_mutant = cell_source.replace(
            "                required.append(line)\n                selection_order.append(line)\n",
            "                pass\n", 1)
        outcomes = {}
        for label, source in (("original", cell_source), ("mutant", require_file_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "scripts/ci").mkdir(parents=True)
                (temp / "scripts/check-known-failing.py").write_text(CHECKER.read_text(encoding="utf-8"), encoding="utf-8")
                (temp / "scripts/qualify-public-cli.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                (temp / "tests").mkdir()
                (temp / "tests/known-failing.json").write_text('{"schema":"p11scope/known-failing/v1","rows":[]}\n', encoding="utf-8")
                (temp / ".github/workflows").mkdir(parents=True)
                (temp / ".github/workflows/main.yml").write_text("jobs: {}\n", encoding="utf-8")
                script = temp / "scripts/ci/check-cell-results.py"
                script.write_text(source, encoding="utf-8")
                rows_path = temp / "results.jsonl"
                rows_path.write_text(json.dumps({"cell": "bonus", "pass": True, "detail": "ok",
                                                 "qualification": "qualified"}) + "\n", encoding="utf-8")
                require_file = temp / "dynamic.txt"
                require_file.write_text("bonus\n", encoding="utf-8")
                output = temp / "typed.json"
                run = subprocess.run([sys.executable, "-I", str(script), str(rows_path),
                                      "--require-file", str(require_file),
                                      "--known-failing-results", str(output),
                                      "--known-failing-runner", "cell:scripts/qualify-public-cli.sh",
                                      "--known-failing-host", "github"], capture_output=True, text=True)
                outcomes[label] = run.returncode == 0
        self.record(results, "cell-require-file-consumption", outcomes["original"], outcomes["mutant"])

        # Both public-cli minimal checker sites must consume the dynamic
        # inventory file; dropping either one is caught by the workflow contract.
        workflow_text = (ROOT / ".github/workflows/privileged-tests.yml").read_text(encoding="utf-8")
        flag = '--require-file "$out/minimal-cells/dynamic-selection.txt"'
        workflow_mutant = workflow_text.replace(flag, "", 1)
        self.record(results, "workflow-dynamic-require-file",
                    workflow_text.count(flag) == 2, workflow_mutant.count(flag) == 2)

        artifact_flag = "cli-out/minimal-cells/known-failing-results.json"
        artifact_mutant = workflow_text.replace(artifact_flag, "", 1)
        self.record(results, "workflow-minimal-typed-artifact",
                    artifact_flag in workflow_text and "cli-out/minimal-cells/dynamic-selection.txt" in workflow_text,
                    artifact_flag in artifact_mutant and "cli-out/minimal-cells/dynamic-selection.txt" in artifact_mutant)

        # A setUpClass skip marks its scope skipped instead of leaving
        # not_run gaps; dropping the class branch recreates the red job.
        class_skip_mutant = self.mutate_source(ROOT / "scripts/typed-python-suite.py",
            'elif qualified in skipped_classes:', 'elif False:')
        class_skip_body = ("import unittest\nclass Skipped(unittest.TestCase):\n"
                           " @classmethod\n def setUpClass(cls): raise unittest.SkipTest('x')\n"
                           " def test_a(self): pass\n"
                           "class Lively(unittest.TestCase):\n def test_b(self): pass\nunittest.main()\n")
        outcomes = {}
        for label, source in (("original", typed_source), ("mutant", class_skip_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                data, _run = self.python_suite_fragment(source, class_skip_body, Path(temporary))
                outcomes[label] = bool(data and data.get("complete"))
        self.record(results, "python-class-skip", outcomes["original"], outcomes["mutant"])

        # A setUpModule skip marks its module's selected tests
        # module-skipped; dropping the module branch leaves the run
        # incomplete.
        module_skip_mutant = self.mutate_source(ROOT / "scripts/typed-python-suite.py",
                                                "if module in skipped_modules:", "if False:")
        module_skip_body = ("import unittest\ndef setUpModule(): raise unittest.SkipTest('x')\n"
                            "class Probe(unittest.TestCase):\n def test_a(self): pass\nunittest.main()\n")
        outcomes = {}
        for label, source in (("original", typed_source), ("mutant", module_skip_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                data, _run = self.python_suite_fragment(source, module_skip_body, Path(temporary))
                outcomes[label] = bool(data and data.get("complete"))
        self.record(results, "python-module-skip", outcomes["original"], outcomes["mutant"])

        # Class-scope matching compares the qualified module.Class: a
        # helper-module skip must not mark a same-named __main__ class.
        # Comparing bare class names marks both and hides the not_run gap.
        qualified_mutant = self.mutate_source(ROOT / "scripts/typed-python-suite.py",
            'elif qualified in skipped_classes:',
            'elif qualified.rsplit(".", 1)[-1] in {name.rsplit(".", 1)[-1] for name in skipped_classes}:')
        helper_body = ("import unittest\nclass Broken(unittest.TestCase):\n"
                       " @classmethod\n def setUpClass(cls): raise unittest.SkipTest('x')\n"
                       " def test_h(self): pass\n")
        qualified_body = ("import unittest\nimport helper_mod\nclass Broken(unittest.TestCase):\n"
                          " @classmethod\n def setUpClass(cls): raise RuntimeError('x')\n"
                          " def test_a(self): pass\n"
                          "def load_tests(loader, tests, ignore):\n"
                          " suite = unittest.TestSuite()\n"
                          " suite.addTests(loader.loadTestsFromTestCase(helper_mod.Broken))\n"
                          " suite.addTests(loader.loadTestsFromTestCase(Broken))\n"
                          " return suite\nunittest.main()\n")
        outcomes = {}
        for label, source in (("original", typed_source), ("mutant", qualified_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                (temp / "helper_mod.py").write_text(helper_body, encoding="utf-8")
                data, _run = self.python_suite_fragment(source, qualified_body, temp)
                outcomes[label] = bool(data) and data.get("complete") is False
        self.record(results, "python-class-qualified", outcomes["original"], outcomes["mutant"])

        # Scope marking must never swallow an error: a setUpClass error
        # stays not_run and incomplete, never scope-skipped.
        error_swallow_mutant = self.mutate_source(ROOT / "scripts/typed-python-suite.py",
                                                  'if state == "skipped":', 'if True:')
        error_body = ("import unittest\nclass Probe(unittest.TestCase):\n"
                      " @classmethod\n def setUpClass(cls): raise RuntimeError('x')\n"
                      " def test_a(self): pass\nunittest.main()\n")
        outcomes = {}
        for label, source in (("original", typed_source), ("mutant", error_swallow_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                data, _run = self.python_suite_fragment(source, error_body, Path(temporary))
                outcomes[label] = bool(data) and data.get("complete") is False
        self.record(results, "python-scope-error-not-swallowed", outcomes["original"], outcomes["mutant"])

        # Repeated declarations for one runner/results stream also
        # compare the dynamic require-file inventory, not only the four
        # inline selection categories.
        require_file_repeated_mutant = checker_source.replace(
            'for key in ("expected", "intermittent", "required", "nonqualifying", "require_file")):',
            'for key in ("expected", "intermittent", "required", "nonqualifying")):', 1)

        def require_file_declaration_refused(source):
            with tempfile.TemporaryDirectory() as temporary:
                checker = Path(temporary) / "check-known-failing.py"
                checker.write_text(source, encoding="utf-8")
                f = fixture(self)
                f.shell_cell(declarations=False)

                def invocation(option):
                    return (
                        "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
                        + option
                        + " --known-failing-results \"$out/kf.json\""
                        + " --known-failing-runner cell:scripts/ci/cells.sh"
                        + " --known-failing-host github\n"
                    )

                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    + invocation("--require-file /tmp/a.txt") + invocation("--require-file /tmp/b.txt"),
                    encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(checker), "--root", str(f.root)],
                                     capture_output=True, text=True)
                return run.returncode != 0

        self.record(results, "workflow-repeated-require-file",
                    require_file_declaration_refused(checker_source),
                    require_file_declaration_refused(require_file_repeated_mutant))

        # A dynamic require-file inventory alone is a nonempty typed
        # selection; ignoring it recreates the false empty-selection
        # refusal for file-only checker invocations.
        require_file_empty_mutant = checker_source.replace('or invocation["require_file"]', 'or []', 1)
        outcomes = {}
        for label, source in (("original", checker_source), ("mutant", require_file_empty_mutant)):
            with tempfile.TemporaryDirectory() as temporary:
                checker = Path(temporary) / "check-known-failing.py"
                checker.write_text(source, encoding="utf-8")
                f = fixture(self)
                f.shell_cell(declarations=False)
                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
                    "--require-file /tmp/dynamic-selection.txt"
                    " --known-failing-results \"$out/kf.json\""
                    " --known-failing-runner cell:scripts/ci/cells.sh"
                    " --known-failing-host github\n",
                    encoding="utf-8")
                run = subprocess.run([sys.executable, "-I", str(checker), "--root", str(f.root)],
                                     capture_output=True, text=True)
                outcomes[label] = run.returncode == 0
        self.record(results, "workflow-require-file-empty-selection", outcomes["original"], outcomes["mutant"])

        total = 52
        self.assertEqual(results["failures"], [],
                         f"surviving producer mutants: {results['failures']}; killed {results['killed']}/{total}")
        print(f"known-failing producer mutation sweep: {results['killed']}/{total} killed")


class MutationSweepTests(unittest.TestCase):
    def test_source_mutation_sweep(self):
        source = CHECKER.read_text(encoding="utf-8")
        mutations = {
            "complete-record": ('if data.get("complete") is not True:', 'if False:'),
            "empty-selection": ('if not isinstance(raw_selection, list) or not raw_selection:', 'if not isinstance(raw_selection, list):'),
            "missing-result": ('if missing_results:\n        problems.append', 'if False:\n        problems.append'),
            "outside-selection": ('if missing_selection:\n        problems.append', 'if False:\n        problems.append'),
            "exact-types": ('if type(left) is not type(right):', 'if False:'),
            "stale-row": ('if result["state"] == "passed" and row["mode"] == "always":', 'if False:'),
            "unlisted-failure": ('if key in listed_keys or result["state"] == "passed" or result["state"] in NEUTRAL_STATES:', 'if True:'),
            "typed-string": ('return isinstance(value, str) and TYPED_STRING_RE.fullmatch(value) is not None', 'return isinstance(value, str)'),
            "required-provenance": ('if not isinstance(raw["reason"], str) or not raw["reason"].strip() or any(\n            ord(character) < 32 or ord(character) == 127 for character in raw["reason"]):', 'if False:'),
            "result-pass-null": ('if raw["signature"] is not None:', 'if False:'),
            "workflow-runner": ('if invocation["runner"] is None or not valid_runner(invocation["runner"]):', 'if False:'),
            "duplicate-result": ('            if key in results:\n                problems.append', '            if False:\n                problems.append'),
            "signature-branch-required": ('if isinstance(raw["signature"], dict) and "branch" not in raw["signature"]:', 'if False:'),
            "host-limited-refused": ("if limited:\n            problems.append", "if False:\n            problems.append"),
            "release-needs-registry": ('if (root / "docs/releases/v0.7.2.md").is_file() and not registry_present:', 'if False:'),
            "cell-equality-runner": ('if isinstance(raw["runner"], str) and raw["runner"].startswith("cell:") and raw["cell"] != raw["test"]:', 'if False:'),
            "cell-equality-signature": ('if isinstance(raw["signature"], dict) and "cell" in raw["signature"] and raw["signature"]["cell"] != raw["cell"]:', 'if False:'),
            "privileged-lib-refused": ('if raw["runner"] == "privileged-lib":', 'if False:'),
            "runner-vocabulary": ('if not valid_runner(raw["runner"]):', 'if False:'),
            "results-discovery-skip": ('discover_executables=args.results is None', 'discover_executables=True'),
            "generic-branch-refused": ('if isinstance(raw.get("signature"), dict) and type(raw["signature"].get("branch")) is str \\\n            and raw["signature"].get("branch") in GENERIC_SIGNATURE_BRANCHES:', 'if False:'),
            "target-release-expiry": ('if (root / "docs/releases" / f"v{row[\'target\']}.md").is_file():', 'if False:'),
            "bogus-host-refused": ('if not isinstance(host, str) or host not in HOSTS:', 'if False:'),
            "cell-judge-runner": ('if invocation.get("runner") != row["runner"]:', 'if False:'),
            "unparsable-checker-mention": ('if ("check-cell-results.py" in executable_script\n                            or "run-cell-script.sh" in executable_script):', 'if False:'),
            "list-null-refused": ('data, problems = strict_json(text, str(path))\n    if data is PARSE_FAILED:\n        return [], problems',
                                  'data, problems = strict_json(text, str(path))\n    if data is None:\n        return [], problems'),
            "registry-null-refused": ('data, problems = strict_json(section[start:end].strip(), "known-issue registry")\n    if data is PARSE_FAILED:',
                                      'data, problems = strict_json(section[start:end].strip(), "known-issue registry")\n    if data is None:'),
            "ignored-null-refused": ('data, problems = strict_json(text, str(path))\n    if data is PARSE_FAILED:\n        return problems',
                                     'data, problems = strict_json(text, str(path))\n    if data is None:\n        return problems'),
            "signature-branch-string": ('if isinstance(raw.get("signature"), dict) and "branch" in raw["signature"] \\\n            and type(raw["signature"].get("branch")) is not str:', 'if False:'),
        }
        green_to_red = {"results-discovery-skip"}

        def pass_item(name="Sample.test_control"):
            return {"path": "tests/python/test_sample.py", "test": name,
                    "state": "passed", "signature": None}

        def malicious_case(name, f):
            """Build input that violates exactly the invariant named by the mutant."""
            if name == "complete-record":
                doc = result_doc([pass_item()])
                doc["complete"] = False
                return doc
            if name == "empty-selection":
                return result_doc([], selection=[])
            if name == "missing-result":
                doc = result_doc([pass_item()])
                doc["results"] = []
                return doc
            if name == "outside-selection":
                doc = result_doc([pass_item()])
                doc["results"].append({**pass_item("Other.test"), "invocation": []})
                return doc
            if name == "exact-types":
                f.registry()
                f.python_suite()
                f.rows([row(signature={"cell": "X", "branch": "B", "count": 1})])
                return result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                                    "signature": {"cell": "X", "branch": "B", "count": True}}])
            if name == "stale-row":
                f.registry()
                f.python_suite()
                f.rows([row()])
                return result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                                    "state": "passed", "signature": None}])
            if name == "unlisted-failure":
                return result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_control"}])
            if name in ("typed-string", "required-provenance"):
                f.registry()
                f.python_suite()
                bad = row(signature={"cell": "X", "branch": "raw log prose"}) if name == "typed-string" else row()
                if name == "required-provenance":
                    bad["reason"] = "bad\nlog text"
                f.rows([bad])
                return None
            if name == "signature-branch-required":
                f.registry()
                f.python_suite()
                generic = row(signature={"cell": "X", "oracle": "unittest"})
                f.rows([generic])
                return None
            if name == "result-pass-null":
                item = pass_item()
                item["signature"] = {"branch": "B"}
                return result_doc([item])
            if name == "workflow-runner":
                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" --require x \\\n"
                    "            --known-failing-results \"$out/kf.json\" \\\n"
                    "            --known-failing-host github\n", encoding="utf-8")
                return None
            if name == "duplicate-result":
                doc = result_doc([pass_item()])
                doc["results"].append({**pass_item(), "invocation": []})
                return doc
            if name == "host-limited-refused":
                f.registry()
                f.python_suite()
                f.rows([row(hosts=["github", "fedora-sm1"])])
                return None
            if name == "release-needs-registry":
                f.release_doc()
                return None
            if name == "cell-equality-runner":
                f.registry()
                f.shell_cell()
                f.rows([row(path="scripts/ci/cells.sh", test="mt-exact",
                            runner="cell:scripts/ci/cells.sh")])
                return None
            if name == "cell-equality-signature":
                f.registry()
                f.python_suite()
                f.rows([row(signature={"cell": "OTHER", "branch": "B"})])
                return None
            if name == "privileged-lib-refused":
                f.registry()
                f.python_suite()
                (f.root / "scripts/run-privileged-lib-tests.sh").write_text(
                    "EXPECTED_FAILURE_TESTS=(\n"
                    "discovery::engine::tests::exit_loader_balanced_benign_transaction_needs_no_terminal_truncation\n"
                    "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64\n"
                    "inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64\n"
                    ")\n"
                    "KNOWN_FAILING_TYPED_TESTS=(\nSample.test_x\n)\n", encoding="utf-8")
                f.rows([row(runner="privileged-lib")])
                return None
            if name == "runner-vocabulary":
                f.registry()
                f.python_suite()
                f.rows([row(runner="bogus-runner")])
                return None
            if name == "results-discovery-skip":
                f.registry()
                f.python_suite()
                f.rows([row(test="Sample.test_missing")])
                return result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_missing"}])
            if name == "generic-branch-refused":
                f.registry()
                f.python_suite()
                f.rows([row(signature={"branch": "failed", "exception": "AssertionError",
                                        "oracle": "unittest"})])
                return None
            if name == "target-release-expiry":
                f.registry()
                f.python_suite()
                f.rows([row(target="0.7.3")])
                target_doc = f.root / "docs/releases/v0.7.3.md"
                target_doc.parent.mkdir(parents=True, exist_ok=True)
                target_doc.write_text("# p11scope v0.7.3\n", encoding="utf-8")
                return None
            if name == "bogus-host-refused":
                f.registry()
                f.shell_cell(declarations=False)
                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
                    "--require mt-exact"
                    " --known-failing-results \"$out/kf.json\""
                    " --known-failing-runner cell:scripts/ci/cells.sh"
                    " --known-failing-host bogus-host\n",
                    encoding="utf-8")
                f.rows([row(path="scripts/ci/cells.sh", test="mt-exact", cell="mt-exact",
                            runner="cell:scripts/ci/cells.sh",
                            signature={"cell": "mt-exact", "branch": "B"})])
                return None
            if name == "cell-judge-runner":
                f.registry()
                f.shell_cell(declarations=False)
                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl\" "
                    "--require mt-exact"
                    " --known-failing-results \"$out/kf.json\""
                    " --known-failing-runner cell:scripts/ci/cells.sh"
                    " --known-failing-host github\n",
                    encoding="utf-8")
                other = f.root / "scripts/ci/other.sh"
                other.write_text(
                    "#!/bin/sh\nif [ \"$1\" = --list-cells ]; then echo mt-exact; exit 0; fi\nexit 0\n",
                    encoding="utf-8")
                other.chmod(0o755)
                f.rows([row(path="scripts/ci/other.sh", test="mt-exact", cell="mt-exact",
                            runner="cell:scripts/ci/other.sh",
                            signature={"cell": "mt-exact", "branch": "B"})])
                return None
            if name == "unparsable-checker-mention":
                (f.root / ".github/workflows/main.yml").write_text(
                    "jobs:\n  test:\n    steps:\n      - run: |\n"
                    "          python3 -I scripts/ci/check-cell-results.py \"$out/results.jsonl --require x\n",
                    encoding="utf-8")
                return None
            if name == "list-null-refused":
                (f.root / "tests/known-failing.json").write_text("null\n", encoding="utf-8")
                return None
            if name == "registry-null-refused":
                (f.root / "docs/known-limitations.md").write_text(
                    "# Known limitations\n\n## Known limitations in 0.7.2\n\n"
                    "<!-- p11scope-known-issues-v1\nnull\n-->\n",
                    encoding="utf-8")
                return None
            if name == "ignored-null-refused":
                (f.root / "tests/ignored-tests.json").write_text("null\n", encoding="utf-8")
                return None
            if name == "signature-branch-string":
                f.registry()
                f.python_suite()
                f.rows([row(signature={"cell": "X", "branch": []})])
                return None
            raise AssertionError(name)

        killed = 0
        failures = []
        for name, (old, new) in mutations.items():
            self.assertIn(old, source, name)
            mutated = source.replace(old, new, 1)
            with tempfile.TemporaryDirectory() as temporary:
                mutant = Path(temporary) / "check-known-failing.py"
                mutant.write_text(mutated)
                f = fixture(self)
                doc = malicious_case(name, f)
                command = [sys.executable, "-I", str(mutant), "--root", str(f.root)]
                if doc is not None:
                    command += ["--results", str(f.results_file(doc))]
                result = subprocess.run(command, capture_output=True, text=True)
                # A killing input is red under the real checker and green only
                # under the mutant, except for green_to_red mutants where the
                # real behavior is green and the mutant turns it red (the
                # results-discovery skip). That typed before/after pair proves
                # this contract test kills the exact check mutation; a mutant
                # that stays at the reference color here is not evidence about
                # the invariant itself.
                reference = subprocess.run([sys.executable, "-I", str(CHECKER), "--root", str(f.root)] +
                                           (["--results", str(f.results_file(doc))] if doc is not None else []),
                                           capture_output=True, text=True)
                if name in green_to_red:
                    killed_here = reference.returncode == 0 and result.returncode != 0
                else:
                    killed_here = reference.returncode != 0 and result.returncode == 0
                if killed_here:
                    killed += 1
                else:
                    failures.append(f"{name}(ref={reference.returncode},mutant={result.returncode})")
        self.assertEqual(failures, [], f"surviving mutants: {failures}; killed {killed}/{len(mutations)}")
        print(f"known-failing mutation sweep: {killed}/{len(mutations)} killed")


if __name__ == "__main__":
    unittest.main()
