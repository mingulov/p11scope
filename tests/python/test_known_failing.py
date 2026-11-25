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
        return row(path="scripts/ci/cells.sh", test="mt-exact", runner=runner)

    def test_valid_cell_row_matches_per_runner_declaration(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        f.rows([self.cell_row()])
        result = f.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_runner_declaration_does_not_satisfy_row(self):
        f = fixture(self)
        f.registry()
        f.shell_cell()
        f.rows([self.cell_row(runner="cell:scripts/ci/other.sh")])
        (f.root / "scripts/ci/other.sh").write_text("#!/bin/sh\nexit 0\n")
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no per-runner declaration", result.stderr)

    def test_missing_row_declaration_fails(self):
        f = fixture(self)
        f.registry()
        f.shell_cell(declared="other-cell")
        f.rows([self.cell_row()])
        result = f.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no per-runner declaration", result.stderr)

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
        f = self.make_f()
        f.rows([row(hosts=["fedora"])])
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "state": "passed", "signature": None}], host="github")
        result = f.run_checker("--results", str(f.results_file(doc)))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_result_signature_is_typed_only(self):
        doc = result_doc([{"path": "tests/python/test_sample.py", "test": "Sample.test_x",
                           "signature": {"detail": "a raw log line"}}])
        self.assert_bad_results(doc, "free-text/log matching")


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
            'for key in ("expected", "intermittent", "required", "nonqualifying")):',
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

        total = 16
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
            "duplicate-result": ('if key in results:\n            problems.append', 'if False:\n            problems.append'),
            "signature-branch-required": ('if isinstance(raw["signature"], dict) and "branch" not in raw["signature"]:', 'if False:'),
        }

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
                # under the mutant. That typed before/after pair proves this
                # contract test kills the exact check mutation; a mutant that
                # stays red here is not evidence about the invariant itself.
                reference = subprocess.run([sys.executable, "-I", str(CHECKER), "--root", str(f.root)] +
                                           (["--results", str(f.results_file(doc))] if doc is not None else []),
                                           capture_output=True, text=True)
                if reference.returncode != 0 and result.returncode == 0:
                    killed += 1
                else:
                    failures.append(f"{name}(ref={reference.returncode},mutant={result.returncode})")
        self.assertEqual(failures, [], f"surviving mutants: {failures}; killed {killed}/{len(mutations)}")
        print(f"known-failing mutation sweep: {killed}/{len(mutations)} killed")


if __name__ == "__main__":
    unittest.main()
