#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract tests for the typed known-failing ledger gate."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
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
        f.rows([row(signature={"cell": "X", "nested": {"branches": ["A", "B"], "count": 2, "exact": True}})])
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
            "unlisted-failure": ('if key in listed_keys or result["state"] == "passed":', 'if True:'),
            "typed-string": ('return isinstance(value, str) and TYPED_STRING_RE.fullmatch(value) is not None', 'return isinstance(value, str)'),
            "required-provenance": ('if not isinstance(raw["reason"], str) or not raw["reason"].strip() or any(\n            ord(character) < 32 or ord(character) == 127 for character in raw["reason"]):', 'if False:'),
            "result-pass-null": ('if raw["signature"] is not None:', 'if False:'),
            "workflow-runner": ('if invocation["runner"] is None or not valid_runner(invocation["runner"]):', 'if False:'),
            "duplicate-result": ('if key in results:\n            problems.append', 'if False:\n            problems.append'),
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
