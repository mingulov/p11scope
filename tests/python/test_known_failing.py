# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the tracked known-failing test list.

The list is a typed exception ledger, never a text allowlist: rows name an
owner-approved KI issue, a typed failure signature and the lane that owns the
fix. scripts/check-known-failing.py validates the list statically and judges
typed runner result records exactly: an always-failing row that passes is
stale, a failing test outside the rows is ordinary red, and a failure with a
different typed signature is ordinary red.

Run: python3 -I tests/python/test_known_failing.py -v
"""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check-known-failing.py"

LIST_SCHEMA = "p11scope/known-failing/v1"
ISSUE_SCHEMA = "p11scope/known-issues/v1"
RESULT_SCHEMA = "p11scope/known-failing-results/v1"
LEGACY_CELL_EXPECTED = (
    "profile-cgroup",
    "trace-cgroup",
    "profile-pid-ia32",
    "run-ia32",
)
LEGACY_CELL_INTERMITTENT = (
    "privileged_run_tree_unprearmed_shortlived_descendants_reach_high_coverage",
    "privileged_run_tree_unprearmed_shortlived_never_pause_still_learns",
    "privileged_run_tree_unprearmed_shortlived_parallel_never_pause_covers_waves",
    "privileged_run_tree_arming_exhaustion_still_stages_and_counts",
)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def row(**changes):
    value = {
        "path": "tests/python/test_example.py",
        "test": "Example.test_fails",
        "issue": "KI-01",
        "target": "0.8.0",
        "runner": "python-suite",
        "signature": {"cell": "EXAMPLE", "branch": "missing_signature"},
        "lane": "v080-example-fix",
        "mode": "always",
        "hosts": ["fedora"],
        "since": "v0.7.1",
        "evidence": "example-report.md",
    }
    value.update(changes)
    return value


def issue_document(issues):
    return {
        "schema": ISSUE_SCHEMA,
        "issues": [{"id": issue, "test": test} for issue, test in issues],
    }


def write_known_limitations(root, issues=None, *, section=True):
    docs = root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    if not section:
        (docs / "known-limitations.md").write_text(
            "# Known limitations (v0.7.0)\n\n## Known limitations in 0.7.0\n",
            encoding="utf-8")
        return
    issue_list = issues if issues is not None else [("KI-01", True)]
    payload = json.dumps(issue_document(issue_list), sort_keys=True)
    headings = "".join(f"### {issue} example issue\n" for issue, _test in issue_list)
    (docs / "known-limitations.md").write_text(
        "# Known limitations (v0.7.2)\n\n"
        "## Known limitations in 0.7.2\n\n"
        "<!-- p11scope-known-issues-v1\n"
        f"{payload}\n"
        "-->\n\n"
        f"{headings}",
        encoding="utf-8")


def write_workflow_declarations(root, expected=LEGACY_CELL_EXPECTED, intermittent=LEGACY_CELL_INTERMITTENT):
    path = root / ".github/workflows/privileged-tests.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["jobs:\n", "  declarations:\n", "    run: |\n"]
    lines.extend(f"      check-cell-results --expected-failure {cell} \\\n" for cell in expected)
    lines.extend(f"      check-cell-results --intermittent-failure {cell} \\\n" for cell in intermittent)
    path.write_text("".join(lines), encoding="utf-8")


def write_ignored_registry(root, sites=()):
    write_json(root / "tests/ignored-tests.json", {
        "schema": "p11scope/ignored-tests/v1",
        "cells": {"known-failing": "typed known-failing row"},
        "sites": list(sites),
    })


def ignored_site(file_name, test):
    return {"file": file_name, "path": test, "reason": "known-failing fixture", "cell": "known-failing"}


def write_fixture(root, rows, issues=None, *, section=True, python_source=None, ignored_sites=()):
    root.mkdir(parents=True, exist_ok=True)
    write_known_limitations(root, issues, section=section)
    write_workflow_declarations(root)
    write_ignored_registry(root, ignored_sites)
    source = python_source if python_source is not None else (
        "class Example:\n"
        "    def test_fails(self):\n"
        "        pass\n"
    )
    test_file = root / "tests/python/test_example.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text(source, encoding="utf-8")
    registry = root / "scripts/run-python-suites.py"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text('RUN = [("test_example.py", [])]\n', encoding="utf-8")
    write_json(root / "tests/known-failing.json", {"schema": LIST_SCHEMA, "rows": rows})
    return root


def valid_fixture(root):
    return write_fixture(root, [row()])


def copy_rust_scanner_helper(root):
    scripts = root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "scripts/check-ignored-tests.py", scripts / "check-ignored-tests.py")


def install_privileged_runner(root, extra_expected=()):
    copy_rust_scanner_helper(root)
    target = root / "scripts/run-privileged-lib-tests.sh"
    shutil.copyfile(ROOT / "scripts/run-privileged-lib-tests.sh", target)
    if extra_expected:
        text = target.read_text(encoding="utf-8")
        insertion = "".join(f"{member}\n" for member in extra_expected)
        text = text.replace("EXPECTED_FAILURE_TESTS=(\n", "EXPECTED_FAILURE_TESTS=(\n" + insertion, 1)
        target.write_text(text, encoding="utf-8")


def write_results(root, name, entries, *, runner="python-suite", host="fedora"):
    path = root / name
    write_json(path, {
        "schema": RESULT_SCHEMA,
        "runner": runner,
        "host": host,
        "results": entries,
    })
    return path


def result_entry(passed, signature, *, path="tests/python/test_example.py", test="Example.test_fails"):
    return {"path": path, "test": test, "passed": passed, "signature": signature}


def run_checker(root, *extra, checker=CHECKER):
    command = [sys.executable, "-I", str(checker), "--root", str(root), *extra]
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


class ProductionListTests(unittest.TestCase):
    def test_real_tree_static_check_passes(self):
        result = run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)


class StaticListTests(unittest.TestCase):
    def exercise(self, rows, issues=None, *, section=True, python_source=None):
        with tempfile.TemporaryDirectory(prefix="known-failing-static-") as temporary:
            root = write_fixture(Path(temporary) / "root", rows, issues,
                                 section=section, python_source=python_source)
            return run_checker(root)

    def test_valid_row_passes_static_check(self):
        result = self.exercise([row()])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_rows_pass_before_the_issue_section_lands(self):
        result = self.exercise([], section=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_rows_do_not_satisfy_a_test_yes_registry(self):
        result = self.exercise([])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test=yes issues without rows: KI-01", result.stderr)

    def test_row_without_issue_authority_fails(self):
        result = self.exercise([row()], section=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no typed known-issue registry", result.stderr)

    def test_unknown_issue_fails(self):
        result = self.exercise([row(issue="KI-99")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a named known issue", result.stderr)

    def test_test_yes_issue_without_a_row_fails(self):
        result = self.exercise([row()], [("KI-01", True), ("KI-02", True)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test=yes issues without rows", result.stderr)

    def test_row_for_an_issue_not_marked_test_yes_fails(self):
        result = self.exercise([row()], [("KI-01", False)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rows for issues not marked test=yes", result.stderr)

    def test_missing_test_file_fails(self):
        result = self.exercise([row(path="tests/python/test_missing.py")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("path does not exist", result.stderr)

    def test_missing_python_test_id_fails(self):
        result = self.exercise([row(test="Example.test_absent")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test id not found", result.stderr)

    def test_python_test_discovery_is_exact(self):
        source = (
            "class Example:\n"
            "    def test_fails_exactly(self):\n"
            "        pass\n"
        )
        result = self.exercise([row(test="Example.test_fails")], python_source=source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test id not found", result.stderr)

    def test_python_suite_must_be_registered(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-registration-") as temporary:
            root = valid_fixture(Path(temporary) / "root")
            (root / "scripts/run-python-suites.py").write_text("RUN = []\n", encoding="utf-8")
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("suite is not registered", result.stderr)

    def test_rust_test_discovery_uses_full_module_paths(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-rust-") as temporary:
            root = Path(temporary) / "root"
            rust_row = row(
                path="src/example.rs",
                test="example::tests::guarded_cell",
                runner="host-matrix",
            )
            write_fixture(root, [rust_row], ignored_sites=[ignored_site("src/example.rs", rust_row["test"])])
            copy_rust_scanner_helper(root)
            source = (
                "#[cfg(test)]\n"
                "mod tests {\n"
                "    #[test]\n"
                "    #[ignore = \"privileged\"]\n"
                "    fn guarded_cell() {}\n"
                "}\n"
            )
            src = root / "src"
            src.mkdir(parents=True)
            (src / "example.rs").write_text(source, encoding="utf-8")
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

            rust_row["test"] = "tests::guarded_cell"
            write_json(root / "tests/known-failing.json", {"schema": LIST_SCHEMA, "rows": [rust_row]})
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("test id not found", result.stderr)

    def test_rust_integration_test_ids_have_no_module_prefix(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-rust-integration-") as temporary:
            root = Path(temporary) / "root"
            rust_row = row(
                path="tests/example.rs",
                test="integration_cell",
                runner="host-matrix",
            )
            write_fixture(root, [rust_row], ignored_sites=[ignored_site("tests/example.rs", "integration_cell")])
            copy_rust_scanner_helper(root)
            tests_dir = root / "tests"
            tests_dir.mkdir(parents=True, exist_ok=True)
            (tests_dir / "example.rs").write_text("#[test]\nfn integration_cell() {}\n", encoding="utf-8")
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

            rust_row["test"] = "tests::integration_cell"
            write_json(root / "tests/known-failing.json", {"schema": LIST_SCHEMA, "rows": [rust_row]})
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("test id not found", result.stderr)

    def test_shell_cell_discovery_matches_case_tokens_exactly(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-shell-") as temporary:
            root = Path(temporary) / "root"
            shell_row = row(
                path="scripts/qualify-example.sh",
                test="mt-exact",
                runner="cell:scripts/qualify-example.sh",
            )
            write_fixture(root, [shell_row])
            write_workflow_declarations(root, expected=LEGACY_CELL_EXPECTED + ("mt-exact",))
            script = root / "scripts/qualify-example.sh"
            script.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "    mt-exact) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

            shell_row["test"] = "mt-extra"
            write_json(root / "tests/known-failing.json", {"schema": LIST_SCHEMA, "rows": [shell_row]})
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("test id not found", result.stderr)

    def make_shell_fixture(self, root, *, mode="always", runner="cell:scripts/qualify-example.sh"):
        cell = "mt-exact"
        shell_row = row(
            path="scripts/qualify-example.sh",
            test=cell,
            runner=runner,
            mode=mode,
        )
        write_fixture(root, [shell_row])
        script = root / "scripts/qualify-example.sh"
        script.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "    mt-exact) exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        return shell_row

    def test_workflow_cell_declarations_match_rows_exactly(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-workflow-") as temporary:
            base = Path(temporary)

            always_root = base / "always"
            self.make_shell_fixture(always_root)
            write_workflow_declarations(always_root, expected=LEGACY_CELL_EXPECTED + ("mt-exact",))
            result = run_checker(always_root)
            self.assertEqual(result.returncode, 0, result.stderr)

            write_workflow_declarations(always_root)
            result = run_checker(always_root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing known-failing rows: mt-exact", result.stderr)

            write_workflow_declarations(
                always_root,
                expected=LEGACY_CELL_EXPECTED + ("mt-exact", "mt-undeclared"),
            )
            result = run_checker(always_root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("undeclared expected/intermittent cells: mt-undeclared", result.stderr)

            intermittent_root = base / "intermittent"
            self.make_shell_fixture(intermittent_root, mode="intermittent")
            write_workflow_declarations(
                intermittent_root,
                intermittent=LEGACY_CELL_INTERMITTENT + ("mt-exact",),
            )
            result = run_checker(intermittent_root)
            self.assertEqual(result.returncode, 0, result.stderr)

            absent_runner_root = base / "absent-runner"
            self.make_shell_fixture(absent_runner_root, runner="cell:scripts/absent.sh")
            write_workflow_declarations(absent_runner_root, expected=LEGACY_CELL_EXPECTED + ("mt-exact",))
            result = run_checker(absent_runner_root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cell runner script does not exist", result.stderr)

    def test_ignored_known_failing_entries_match_rust_rows_exactly(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-ignored-") as temporary:
            root = Path(temporary) / "root"
            test_id = "example::tests::guarded_cell"
            rust_row = row(path="src/example.rs", test=test_id, runner="host-matrix")
            write_fixture(root, [rust_row], ignored_sites=[ignored_site("src/example.rs", test_id)])
            copy_rust_scanner_helper(root)
            src = root / "src"
            src.mkdir(parents=True)
            (src / "example.rs").write_text(
                "#[cfg(test)]\n"
                "mod tests {\n"
                "    #[test]\n"
                "    fn guarded_cell() {}\n"
                "}\n",
                encoding="utf-8",
            )
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

            write_ignored_registry(root)
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing cell=known-failing rows", result.stderr)

            write_ignored_registry(root, [
                ignored_site("src/example.rs", test_id),
                ignored_site("src/example.rs", "example::tests::undeclared"),
            ])
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("entries without rows", result.stderr)

    def test_privileged_runner_expected_lists_match_rows_exactly(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-privileged-") as temporary:
            root = valid_fixture(Path(temporary) / "root")
            install_privileged_runner(root, extra_expected=["synthetic::undeclared_cell"])
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("undeclared expected failures", result.stderr)

    def test_privileged_row_must_be_declared_by_runner(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-privileged-row-") as temporary:
            root = Path(temporary) / "root"
            test_id = "example::tests::guarded_cell"
            privileged_row = row(
                path="src/example.rs",
                test=test_id,
                runner="privileged-lib",
            )
            write_fixture(root, [privileged_row], ignored_sites=[ignored_site("src/example.rs", test_id)])
            src = root / "src"
            src.mkdir(parents=True)
            (src / "example.rs").write_text(
                "#[cfg(test)]\n"
                "mod tests {\n"
                "    #[test]\n"
                "    fn guarded_cell() {}\n"
                "}\n",
                encoding="utf-8",
            )

            install_privileged_runner(root)
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing known-failing rows", result.stderr)

            install_privileged_runner(root, extra_expected=[test_id])
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_row_shape_and_values_fail(self):
        cases = [
            ("extra-key", row(extra=True), "unknown fields"),
            ("no-issue", row(issue=""), "issue"),
            ("bad-target", row(target="0.9.0"), "target"),
            ("bad-target-type", row(target=["0.8.0"]), "target"),
            ("bad-mode", row(mode="sometimes"), "mode"),
            ("bad-mode-type", row(mode=["always"]), "mode"),
            ("bad-runner-type", row(runner=["python-suite"]), "runner"),
            ("no-lane", row(lane=""), "lane"),
            ("bad-host", row(hosts=["fedora-sm2"]), "hosts"),
            ("duplicate-host", row(hosts=["fedora", "fedora"]), "hosts"),
            ("absolute-path", row(path="/tests/python/test_example.py"), "path"),
            ("dotdot-path", row(path="tests/../tests/python/test_example.py"), "path"),
            ("empty-signature", row(signature={}), "signature"),
            ("text-signature", row(signature={"log_contains": "assertion text"}), "free-text"),
            ("message-signature", row(signature={"failure_message": "assertion text"}), "free-text"),
        ]
        for name, value, message in cases:
            with self.subTest(name=name):
                result = self.exercise([value])
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn(message, result.stderr, name)

    def test_duplicate_rows_fail(self):
        result = self.exercise([row(), row()])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate row", result.stderr)

    def test_bad_list_schema_and_duplicate_json_keys_fail(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-json-") as temporary:
            root = valid_fixture(Path(temporary) / "root")
            write_json(root / "tests/known-failing.json", {"schema": "wrong", "rows": []})
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("schema", result.stderr)
            (root / "tests/known-failing.json").write_text(
                '{"schema":"p11scope/known-failing/v1","rows":[],"rows":[]}\n',
                encoding="utf-8")
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate JSON key", result.stderr)

    def test_malformed_or_multiple_issue_registry_blocks_fail(self):
        for name, marker_count in (("absent", 0), ("multiple", 2)):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="known-failing-issues-") as temporary:
                root = Path(temporary) / "root"
                write_fixture(root, [])
                docs = root / "docs/known-limitations.md"
                text = docs.read_text(encoding="utf-8")
                if marker_count == 0:
                    start = text.index("<!-- p11scope-known-issues-v1")
                    end = text.index("-->", start) + 3
                    text = text[:start] + text[end:]
                else:
                    block_start = text.index("<!-- p11scope-known-issues-v1")
                    block_end = text.index("-->", block_start) + 3
                    text = text + "\n" + text[block_start:block_end] + "\n"
                docs.write_text(text, encoding="utf-8")
                result = run_checker(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("known-issue registry", result.stderr)

    def test_issue_registry_and_prose_sections_match_exactly(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-prose-") as temporary:
            root = valid_fixture(Path(temporary) / "root")
            docs = root / "docs/known-limitations.md"
            text = docs.read_text(encoding="utf-8")
            without_heading = text.replace("### KI-01 example issue\n", "")
            docs.write_text(without_heading, encoding="utf-8")
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("without a KI section: KI-01", result.stderr)

            docs.write_text(text + "\n### KI-02 undocumented in the registry\n", encoding="utf-8")
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("sections missing from the typed registry: KI-02", result.stderr)


class ResultJudgmentTests(unittest.TestCase):
    def exercise(self, entries, *, rows=None, host="fedora"):
        with tempfile.TemporaryDirectory(prefix="known-failing-results-") as temporary:
            root = valid_fixture(Path(temporary) / "root")
            if rows is not None:
                write_json(root / "tests/known-failing.json", {"schema": LIST_SCHEMA, "rows": rows})
            results = write_results(root, "results.json", entries, host=host)
            return run_checker(root, "--results", str(results))

    def expected_failure(self, **changes):
        value = result_entry(False, {"cell": "EXAMPLE", "branch": "missing_signature"})
        value.update(changes)
        return value

    def test_matching_expected_failure_passes(self):
        result = self.exercise([self.expected_failure()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 expected failures", result.stdout)

    def test_signature_equality_is_typed_not_key_order(self):
        entry = self.expected_failure(signature={"branch": "missing_signature", "cell": "EXAMPLE"})
        result = self.exercise([entry])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_listed_always_row_that_passes_is_stale(self):
        result = self.exercise([result_entry(True, None)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale row", result.stderr)

    def test_intermittent_row_may_pass(self):
        intermittent = row(mode="intermittent")
        result = self.exercise([result_entry(True, None)], rows=[intermittent])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unlisted_failure_fails_even_beside_a_matching_row(self):
        other = result_entry(False, {"branch": "other"}, test="Example.test_other")
        result = self.exercise([self.expected_failure(), other])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failing test not listed", result.stderr)

    def test_wrong_signature_is_an_ordinary_failure(self):
        entry = self.expected_failure(signature={"cell": "EXAMPLE", "branch": "different"})
        result = self.exercise([entry])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failure signature mismatch", result.stderr)

    def test_numeric_type_difference_is_a_signature_mismatch(self):
        typed_row = row(signature={"branch": "missing_signature", "count": 1})
        entry = self.expected_failure(signature={"branch": "missing_signature", "count": 1.0})
        result = self.exercise([entry], rows=[typed_row])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failure signature mismatch", result.stderr)

        bool_entry = self.expected_failure(signature={"branch": "missing_signature", "count": True})
        result = self.exercise([bool_entry], rows=[typed_row])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failure signature mismatch", result.stderr)

    def test_missing_observation_for_a_listed_row_fails(self):
        result = self.exercise([])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("listed row has no result", result.stderr)

    def test_host_filter_selects_exact_hosts(self):
        result = self.exercise([], host="fedora-sm1")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.exercise([], host="fedora")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("listed row has no result", result.stderr)

    def test_result_schema_and_result_rows_are_strict(self):
        with tempfile.TemporaryDirectory(prefix="known-failing-bad-results-") as temporary:
            root = valid_fixture(Path(temporary) / "root")
            cases = [
                {"schema": "wrong", "runner": "python-suite", "host": "fedora", "results": []},
                {"schema": RESULT_SCHEMA, "runner": "python-suite", "host": "fedora", "results": [], "extra": 1},
                {"schema": RESULT_SCHEMA, "runner": "python-suite", "host": "fedora-sm", "results": []},
                {"schema": RESULT_SCHEMA, "runner": "python-suite", "host": "fedora",
                 "results": [{"path": "x", "test": "t", "passed": False}]},
                {"schema": RESULT_SCHEMA, "runner": "python-suite", "host": "fedora",
                 "results": [{"path": [], "test": "t", "passed": False, "signature": {"branch": "x"}}]},
                {"schema": RESULT_SCHEMA, "runner": "python-suite", "host": "fedora",
                 "results": [result_entry(False, {"branch": "x"}), result_entry(False, {"branch": "y"})]},
            ]
            for index, document in enumerate(cases):
                with self.subTest(case=index):
                    results = root / f"bad-{index}.json"
                    write_json(results, document)
                    result = run_checker(root, "--results", str(results))
                    self.assertNotEqual(result.returncode, 0)


class MutationSweepTests(unittest.TestCase):
    """Source mutations of the checker must change at least one verdict."""

    def case_roots(self, base):
        cases = {}

        def add(name, rows, issues=None, section=True, results=None, python_source=None):
            root = base / name
            write_fixture(root, rows, issues, section=section, python_source=python_source)
            result_path = None
            if results is not None:
                result_path = write_results(root, "results.json", results)
            cases[name] = (root, result_path)

        valid_row = row()
        matching = result_entry(False, {"cell": "EXAMPLE", "branch": "missing_signature"})
        add("valid", [valid_row])
        add("missing-test", [row(path="tests/python/test_missing.py")])
        add("missing-test-id", [row(test="Example.test_absent")])
        unknown_row = row(test="Example.test_other", issue="KI-99")
        add("unknown-issue", [valid_row, unknown_row], python_source=(
            "class Example:\n"
            "    def test_fails(self):\n"
            "        pass\n"
            "    def test_other(self):\n"
            "        pass\n"
        ))
        add("missing-issue-row", [valid_row], [("KI-01", True), ("KI-02", True)])
        add("duplicate-row", [valid_row, copy.deepcopy(valid_row)])
        add("invalid-mode", [row(mode="sometimes")])
        add("runtime-expected", [valid_row], results=[matching])
        add("runtime-stale", [valid_row], results=[result_entry(True, None)])
        unlisted = result_entry(False, {"branch": "other"}, test="Example.test_other")
        add("runtime-unlisted", [valid_row], results=[matching, unlisted])
        wrong = result_entry(False, {"cell": "EXAMPLE", "branch": "different"})
        add("runtime-wrong-signature", [valid_row], results=[wrong])
        add("runtime-missing-observation", [valid_row], results=[])

        bad = base / "bad-schema"
        write_fixture(bad, [], [("KI-01", False)])
        write_json(bad / "tests/known-failing.json", {"schema": "wrong", "rows": []})
        cases["bad-schema"] = (bad, None)

        prose_missing = base / "prose-missing"
        write_fixture(prose_missing, [valid_row])
        docs = prose_missing / "docs/known-limitations.md"
        original_docs = docs.read_text(encoding="utf-8")
        docs.write_text(original_docs.replace("### KI-01 example issue\n", ""), encoding="utf-8")
        cases["prose-missing"] = (prose_missing, None)

        prose_extra = base / "prose-extra"
        write_fixture(prose_extra, [valid_row])
        docs = prose_extra / "docs/known-limitations.md"
        docs.write_text(
            docs.read_text(encoding="utf-8") + "\n### KI-02 not in the typed registry\n",
            encoding="utf-8",
        )
        cases["prose-extra"] = (prose_extra, None)

        def shell_case(name, workflow=True, extra_declaration=False):
            root = base / name
            shell_row = row(
                path="scripts/qualify-example.sh",
                test="mt-exact",
                runner="cell:scripts/qualify-example.sh",
            )
            write_fixture(root, [shell_row])
            (root / "scripts/qualify-example.sh").write_text(
                "case \"$1\" in\n    mt-exact) exit 0 ;;\nesac\n",
                encoding="utf-8",
            )
            if workflow:
                expected = LEGACY_CELL_EXPECTED + ("mt-exact",)
                if extra_declaration:
                    expected += ("mt-undeclared",)
                write_workflow_declarations(root, expected=expected)
            cases[name] = (root, None)

        shell_case("workflow-missing", workflow=False)
        shell_case("workflow-extra", extra_declaration=True)

        ignored = base / "ignored-missing"
        rust_row = row(path="src/example.rs", test="example::tests::guarded_cell", runner="host-matrix")
        write_fixture(ignored, [rust_row])
        copy_rust_scanner_helper(ignored)
        (ignored / "src").mkdir(parents=True)
        (ignored / "src/example.rs").write_text(
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn guarded_cell() {}\n}\n",
            encoding="utf-8",
        )
        cases["ignored-missing"] = (ignored, None)

        privileged = base / "privileged-extra"
        write_fixture(privileged, [valid_row])
        install_privileged_runner(privileged, extra_expected=["synthetic::undeclared_cell"])
        cases["privileged-extra"] = (privileged, None)
        return cases

    def expected_vectors(self):
        return {
            "valid": 0,
            "bad-schema": 1,
            "missing-test": 1,
            "missing-test-id": 1,
            "unknown-issue": 1,
            "missing-issue-row": 1,
            "duplicate-row": 1,
            "invalid-mode": 1,
            "runtime-expected": 0,
            "runtime-stale": 1,
            "runtime-unlisted": 1,
            "runtime-wrong-signature": 1,
            "runtime-missing-observation": 1,
            "prose-missing": 1,
            "prose-extra": 1,
            "workflow-missing": 1,
            "workflow-extra": 1,
            "ignored-missing": 1,
            "privileged-extra": 1,
        }

    def run_vector(self, checker, cases, only=None):
        vector = {}
        selected = cases.items() if only is None else ((name, cases[name]) for name in only)
        for name, (root, results) in selected:
            extra = [] if results is None else ["--results", str(results)]
            outcome = run_checker(root, *extra, checker=checker)
            if outcome.returncode == 0:
                vector[name] = 0
            elif "Traceback" in outcome.stderr:
                vector[name] = 2
            else:
                vector[name] = 1
        return vector

    def test_source_mutation_sweep(self):
        mutations = [
            ("list-schema", 'if data.get("schema") != LIST_SCHEMA:', 'if False:'),
            ("test-exists", 'if not test_exists(root, row):', 'if False:'),
            ("unknown-issue", 'if unknown_issues:', 'if False:'),
            ("missing-issue-row", 'if missing_issue_rows:', 'if False:'),
            ("duplicate-row", 'if key in seen_row_keys:', 'if False:'),
            ("mode-closed-set", 'if not isinstance(raw["mode"], str) or raw["mode"] not in MODES:', 'if False:'),
            ("stale-pass", 'if result["passed"] and row["mode"] == "always":', 'if False:'),
            ("unlisted-failure", 'if key not in listed_keys and result["passed"] is False:', 'if False:'),
            ("signature-equality", 'elif not json_exact_equal(result["signature"], row["signature"]):', 'elif False:'),
            ("missing-observation", 'if key not in results_by_key:', 'if False:'),
            ("prose-missing",
             'problems.append("known-issue registry entries without a KI section: " + ", ".join(missing_sections))',
             'pass'),
            ("prose-extra",
             'problems.append("KI sections missing from the typed registry: " + ", ".join(unregistered_sections))',
             'pass'),
            ("workflow-missing",
             'problems.append(f"workflow {label} declarations missing known-failing rows: " + ", ".join(missing))',
             'pass'),
            ("workflow-extra",
             'problems.append(f"workflow {label} has undeclared expected/intermittent cells: " + ", ".join(extra))',
             'pass'),
            ("ignored-missing",
             'problems.append("ignored-tests missing cell=known-failing rows: " + rendered)',
             'pass'),
            ("privileged-extra",
             'problems.append("privileged-lib runner has undeclared expected failures: " + ", ".join(extra))',
             'pass'),
        ]
        mutation_cases = {
            "list-schema": ["valid", "bad-schema"],
            "test-exists": ["valid", "missing-test", "missing-test-id"],
            "unknown-issue": ["valid", "unknown-issue"],
            "missing-issue-row": ["valid", "missing-issue-row"],
            "duplicate-row": ["valid", "duplicate-row"],
            "mode-closed-set": ["valid", "invalid-mode"],
            "stale-pass": ["runtime-expected", "runtime-stale"],
            "unlisted-failure": ["runtime-expected", "runtime-unlisted"],
            "signature-equality": ["runtime-expected", "runtime-wrong-signature"],
            "missing-observation": ["runtime-expected", "runtime-missing-observation"],
            "prose-missing": ["valid", "prose-missing"],
            "prose-extra": ["valid", "prose-extra"],
            "workflow-missing": ["valid", "workflow-missing"],
            "workflow-extra": ["valid", "workflow-extra"],
            "ignored-missing": ["valid", "ignored-missing"],
            "privileged-extra": ["valid", "privileged-extra"],
        }
        source = CHECKER.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="known-failing-mutations-") as temporary:
            base = Path(temporary)
            cases = self.case_roots(base / "cases")
            wanted = self.expected_vectors()
            control = self.run_vector(CHECKER, cases)
            self.assertEqual(control, wanted)
            survivors = []
            for name, old, new in mutations:
                with self.subTest(mutation=name):
                    self.assertIn(old, source, f"mutation anchor missing: {name}")
                    mutated = source.replace(old, new, 1)
                    mutant = base / f"mutant-{name}.py"
                    mutant.write_text(mutated, encoding="utf-8")
                    names = mutation_cases[name]
                    got = self.run_vector(mutant, cases, only=names)
                    if got != {case: control[case] for case in names}:
                        continue
                    survivors.append(name)
            self.assertEqual(survivors, [], f"mutation survivors: {survivors}")


if __name__ == "__main__":
    unittest.main()
