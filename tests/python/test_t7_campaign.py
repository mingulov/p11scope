# SPDX-License-Identifier: GPL-3.0-or-later
"""Ordinary controls for the owned T7 runner; never execute BPF here."""
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = runpy.run_path(str(ROOT / "scripts/run-t7-static-campaign.py"))


class CampaignTests(unittest.TestCase):
    def test_ids_in_different_kernel_namespaces_remain_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            def run(command, **kwargs):
                return subprocess.CompletedProcess(command, 0, '[{"id":7}]', '')
            census = RUNNER["take_census"](Path(directory), "before", run=run)
            self.assertEqual(census, [("link", 7), ("map", 7), ("prog", 7)])

    def test_census_order_does_not_depend_on_numeric_text_sort(self):
        self.assertEqual(
            RUNNER["parse_census"]("map", '[{"id":100},{"id":2},{"id":11}]'),
            [("map", 2), ("map", 11), ("map", 100)],
        )

    def test_failed_enumeration_is_never_an_empty_census(self):
        with tempfile.TemporaryDirectory() as directory:
            def run(command, **kwargs):
                return subprocess.CompletedProcess(command, 1, '[]', 'permission denied')
            with self.assertRaisesRegex(ValueError, "enumeration failed"):
                RUNNER["take_census"](Path(directory), "before", run=run)
            self.assertIn("permission denied", (Path(directory) / "before-map.stderr").read_text())
            self.assertFalse((Path(directory) / "before.json").exists())

    def test_malformed_missing_duplicate_or_nonpositive_ids_are_rejected(self):
        for payload in ['null', '{}', '[{}]', '[{"id":0}]', '[{"id":true}]',
                        '[{"id":"7"}]', '[{"id":7},{"id":7}]', 'broken']:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                RUNNER["parse_census"]("map", payload)

    def test_empty_successful_enumeration_is_allowed(self):
        self.assertEqual(RUNNER["parse_census"]("map", '[]'), [])

    def test_selector_must_list_exactly_one_body(self):
        selector = "module::owned_test"
        for output in ["0 tests, 0 benchmarks\n", "different: test\n\n1 test, 0 benchmarks\n",
                       selector + ": test\nother: test\n\n2 tests, 0 benchmarks\n"]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                RUNNER["validate_selector"](selector, output)
        RUNNER["validate_selector"](selector, selector + ": test\n\n1 test, 0 benchmarks\n")

    def test_zero_tests_and_failed_tests_cannot_pass(self):
        for log in ["test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0s\n",
                    "running 1 test\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"]:
            with self.subTest(log=log), self.assertRaises(ValueError):
                RUNNER["validate_test_exit"](0, log)
        good = "running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 1s\n"
        RUNNER["validate_test_exit"](0, good)
        with self.assertRaises(ValueError):
            RUNNER["validate_test_exit"](101, good)

    def test_inventory_requires_all_four_phases_and_terminal(self):
        phases = ["pre_go", "after_go", "after_repeat", "terminal"]
        rows = []
        for phase in phases:
            rows.append({"kind": "usage_phase", "phase": phase,
                         "positive_count": 0 if phase == "pre_go" else 2, "cells_read": 2,
                         "newly_positive": [0, 1] if phase == "after_go" else [],
                         "usage_integrity_failures": 0, "usage_read_failures": 0})
        rows.append({"kind": "terminal", "phase": "terminal", "usage_positive": 2})
        RUNNER["validate_inventory_phases"](rows, 2)
        for bad in [rows[:-1], rows[1:], rows + [rows[-1]]]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                RUNNER["validate_inventory_phases"](bad, 2)
        changed = json.loads(json.dumps(rows))
        changed[1]["newly_positive"] = [1, 2]
        with self.assertRaises(ValueError):
            RUNNER["validate_inventory_phases"](changed, 2)


if __name__ == "__main__":
    unittest.main()
