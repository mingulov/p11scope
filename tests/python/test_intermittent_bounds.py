# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Intermittent-bounds gate controls; every verdict has a twin.

scripts/ci/check-intermittent-bounds.py fails once an intermittent
cell has gone N runs without passing on a kernel leg. These tests
judge pre-fetched histories (--history-json), never the network.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "check-intermittent-bounds.py"
CELL = "flaky_cell"
OTHER = "steady_cell"


def row(cell, passed, qualification="qualified"):
    return {"cell": cell, "pass": passed, "qualification": qualification,
            "detail": "ok"}


def history(runs):
    return {"runs": runs}


def run_entry(run_id, branch="test/x", host_rows=(), guest_rows=()):
    return {"id": run_id, "branch": branch,
            "results": {"host": list(host_rows),
                        "v6.6.157": list(guest_rows)}}


class IntermittentBoundsTests(unittest.TestCase):
    def run_bounds(self, document, *extra, window=3):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            path.write_text(json.dumps(document))
            args = [sys.executable, "-I", str(SCRIPT),
                    "--history-json", str(path),
                    "--window", str(window),
                    "--kernel", "host", "--kernel", "v6.6.157",
                    *extra]
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=30)

    def test_pass_anywhere_in_window_holds(self):
        doc = history([
            run_entry(3, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, False, "expected-failure")]),
            run_entry(2, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, False, "expected-failure")]),
        ])
        # Guest passed on run 2; host never did: host fails, guest holds.
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{CELL} on host went 3 runs without passing",
                      result.stderr)
        self.assertIn("lanes: task/fix", result.stderr)
        self.assertIn(f"PASS {CELL} on v6.6.157: last pass 2",
                      result.stdout)

    def test_all_pass_holds(self):
        doc = history([
            run_entry(2, host_rows=[row(CELL, True)],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(
            doc, "--cell", f"{CELL}=task/fix",
            "--cell", f"{CELL}=task/other")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 cells bounded over 2 runs x 2 kernels",
                      result.stdout)

    def test_window_counts_runs_not_rows(self):
        # Three misses then a pass outside the window: the window
        # holds only misses and must fail.
        doc = history([
            run_entry(4, host_rows=[row(CELL, False, "expected-failure")]),
            run_entry(3, host_rows=[row(CELL, False, "expected-failure")]),
            run_entry(2, host_rows=[row(CELL, False, "expected-failure")]),
            run_entry(1, host_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("went 3 runs without passing", result.stderr)
        self.assertNotIn("last pass 1", result.stdout)

    def test_missing_leg_bootstraps_without_failing(self):
        # The cell never ran on the guest leg in the window (no rows
        # at all there): bootstrap note, not a failure. Host passed.
        doc = history([
            run_entry(2, host_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"BOOTSTRAP: {CELL} on v6.6.157 never ran",
                      result.stdout)

    def test_empty_history_bootstraps_once(self):
        result = self.run_bounds(history([]),
                                 "--cell", f"{CELL}=task/fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("BOOTSTRAP: no runs", result.stdout)

    def test_two_cells_judged_independently(self):
        doc = history([
            run_entry(2, host_rows=[row(CELL, False, "expected-failure"),
                                    row(OTHER, True)],
                      guest_rows=[row(CELL, False, "expected-failure"),
                                  row(OTHER, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure"),
                                    row(OTHER, True)],
                      guest_rows=[row(CELL, False, "expected-failure"),
                                  row(OTHER, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix",
                                 "--cell", f"{OTHER}=task/other")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{CELL} on host went", result.stderr)
        self.assertIn(f"PASS {OTHER} on host", result.stdout)

    def test_bad_cell_shape_refused(self):
        result = self.run_bounds(history([]), "--cell", "flaky")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("want CELL=LANE", result.stderr)

    def test_missing_history_file_refused(self):
        args = [sys.executable, "-I", str(SCRIPT),
                "--history-json", "/nonexistent/history.json",
                "--cell", f"{CELL}=task/fix"]
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot read", result.stderr)


if __name__ == "__main__":
    unittest.main()
