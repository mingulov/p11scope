# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Intermittent-bounds gate controls; every verdict has a twin.

scripts/ci/check-intermittent-bounds.py fails once an intermittent
cell has gone N runs without passing on a kernel leg. These tests
judge pre-fetched histories (--history-json), never the network.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
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

    def test_missing_leg_fails_not_bootstraps(self):
        # The cell never ran on the guest leg in the window (no rows
        # at all there): a dropped or renamed cell disables no
        # bound. Host passed; the gate still fails.
        doc = history([
            run_entry(2, host_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{CELL} on v6.6.157 never ran in the window",
                      result.stderr)
        self.assertIn("disables no bound", result.stderr)

    def test_empty_history_fails_not_bootstraps(self):
        result = self.run_bounds(history([]),
                                 "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to pass on no evidence", result.stderr)

    def test_missing_leg_artifacts_fail(self):
        # No run-tree artifacts at all for the guest leg in the
        # window: a missing leg disables no bound either.
        doc = history([
            {"id": 2, "branch": "test/x",
             "results": {"host": [row(CELL, True)], "v6.6.157": None}},
            {"id": 1, "branch": "test/x",
             "results": {"host": [row(CELL, True)], "v6.6.157": None}},
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no run-tree artifacts in", result.stderr)

    def test_pass_with_failed_qualification_is_not_a_pass(self):
        # An inconsistent row (pass with failed qualification)
        # never resets the window.
        doc = history([
            run_entry(2, host_rows=[{"cell": CELL, "pass": True,
                                     "qualification": "failed",
                                     "detail": "inconsistent"}],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{CELL} on host went", result.stderr)
        self.assertIn(f"PASS {CELL} on v6.6.157", result.stdout)

    def test_unexpected_pass_does_not_reset_the_window(self):
        # pass with expected-failure is an unexpected pass at the
        # source, not a positive qualified cell.
        doc = history([
            run_entry(2, host_rows=[{"cell": CELL, "pass": True,
                                     "qualification": "expected-failure",
                                     "detail": "UNEXPECTED PASS"}],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{CELL} on host went", result.stderr)

    def test_history_with_non_boolean_pass_is_refused(self):
        # Schema-invalid rows never reach the judge: --history-json
        # input with a non-boolean pass fails at load.
        doc = history([
            run_entry(2, host_rows=[{"cell": CELL, "pass": "yes",
                                     "qualification": "qualified",
                                     "detail": "ok"}],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pass must be a boolean", result.stderr)

    def test_history_missing_detail_is_refused(self):
        # Devin's case: a pass-shaped row missing `detail` must not
        # reset the window; the history input is refused instead.
        doc = history([
            run_entry(2, host_rows=[{"cell": CELL, "pass": True,
                                     "qualification": "qualified"}],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("row must have exactly cell/pass/qualification/detail",
                      result.stderr)

    def test_history_extra_key_is_refused(self):
        doc = history([
            run_entry(2, host_rows=[dict(row(CELL, True), notes="extra")],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("row must have exactly cell/pass/qualification/detail",
                      result.stderr)

    def test_history_non_string_detail_is_refused(self):
        bad = row(CELL, True)
        bad["detail"] = ["ok"]
        doc = history([
            run_entry(2, host_rows=[bad],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("detail must be a string", result.stderr)

    def test_history_wrong_key_types_are_refused(self):
        bad = {"cell": 42, "pass": True, "qualification": "qualified",
               "detail": "ok"}
        doc = history([
            run_entry(2, host_rows=[bad],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cell must be a nonempty string", result.stderr)

    def test_bounds_leaves_no_bytecode_beside_shared_validator(self):
        # A gate must not mutate the tree it validates: importing
        # the shared row validator must not drop __pycache__ next
        # to the staged scripts.
        cache = SCRIPT.parent / "__pycache__"
        shutil.rmtree(cache, ignore_errors=True)
        doc = history([
            run_entry(1, host_rows=[row(CELL, True)],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix",
                                 window=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(cache.exists())

    def test_history_duplicate_keys_are_refused(self):
        # Duplicate JSON keys collapse lossily under bare
        # json.loads; the history document is parsed strictly,
        # so a flipped pass bit never reaches the judge.
        text = (
            '{"runs": [{"id": 2, "branch": "test/x", "results": {"host": ['
            '{"cell": "flaky_cell", "pass": false, "pass": true, '
            '"qualification": "qualified", "detail": "ok"}], '
            '"v6.6.157": []}}, '
            '{"id": 1, "branch": "test/x", "results": {"host": [], '
            '"v6.6.157": []}}]}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            path.write_text(text)
            args = [sys.executable, "-I", str(SCRIPT),
                    "--history-json", str(path),
                    "--window", "3",
                    "--kernel", "host", "--kernel", "v6.6.157",
                    "--cell", f"{CELL}=task/fix"]
            result = subprocess.run(args, capture_output=True, text=True,
                                    timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate key", result.stderr)
        self.assertNotIn("last pass", result.stdout)

    def test_live_malformed_artifact_is_skipped_loudly(self):
        # The live fetch path (fake gh below, no network): an
        # artifact whose rows fail the shared schema is skipped
        # with a loud note and contributes neither pass nor miss.
        # Run 7's host artifact carries a pass-shaped row missing
        # `detail` (Devin's case over the live path); run 6 is
        # valid but never ran the cell. The gate fails closed on
        # both legs instead of counting the malformed row.
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            bad = tmpdir / "bad.zip"
            with zipfile.ZipFile(bad, "w") as bundle:
                bundle.writestr(
                    "cells/results.jsonl",
                    json.dumps({"cell": CELL, "pass": True,
                                "qualification": "qualified"})
                    + "\n",
                )
            good = tmpdir / "good.zip"
            with zipfile.ZipFile(good, "w") as bundle:
                bundle.writestr(
                    "cells/results.jsonl", json.dumps(row(OTHER, True)) + "\n"
                )
            fake = tmpdir / "gh"
            fake.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "run" ]; then\n'
                '  echo \'[{"databaseId": 7, "headBranch": "test/x",'
                ' "conclusion": "failure", "createdAt": "t"},'
                ' {"databaseId": 6, "headBranch": "test/x",'
                ' "conclusion": "success", "createdAt": "t"}]\'\n'
                "elif [ \"$2\" = \"repos/x/y/actions/runs/7/artifacts\" ]; then\n"
                f"  printf 'run-tree-host\\tfile://{bad}\\tfalse\\n'\n"
                "elif [ \"$2\" = \"repos/x/y/actions/runs/6/artifacts\" ]; then\n"
                f"  printf 'run-tree-host\\tfile://{good}\\tfalse\\n'\n"
                "else\n"
                '  cat "${2#file://}"\n'
                "fi\n"
            )
            fake.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = str(tmpdir) + ":" + env["PATH"]
            args = [sys.executable, "-I", str(SCRIPT),
                    "--repo", "x/y", "--window", "3",
                    "--kernel", "host", "--kernel", "v6.6.157",
                    "--cell", f"{CELL}=task/fix"]
            proc = subprocess.run(args, capture_output=True, text=True,
                                  timeout=30, env=env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SKIP run 7 host: unusable artifact", proc.stdout)
        self.assertIn(f"{CELL} on host never ran in the window", proc.stderr)
        self.assertIn("has no run-tree artifacts in", proc.stderr)
        self.assertNotIn("last pass", proc.stdout)

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

    def test_duplicate_cell_history_is_refused(self):
        # Devin's repro: run 2 host carries an expected-failure row
        # plus a duplicate qualified-pass row for the same cell.
        # The per-run contract allows one row per cell, so the
        # duplicate positive must never reset the window.
        doc = history([
            run_entry(2, host_rows=[row(CELL, False, "expected-failure"),
                                    row(CELL, True)],
                      guest_rows=[row(CELL, True)]),
            run_entry(1, host_rows=[row(CELL, False, "expected-failure")],
                      guest_rows=[row(CELL, True)]),
        ])
        result = self.run_bounds(doc, "--cell", f"{CELL}=task/fix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate cell", result.stderr)
        self.assertNotIn(f"PASS {CELL} on host", result.stdout)

    def test_live_duplicate_cell_artifact_is_skipped_loudly(self):
        # Live fetch path (fake gh, no network): a zip whose
        # results carry two rows for one cell is unusable as a
        # whole, exactly like a schema-invalid artifact.
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            archive = tmpdir / "results.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(
                    "cells/results.jsonl",
                    json.dumps(row(CELL, False, "expected-failure")) + "\n"
                    + json.dumps(row(CELL, True)) + "\n",
                )
            fake = tmpdir / "gh"
            fake.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "run" ]; then\n'
                "  echo '[{\"databaseId\": 7, \"headBranch\": \"test/x\","
                ' "conclusion": "failure", "createdAt": "t"}]\'\n'
                'elif [ "$2" = "repos/x/y/actions/runs/7/artifacts" ]; then\n'
                f"  printf 'run-tree-host\\tfile://{archive}\\tfalse\\n'\n"
                "else\n"
                '  cat "${2#file://}"\n'
                "fi\n"
            )
            fake.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = str(tmpdir) + ":" + env["PATH"]
            args = [sys.executable, "-I", str(SCRIPT),
                    "--repo", "x/y", "--window", "3",
                    "--kernel", "host",
                    "--cell", f"{CELL}=task/fix"]
            proc = subprocess.run(args, capture_output=True, text=True,
                                  timeout=30, env=env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SKIP run 7 host: unusable artifact", proc.stdout)
        self.assertIn("duplicate cell", proc.stdout)
        self.assertNotIn("last pass", proc.stdout)

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
