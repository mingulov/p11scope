#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""First-use sweep oracle twins.

The oracle (scripts/measure-first-use.py) measures one sweep cell from the
fixture ledger of tests/fixtures/system-first-use.c (delay/mode knobs) plus
the observer record: the exact missed-call count from the provider body
counter versus observed calls, and the caller-attribution count from
trace/profile caller labels versus the ledger pid. The two shares stay
separate numbers; a gated cell never counts as positive. Healthy and
mutation twins run unignored; every mutation names the refused field or
comparison.
"""

import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "scripts" / "measure-first-use.py"
SOURCE = ROOT / "tests" / "fixtures" / "system-first-use.c"

try:
    _SPEC = importlib.util.spec_from_file_location(
        "measure_first_use", ORACLE_PATH
    )
    ORACLE = importlib.util.module_from_spec(_SPEC)
    _SPEC.loader.exec_module(ORACLE)
except OSError:
    ORACLE = None


def require_oracle(test):
    """Fail naming the missing production file or return the oracle."""
    if ORACLE is None:
        test.fail(f"oracle missing: {ORACLE_PATH} (implementation not present)")
    return ORACLE


PID = 4242
BIRTH = 1000
MODULE_DEV = 41
MODULE_INO = 777
NS_INO = 555
MODES = ("known-inode", "equal-bytes-new-inode", "unseen-provider",
         "late-heap")
DELAYS = (0, 10, 100, 1000)
COPY_MODES = ("equal-bytes-new-inode", "unseen-provider")


def base_row(phase, mono_ns, extra=None, module_ino=MODULE_INO):
    row = {"phase": phase, "mono_ns": mono_ns, "pid": PID, "birth": BIRTH,
           "module_dev": MODULE_DEV, "module_ino": module_ino,
           "mount_ns_ino": NS_INO}
    if extra:
        row.update(extra)
    return row


def healthy_cell(mode="known-inode", delay_us=100, armed="ungated"):
    """Canned complete knob ledger: verified, cell, one body call."""
    storage = "heap" if mode == "late-heap" else "file"
    module_ino = MODULE_INO + 1 if mode in COPY_MODES else MODULE_INO
    verified = 10_000
    body = verified + delay_us * 1000 + 50_000
    rows = [
        base_row("object_stat", 1_000, module_ino=module_ino),
        base_row("mapped", 2_000, {"table_present": True},
                 module_ino=module_ino),
        base_row("publication_returned", 5_000, module_ino=module_ino),
        base_row("table_verified", verified,
                 {"entries": 68, "table_storage": storage,
                  "entry_address": 99}, module_ino=module_ino),
    ]
    cell = {"mode": mode, "delay_us": delay_us, "armed": armed}
    if mode in COPY_MODES:
        cell.update({"source_dev": MODULE_DEV, "source_ino": MODULE_INO,
                     "bytes_equal": mode == "equal-bytes-new-inode",
                     "size_delta": 0 if mode == "equal-bytes-new-inode"
                     else 256})
    rows.append(base_row("cell", verified + 1_000, cell,
                         module_ino=module_ino))
    rows.append(base_row("entry_executed", body, {"body_count": 1},
                         module_ino=module_ino))
    rows.append(base_row("entry_returned", body + 1_000, {"rv": 0},
                         module_ino=module_ino))
    rows.append(base_row("unloaded", body + 2_000, module_ino=module_ino))
    return rows


def healthy_observer(observed=1, unknown=0, pid=PID):
    rows = [{"pid": pid, "label": "workload"}
            for _ in range(observed - unknown)]
    rows += [{"pid": pid, "label": "Unknown executable"}
             for _ in range(unknown)]
    return {"observed_calls": observed, "caller_rows": rows}


class CellValidationTests(unittest.TestCase):
    def test_complete_cell_validates_with_facts(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell("known-inode", 100,
                                                 "ungated"))
        self.assertEqual(cell["mode"], "known-inode")
        self.assertEqual(cell["delay_us"], 100)
        self.assertEqual(cell["armed"], "ungated")
        self.assertTrue(cell["complete"])
        self.assertEqual(cell["body_count"], 1)
        self.assertEqual(cell["storage"], "file")
        self.assertTrue(cell["delay_honored"])
        self.assertEqual(cell["pid"], PID)

    def test_default_ledger_without_cell_row_is_refused(self):
        oracle = require_oracle(self)
        rows = [row for row in healthy_cell() if row["phase"] != "cell"]
        with self.assertRaisesRegex(oracle.MeasureError, "not a knob cell"):
            oracle.validate_cell(rows)

    def test_second_cell_row_is_refused(self):
        oracle = require_oracle(self)
        rows = healthy_cell()
        rows.insert(1, dict(rows[4]))
        with self.assertRaisesRegex(oracle.MeasureError, "one cell row"):
            oracle.validate_cell(rows)

    def test_unknown_mode_delay_and_arm_are_refused(self):
        oracle = require_oracle(self)
        rows = healthy_cell()
        rows[4]["mode"] = "future-mode"
        with self.assertRaisesRegex(oracle.MeasureError, "unknown mode"):
            oracle.validate_cell(rows)
        rows = healthy_cell()
        rows[4]["delay_us"] = 5
        with self.assertRaisesRegex(oracle.MeasureError, "unknown delay"):
            oracle.validate_cell(rows)
        rows = healthy_cell()
        rows[4]["armed"] = "maybe"
        with self.assertRaisesRegex(oracle.MeasureError, "unknown armed"):
            oracle.validate_cell(rows)

    def test_dishonored_delay_is_refused(self):
        oracle = require_oracle(self)
        rows = healthy_cell(delay_us=1000)
        rows[5]["mono_ns"] = rows[3]["mono_ns"] + 1_000
        with self.assertRaisesRegex(oracle.MeasureError,
                                    "delay not honored"):
            oracle.validate_cell(rows)

    def test_late_heap_cell_without_heap_publication_is_refused(self):
        oracle = require_oracle(self)
        rows = healthy_cell("late-heap")
        rows[3]["table_storage"] = "file"
        with self.assertRaisesRegex(oracle.MeasureError,
                                    "without heap publication"):
            oracle.validate_cell(rows)

    def test_copy_mode_needs_distinct_source_identity(self):
        oracle = require_oracle(self)
        rows = healthy_cell("equal-bytes-new-inode")
        del rows[4]["source_ino"]
        with self.assertRaisesRegex(oracle.MeasureError, "source identity"):
            oracle.validate_cell(rows)
        rows = healthy_cell("unseen-provider")
        rows[4]["bytes_equal"] = True
        with self.assertRaisesRegex(oracle.MeasureError, "bytes_equal"):
            oracle.validate_cell(rows)

    def test_incomplete_cell_reports_not_complete(self):
        oracle = require_oracle(self)
        rows = [row for row in healthy_cell()
                if row["phase"] not in ("entry_executed", "entry_returned",
                                        "unloaded")]
        cell = oracle.validate_cell(rows)
        self.assertFalse(cell["complete"])
        self.assertEqual(cell["body_count"], 0)

    def test_mixed_pid_ledger_is_refused(self):
        oracle = require_oracle(self)
        rows = healthy_cell()
        rows[5]["pid"] = 9999
        with self.assertRaisesRegex(oracle.MeasureError, "mixes"):
            oracle.validate_cell(rows)

    def test_corrupt_body_count_is_refused(self):
        oracle = require_oracle(self)
        rows = healthy_cell()
        rows[5]["body_count"] = "1"
        with self.assertRaisesRegex(oracle.MeasureError, "body_count"):
            oracle.validate_cell(rows)

    def test_missing_table_verified_means_incomplete(self):
        oracle = require_oracle(self)
        rows = [row for row in healthy_cell()
                if row["phase"] != "table_verified"]
        cell = oracle.validate_cell(rows)
        self.assertFalse(cell["complete"])
        self.assertIsNone(cell["storage"])

    def test_copy_field_mismatches_are_refused(self):
        oracle = require_oracle(self)
        cases = [
            ("equal-bytes-new-inode", {"bytes_equal": False}, "bytes_equal"),
            ("unseen-provider", {"size_delta": 0}, "size_delta"),
        ]
        for mode, patch, reason in cases:
            with self.subTest(mode=mode, patch=patch):
                rows = healthy_cell(mode)
                rows[4].update(patch)
                with self.assertRaisesRegex(oracle.MeasureError, reason):
                    oracle.validate_cell(rows)
        rows = healthy_cell("equal-bytes-new-inode")
        rows[4]["source_ino"] = rows[4]["module_ino"]
        with self.assertRaisesRegex(oracle.MeasureError, "source identity"):
            oracle.validate_cell(rows)


class MissedCallTests(unittest.TestCase):
    def test_exact_missed_count_is_reported(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell())
        missed = oracle.missed_calls(cell, healthy_observer(1))
        self.assertEqual(missed, {"body_calls": 1, "observed_calls": 1,
                                  "missed_calls": 0})
        missed = oracle.missed_calls(cell, healthy_observer(0))
        self.assertEqual(missed["missed_calls"], 1)

    def test_observer_overcount_is_refused(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell())
        with self.assertRaisesRegex(oracle.MeasureError,
                                    "counted 2 calls but the body ran 1"):
            oracle.missed_calls(cell, healthy_observer(2))

    def test_malformed_observer_is_refused(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell())
        cases = [
            ({}, "observed_calls"),
            ({"observed_calls": -1, "caller_rows": []}, "observed_calls"),
            ({"observed_calls": 1, "caller_rows": {}}, "caller_rows"),
            ({"observed_calls": 1, "caller_rows": ["x"]}, "caller row"),
        ]
        for observer, reason in cases:
            with self.subTest(observer=observer):
                with self.assertRaisesRegex(oracle.MeasureError, reason):
                    oracle.cell_verdict(cell, observer)


class AttributionTests(unittest.TestCase):
    def test_attributed_and_unknown_counts_stay_separate(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell())
        attributed = oracle.attribution(cell, healthy_observer(3, unknown=1))
        self.assertEqual(attributed, {"observed_calls": 3,
                                      "attributed_calls": 2})

    def test_caller_rows_must_account_every_observed_call(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell())
        observer = healthy_observer(2)
        observer["caller_rows"].pop()
        with self.assertRaisesRegex(oracle.MeasureError,
                                    "do not account observed 2"):
            oracle.attribution(cell, observer)

    def test_foreign_pid_caller_row_is_refused(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell())
        observer = healthy_observer(1, pid=9999)
        with self.assertRaisesRegex(oracle.MeasureError,
                                    "outside the cell pid 4242"):
            oracle.attribution(cell, observer)


class ReportShapeTests(unittest.TestCase):
    def test_separate_sections_pass(self):
        oracle = require_oracle(self)
        report = {"missed": {"body_calls": 1, "observed_calls": 1,
                             "missed_calls": 0},
                  "attribution": {"observed_calls": 1,
                                  "attributed_calls": 1}}
        self.assertEqual(oracle.validate_report(report)["verdict"], "pass")

    def test_merged_share_is_refused(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.MeasureError, "separate"):
            oracle.validate_report({"share": 0.5})

    def test_missing_attribution_is_refused(self):
        oracle = require_oracle(self)
        report = {"missed": {"body_calls": 1, "observed_calls": 1,
                             "missed_calls": 0}}
        with self.assertRaisesRegex(oracle.MeasureError, "separate"):
            oracle.validate_report(report)

    def test_float_counts_are_refused(self):
        oracle = require_oracle(self)
        report = {"missed": {"body_calls": 1, "observed_calls": 1,
                             "missed_calls": 0.0},
                  "attribution": {"observed_calls": 1,
                                  "attributed_calls": 1}}
        with self.assertRaisesRegex(oracle.MeasureError, "integers"):
            oracle.validate_report(report)

    def test_sections_disagreeing_on_observed_are_refused(self):
        oracle = require_oracle(self)
        report = {"missed": {"body_calls": 2, "observed_calls": 2,
                             "missed_calls": 0},
                  "attribution": {"observed_calls": 1,
                                  "attributed_calls": 1}}
        with self.assertRaisesRegex(oracle.MeasureError, "disagree"):
            oracle.validate_report(report)

    def test_report_arithmetic_is_checked(self):
        oracle = require_oracle(self)
        bad_missed = {
            "missed": {"body_calls": 2, "observed_calls": 1,
                       "missed_calls": 5},
            "attribution": {"observed_calls": 1, "attributed_calls": 1}}
        with self.assertRaisesRegex(oracle.MeasureError, "disagree"):
            oracle.validate_report(bad_missed)
        over_observed = {
            "missed": {"body_calls": 1, "observed_calls": 2,
                       "missed_calls": 0},
            "attribution": {"observed_calls": 2, "attributed_calls": 2}}
        with self.assertRaisesRegex(oracle.MeasureError, "above body"):
            oracle.validate_report(over_observed)
        over_attributed = {
            "missed": {"body_calls": 2, "observed_calls": 1,
                       "missed_calls": 1},
            "attribution": {"observed_calls": 1, "attributed_calls": 3}}
        with self.assertRaisesRegex(oracle.MeasureError, "outside observed"):
            oracle.validate_report(over_attributed)


class VerdictTests(unittest.TestCase):
    def test_ungated_complete_cell_is_positive(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell("known-inode", 10,
                                                 "ungated"))
        verdict = oracle.cell_verdict(cell, healthy_observer(1))
        self.assertTrue(verdict["positive"])
        self.assertEqual(verdict["missed"]["missed_calls"], 0)
        self.assertEqual(verdict["attribution"]["attributed_calls"], 1)

    def test_prearmed_complete_cell_is_positive(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell("known-inode", 10,
                                                 "prearmed"))
        verdict = oracle.cell_verdict(cell, healthy_observer(1))
        self.assertTrue(verdict["positive"])
        self.assertEqual(verdict["armed"], "prearmed")

    def test_gated_cell_never_counts_as_positive(self):
        oracle = require_oracle(self)
        cell = oracle.validate_cell(healthy_cell("known-inode", 10, "gated"))
        verdict = oracle.cell_verdict(cell, healthy_observer(1))
        self.assertFalse(verdict["positive"])
        self.assertIn("gated", verdict["reason"])

    def test_incomplete_cell_is_not_positive(self):
        oracle = require_oracle(self)
        rows = [row for row in healthy_cell()
                if row["phase"] != "entry_executed"]
        cell = oracle.validate_cell(rows)
        verdict = oracle.cell_verdict(cell, healthy_observer(0))
        self.assertFalse(verdict["positive"])

    def test_full_sweep_matrix_is_positive(self):
        oracle = require_oracle(self)
        positives = 0
        for mode in MODES:
            for delay_us in DELAYS:
                for armed in ("ungated", "prearmed"):
                    cell = oracle.validate_cell(
                        healthy_cell(mode, delay_us, armed))
                    verdict = oracle.cell_verdict(
                        cell, healthy_observer(1))
                    self.assertTrue(verdict["positive"], (mode, delay_us))
                    positives += 1
        self.assertEqual(positives, 32)


class BoundTableTests(unittest.TestCase):
    TABLE = {"0": 1, "10": 1, "100": 0, "1000": 0}

    def test_sweep_within_bounds_passes(self):
        oracle = require_oracle(self)
        entries = [{"mode": "known-inode", "delay_us": 100,
                    "missed_calls": 0},
                   {"mode": "late-heap", "delay_us": 0, "missed_calls": 1}]
        verdict = oracle.check_bounds(entries, dict(self.TABLE))
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["cells"], 2)

    def test_bound_exceedance_fails_naming_mode_and_delay(self):
        oracle = require_oracle(self)
        entries = [{"mode": "unseen-provider", "delay_us": 1000,
                    "missed_calls": 1}]
        with self.assertRaisesRegex(oracle.MeasureError,
                                    "unseen-provider at delay 1000"):
            oracle.check_bounds(entries, dict(self.TABLE))

    def test_malformed_bound_table_is_refused(self):
        oracle = require_oracle(self)
        entries = [{"mode": "known-inode", "delay_us": 100,
                    "missed_calls": 0}]
        with self.assertRaisesRegex(oracle.MeasureError, "bound table"):
            oracle.check_bounds(entries, {"100": 0})
        with self.assertRaisesRegex(oracle.MeasureError, "bound table"):
            oracle.check_bounds(entries, {"0": 1, "10": 1, "100": 0,
                                          "1000": -1})


class FirstUseKnobFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="p11scope-knob-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.base = Path(cls.build.name)
        cls.driver = cls.base / "driver"
        flags = ["gcc", "-O0", "-g", "-Wall", "-Wextra", "-Werror"]
        subprocess.run([*flags, str(SOURCE), "-ldl", "-o", str(cls.driver)],
                       check=True)
        cls.providers = {}
        for kind, extra in (("file", []), ("heap", ["-DT2_HEAP_TABLE"])):
            path = cls.base / f"provider-{kind}.so"
            subprocess.run([*flags, "-shared", "-fPIC", "-DT2_PROVIDER",
                            *extra, str(SOURCE), "-o", str(path)], check=True)
            cls.providers[kind] = path

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="p11scope-knob-case-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.ledger = self.work / "ledger.jsonl"

    def run_driver(self, *args, timeout=10):
        return subprocess.run([str(self.driver), *args], capture_output=True,
                              text=True, timeout=timeout)

    def rows(self):
        return [json.loads(line) for line in
                self.ledger.read_text().splitlines() if line.strip()]

    def test_default_run_has_no_cell_row(self):
        result = self.run_driver(str(self.providers["file"]),
                                 str(self.ledger), "-", "-")
        self.assertEqual(result.returncode, 0, result.stderr)
        phases = [row["phase"] for row in self.rows()]
        self.assertEqual(phases, ["object_stat", "mapped",
                                  "publication_returned", "table_verified",
                                  "entry_executed", "entry_returned",
                                  "unloaded"])

    def test_known_inode_cell_carries_mode_delay_and_arm(self):
        result = self.run_driver(
            str(self.providers["file"]), str(self.ledger), "-", "-",
            "--delay-us", "100", "--mode", "known-inode")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        rows = self.rows()
        self.assertEqual([row["phase"] for row in rows],
                         ["object_stat", "mapped", "publication_returned",
                          "table_verified", "cell", "entry_executed",
                          "entry_returned", "unloaded"])
        cell = rows[4]
        self.assertEqual(cell["mode"], "known-inode")
        self.assertEqual(cell["delay_us"], 100)
        self.assertEqual(cell["armed"], "ungated")
        self.assertNotIn("source_ino", cell)
        executed = next(row for row in rows
                        if row["phase"] == "entry_executed")
        verified = next(row for row in rows
                        if row["phase"] == "table_verified")
        self.assertGreaterEqual(executed["mono_ns"] - verified["mono_ns"],
                                100 * 1000)

    def test_knob_order_is_free(self):
        result = self.run_driver(
            str(self.providers["file"]), str(self.ledger), "-", "-",
            "--mode", "known-inode", "--delay-us", "10")
        self.assertEqual(result.returncode, 0, result.stderr)
        cell = next(row for row in self.rows() if row["phase"] == "cell")
        self.assertEqual((cell["mode"], cell["delay_us"]),
                         ("known-inode", 10))

    def test_every_delay_is_honored_on_the_stamps(self):
        for delay_us in DELAYS:
            with self.subTest(delay_us=delay_us):
                ledger = self.work / f"ledger-{delay_us}.jsonl"
                result = self.run_driver(
                    str(self.providers["file"]), str(ledger), "-", "-",
                    "--delay-us", str(delay_us))
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = [json.loads(line) for line in
                        ledger.read_text().splitlines() if line.strip()]
                executed = next(row for row in rows
                                if row["phase"] == "entry_executed")
                verified = next(row for row in rows
                                if row["phase"] == "table_verified")
                self.assertGreaterEqual(
                    executed["mono_ns"] - verified["mono_ns"],
                    delay_us * 1000)

    def test_equal_bytes_copy_uses_a_new_inode(self):
        result = self.run_driver(
            str(self.providers["file"]), str(self.ledger), "-", "-",
            "--mode", "equal-bytes-new-inode")
        self.assertEqual(result.returncode, 0, result.stderr)
        copies = sorted(self.work.glob("*.provider-copy.so"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(hashlib.sha256(copies[0].read_bytes()).digest(),
                         hashlib.sha256(
                             self.providers["file"].read_bytes()).digest())
        self.assertNotEqual(copies[0].stat().st_ino,
                            self.providers["file"].stat().st_ino)
        rows = self.rows()
        cell = next(row for row in rows if row["phase"] == "cell")
        self.assertEqual(cell["module_ino"], copies[0].stat().st_ino)
        self.assertEqual(cell["source_ino"],
                         self.providers["file"].stat().st_ino)
        self.assertTrue(cell["bytes_equal"])
        self.assertEqual(cell["size_delta"], 0)

    def test_unseen_copy_differs_in_bytes(self):
        result = self.run_driver(
            str(self.providers["file"]), str(self.ledger), "-", "-",
            "--mode", "unseen-provider")
        self.assertEqual(result.returncode, 0, result.stderr)
        copies = sorted(self.work.glob("*.provider-copy.so"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].stat().st_size,
                         self.providers["file"].stat().st_size + 256)
        self.assertNotEqual(hashlib.sha256(copies[0].read_bytes()).digest(),
                            hashlib.sha256(
                                self.providers["file"].read_bytes()).digest())
        rows = self.rows()
        cell = next(row for row in rows if row["phase"] == "cell")
        self.assertFalse(cell["bytes_equal"])
        self.assertEqual(cell["size_delta"], 256)

    def test_late_heap_refuses_a_file_backed_table(self):
        result = self.run_driver(
            str(self.providers["file"]), str(self.ledger), "-", "-",
            "--mode", "late-heap")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("heap", result.stderr)
        phases = [row["phase"] for row in self.rows()]
        self.assertIn("table_verified", phases)
        self.assertNotIn("entry_executed", phases)

    def test_late_heap_accepts_heap_publication(self):
        result = self.run_driver(
            str(self.providers["heap"]), str(self.ledger), "-", "-",
            "--mode", "late-heap")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.rows()
        verified = next(row for row in rows
                        if row["phase"] == "table_verified")
        self.assertEqual(verified["table_storage"], "heap")
        cell = next(row for row in rows if row["phase"] == "cell")
        self.assertEqual(cell["mode"], "late-heap")

    def test_prearmed_gates_report_prearmed(self):
        publication = self.work / "publish-go"
        entry = self.work / "entry-go"
        publication.touch()
        entry.touch()
        result = self.run_driver(
            str(self.providers["file"]), str(self.ledger),
            str(publication), str(entry), "--delay-us", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        cell = next(row for row in self.rows() if row["phase"] == "cell")
        self.assertEqual(cell["armed"], "prearmed")

    def test_waited_gate_reports_gated(self):
        entry = self.work / "entry-go"
        child = subprocess.Popen(
            [str(self.driver), str(self.providers["file"]),
             str(self.ledger), "-", str(entry), "--delay-us", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def settle():
            if child.poll() is None:
                child.terminate()
            child.communicate(timeout=5)
        self.addCleanup(settle)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.ledger.exists():
                phases = [json.loads(line)["phase"] for line in
                          self.ledger.read_text().splitlines()
                          if line.strip()]
                if "table_verified" in phases:
                    break
            time.sleep(0.01)
        else:
            self.fail("fixture did not reach table_verified")
        time.sleep(0.05)
        entry.touch()
        _, error = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 0, error)
        cell = next(row for row in self.rows() if row["phase"] == "cell")
        self.assertEqual(cell["armed"], "gated")

    def test_bad_knobs_exit_usage(self):
        cases = [
            ("--delay-us", "5"),
            ("--delay-us",),
            ("--mode", "bogus"),
            ("--mode", "known-inode", "--mode", "late-heap"),
            ("--bogus", "1"),
            ("stray",),
        ]
        for number, extra in enumerate(cases):
            with self.subTest(extra=extra):
                ledger = self.work / f"ledger-bad-{number}.jsonl"
                result = self.run_driver(
                    str(self.providers["file"]), str(ledger), "-", "-",
                    *extra)
                self.assertEqual(result.returncode, 2, extra)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(ledger.exists())

    def test_copy_collision_exits_setup_error(self):
        (self.work / "ledger.jsonl.provider-copy.so").write_text("stale\n")
        result = self.run_driver(
            str(self.providers["file"]), str(self.ledger), "-", "-",
            "--mode", "equal-bytes-new-inode")
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertFalse(self.ledger.exists())

    def test_knobs_after_receipt_args_keep_receipt_order(self):
        result = self.run_driver(
            str(self.providers["file"]), str(self.ledger), "-", "-",
            "3", "bad-nonce", str(self.work),
            "--delay-us", "10", "--mode", "known-inode")
        self.assertEqual(result.returncode, 2)
        self.assertIn("receipt arguments", result.stderr)
        self.assertFalse(self.ledger.exists())


class OracleCliTests(unittest.TestCase):
    def run_cli(self, argv):
        oracle = require_oracle(self)
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = oracle.main(argv)
        return code, out.getvalue(), err.getvalue()

    def write_inputs(self, directory, rows, observer):
        ledger = Path(directory) / "ledger.jsonl"
        with open(ledger, "w", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row) + "\n")
        seen = Path(directory) / "observer.json"
        seen.write_text(json.dumps(observer))
        return ledger, seen

    def test_cli_reports_a_positive_cell(self):
        require_oracle(self)
        work = tempfile.TemporaryDirectory(prefix="p11scope-firstuse-cli-")
        self.addCleanup(work.cleanup)
        ledger, seen = self.write_inputs(
            work.name, healthy_cell("known-inode", 100, "ungated"),
            healthy_observer(1))
        code, out, _ = self.run_cli([str(ledger), str(seen)])
        self.assertEqual(code, 0)
        verdict = json.loads(out)
        self.assertTrue(verdict["positive"])

    def test_cli_reports_gated_as_not_positive(self):
        require_oracle(self)
        work = tempfile.TemporaryDirectory(prefix="p11scope-firstuse-cli-")
        self.addCleanup(work.cleanup)
        ledger, seen = self.write_inputs(
            work.name, healthy_cell("known-inode", 100, "gated"),
            healthy_observer(1))
        code, out, _ = self.run_cli([str(ledger), str(seen)])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["positive"])

    def test_cli_refuses_an_overcount(self):
        require_oracle(self)
        work = tempfile.TemporaryDirectory(prefix="p11scope-firstuse-cli-")
        self.addCleanup(work.cleanup)
        ledger, seen = self.write_inputs(
            work.name, healthy_cell(), healthy_observer(2))
        code, _, err = self.run_cli([str(ledger), str(seen)])
        self.assertEqual(code, 1)
        self.assertIn("first-use refused", err)

    def test_cli_bounds_flag_gates_the_cell(self):
        require_oracle(self)
        work = tempfile.TemporaryDirectory(prefix="p11scope-firstuse-cli-")
        self.addCleanup(work.cleanup)
        ledger, seen = self.write_inputs(
            work.name, healthy_cell("known-inode", 1000, "ungated"),
            healthy_observer(0))
        bounds = Path(work.name) / "bounds.json"
        bounds.write_text(json.dumps({"0": 1, "10": 1, "100": 0,
                                      "1000": 0}))
        code, _, err = self.run_cli([str(ledger), str(seen),
                                     "--bounds", str(bounds)])
        self.assertEqual(code, 1)
        self.assertIn("above bound", err)

    def test_cli_bounds_flag_skips_a_gated_cell(self):
        require_oracle(self)
        work = tempfile.TemporaryDirectory(prefix="p11scope-firstuse-cli-")
        self.addCleanup(work.cleanup)
        ledger, seen = self.write_inputs(
            work.name, healthy_cell("known-inode", 1000, "gated"),
            healthy_observer(0))
        bounds = Path(work.name) / "bounds.json"
        bounds.write_text(json.dumps({"0": 1, "10": 1, "100": 0,
                                      "1000": 0}))
        code, out, _ = self.run_cli([str(ledger), str(seen),
                                     "--bounds", str(bounds)])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["positive"])


if __name__ == "__main__":
    unittest.main()
