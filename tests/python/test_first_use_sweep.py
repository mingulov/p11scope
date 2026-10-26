#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Transient first-use sweep driver twins.

The driver (scripts/run-first-use-sweep.py) runs the 32 installed sweep
cells (4 modes x 4 delays x {ungated, prearmed}) against one observer in a
single host window, judges each cell through scripts/measure-first-use.py,
and writes the delay-indexed bound table. These twins drive the driver's
table, verdict, trace-parsing and bounded-run seams with fake
observer/ledger outputs and small owned inputs: a healthy table, a missing
cell, a gated cell counted positive, an oracle refusal (copy mode without
source identity) and a timeout. Nothing here needs privileges.
"""

import importlib.util
import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SWEEP_PATH = ROOT / "scripts" / "run-first-use-sweep.py"
ORACLE_PATH = ROOT / "scripts" / "measure-first-use.py"


def _load(name, path):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except OSError:
        return None
    return module


SWEEP = _load("first_use_sweep", SWEEP_PATH)
ORACLE = _load("measure_first_use", ORACLE_PATH)


def require_sweep(test):
    """Fail naming the missing production file or return the driver."""
    if SWEEP is None:
        test.fail(f"driver missing: {SWEEP_PATH} (implementation not present)")
    return SWEEP


def require_oracle(test):
    """Fail naming the missing oracle file or return it."""
    if ORACLE is None:
        test.fail(f"oracle missing: {ORACLE_PATH} (implementation not present)")
    return ORACLE


MODES = ("known-inode", "equal-bytes-new-inode", "unseen-provider",
         "late-heap")
DELAYS = (0, 10, 100, 1000)
ARMS = ("ungated", "prearmed")
META = {"source_revision": "0" * 40,
        "observer": {"path": "/tmp/p11scope", "sha256": "ab" * 32},
        "started_unix": 1_000, "finished_unix": 2_000}


def fake_cell(mode="known-inode", delay_us=100, armed="ungated", missed=0,
              observed=1, attributed=1, body=1, status="ok", reason="",
              armed_ledger=None):
    record = {"mode": mode, "delay_us": delay_us, "armed": armed,
              "status": status}
    if status == "ok":
        record.update({
            "armed_ledger": armed if armed_ledger is None else armed_ledger,
            "body_calls": body, "observed_calls": observed,
            "missed_calls": missed, "attributed_calls": attributed,
            "positive": True, "duration_s": 7.5,
            "completeness": "COMPLETE", "final_drain": True,
            "event_loss": 0, "extra_functions": {},
            "observer_argv": ["p11scope", "run"]})
    else:
        record["reason"] = reason or f"{status} in cell"
    return record


def healthy_campaign(missed_at=None):
    """All 32 fabricated positive cells; missed_at maps keys to missed 1."""
    missed_at = missed_at or {}
    return [fake_cell(mode, delay, arm,
                      missed=missed_at.get((mode, delay, arm), 0),
                      observed=1 - missed_at.get((mode, delay, arm), 0),
                      attributed=1 - missed_at.get((mode, delay, arm), 0))
            for mode in MODES for delay in DELAYS for arm in ARMS]


TRACE_HEAD = ("Trace \u2014 completed call events in arrival order\n"
              "Executable labels use verified observed paths; "
              "event PID/TID remain diagnostic identifiers.\n"
              "CAPTURE privacy=allowlisted\n")


def trace_row(pid=4242, tid=4242, fn="C_Initialize", label='"fixture"',
              path=' exe="/tmp/fixture"', rv="CKR_OK", duration="3.0\u00b5s"):
    return (f"00:00:01.000000 {label} (PID {pid}, TID {tid}){path} "
            f"{fn} \u2192 {rv} {duration}\n")


def trace_tail(count=1):
    counts = {"stats_entered": count, "stats_returned": count,
              "raw_calls": count}
    evidence = {"privacy_mode": "allowlisted", "completeness": "COMPLETE",
                "final_drain": True, "trace_truncated": False,
                "event_loss": 0}
    return (f"COUNT_EVIDENCE {json.dumps(counts)}\n"
            f"EVIDENCE {json.dumps(evidence)}\n")


def healthy_trace(**row):
    return TRACE_HEAD + trace_row(**row) + trace_tail()


class CampaignTableTests(unittest.TestCase):
    def test_healthy_campaign_passes_with_exact_bounds(self):
        sweep = require_sweep(self)
        missed_at = {("late-heap", 0, "ungated"): 1,
                     ("unseen-provider", 10, "prearmed"): 1}
        result = sweep.build_campaign(healthy_campaign(missed_at), dict(META))
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["table"]["bounds"],
                         {"0": 1, "10": 1, "100": 0, "1000": 0})
        self.assertEqual(len(result["table"]["cells"]), 32)
        first = result["table"]["cells"][0]
        self.assertEqual((first["mode"], first["delay_us"], first["armed"]),
                         ("equal-bytes-new-inode", 0, "prearmed"))
        self.assertEqual(result["table"]["schema"],
                         "p11scope-first-use-sweep/1")

    def test_markdown_table_carries_missed_and_attributed_integers(self):
        sweep = require_sweep(self)
        missed_at = {("known-inode", 0, "ungated"): 1}
        result = sweep.build_campaign(healthy_campaign(missed_at), dict(META))
        lines = result["markdown"].splitlines()
        self.assertEqual(lines[0],
                         "| mode | arm | 0 us | 10 us | 100 us | 1000 us |")
        known_ungated = next(line for line in lines
                             if line.startswith("| known-inode | ungated |"))
        self.assertEqual(known_ungated,
                         "| known-inode | ungated | 1/0 | 0/1 | 0/1 | 0/1 |")
        self.assertEqual(lines[-1],
                         "| bound (max missed) | | 1 | 0 | 0 | 0 |")

    def test_bound_table_feeds_the_oracle_checker(self):
        sweep = require_sweep(self)
        oracle = require_oracle(self)
        missed_at = {("late-heap", 0, "ungated"): 1}
        result = sweep.build_campaign(healthy_campaign(missed_at), dict(META))
        entries = [{"mode": cell["mode"], "delay_us": cell["delay_us"],
                    "missed_calls": cell["missed_calls"]}
                   for cell in result["table"]["cells"]]
        checked = oracle.check_bounds(entries, result["table"]["bounds"])
        self.assertEqual(checked, {"verdict": "pass", "cells": 32})
        over = [{"mode": "known-inode", "delay_us": 100, "missed_calls": 5}]
        with self.assertRaisesRegex(oracle.MeasureError, "above bound"):
            oracle.check_bounds(over, result["table"]["bounds"])

    def test_non_integer_counts_are_refused(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records[0]["missed_calls"] = 0.0
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("integer" in error for error in result["errors"]))


class MissingCellTests(unittest.TestCase):
    def test_missing_cell_fails_naming_its_key(self):
        sweep = require_sweep(self)
        records = [record for record in healthy_campaign()
                   if (record["mode"], record["delay_us"], record["armed"])
                   != ("late-heap", 1000, "prearmed")]
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("late-heap" in error and "1000" in error
                            and "prearmed" in error
                            for error in result["errors"]),
                        result["errors"])

    def test_duplicate_cell_fails(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records.append(dict(records[0]))
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("duplicate" in error for error in result["errors"]),
                        result["errors"])

    def test_unknown_cell_key_fails(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records[0] = fake_cell("future-mode", 0, "ungated")
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("future-mode" in error
                            for error in result["errors"]),
                        result["errors"])

    def test_malformed_record_fails_without_crashing(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records[0] = {"mode": None, "delay_us": 0, "armed": "ungated",
                      "status": "ok"}
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(result["errors"])

    def test_empty_campaign_fails_without_a_silent_skip(self):
        sweep = require_sweep(self)
        result = sweep.build_campaign([], dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(result["errors"])


class GatedPositiveTests(unittest.TestCase):
    def test_gated_cell_counting_positive_fails(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records[0]["armed_ledger"] = "gated"
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("gated" in error and "positive" in error
                            for error in result["errors"]),
                        result["errors"])

    def test_arm_mismatch_fails_even_when_not_positive(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records[0]["armed_ledger"] = "prearmed"
        records[0]["armed"] = "ungated"
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("prearmed" in error and "ungated" in error
                            for error in result["errors"]),
                        result["errors"])

    def test_non_positive_cell_fails(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records[0]["positive"] = False
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(result["errors"])


class OracleFailureTests(unittest.TestCase):
    def test_oracle_refusal_fails_naming_cell_and_reason(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records[0] = fake_cell("equal-bytes-new-inode", 0, "ungated",
                               status="oracle-refused",
                               reason="copy mode without source identity")
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("equal-bytes-new-inode" in error
                            and "source identity" in error
                            for error in result["errors"]),
                        result["errors"])

    def test_copy_mode_without_source_identity_is_an_oracle_refusal(self):
        oracle = require_oracle(self)
        cell = {"mode": "equal-bytes-new-inode", "delay_us": 0,
                "armed": "ungated"}
        rows = [
            {"phase": "object_stat", "mono_ns": 1, "pid": 7, "birth": 9,
             "module_dev": 3, "module_ino": 8, "mount_ns_ino": 5},
            {"phase": "cell", "mono_ns": 2, "pid": 7, "birth": 9,
             "module_dev": 3, "module_ino": 8, "mount_ns_ino": 5, **cell},
        ]
        with self.assertRaisesRegex(oracle.MeasureError, "source identity"):
            oracle.validate_cell(rows)


class ObserverArgvTests(unittest.TestCase):
    def argv(self, sweep, mode="known-inode", delay_us=100, pause="never"):
        built = {"driver": Path("/tmp/build/first-use-driver"),
                 "providers": {"file": Path("/tmp/build/provider-file.so"),
                               "heap": Path("/tmp/build/provider-heap.so")}}
        return sweep.observer_argv(
            Path("/tmp/p11scope"), built["providers"]["file"], built,
            Path("/tmp/cell/ledger.jsonl"), Path("-"), Path("-"),
            mode, delay_us, Path("/tmp/cell/trace.out"), pause)

    def test_pause_policy_selects_the_observer_hold(self):
        sweep = require_sweep(self)
        argv = self.argv(sweep, pause="auto")
        self.assertEqual(argv[argv.index("--pause") + 1], "auto")

    def test_owned_child_trace_with_raw_transient_window(self):
        sweep = require_sweep(self)
        argv = self.argv(sweep)
        self.assertEqual(argv[:3], ["/tmp/p11scope", "run", "--trace"])
        self.assertIn("--pause", argv)
        self.assertEqual(argv[argv.index("--pause") + 1], "never")
        self.assertIn("--module", argv)
        child = argv[argv.index("--") + 1:]
        self.assertEqual(child[-4:], ["--mode", "known-inode",
                                     "--delay-us", "100"])

    def test_copy_modes_omit_the_module_pin(self):
        sweep = require_sweep(self)
        for mode in ("equal-bytes-new-inode", "unseen-provider"):
            with self.subTest(mode=mode):
                self.assertNotIn("--module", self.argv(sweep, mode))
        self.assertIn("--module", self.argv(sweep, "late-heap"))


class TimeoutTests(unittest.TestCase):
    def test_bounded_run_kills_a_hung_command(self):
        sweep = require_sweep(self)
        argv = [sys.executable, "-c", "import time; time.sleep(30)"]
        started = time.monotonic()
        with self.assertRaisesRegex(sweep.SweepTimeout, "[Tt]imeout"):
            sweep.run_bounded(argv, timeout_s=0.2)
        self.assertLess(time.monotonic() - started, 15)

    def test_bounded_run_returns_a_quick_command(self):
        sweep = require_sweep(self)
        done = sweep.run_bounded(
            [sys.executable, "-c", "print('ready')"], timeout_s=10)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, b"ready\n")

    def test_timeout_cell_fails_the_campaign(self):
        sweep = require_sweep(self)
        records = healthy_campaign()
        records[0] = fake_cell("known-inode", 0, "ungated",
                               status="timeout",
                               reason="cell exceeded 120s")
        result = sweep.build_campaign(records, dict(META))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("known-inode" in error and "timeout" in error
                            for error in result["errors"]),
                        result["errors"])


class TraceParseTests(unittest.TestCase):
    def test_named_body_row_parses(self):
        sweep = require_sweep(self)
        parsed = sweep.parse_trace(healthy_trace())
        self.assertEqual(parsed["errors"], [])
        self.assertEqual(len(parsed["rows"]), 1)
        row = parsed["rows"][0]
        self.assertEqual((row["pid"], row["tid"], row["fn"]), (4242, 4242,
                                                              "C_Initialize"))
        self.assertEqual(row["label"], "fixture")
        self.assertEqual(sweep.check_counts(parsed["rows"], parsed["counts"]),
                         [])
        self.assertEqual(sweep.check_evidence(parsed["evidence"]), [])

    def test_unknown_label_row_parses_without_a_name(self):
        sweep = require_sweep(self)
        text = (TRACE_HEAD
                + trace_row(label="Unknown executable", path="")
                + trace_tail())
        parsed = sweep.parse_trace(text)
        self.assertEqual(parsed["errors"], [])
        self.assertIsNone(parsed["rows"][0]["label"])
        record = sweep.build_observer_record(
            sweep.select_body_rows(parsed["rows"], 4242)["body"])
        self.assertEqual(record, {"observed_calls": 1, "caller_rows":
                                  [{"pid": 4242,
                                    "label": "Unknown executable"}]})

    def test_foreign_pid_and_other_functions_are_separated(self):
        sweep = require_sweep(self)
        text = (TRACE_HEAD + trace_row() + trace_row(pid=9999)
                + trace_row(fn="C_GetFunctionList") + trace_tail(count=3))
        parsed = sweep.parse_trace(text)
        self.assertEqual(parsed["errors"], [])
        selected = sweep.select_body_rows(parsed["rows"], 4242)
        self.assertEqual(len(selected["body"]), 1)
        self.assertEqual(len(selected["foreign"]), 1)
        self.assertEqual([row["fn"] for row in selected["extras"]],
                         ["C_GetFunctionList"])

    def test_unexpected_line_is_an_error(self):
        sweep = require_sweep(self)
        parsed = sweep.parse_trace(healthy_trace() + "mystery line\n")
        self.assertTrue(any("mystery" in error for error in parsed["errors"]),
                        parsed["errors"])

    def test_lost_and_truncated_lines_are_errors(self):
        sweep = require_sweep(self)
        parsed = sweep.parse_trace(TRACE_HEAD + "LOST 2 events\n"
                                   + trace_tail(count=0))
        self.assertTrue(any("LOST" in error for error in parsed["errors"]),
                        parsed["errors"])
        parsed = sweep.parse_trace(TRACE_HEAD + trace_row()
                                   + "TRUNCATED at 1 events (default cap; "
                                   "pass --max-events <n> to change it)\n"
                                   + trace_tail())
        self.assertTrue(any("TRUNCATED" in error
                            for error in parsed["errors"]),
                        parsed["errors"])

    def test_count_disagreement_is_an_error(self):
        sweep = require_sweep(self)
        parsed = sweep.parse_trace(TRACE_HEAD + trace_row()
                                   + trace_tail(count=2))
        self.assertTrue(sweep.check_counts(parsed["rows"], parsed["counts"]))

    def test_missing_terminal_records_are_errors(self):
        sweep = require_sweep(self)
        parsed = sweep.parse_trace(TRACE_HEAD + trace_row())
        self.assertTrue(sweep.check_counts(parsed["rows"], parsed["counts"]))
        self.assertTrue(sweep.check_evidence(parsed["evidence"]))

    def test_non_ok_body_return_is_an_error(self):
        sweep = require_sweep(self)
        parsed = sweep.parse_trace(healthy_trace(rv="0x150"))
        self.assertEqual(parsed["errors"], [])
        body = sweep.select_body_rows(parsed["rows"], 4242)["body"]
        self.assertTrue(any("0x150" in error for error in
                            sweep.check_body_returns(body)),
                        "a body row disagreeing with the ledgered rv 0 "
                        "must fail")
        self.assertEqual(sweep.check_body_returns(
            sweep.select_body_rows(
                sweep.parse_trace(healthy_trace())["rows"], 4242)["body"]),
            [])

    def test_lossy_evidence_is_an_error(self):
        sweep = require_sweep(self)
        evidence = [{"privacy_mode": "allowlisted", "event_loss": 1,
                     "final_drain": True}]
        self.assertTrue(any("event_loss" in error for error in
                            sweep.check_evidence(evidence)))
        evidence = [{"privacy_mode": "allowlisted", "event_loss": 0,
                     "final_drain": False}]
        self.assertTrue(sweep.check_evidence(evidence))


if __name__ == "__main__":
    unittest.main()
