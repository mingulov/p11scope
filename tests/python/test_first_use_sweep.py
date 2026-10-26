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

import contextlib
import grp
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

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


def _unknown_gid():
    """A gid the host does not know, for the unknown-gid twin."""
    candidate = 59999
    while True:
        try:
            grp.getgrgid(candidate)
        except KeyError:
            return candidate
        candidate += 1


def _preflight_args(tmp, uid, gid, out=None):
    """A preflight namespace whose files all exist and pass."""
    observer = tmp / "p11scope"
    observer.write_bytes(b"#!/bin/sh\nexit 0\n")
    observer.chmod(0o755)
    measure = tmp / "measure-first-use.py"
    measure.write_text("# oracle\n")
    fixture = tmp / "system-first-use.c"
    fixture.write_text("/* fixture */\n")
    return Namespace(uid=uid, gid=gid, observer=str(observer),
                     measure=str(measure), fixture_source=str(fixture),
                     gcc=sys.executable, cell_timeout=120,
                     out=str(tmp / "out") if out is None else out)


class PreflightTests(unittest.TestCase):
    def test_unknown_gid_is_refused_up_front(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            args = _preflight_args(Path(tmp), os.getuid(), _unknown_gid())
            with mock.patch("os.geteuid", return_value=0):
                with self.assertRaisesRegex(sweep.SweepError,
                                            "unknown workload gid"):
                    sweep.preflight(args)

    def test_known_uid_and_gid_pass_preflight(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            args = _preflight_args(Path(tmp), os.getuid(), os.getgid())
            with mock.patch("os.geteuid", return_value=0):
                ready = sweep.preflight(args)
            self.assertTrue(ready["out"].is_dir())

    def test_uncreatable_out_dir_is_a_refusal_not_a_traceback(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("not a dir\n")
            args = _preflight_args(Path(tmp), os.getuid(), os.getgid(),
                                   out=str(blocker / "sub"))
            with mock.patch("os.geteuid", return_value=0):
                with self.assertRaisesRegex(sweep.SweepError,
                                            "cannot create out dir"):
                    sweep.preflight(args)

    def test_existing_out_dir_keeps_its_refusal(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            args = _preflight_args(Path(tmp), os.getuid(), os.getgid(),
                                   out=str(out))
            with mock.patch("os.geteuid", return_value=0):
                with self.assertRaisesRegex(sweep.SweepError,
                                            "refusing to reuse out dir"):
                    sweep.preflight(args)

    def test_main_turns_an_os_error_into_a_refusal(self):
        sweep = require_sweep(self)
        argv = ["--observer", "/tmp/p11scope", "--uid", "1", "--gid", "1",
               "--out", "/tmp/out"]
        stderr = io.StringIO()
        with mock.patch.object(sweep, "preflight",
                               side_effect=OSError("disk gone")):
            with contextlib.redirect_stderr(stderr):
                status = sweep.main(argv)
        self.assertEqual(status, 1)
        self.assertIn("sweep refused: disk gone", stderr.getvalue())


FAKE_GCC_FAIL = ("import sys\n"
                 "sys.stderr.write('cc1: fatal error: boom\\n')\n"
                 "sys.exit(1)\n")

FAKE_GCC_PROVIDER_FAIL = (
    "import sys\n"
    "argv = sys.argv[1:]\n"
    "if '-shared' in argv:\n"
    "    sys.stderr.write('provider boom\\n')\n"
    "    sys.exit(1)\n"
    "out = argv[argv.index('-o') + 1]\n"
    "open(out, 'wb').write(b'fake')\n")

FAKE_GCC_OK = ("import sys\n"
               "argv = sys.argv[1:]\n"
               "out = argv[argv.index('-o') + 1]\n"
               "open(out, 'wb').write(b'fake')\n")


def _fake_gcc(tmp, body):
    path = tmp / "gcc"
    path.write_text(f"#!{sys.executable}\n" + body)
    path.chmod(0o755)
    return str(path)


class FixtureBuildTests(unittest.TestCase):
    def test_driver_build_failure_keeps_the_compiler_error(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            source = tmp / "system-first-use.c"
            source.write_text("/* fixture */\n")
            with self.assertRaisesRegex(sweep.SweepError, "cc1.*boom"):
                sweep.compile_fixture(_fake_gcc(tmp, FAKE_GCC_FAIL),
                                      source, tmp / "build")

    def test_provider_build_failure_keeps_the_compiler_error(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            source = tmp / "system-first-use.c"
            source.write_text("/* fixture */\n")
            with self.assertRaisesRegex(sweep.SweepError, "provider boom"):
                sweep.compile_fixture(
                    _fake_gcc(tmp, FAKE_GCC_PROVIDER_FAIL), source,
                    tmp / "build")

    def test_successful_build_returns_driver_and_providers(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            source = tmp / "system-first-use.c"
            source.write_text("/* fixture */\n")
            built = sweep.compile_fixture(_fake_gcc(tmp, FAKE_GCC_OK),
                                          source, tmp / "build")
            self.assertTrue(built["driver"].is_file())
            self.assertEqual(set(built["providers"]), {"file", "heap"})


def _stream_row(pid=4242, fn="C_Initialize"):
    return {"label": "fixture", "pid": pid, "tid": pid, "path": "/tmp/fixture",
            "fn": fn, "rv": "CKR_OK", "duration": "3.0µs"}


def _stream_counts(count=1):
    return [{"stats_entered": count, "stats_returned": count,
             "raw_calls": count}]


def _stream_evidence(**extra):
    record = {"privacy_mode": "allowlisted", "completeness": "COMPLETE",
              "final_drain": True, "event_loss": 0}
    record.update(extra)
    return [record]


def _parsed(rows, counts, evidence):
    return {"rows": rows, "counts": counts, "evidence": evidence, "errors": []}


class StreamCompareTests(unittest.TestCase):
    def test_row_disagreement_is_an_error(self):
        sweep = require_sweep(self)
        file_parsed = _parsed([_stream_row()], _stream_counts(),
                              _stream_evidence())
        stdout_parsed = _parsed([_stream_row(fn="C_GetFunctionList")],
                                _stream_counts(), _stream_evidence())
        self.assertEqual(sweep.compare_streams(file_parsed, stdout_parsed),
                         ["stdout/file trace row disagreement"])

    def test_count_disagreement_is_an_error(self):
        sweep = require_sweep(self)
        file_parsed = _parsed([_stream_row()], _stream_counts(count=1),
                              _stream_evidence())
        stdout_parsed = _parsed([_stream_row()], _stream_counts(count=2),
                                _stream_evidence())
        self.assertEqual(sweep.compare_streams(file_parsed, stdout_parsed),
                         ["stdout/file terminal count disagreement"])

    def test_evidence_disagreement_is_an_error(self):
        sweep = require_sweep(self)
        file_parsed = _parsed([_stream_row()], _stream_counts(),
                              _stream_evidence())
        stdout_parsed = _parsed([_stream_row()], _stream_counts(),
                                _stream_evidence(event_loss=1))
        self.assertEqual(sweep.compare_streams(file_parsed, stdout_parsed),
                         ["stdout/file terminal evidence disagreement"])

    def test_sink_only_difference_passes(self):
        sweep = require_sweep(self)
        file_parsed = _parsed(
            [_stream_row()], _stream_counts(),
            _stream_evidence(scheduling={"sink_stall_ms": 0,
                                         "sink_timeouts": 0,
                                         "sink_dropped_bytes": 0}))
        stdout_parsed = _parsed(
            [_stream_row()], _stream_counts(),
            _stream_evidence(scheduling={"sink_stall_ms": 5,
                                         "sink_timeouts": 0,
                                         "sink_dropped_bytes": 0}))
        self.assertEqual(sweep.compare_streams(file_parsed, stdout_parsed),
                         [])

    def test_identical_streams_agree(self):
        sweep = require_sweep(self)
        file_parsed = _parsed([_stream_row()], _stream_counts(),
                              _stream_evidence())
        stdout_parsed = _parsed([_stream_row()], _stream_counts(),
                                _stream_evidence())
        self.assertEqual(sweep.compare_streams(file_parsed, stdout_parsed),
                         [])

    def test_foreign_pid_rows_are_rejected(self):
        sweep = require_sweep(self)
        selected = sweep.select_body_rows(
            [_stream_row(pid=4242), _stream_row(pid=9999)], 4242)
        self.assertEqual(sweep.check_foreign_rows(selected, 4242),
                         ["trace captured 1 rows outside the cell pid 4242"])

    def test_cell_only_rows_pass_the_pid_check(self):
        sweep = require_sweep(self)
        selected = sweep.select_body_rows([_stream_row(pid=4242)], 4242)
        self.assertEqual(sweep.check_foreign_rows(selected, 4242), [])


def _strict_evidence(**extra):
    record = {"privacy_mode": "allowlisted", "completeness": "COMPLETE",
              "final_drain": True, "event_loss": 0}
    record.update(extra)
    return [record]


class EvidenceStrictnessTests(unittest.TestCase):
    def test_missing_completeness_is_an_error(self):
        sweep = require_sweep(self)
        evidence = [{"privacy_mode": "allowlisted", "final_drain": True,
                     "event_loss": 0}]
        self.assertTrue(any("completeness" in error for error in
                            sweep.check_evidence(evidence)),
                        "an exact-count cell must prove its completeness")

    def test_unknown_completeness_is_an_error(self):
        sweep = require_sweep(self)
        self.assertTrue(any("completeness" in error for error in
                            sweep.check_evidence(
                                _strict_evidence(completeness="BOGUS"))))

    def test_complete_and_partial_pass(self):
        sweep = require_sweep(self)
        for value in ("COMPLETE", "PARTIAL"):
            with self.subTest(completeness=value):
                self.assertEqual(
                    sweep.check_evidence(_strict_evidence(completeness=value)),
                    [])

    def test_sink_timeouts_are_an_error(self):
        sweep = require_sweep(self)
        evidence = _strict_evidence(scheduling={"sink_stall_ms": 0,
                                                "sink_timeouts": 1,
                                                "sink_dropped_bytes": 0})
        self.assertTrue(any("sink_timeouts" in error for error in
                            sweep.check_evidence(evidence)))

    def test_sink_dropped_bytes_are_an_error(self):
        sweep = require_sweep(self)
        evidence = _strict_evidence(scheduling={"sink_stall_ms": 0,
                                                "sink_timeouts": 0,
                                                "sink_dropped_bytes": 9})
        self.assertTrue(any("sink_dropped_bytes" in error for error in
                            sweep.check_evidence(evidence)))

    def test_zero_sink_counters_pass(self):
        sweep = require_sweep(self)
        evidence = _strict_evidence(scheduling={"sink_stall_ms": 0,
                                                "sink_timeouts": 0,
                                                "sink_dropped_bytes": 0})
        self.assertEqual(sweep.check_evidence(evidence), [])

    def test_sink_stall_milliseconds_are_an_error(self):
        sweep = require_sweep(self)
        evidence = _strict_evidence(scheduling={"sink_stall_ms": 1,
                                                "sink_timeouts": 0,
                                                "sink_dropped_bytes": 0})
        self.assertTrue(any("sink_stall_ms" in error for error in
                            sweep.check_evidence(evidence)))


def _cell_line(**extra):
    row = {"phase": "cell", "mono_ns": 2, "pid": 7, "birth": 9,
           "module_dev": 3, "module_ino": 8, "mount_ns_ino": 5,
           "mode": "known-inode", "delay_us": 0, "armed": "ungated"}
    row.update(extra)
    return json.dumps(row) + "\n"


class LedgerBoundTests(unittest.TestCase):
    def test_oversize_ledger_is_refused(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            pad = json.dumps({"phase": "pad", "blob": "x" * 40000}) + "\n"
            ledger.write_text(_cell_line() + pad * 30)
            with self.assertRaisesRegex(ValueError, "byte limit"):
                sweep._read_ledger(ledger)

    def test_overlong_ledger_is_refused(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            pad = json.dumps({"phase": "pad"}) + "\n"
            ledger.write_text(pad * 1024 + _cell_line())
            with self.assertRaisesRegex(ValueError, "row limit"):
                sweep._read_ledger(ledger)

    def test_duplicate_key_ledger_is_refused(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            ledger.write_text('{"phase": "cell", "phase": "cell"}\n')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                sweep._read_ledger(ledger)

    def test_small_valid_ledger_reads(self):
        sweep = require_sweep(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            pad = json.dumps({"phase": "pad"}) + "\n"
            ledger.write_text(pad * 3 + _cell_line() + "\n")
            rows, cell = sweep._read_ledger(ledger)
            self.assertEqual(len(rows), 4)
            self.assertEqual(cell["pid"], 7)


if __name__ == "__main__":
    unittest.main()
