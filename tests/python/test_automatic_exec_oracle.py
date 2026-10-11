#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Adversarial controls for the H6 installed-acceptance oracle.

Loads scripts/qualify-automatic-exec.py (the oracle under test) via runpy
and proves each H6 verdict leg both ways: the required rejects
(all-unknown "positive", wrong successor name, outside-scope count,
duplicate return, missing measured phase, manual-rebind path) and the
nonempty ledger-matched accept, plus order-attribution, purity,
abandoned-accounting, reuse, profile/metrics and inventory legs.

Oracle inputs are synthetic. Harness controls use ordinary owned pipes and
Python subprocesses; no privileged observer capture or cgroups are run.
"""

import copy
import inspect
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))

START = 1_000_000_000_000
READY = START + 1_000_000_000
STOP = START + 20_000_000_000
PIN = {"path": "/w/lib.so", "dev": [8, 1], "ino": 111,
       "mapping": {"dev": [8, 1], "ino": 111},
       "sha256": "0" * 64}


def named_row(pid, tid, path, fn, rv="CKR_OK", dur="10µs", wall="21:37:58.638119"):
    label = json.dumps(Path(path).name)
    return (f'{wall} {label} (PID {pid}, TID {tid}) exe={json.dumps(path)} '
            f'{fn} [semantics unverified] → {rv} {dur}')


def unknown_row(pid, tid, fn, rv="CKR_OK", dur="10µs", wall="21:37:58.638119"):
    return (f"{wall} Unknown executable (PID {pid}, TID {tid}) "
            f"{fn} [semantics unverified] → {rv} {dur}")


def evidence(backend="singles", in_flight=0, losses=0, **over):
    ev = {"privacy_mode": "allowlisted", "trace_truncated": False,
          "event_loss": 0, "start_insert_failures": 0, "unmatched_returns": 0,
          "rv_update_failures": 0, "cgroup_scope_failures": 0,
          "process_tracking_failures": 0, "process_tracking_evictions": 0,
          "final_drain": True, "completeness": "PARTIAL",
          "in_flight_at_end": in_flight, "task_uprobe_link_losses": losses,
          "attach_backend": {"selection": backend, "fallback": None,
                             "mechanisms": ["uprobe"]}}
    ev.update(over)
    return ev


def trace_text(rows, entered, returned, ev):
    lines = ["Trace — completed call events in arrival order",
             "Executable labels use verified observed paths; event PID/TID remain diagnostic identifiers.",
             "CAPTURE privacy=allowlisted"]
    lines.extend(rows)
    lines.append(json.dumps({"stats_entered": entered, "stats_returned": returned,
                             "raw_calls": len(rows)}).join(["COUNT_EVIDENCE ", ""]))
    lines.append("EVIDENCE " + json.dumps(ev))
    return "\n".join(lines) + "\n"


def image_record(image, path, t):
    return {"kind": "image", "image": image, "pid": 1000, "start_time": 7777,
            "path": path, "dev": [8, 1], "ino": 100 + image, "mtime_ns": 222,
            "pid_namespace": 1, "time_namespace": 2, "t": t}


def target_record(image, fn):
    return {"kind": "target", "image": image, "fn": fn, "dev": [8, 1],
            "ino": 111, "file_offset": 4096}


def call_record(image, fn, rv, phase, scope, t0, t1, tid=1000):
    return {"kind": "call", "image": image, "pid": 1000, "tid": tid, "fn": fn,
            "rv": rv, "phase": phase, "scope": scope, "sess": 1, "t0": t0, "t1": t1}


def base_receipt(**over):
    receipt = {"cell": "pid-leader", "leg": "trace/singles", "scope_kind": "pid",
               "pid": 1000, "known_tids": [1000], "owned_pids": [1000],
               "provider_before": dict(PIN), "provider_after": dict(PIN),
               "privacy_canaries": [], "observer_stderr": "", "observer_rc": 0,
               "caller_rc": 0, "observer_started_ns": START, "observer_ready_ns": READY,
               "observer_stopped_ns": STOP, "scope_created_ns": START - 1,
               "pid_namespace": 1, "time_namespace": 2,
               "stop_latency_seconds": 0.1, "stop_limit_seconds": 5,
               "successor_policy": "no-transition", "manual_rebind": False, "abandoned_expected": 0,
               "reuse_expected": {}, "requested_backend": "singles"}
    receipt.update(over)
    return receipt


def add_trace_successor_control(text, ledger, receipt):
    measured = receipt["measured"]
    population = [call for call in ledger if call["kind"] == "call" and call["phase"] in measured["phases"]]
    image_id = population[0]["image"]
    image = next(row for row in receipt["images"] if row["image"] == image_id)
    t0 = measured["t0"] - 1000
    marker = call_record(image_id, "C_GetInfo", 0, "successor-marker", "selected", t0, t0 + 10)
    ledger.extend((target_record(image_id, "C_GetInfo"), marker))
    receipt["phases"].append({"image": image_id, "fn": "C_GetInfo", "phase": "successor-marker",
                              "scope": "selected", "count": 1, "t0": t0, "t1": t0 + 10})
    receipt["warmup"]["t1"] = t0 + 10
    receipt["warmup"]["expected_calls"] += 1
    receipt["warmup"]["phases"].append("successor-marker")
    receipt["first_unknown_images"] = []
    rows, counts, evs, _ = H6["N3_PARSE_TRACE"](text)
    early = len(rows) - len(population)
    lines = text.splitlines()[3:-2]
    for index in range(early, len(lines)):
        match = H6["ROW"].fullmatch(lines[index])
        lines[index] = named_row(int(match["pid"]), int(match["tid"]), image["path"], match["fn"], match["rv"])
    lines.insert(early, named_row(image["pid"], image["pid"], image["path"], "C_GetInfo"))
    receipt["successor_policy"] = "public-successor"
    receipt["successor_ready"] = [{"image": image_id, "proof_kind": "trace-row", "started_ns": t0,
        "observed_ns": t0 + 20, "deadline_ns": t0 + 1_000_000_000, "attempts": 1, "max_attempts": 20,
        "output_cursor": 3 + early, "proof_cursor": 4 + early, "marker_fn": "C_GetInfo", "phases": ["successor-marker"]}]
    return trace_text(lines, counts[0]["stats_entered"] + 1, counts[0]["stats_returned"] + 1, evs[0]), ledger, receipt


def caller_inputs(raw=False):
    """Leader exec A->B, pid scope: the nonempty ledger-matched control."""
    warm0 = READY + 100_000_000
    meas0 = READY + 500_000_000
    ledger = [
        image_record(0, "/w/caller-a", READY - 500_000_000),
        target_record(0, "C_GenerateRandom"),
        target_record(0, "C_Initialize"),
        call_record(0, "C_Initialize", 0, "setup", "selected", START - 10, START - 5),
        call_record(0, "C_GenerateRandom", 0, "warm", "selected", warm0, warm0 + 10),
        call_record(0, "C_GenerateRandom", 0, "warm", "selected", warm0 + 20, warm0 + 30),
        {"kind": "exec", "image": 0, "pid": 1000, "tid": 1000, "start_time": 7777,
         "mode": "leader", "path": "/w/caller-b", "scope": "selected",
         "t": warm0 + 100},
        image_record(1, "/w/caller-b", warm0 + 200),
        target_record(1, "C_Initialize"),
        target_record(1, "C_GetSessionInfo"),
        call_record(1, "C_Initialize", 0, "setup", "outside", warm0 + 210, warm0 + 220),
        call_record(1, "C_GetSessionInfo", 0, "measured", "selected", meas0, meas0 + 10),
        call_record(1, "C_GetSessionInfo", 0, "measured", "selected", meas0 + 20, meas0 + 30),
        call_record(1, "C_GetSessionInfo", 0, "measured", "selected", meas0 + 40, meas0 + 50),
    ]
    request = next(row for row in ledger if row["kind"] == "exec")
    receipt = base_receipt(
        images=[image_record(0, "/w/caller-a", READY - 500_000_000),
                image_record(1, "/w/caller-b", warm0 + 200)],
        exec_transitions=[{"from_image": 0, "to_image": 1, "mode": "leader",
                           "same_path": False, "t0": warm0 + 50, "t1": warm0 + 300,
                           "request": request}],
        phases=[{"image": 0, "fn": "C_GenerateRandom", "phase": "warm",
                 "scope": "selected", "count": 2, "t0": warm0 - 1, "t1": warm0 + 40},
                {"image": 1, "fn": "C_GetSessionInfo", "phase": "measured",
                 "scope": "selected", "count": 3, "t0": meas0 - 1, "t1": meas0 + 60}],
        measured={"label": "stable", "t0": meas0 - 1, "t1": meas0 + 60,
                  "expected_calls": 3, "phases": ["measured"]},
        warmup={"label": "pre", "t0": warm0 - 1, "t1": warm0 + 40,
                "expected_calls": 2, "phases": ["warm"]},
        require_named=True, require_named_images=[1], first_unknown_images=[1],
        reuse_expected={"session": True},
        session_reuse={"observed": True, "pre": 1, "post": 1})
    rows = [
        named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom"),
        named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom"),
        unknown_row(1000, 1000, "C_Initialize"),
        unknown_row(1000, 1000, "C_GetSessionInfo"),
        named_row(1000, 1000, "/w/caller-b", "C_GetSessionInfo"),
        named_row(1000, 1000, "/w/caller-b", "C_GetSessionInfo"),
    ]
    # In-window: 2 warm + 1 setup + 3 measured = 6 (gen0 setup is pre-ready).
    text = trace_text(rows, 6, 6, evidence())
    return (text, ledger, receipt) if raw else add_trace_successor_control(text, ledger, receipt)


def b_style_inputs(raw=False):
    """Nonleader exec with an abandoned in-flight frame and rv-5 pattern."""
    pre0 = READY + 100_000_000
    post0 = READY + 600_000_000
    worker = 1042
    ledger = [
        image_record(0, "/w/before", READY - 500_000_000),
        target_record(0, "C_Initialize"),
        call_record(0, "C_Initialize", 0, "pre", "selected", pre0, pre0 + 10, worker),
        call_record(0, "C_Initialize", 5, "pre", "selected", pre0, pre0 + 10, worker),
        call_record(0, "C_Initialize", 0, "pre", "selected", pre0, pre0 + 10, worker),
        {"kind": "exec", "image": 0, "pid": 1000, "tid": worker, "start_time": 7777,
         "mode": "nonleader", "path": "/w/after", "scope": "selected", "t": pre0 + 100},
        image_record(1, "/w/after", pre0 + 200),
        target_record(1, "C_Initialize"),
        call_record(1, "C_Initialize", 0, "post", "selected", post0, post0 + 10),
        call_record(1, "C_Initialize", 5, "post", "selected", post0, post0 + 10),
    ]
    request = next(row for row in ledger if row["kind"] == "exec")
    receipt = base_receipt(
        cell="pid-nonleader-cold",
        known_tids=[1000, worker],
        images=[image_record(0, "/w/before", READY - 500_000_000),
                image_record(1, "/w/after", pre0 + 200)],
        exec_transitions=[{"from_image": 0, "to_image": 1, "mode": "nonleader",
                           "same_path": False, "t0": pre0 + 50, "t1": pre0 + 300,
                           "request": request}],
        phases=[{"image": 0, "fn": "C_Initialize", "phase": "pre",
                 "scope": "selected", "count": 3, "t0": pre0 - 1, "t1": pre0 + 20},
                {"image": 1, "fn": "C_Initialize", "phase": "post",
                 "scope": "selected", "count": 2, "t0": post0 - 1, "t1": post0 + 20}],
        measured={"label": "stable", "t0": post0 - 1, "t1": post0 + 20,
                  "expected_calls": 2, "phases": ["post"]},
        warmup={"label": "pre", "t0": pre0 - 1, "t1": pre0 + 20,
                "expected_calls": 3, "phases": ["pre"]},
        require_named=True, require_named_images=[1], first_unknown_images=[],
        abandoned_expected=1, abandoned_by_fn={"C_Initialize": 1},
        reuse_expected={"token": True}, token_reuse={"observed": True})
    rows = [
        unknown_row(1000, worker, "C_Initialize", "CKR_OK"),
        unknown_row(1000, worker, "C_Initialize", "CKR_GENERAL_ERROR"),
        unknown_row(1000, worker, "C_Initialize", "CKR_OK"),
        unknown_row(1000, 1000, "C_Initialize", "CKR_OK"),
        named_row(1000, 1000, "/w/after", "C_Initialize", "CKR_GENERAL_ERROR"),
    ]
    text = trace_text(rows, 6, 5, evidence(in_flight=1, losses=1))
    return (text, ledger, receipt) if raw else add_trace_successor_control(text, ledger, receipt)


def live_frame(functions, evidence_line="Evidence: 4/4 probes attached → PARTIAL: attribution withheld (count-only slots)"):
    completed = sum(row[1] for row in functions)
    errors = sum(row[2] for row in functions)
    opened = sum(row[3] for row in functions)
    return ("\x1b[2J\x1b[Hp11scope — pid scope — up 00:00:01 — mode profile — privacy=allowlisted — provider\n"
            + profile_stdout(completed, errors, opened).split("\n", 1)[1]
            + "FUNCTION CALLS ERR p50~ p95~ p99~ IN-FLIGHT\n"
            + "".join(f"{fn} {calls} {err} 1µs 1µs 1µs {flight}\n"
                      for fn, calls, err, flight in functions)
            + "(~ = log2-bucket approximation, lower bound)\n" + evidence_line + "\n")


def rapid_successor_inputs():
    text, ledger, receipt = caller_inputs()
    lines = text.splitlines()[3:-2]
    old_proof = receipt["successor_ready"][0]
    for row in ledger:
        if row.get("phase") == "measured": row["phase"] = "middle"
    middle = next(phase for phase in receipt["phases"] if phase["phase"] == "measured")
    middle.update(phase="middle", output_cursor=old_proof["proof_cursor"], output_end=3 + len(lines))
    receipt["phases"][0].update(output_cursor=3, output_end=5)
    image = image_record(2, "/w/caller-c", READY + 700_000_000)
    request = {"kind": "exec", "image": 1, "pid": 1000, "tid": 1000, "start_time": 7777,
               "mode": "leader", "path": image["path"], "scope": "selected", "t": READY + 600_000_000}
    ledger.extend((request, image, target_record(2, "C_GenerateRandom"), target_record(2, "C_GetSessionInfo")))
    t0 = READY + 800_000_000
    marker = call_record(2, "C_GenerateRandom", 0, "successor-2", "selected", t0, t0 + 10)
    ledger.extend((marker, call_record(2, "C_GetSessionInfo", 0, "measured", "selected", t0 + 100, t0 + 110),
                   call_record(2, "C_GetSessionInfo", 0, "measured", "selected", t0 + 120, t0 + 130)))
    receipt["images"].append(image)
    receipt["exec_transitions"].append({"from_image": 1, "to_image": 2, "mode": "leader", "same_path": False,
                                        "t0": request["t"] - 1, "t1": image["t"] + 1, "request": request})
    receipt["phases"].extend(({"image": 2, "fn": "C_GenerateRandom", "phase": marker["phase"], "scope": "selected",
                               "count": 1, "t0": t0, "t1": t0 + 10},
                              {"image": 2, "fn": "C_GetSessionInfo", "phase": "measured", "scope": "selected",
                               "count": 2, "t0": t0 + 100, "t1": t0 + 130}))
    receipt["successor_ready"].append({"image": 2, "proof_kind": "trace-row", "started_ns": t0,
        "observed_ns": t0 + 20, "deadline_ns": t0 + 1_000_000_000, "attempts": 1, "max_attempts": 20,
        "output_cursor": 3 + len(lines), "proof_cursor": 4 + len(lines), "marker_fn": "C_GenerateRandom", "phases": [marker["phase"]]})
    receipt["warmup"].update(t1=t0 + 10, expected_calls=7, phases=["warm", "successor-marker", "middle", marker["phase"]])
    receipt["measured"].update(t0=t0 + 100, t1=t0 + 130, expected_calls=2)
    receipt["trace_generation_guards"] = True
    receipt["require_named_images"] = [2]
    lines.extend((named_row(1000, 1000, image["path"], "C_GenerateRandom"),
                  named_row(1000, 1000, image["path"], "C_GetSessionInfo"),
                  named_row(1000, 1000, image["path"], "C_GetSessionInfo")))
    return trace_text(lines, len(lines), len(lines), evidence()), ledger, receipt


class BDispatchClockTest(unittest.TestCase):
    def test_dispatch_lower_bound_precedes_a_real_child_read(self):
        read_fd, write_fd = os.pipe()
        observed = []
        def receive():
            self.assertEqual(os.read(read_fd, 1), b"W")
            observed.append(time.monotonic_ns())
        reader = threading.Thread(target=receive)
        reader.start()
        class Pipe:
            def write(self, byte): os.write(write_fd, byte.encode())
            def flush(self): reader.join(1)
        class Owner:
            def verify(self): pass
        driver = H6["BDriver"].__new__(H6["BDriver"])
        driver.owned, driver.stamps = Owner(), {}
        driver.owned.popen = mock.Mock(stdin=Pipe())
        try:
            driver.send("W", "warm")
            self.assertEqual(len(observed), 1)
            self.assertLessEqual(driver.stamps["warm"], observed[0])
        finally:
            os.close(write_fd)
            reader.join(1)
            os.close(read_fd)


class RapidSuccessorTest(unittest.TestCase):
    def test_distinct_returned_markers_and_prior_drains_disambiguate_reused_keys(self):
        text, ledger, receipt = rapid_successor_inputs()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["measured_calls"], 2)
        self.assertEqual(result["image_generation_populations"][2], {"named": 3, "unknown": 0})

    def test_missing_wrong_or_stale_prior_drain_keeps_generations_ambiguous(self):
        for change in ("missing", "stale", "wrong", "reused-marker"):
            text, ledger, receipt = rapid_successor_inputs()
            middle = next(phase for phase in receipt["phases"] if phase["phase"] == "middle")
            if change == "missing": del middle["output_end"]
            elif change == "stale": middle["output_end"] += 1
            elif change == "wrong": middle["output_cursor"] += 1
            else: receipt["successor_ready"][1]["marker_fn"] = "C_GetInfo"
            result = H6["evaluate_trace_h6"](text, ledger, receipt)
            self.assertFalse(result["pass"], result)


class DetailedFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="h6-fixture-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        source = ROOT / "tests/fixtures/detailed-nonleader-exec.c"
        for name, flags in (("provider.so", ["-DDETAILED_EXEC_PROVIDER", "-fPIC", "-shared"]),
                            ("before", []), ("after", ["-DDETAILED_EXEC_AFTER"])):
            result = subprocess.run(["cc", *H6["B_CFLAGS"], *flags, str(source), "-ldl",
                                     "-o", str(cls.directory / name)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stderr)

    def child(self, after=True, warm=False, failed=False):
        provider = str(self.directory / "provider.so")
        argv = ([str(self.directory / "after"), provider, str(os.getpid()), "43"] if after
                else [str(self.directory / "before"), provider, str(self.directory / "after"),
                      str(self.directory / "absent"), str(os.getpid()), "43", "1" if failed else "0"])
        if warm:
            argv += ["17", "0", "1"]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=2)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
        self.addCleanup(cleanup)
        reader = H6["Reader"](proc.stdout, self.directory / f"child-{proc.pid}.txt")
        self.addCleanup(reader.thread.join, 2)
        index = 0
        def expect(prefix):
            nonlocal index
            line, index = H6["expect_line"](reader, index, prefix, 2)
            return line.split()
        def send(command):
            proc.stdin.write(command)
            proc.stdin.flush()
        return proc, expect, send

    def test_legacy_after_defaults_remain_17_calls(self):
        proc, expect, send = self.child()
        expect("NEW_READY")
        send("P")
        expect("POST_BODY")
        send("R")
        done = expect("NEW_DONE")
        self.assertEqual([int(v) for v in done[3:6]], [17, 9, 8])
        send("F")
        self.assertEqual(proc.wait(timeout=2), 0)

    def test_opt_in_real_w_attempts_precede_fixed_measurement(self):
        proc, expect, send = self.child(warm=True)
        expect("NEW_READY")
        for sequence in (1, 2):
            send("W")
            done = expect("WARM_DONE")
            self.assertEqual([int(v) for v in done[3:5]], [sequence, 0])
            self.assertLessEqual(int(done[5]), int(done[6]))
        send("P")
        expect("POST_BODY")
        send("R")
        self.assertEqual([int(v) for v in expect("NEW_DONE")[3:6]], [17, 9, 8])
        send("F")
        self.assertEqual(proc.wait(timeout=2), 0)

    def test_nonleader_exec_legacy_defaults_and_opt_in_warmup(self):
        for warm in (False, True):
            with self.subTest(warm=warm):
                proc, expect, send = self.child(after=False, warm=warm)
                expect("READY")
                send("G")
                expect("THREAD")
                expect("WORKER_DONE")
                expect("EXEC_BODY")
                send("X")
                expect("NEW_READY")
                if warm:
                    send("W")
                    self.assertEqual([int(v) for v in expect("WARM_DONE")[3:5]], [1, 0])
                send("P")
                expect("POST_BODY")
                send("R")
                self.assertEqual([int(v) for v in expect("NEW_DONE")[3:6]], [17, 9, 8])
                send("F")
                self.assertEqual(proc.wait(timeout=2), 0)

    def test_failed_exec_retains_exact_29_15_14_control(self):
        proc, expect, send = self.child(after=False, failed=True)
        expect("READY")
        send("G")
        expect("THREAD")
        expect("WORKER_DONE")
        expect("EXEC_BODY")
        send("X")
        expect("EXEC_FAILED")
        send("R")
        self.assertEqual([int(v) for v in expect("DONE")[3:7]], [29, 15, 14, 5])
        send("F")
        self.assertEqual(proc.wait(timeout=2), 0)


class LiveFrameTest(unittest.TestCase):
    def parse(self, text, final=True):
        self.assertTrue(callable(H6.get("parse_live_frames")), "bounded complete-frame parser missing")
        return H6["parse_live_frames"](text, final=final)

    def test_complete_cumulative_frames_use_last_snapshot(self):
        frames = self.parse(live_frame([("C_GetInfo", 1, 0, 0)])
                            + live_frame([("C_GetInfo", 2, 0, 0)]))
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[-1]["functions"]["C_GetInfo"]["calls"], 2)
        self.assertEqual(frames[-1]["totals"], [2, 0, 0])

    def test_incomplete_frame_waits_until_evidence_terminates(self):
        text = live_frame([("C_GetInfo", 1, 0, 0)])
        self.assertEqual(self.parse(text[:-1], final=False), [])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.parse(text[:-1])

    def test_malformed_duplicate_and_overflow_frames_fail(self):
        for text in (live_frame([("C_GetInfo", 1, 0, 0), ("C_GetInfo", 1, 0, 0)]),
                     live_frame([("C_GetInfo", 1, 0, 0)]).replace("1 completed calls", "3 completed calls"),
                     "\x1b[2J\x1b[H" + "x" * 65537):
            with self.subTest(text=text[:70]), self.assertRaises(ValueError):
                self.parse(text)

    def test_empty_eof_has_no_proof(self):
        self.assertEqual(self.parse(""), [])


class WarmSuccessorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="h6-warm-")
        self.addCleanup(self.temporary.cleanup)
        read_fd, write_fd = os.pipe()
        self.stream = os.fdopen(read_fd, encoding="utf-8")
        self.writer = os.fdopen(write_fd, "w", encoding="utf-8")
        self.capture = H6["Reader"](self.stream, Path(self.temporary.name) / "capture.txt")
        self.addCleanup(self.stream.close)
        self.addCleanup(self.capture.thread.join, 2)
        self.addCleanup(self.writer.close)
        self.image = {"image": 1, "pid": 1000, "path": "/w/after"}

    def emit(self, row):
        self.writer.write(row + "\n")
        self.writer.flush()

    def test_retry_preserves_actual_attempt_sequence(self):
        attempts = []
        def attempt(seq, remaining):
            self.assertGreater(remaining, 0)
            attempts.append(seq)
            self.emit(unknown_row(1000, 1000, "C_GetInfo") if seq == 1 else
                      named_row(1000, 1000, "/w/after", "C_GetInfo"))
            return f"warm-{seq}"
        proof = H6["warm_successor"](self.capture, self.image, attempt, max_attempts=2, timeout=2)
        self.assertEqual(attempts, [1, 2])
        self.assertEqual(proof["phases"], ["warm-1", "warm-2"])
        self.assertEqual(proof["attempts"], 2)
        self.assertLessEqual(proof["observed_ns"], proof["deadline_ns"])

    def test_old_unknown_wrong_and_stale_rows_cannot_prove_successor(self):
        self.emit(named_row(1000, 1000, "/w/after", "C_GetInfo"))
        H6["expect_line"](self.capture, 0, "21:", 1)
        def attempt(seq, _remaining):
            for row in (unknown_row(1000, 1000, "C_GetInfo"),
                        named_row(1000, 1000, "/w/before", "C_GetInfo"),
                        named_row(1000, 1000, "/w/after", "C_GenerateRandom")):
                self.emit(row)
            return f"warm-{seq}"
        with self.assertRaisesRegex(TimeoutError, "budget exhausted"):
            H6["warm_successor"](self.capture, self.image, attempt, max_attempts=1, timeout=2)

    def test_absolute_deadline_cannot_accept_late_attempt_ack(self):
        def attempt(seq, _remaining):
            time.sleep(0.07)
            self.emit(named_row(1000, 1000, "/w/after", "C_GetInfo"))
            H6["expect_line"](self.capture, 0, "21:", 1)
            return f"warm-{seq}"
        with self.assertRaisesRegex(TimeoutError, "exhausted"):
            H6["warm_successor"](self.capture, self.image, attempt, timeout=0.05)

    def test_eof_cannot_prove_successor(self):
        self.writer.close()
        self.capture.thread.join(1)
        with self.assertRaisesRegex(EOFError, "stream ended"):
            H6["warm_successor"](self.capture, self.image, lambda seq, remaining: f"warm-{seq}", timeout=1)


class PtyCaptureTest(unittest.TestCase):
    def test_reader_timeout_closes_its_owned_master(self):
        with tempfile.TemporaryDirectory(prefix="h6-pty-timeout-") as directory:
            master, slave = os.openpty()
            capture = H6["PtyCapture"](master, Path(directory) / "stdout.txt")
            try:
                with self.assertRaises(TimeoutError):
                    capture.finish(timeout=0.05)
                self.assertFalse(capture.thread.is_alive())
                with self.assertRaises(OSError):
                    os.fstat(master)
            finally:
                os.close(slave)
                capture.thread.join(2)

    def test_real_split_frame_and_linux_eio_close_are_eof(self):
        with tempfile.TemporaryDirectory(prefix="h6-pty-") as directory:
            master, slave = os.openpty()
            capture = H6["PtyCapture"](master, Path(directory) / "stdout.txt")
            data = live_frame([("C_GetInfo", 1, 0, 0)]).encode()
            child = subprocess.Popen([sys.executable, "-c",
                "import os,time; data=" + repr(data) + "; os.write(1,data[:3]); time.sleep(.03); os.write(1,data[3:])"],
                stdout=slave, stderr=subprocess.PIPE)
            os.close(slave)
            try:
                self.assertEqual(child.wait(timeout=2), 0)
                capture.finish()
                self.assertEqual(capture.frames[-1]["totals"], [1, 0, 0])
                with self.assertRaises(OSError):
                    os.fstat(master)
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=2)
                child.stderr.close()
                capture.thread.join(2)


class SameObserverCounterTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="h6-counter-")
        self.addCleanup(self.temporary.cleanup)
        master, self.slave = os.openpty()
        self.capture = H6["PtyCapture"](master, Path(self.temporary.name) / "capture.txt")
        def close():
            os.close(self.slave)
            self.capture.finish()
        self.addCleanup(close)
        self.image = {"image": 1, "pid": 1000, "path": "/w/after"}

    def frame(self, count):
        os.write(self.slave, live_frame([("C_GetInfo", count, 0, 0)]).encode())

    def test_actual_pty_counter_advance_supplies_complete_snapshots(self):
        self.frame(1)
        def attempt(seq, _remaining):
            self.frame(2)
            return f"warm-{seq}"
        proof = H6["warm_successor"](self.capture, self.image, attempt, mode="metrics", timeout=1)
        self.assertEqual(proof["proof_kind"], "live-counter")
        self.assertEqual(proof["baseline"]["functions"]["C_GetInfo"]["calls"], 1)
        self.assertEqual(proof["snapshot"]["functions"]["C_GetInfo"]["calls"], 2)
        self.assertGreaterEqual(proof["snapshot"]["start_cursor"], proof["output_cursor"])

    def test_fresh_identical_redraw_is_not_a_counter_advance(self):
        self.frame(1)
        def attempt(seq, _remaining):
            self.frame(1)
            return f"warm-{seq}"
        with self.assertRaisesRegex(TimeoutError, "budget exhausted"):
            H6["warm_successor"](self.capture, self.image, attempt, mode="profile", max_attempts=1, timeout=1)

    def test_retry_receipt_keeps_later_displayed_warm_return_in_early_coverage(self):
        doc, _, ledger, receipt = profile_inputs()
        # Put the independent fixture history before the real helper interval.
        shift = time.monotonic_ns() - READY - 1_000_000_000
        for row in [*ledger, *receipt["images"], *receipt["phases"],
                    receipt["warmup"], receipt["measured"],
                    *receipt["exec_transitions"], receipt["exec_transitions"][0]["request"]]:
            for key in ("t", "t0", "t1"):
                if key in row:
                    row[key] += shift
        for key in ("observer_started_ns", "observer_ready_ns", "observer_stopped_ns", "scope_created_ns"):
            receipt[key] += shift
        ledger = [row for row in ledger if row.get("phase") != "successor-marker"]
        receipt["phases"] = [row for row in receipt["phases"] if row["phase"] != "successor-marker"]
        os.write(self.slave, live_frame([("C_Initialize", 3, 1, 1)]).encode())
        warm_calls = []
        def attempt(seq, _remaining):
            t0 = time.monotonic_ns()
            # Attempt 1 completes without a redraw. During attempt 2 the
            # observer displays only attempt 1; both controlled attempts are retained.
            if seq == 2:
                os.write(self.slave, live_frame([("C_Initialize", 3, 1, 1), ("C_GetInfo", 1, 0, 0)]).encode())
            call = call_record(1, "C_GetInfo", 0, f"warm-{seq}", "selected", t0, time.monotonic_ns())
            warm_calls.append(call)
            return call["phase"]
        proof = H6["warm_successor"](self.capture, self.image, attempt, mode="profile", max_attempts=2, timeout=2)
        self.assertEqual(proof["attempts"], 2)
        self.assertEqual(proof["snapshot"]["functions"]["C_GetInfo"]["calls"], 1)
        ledger.extend(warm_calls)
        receipt["successor_ready"] = [proof]
        receipt["warmup"].update(t1=warm_calls[-1]["t1"], expected_calls=5,
                                 phases=["pre", "warm-1", "warm-2"])
        receipt["phases"].extend({"image": 1, "fn": "C_GetInfo", "phase": call["phase"],
            "scope": "selected", "count": 1, "t0": call["t0"], "t1": call["t1"]} for call in warm_calls)
        measured_t0 = time.monotonic_ns()
        for index, call in enumerate(row for row in ledger if row.get("phase") == "post"):
            call.update(t0=measured_t0 + index * 20, t1=measured_t0 + index * 20 + 10)
        receipt["measured"].update(t0=measured_t0, t1=measured_t0 + 40)
        next(row for row in receipt["phases"] if row["phase"] == "post").update(
            t0=measured_t0, t1=measured_t0 + 40)
        os.write(self.slave, live_frame([("C_Initialize", 5, 2, 1), ("C_GetInfo", 2, 0, 0)]).encode())
        H6["_output_wait"](self.capture,
            lambda: True if self.capture.frames and self.capture.frames[-1]["totals"] == [7, 2, 1] else None,
            time.monotonic_ns() + 1_000_000_000)
        receipt["observer_stopped_ns"] = time.monotonic_ns()
        doc["functions"][1]["calls"] = 2
        for mode in ("profile", "metrics"):
            with self.subTest(mode=mode):
                result = H6[f"evaluate_{mode}_h6"](
                    profile_doc(doc["functions"], mode=mode), "".join(self.capture.lines), ledger, receipt)
                self.assertTrue(result["pass"], result)
                self.assertEqual(result["completed_calls"], 7)
                self.assertEqual(result["returned_errors"], 2)
                self.assertEqual(result["measured_calls"], 2)
                self.assertEqual(result["early_coverage"],
                    {"expected": 5, "observed_named": 5, "observed_unknown": 0, "deficit": 0})


def real_early_gap():
    return {"completeness": "PARTIAL", "verdict_detail": "concrete_gap", "unprotected_live_windows": 1,
            "gap_classes": {"observation": {"status": "lossy", "causes": ["unprotected_live_windows"]}}}


class EarlyCoverageTest(unittest.TestCase):
    def deficit(self, gap=True):
        text, ledger, receipt = caller_inputs()
        proof = receipt["successor_ready"][0]
        # The entered/returned attempt is independent even when no public row survives.
        call = next(row for row in ledger if row.get("phase") == "successor-marker" and row["kind"] == "call")
        missed = dict(call, phase="successor-missed", t0=call["t0"] - 20, t1=call["t0"] - 10)
        ledger.append(missed)
        receipt["phases"].append({"image": 1, "fn": "C_GetInfo", "phase": missed["phase"],
                                  "scope": "selected", "count": 1, "t0": missed["t0"], "t1": missed["t1"]})
        receipt["warmup"]["expected_calls"] += 1
        receipt["warmup"]["phases"].append(missed["phase"])
        proof["started_ns"] = missed["t0"]
        proof["phases"].insert(0, missed["phase"])
        proof["attempts"] = 2
        rows, counts, evs, _ = H6["N3_PARSE_TRACE"](text)
        if gap:
            evs[0].update(real_early_gap())
        return trace_text(text.splitlines()[3:-2], counts[0]["stats_entered"], counts[0]["stats_returned"], evs[0]), ledger, receipt

    def test_honest_early_deficit_keeps_exact_nonempty_measurement(self):
        text, ledger, receipt = self.deficit()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["early_coverage"], {"expected": 5, "observed_named": 3, "observed_unknown": 1, "deficit": 1})
        self.assertEqual(result["measured_calls"], 3)
        self.assertEqual(result["api_returned"], 7)
        self.assertEqual(result["expected_api_returns"], 8)

    def test_deficit_requires_relevant_real_gap(self):
        for gap in ({}, {"verdict_detail": "attribution_only"}, {"task_uprobe_link_losses": 3},
                    {**real_early_gap(), "unprotected_live_windows": 0},
                    {**real_early_gap(), "completeness": "COMPLETE"}):
            with self.subTest(gap=gap):
                text, ledger, receipt = self.deficit(gap=False)
                rows, counts, evs, _ = H6["N3_PARSE_TRACE"](text)
                evs[0].update(gap)
                text = trace_text(text.splitlines()[3:-2], 7, 7, evs[0])
                result = H6["evaluate_trace_h6"](text, ledger, receipt)
                self.assertFalse(result["pass"])
                self.assertIn("early deficit lacks relevant real product concrete-gap/PARTIAL evidence", result["errors"])

    def test_stable_missing_duplicate_zero_unknown_and_native_loss_stay_red(self):
        for change in ("missing", "duplicate", "zero", "unknown", "native-loss"):
            with self.subTest(change=change):
                text, ledger, receipt = self.deficit()
                lines = text.splitlines()[3:-2]
                if change == "missing": lines.pop()
                elif change == "duplicate": lines.append(lines[-1])
                elif change == "zero": lines = lines[:-3]
                elif change == "unknown": lines[-1] = unknown_row(1000, 1000, "C_GetSessionInfo")
                ev = evidence(**real_early_gap(), event_loss=1 if change == "native-loss" else 0)
                result = H6["evaluate_trace_h6"](trace_text(lines, len(lines), len(lines), ev), ledger, receipt)
                self.assertFalse(result["pass"], result)


class SuccessorGateTest(unittest.TestCase):
    def test_rejects_missing_successor_proof_despite_initial_ready(self):
        text, ledger, receipt = caller_inputs(raw=True)
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("successor" in error for error in result["errors"]), result)

    def test_missing_independent_successor_image_receipt_is_a_red_verdict(self):
        text, ledger, receipt = caller_inputs()
        receipt["images"] = receipt["images"][:1]
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("image" in error for error in result["errors"]), result)

    def test_rejects_invalid_deadline_attempt_or_current_image_receipt(self):
        for changes in ({"attempts": 0}, {"attempts": 2}, {"max_attempts": 0},
                        {"deadline_ns": READY}, {"deadline_ns": STOP + 30_000_000_000},
                        {"image": 0}, {"observed_ns": STOP}, {"proof_kind": "fixture-ready"}):
            with self.subTest(changes=changes):
                text, ledger, receipt = caller_inputs()
                receipt["successor_ready"][0].update(changes)
                self.assertFalse(H6["evaluate_trace_h6"](text, ledger, receipt)["pass"])

    def test_wrong_old_or_unknown_public_marker_cannot_support_receipt(self):
        for path in ("/w/before", "/w/wrong", None):
            text, ledger, receipt = caller_inputs()
            proof = receipt["successor_ready"][0]
            lines = text.splitlines()
            lines[proof["proof_cursor"] - 1] = (unknown_row(1000, 1000, "C_GetInfo") if path is None
                                              else named_row(1000, 1000, path, "C_GetInfo"))
            result = H6["evaluate_trace_h6"]("\n".join(lines) + "\n", ledger, receipt)
            self.assertFalse(result["pass"])
            self.assertTrue(any("public marker" in error for error in result["errors"]), result)

    def test_rejects_empty_successor_warmup(self):
        text, ledger, receipt = caller_inputs(raw=True)
        receipt["successor_policy"] = "public-successor"
        receipt["successor_ready"] = [{"image": 1, "proof_kind": "trace-row",
            "started_ns": READY + 300_000_000, "observed_ns": READY + 400_000_000,
            "deadline_ns": READY + 2_000_000_000, "max_attempts": 20, "attempts": 0,
            "output_cursor": 3, "proof_cursor": 4, "marker_fn": "C_GetInfo", "phases": []}]
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("successor" in error for error in result["errors"]), result)

    def test_rejects_measurement_before_successor_proof(self):
        text, ledger, receipt = caller_inputs(raw=True)
        receipt["successor_policy"] = "public-successor"
        receipt["successor_ready"] = [{"image": 1, "proof_kind": "trace-row",
            "started_ns": READY + 300_000_000, "observed_ns": READY + 900_000_000,
            "deadline_ns": READY + 2_000_000_000, "max_attempts": 20, "attempts": 1,
            "output_cursor": 3, "proof_cursor": 4, "marker_fn": "C_GetInfo", "phases": ["warm-successor"]}]
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("successor" in error for error in result["errors"]), result)

    def test_rejects_stale_public_proof_cursor(self):
        text, ledger, receipt = caller_inputs(raw=True)
        receipt["successor_policy"] = "public-successor"
        receipt["successor_ready"] = [{"image": 1, "proof_kind": "trace-row",
            "started_ns": READY + 300_000_000, "observed_ns": READY + 400_000_000,
            "deadline_ns": READY + 2_000_000_000, "max_attempts": 20, "attempts": 1,
            "output_cursor": 4, "proof_cursor": 4, "marker_fn": "C_GetInfo", "phases": ["warm-successor"]}]
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("successor" in error for error in result["errors"]), result)


class ReaderReadinessTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="h6-reader-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def pipe_reader(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, encoding="utf-8")
        writer = os.fdopen(write_fd, "w", encoding="utf-8")
        reader = H6["Reader"](stream, self.directory / "reader.txt")
        self.addCleanup(stream.close)
        self.addCleanup(reader.thread.join, 2)
        self.addCleanup(writer.close)
        return reader, writer

    def test_reader_temporary_directory_uses_configured_temp_parent(self):
        self.assertEqual(self.directory.parent, Path(tempfile.gettempdir()))

    def test_expect_line_waits_for_real_reader_delayed_ack(self):
        reader, writer = self.pipe_reader()

        def write_ack():
            writer.write("unrelated\nNEW_READY image=1\n")
            writer.flush()

        timer = threading.Timer(0.05, write_ack)
        self.addCleanup(timer.join, 2)
        timer.start()
        self.assertEqual(H6["expect_line"](reader, 0, "NEW_READY", 2),
                         ("NEW_READY image=1\n", 2))

    def test_expect_line_eof_is_bounded(self):
        reader, writer = self.pipe_reader()
        writer.close()
        reader.thread.join(2)
        self.assertFalse(reader.thread.is_alive())
        with self.assertRaisesRegex(EOFError, "stream ended"):
            H6["expect_line"](reader, 0, "NEW_READY", 2)

    def test_expect_line_preserves_timeout_with_open_stream(self):
        reader, _ = self.pipe_reader()
        with self.assertRaisesRegex(TimeoutError, "timed out"):
            H6["expect_line"](reader, 0, "NEW_READY", 0.05)

    def test_expect_line_surfaces_real_reader_error(self):
        stream = io.TextIOWrapper(io.BytesIO(b"\xff"), encoding="utf-8")
        self.addCleanup(stream.close)
        reader = H6["Reader"](stream, self.directory / "bad-reader.txt")
        reader.thread.join(2)
        self.assertFalse(reader.thread.is_alive())
        with self.assertRaisesRegex(ValueError, "decode"):
            H6["expect_line"](reader, 0, "NEW_READY", 2)

    def test_real_pipe_preserves_split_utf8_ledgers_and_final_unterminated_line(self):
        reader, writer = self.pipe_reader()
        text = 'N3LEDGER {"kind":"first","text":"€"}\r\nN3LEDGER {"kind":"last"}'
        data = text.encode()
        split = data.index("€".encode()) + 1
        os.write(writer.fileno(), data[:split])
        os.write(writer.fileno(), data[split:])
        writer.close()
        self.assertEqual(reader.finish(), text.replace("\r\n", "\n"))
        self.assertEqual(reader.records, [{"kind": "first", "text": "€"}, {"kind": "last"}])

    def test_real_pipe_invalid_utf8_is_a_cleanup_error(self):
        reader, writer = self.pipe_reader()
        os.write(writer.fileno(), b"\xff")
        writer.close()
        with self.assertRaisesRegex(ValueError, "decode"):
            reader.finish()


class LegCleanupTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="h6-leg-cleanup-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.globals = H6["run_cell_backend"].__globals__
        self.ctx = H6["Case"](SimpleNamespace(out=self.directory, uid=os.getuid(), gid=os.getgid()))
        input_path = self.directory / "case-input"
        input_path.write_text("owned input pin\n")
        self.case_pin = H6["FilePin"](input_path)
        self.ctx.pins = {"caller": self.case_pin}
        self.ctx.provider_pin = self.case_pin
        self.ctx.binary = self.case_pin
        self.spawned, self.local_pins = [], []
        self.addCleanup(self.release_test_resources)

    def release_test_resources(self):
        for owner, readers in self.spawned:
            try:
                pid, status = os.waitpid(owner.pid, os.WNOHANG)
                if not pid or not (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                    # waitpid proves this remains our actual unreaped child;
                    # a completed/reused PID raises ChildProcessError instead.
                    os.kill(owner.pid, 9)
                    pid, status = os.waitpid(owner.pid, 0)
                owner.popen.returncode = os.waitstatus_to_exitcode(status)
            except ChildProcessError:
                pass
            for reader in readers:
                reader.thread.join(2)
            for stream in (owner.popen.stdin, owner.popen.stdout, owner.popen.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            owner.close()
        for pin in [*self.local_pins, self.case_pin]:
            if getattr(pin, "fd", None) is not None:
                try:
                    pin.close()
                except OSError:
                    pass
                pin.fd = None

    def child(self, owners, readers, leg_dir, code=None, **_options):
        owned = H6["spawn_owned"](owners,
            [sys.executable, "-I", "-c", code or "import sys; print('alive',flush=True); sys.stdin.read()"],
            os.getuid(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        stdout = H6["Reader"](owned.popen.stdout, Path(leg_dir) / f"child-{owned.pid}.out")
        stderr = H6["Reader"](owned.popen.stderr, Path(leg_dir) / f"child-{owned.pid}.err")
        readers.extend((stdout, stderr))
        stdout.record = lambda *_args, **_kwargs: {"image": 0}
        self.spawned.append((owned, [stdout, stderr]))
        return owned, stdout, stderr

    def patches(self, ready):
        pin_class = H6["FilePin"]
        def pin(path):
            result = pin_class(path)
            self.local_pins.append(result)
            return result
        def caller(owners, readers, leg_dir, *_args, **kwargs):
            return self.child(owners, readers, leg_dir, **kwargs)
        def observer(owners, readers, leg_dir, *_args, **kwargs):
            owned, stdout, stderr = self.child(owners, readers, leg_dir, **kwargs)
            return owned, stdout, stderr, time.monotonic_ns()
        return mock.patch.dict(self.globals, {
            "init_token": lambda *_args: dict(os.environ), "FilePin": pin,
            "spawn_caller": caller, "spawn_observer": observer,
            "observer_ready": ready, "stop_caller": lambda *_args: 0}), \
            mock.patch.object(pin_class, "image_receipt", return_value={"image": 0})

    def assert_released(self, resources=None):
        for owner, readers in self.spawned if resources is None else resources:
            self.assertIsNotNone(owner.popen.poll(), "prior owned process survived its leg")
            self.assertFalse((Path("/proc") / str(owner.pid)).exists(), "prior child was not actually reaped")
            self.assertIsNone(owner.pidfd, "prior pidfd survived its leg")
            self.assertTrue(all(not reader.thread.is_alive() for reader in readers))
            self.assertTrue(all(stream.closed for stream in
                (owner.popen.stdin, owner.popen.stdout, owner.popen.stderr) if stream is not None))
        os.fstat(self.case_pin.fd)

    def test_failed_leg_reaps_before_next_observer(self):
        def fail(*_args):
            raise H6["SetupError"]("controlled setup failure")
        patch, image_patch = self.patches(fail)
        with patch, image_patch:
            first = H6["run_cell_backend"](self.ctx, "pid-leader", "singles")
            previous = list(self.spawned)
            original_observer = self.globals["spawn_observer"]
            observed = []
            def next_observer(*args, **kwargs):
                observed.append(all(owner.popen.poll() is not None for owner, _ in previous))
                return original_observer(*args, **kwargs)
            with mock.patch.dict(self.globals, {"spawn_observer": next_observer}):
                second = H6["run_cell_backend"](self.ctx, "pid-leader", "multi")
        self.assertFalse(first[0]["pass"])
        self.assertFalse(second[0]["pass"])
        self.assertEqual(observed, [True], "next observer began while the previous leg still lived")
        self.assert_released()

    def test_early_refusal_releases_all_owned_resources(self):
        def refuse(*_args):
            raise H6["BackendRefused"]("controlled backend refusal")
        patch, image_patch = self.patches(refuse)
        with patch, image_patch:
            results = H6["run_cell_backend"](self.ctx, "pid-leader", "singles")
        self.assertEqual([row["status"] for row in results], ["negative"] * 3)
        self.assert_released()

    def driven_patches(self, oracle):
        def phase(caller, stdout, fn, count, delay, name, scope, image, group, phases, **_kwargs):
            t0 = time.monotonic_ns()
            phases.append({"fn": fn, "count": count, "phase": name, "image": image,
                           "scope": scope, "t0": t0, "t1": t0 + 1})
        def drain(capture, caller, stdout, fn, count, delay, name, image, phases):
            phase(caller, stdout, fn, count, delay, name, "selected", image, None, phases)
        def execute(caller, stdout, images, method, target):
            images.append({"image": 1})
            return {}, {}, time.monotonic_ns(), time.monotonic_ns()
        def warm(capture, caller, stdout, image, phases, *_args, **_kwargs):
            phase(caller, stdout, "C_GetInfo", 1, 0, "successor", "selected", 1, None, phases)
            return {}
        return mock.patch.dict(self.globals, {
            "drain_trace_phase": drain, "n3_command": phase, "caller_exec": execute,
            "warm_caller": warm, "stop_observer": lambda *_args: (0, time.monotonic_ns(), 0),
            "finish_readers": lambda *_args: None, "provider_receipt": lambda *_args: dict(PIN),
            "evaluate_trace_h6": oracle})

    def run_driven_leg(self, oracle):
        patch, image_patch = self.patches(lambda *_args: time.monotonic_ns())
        leg_dir = self.directory / "driven"
        leg_dir.mkdir()
        (leg_dir / "trace.file.txt").write_text("controlled oracle input\n")
        with patch, image_patch, self.driven_patches(oracle):
            return H6["run_pid_caller_leg"](self.ctx, "pid-leader", "singles", "trace", leg_dir, False)

    def test_oracle_exception_cleans_leg_resources(self):
        def oracle(*_args):
            raise ValueError("controlled oracle exception")
        with self.assertRaisesRegex(ValueError, "controlled oracle exception"):
            self.run_driven_leg(oracle)
        self.assert_released()

    def test_successful_leg_releases_fds_without_closing_case_pins(self):
        result = self.run_driven_leg(lambda *_args: {"cell": "pid-leader", "leg": "trace/singles", "pass": True})
        self.assertTrue(result["pass"])
        self.assert_released()
        self.assertTrue(all(pin.fd is None for pin in self.local_pins))
        totals = dict(self.ctx.cleanup_totals)
        for scope in self.ctx.scopes:
            H6["cleanup_leg_resources"](scope)
        self.assertEqual(self.ctx.cleanup_totals, totals)

    def test_interrupted_leg_cleans_before_propagating(self):
        def interrupt(*_args):
            raise KeyboardInterrupt("controlled interruption")
        patch, image_patch = self.patches(interrupt)
        with patch, image_patch, self.assertRaises(KeyboardInterrupt):
            H6["run_pid_caller_leg"](self.ctx, "pid-leader", "singles", "trace", self.directory / "interrupt", False)
        self.assert_released()

    def test_partial_spawn_failure_cleans_registered_child_and_started_reader(self):
        spawned, started_readers = [], []
        original_spawn, reader_class = H6["spawn_owned"], H6["Reader"]
        original_init, original_read = reader_class.__init__, reader_class._read
        def spawn(owners, argv, _uid, **options):
            owned = original_spawn(owners, argv, os.getuid(), **options)
            spawned.append(owned)
            return owned
        def delayed_read(reader):
            time.sleep(0.1)
            original_read(reader)
        def fail_constructor(reader, *args):
            original_init(reader, *args)
            started_readers.append(reader)
            raise OSError("controlled reader constructor failure")
        @H6["owned_leg"]
        def leg(ctx):
            return H6["spawn_observer"](ctx.owners, ctx.readers, self.directory,
                [sys.executable, "-I", "-c", "import time; print('alive',flush=True); time.sleep(30)"], dict(os.environ))
        with mock.patch.dict(self.globals, {"spawn_owned": spawn}), \
                mock.patch.object(reader_class, "_read", delayed_read), \
                mock.patch.object(reader_class, "__init__", fail_constructor), \
                self.assertRaisesRegex(OSError, "controlled reader constructor failure"):
            leg(self.ctx)
        try:
            self.assertIsNotNone(spawned[0].popen.poll())
            self.assertIsNone(spawned[0].pidfd)
            self.assertFalse(started_readers[0].thread.is_alive(), "unregistered reader survived constructor failure")
            self.assertTrue(spawned[0].popen.stdout.closed)
        finally:
            for reader in started_readers:
                reader.thread.join(2)
            for owner in spawned:
                if owner.popen.poll() is None:
                    owner.popen.kill()
                    owner.popen.wait(timeout=2)
                for stream in (owner.popen.stdout, owner.popen.stderr):
                    if not stream.closed:
                        stream.close()
                owner.close()

    def matrix(self, runner, *, pin_close_failure=False):
        created_pins = []
        pin_class = H6["FilePin"]
        def pin(path):
            value = pin_class(path)
            created_pins.append(value)
            if pin_close_failure and len(created_pins) == 1:
                close = value.close
                def fail_close():
                    close()
                    value.fd = None
                    raise OSError("controlled final pin cleanup failure")
                value.close = fail_close
            return value
        out = self.directory / "matrix"
        argv = ["--binary", str(self.case_pin.path), "--provider", str(self.case_pin.path),
                "--discover", str(self.case_pin.path), "--source-revision", "0" * 40,
                "--uid", "1001", "--gid", "1001", "--cells", "pid-leader",
                "--backends", "singles,multi", "--out", str(out)]
        def cell(ctx, directory, backend):
            return [runner(ctx, directory, backend)]
        try:
            with mock.patch.dict(self.globals, {"FilePin": pin,
                    "compile_case_fixtures": lambda *_args: {}, "symbol_file_offset": lambda *_args: 0}), \
                    mock.patch.dict(H6["CELL_RUNNERS"], {"pid-leader": cell}), \
                    mock.patch.object(os, "geteuid", return_value=0):
                rc = H6["main"](argv)
            return rc, json.loads((out / "summary.json").read_text()), json.loads((out / "cleanup.json").read_text())
        finally:
            for value in created_pins:
                if value.fd is not None:
                    try:
                        os.close(value.fd)
                    except OSError:
                        pass
                    value.fd = None

    def test_cleanup_failure_stops_matrix_and_fails_summary_even_after_setup_failure(self):
        started = []
        removed = []
        class FailedGroup:
            def remove(self):
                removed.append(True)
                raise OSError("controlled cgroup cleanup failure")
        @H6["owned_leg"]
        def runner(ctx, directory, backend):
            started.append(backend)
            self.child(ctx.owners, ctx.readers, directory)
            ctx.groups.append(FailedGroup())
            raise H6["SetupError"]("controlled primary setup failure")
        try:
            rc, summary, cleanup = self.matrix(runner)
        except H6["LegCleanupError"] as error:
            self.fail(f"cleanup failure escaped without a failed summary: {error}")
        self.assertEqual(rc, 1)
        self.assertEqual(started, ["singles"], "cleanup failure allowed another observer leg")
        self.assertEqual(removed, [True], "final backstop repeated completed cleanup")
        self.assertGreater(summary["failed"], 0)
        self.assertTrue(any("controlled primary setup failure" in error and "controlled cgroup cleanup failure" in error
                            for result in summary["legs"] for error in result["errors"]))
        self.assertTrue(any("controlled cgroup cleanup failure" in error for error in cleanup["errors"]))
        self.assert_released()

    def test_final_cleanup_failure_prevents_a_success_summary(self):
        @H6["owned_leg"]
        def runner(ctx, directory, backend):
            self.child(ctx.owners, ctx.readers, directory)
            return {"cell": "pid-leader", "leg": backend, "status": "pass", "pass": True}
        rc, summary, cleanup = self.matrix(runner, pin_close_failure=True)
        self.assertEqual(rc, 1, "main decided success before final cleanup")
        self.assertGreater(summary["failed"], 0)
        self.assertTrue(any("controlled final pin cleanup failure" in error for error in cleanup["errors"]))
        self.assert_released()

    def test_ptrace_stopped_owned_child_is_killed_and_actually_reaped(self):
        timer = None
        code = ("import ctypes,os,signal,sys; libc=ctypes.CDLL(None,use_errno=True); "
                "rc=libc.ptrace(0,0,0,0); print('trace='+str(rc),flush=True); "
                "os.kill(os.getpid(),signal.SIGSTOP) if rc==0 else sys.exit(83); sys.stdin.read()")
        @H6["owned_leg"]
        def leg(ctx):
            nonlocal timer
            owner, stdout, _ = self.child(ctx.owners, ctx.readers, self.directory, code=code)
            ctx.traced.append(owner)
            stdout.wait(lambda reader: any(line.startswith("trace=") for line in reader.lines), 1)
            if "trace=-1\n" in stdout.lines:
                self.skipTest("host denies unprivileged tracing of the owned direct child")
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                if "t" in H6["proc_task_states"](owner.pid).values():
                    break
                time.sleep(0.01)
            else:
                self.fail("owned child never reached its real ptrace stop")
            # A backstop bounds the RED control even when legacy Popen.poll
            # mistakes the ptrace stop for process death. It never reaps it.
            def kill_original():
                try:
                    owner.verify()
                    os.kill(owner.pid, 9)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            timer = threading.Timer(1, kill_original)
            timer.start()
            raise H6["SetupError"]("controlled failure with ptrace-stopped child")
        try:
            with self.assertRaisesRegex(H6["SetupError"], "ptrace-stopped child"):
                leg(self.ctx)
            self.assert_released()
        finally:
            if timer is not None:
                timer.cancel()
                timer.join(2)

    def test_pipe_cleanup_settles_reader_without_waiting_for_an_open_writer(self):
        read_fd, write_fd = os.pipe()
        stream, writer = os.fdopen(read_fd, encoding="utf-8"), os.fdopen(write_fd, "w")
        scope = H6["LegContext"](self.ctx)
        reader = H6["owned_reader"](scope.readers, H6["Reader"], stream, self.directory / "held-pipe.txt")
        timer = threading.Timer(2, writer.close)
        timer.start()
        original_join = reader.thread.join
        calls = []
        def short_first_join(timeout=None):
            calls.append(True)
            return original_join(0.02 if len(calls) == 1 else timeout)
        try:
            with mock.patch.object(reader.thread, "join", side_effect=short_first_join), \
                    self.assertRaises(H6["LegCleanupError"]):
                H6["cleanup_leg_resources"](scope)
            self.assertFalse(reader.thread.is_alive())
            self.assertTrue(stream.closed)
            self.assertFalse(writer.closed, "cleanup blocked closing a pipe still read by its thread")
        finally:
            timer.cancel()
            writer.close()
            timer.join(2)
            reader.thread.join(2)
            stream.close()

    def test_rapid_main_releases_resources_before_reuse_and_death_observers(self):
        cell_dir = self.directory / "rapid-chain"
        trace_dir = cell_dir / "singles" / "trace"
        trace_dir.mkdir(parents=True)
        (trace_dir / "trace.file.txt").write_text("controlled oracle input\n")
        order = []
        def control(label):
            @H6["owned_leg"]
            def run(ctx, leg_dir, backend, env, *args):
                self.assert_released()  # includes the preceding control on entry to death
                image_pin = args[-1]
                os.fstat(image_pin.fd)
                self.assertTrue(all(pin.fd is not None for pin in self.local_pins))
                order.append(label)
                Path(leg_dir).mkdir(parents=True)
                self.child(ctx.owners, ctx.readers, leg_dir)
                return {"cell": "rapid-chain", "leg": label, "pass": True}
            return run
        patch, image_patch = self.patches(lambda *_args: time.monotonic_ns())
        with patch, image_patch, self.driven_patches(lambda *_args: {"leg": "main", "pass": True}), \
                mock.patch.dict(self.globals, {"run_reuse_control": control("reuse"),
                                               "run_group_death_leg": control("death")}):
            results = H6["run_rapid_chain"](self.ctx, cell_dir, "singles")
        self.assertEqual(order, ["reuse", "death"])
        self.assertEqual([row["leg"] for row in results], ["main", "reuse", "death"])
        self.assertEqual([row["leg"] for row in self.ctx.completed_results], ["main", "reuse", "death"])
        self.assert_released()
        self.assertTrue(all(pin.fd is None for pin in self.local_pins))

    def test_partial_pty_acquisition_closes_fds_and_settles_started_thread(self):
        original_open, capture_class = H6["pty"].openpty, H6["PtyCapture"]
        original_init = capture_class.__init__
        for failure in ("before-reader", "after-reader", "spawn"):
            with self.subTest(failure=failure):
                fds, captures = [], []
                def openpty():
                    result = original_open()
                    fds.extend(result)
                    return result
                def initialize(reader, *args):
                    captures.append(reader)
                    if failure != "before-reader":
                        original_init(reader, *args)
                    if failure != "spawn":
                        raise OSError("controlled PTY acquisition failure")
                def spawn(*_args, **_kwargs):
                    raise OSError("controlled PTY acquisition failure")
                @H6["owned_leg"]
                def leg(ctx):
                    H6["spawn_observer"](ctx.owners, ctx.readers, self.directory, [], dict(os.environ), live=True)
                with mock.patch.object(H6["pty"], "openpty", side_effect=openpty), \
                        mock.patch.object(capture_class, "__init__", initialize), \
                        mock.patch.dict(self.globals, {"spawn_owned": spawn}), \
                        self.assertRaisesRegex(OSError, "PTY acquisition failure"):
                    leg(self.ctx)
                for fd in fds:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                self.assertIsNone(captures[0].master)
                if captures[0].thread is not None:
                    self.assertFalse(captures[0].thread.is_alive())
                    self.assertEqual(captures[0].errors, [])
        self.assertFalse(self.ctx.cleanup_failed)

    def test_seized_child_is_enrolled_before_options_failure(self):
        original_ptrace = H6["_ptrace"]
        timer = None
        @H6["owned_leg"]
        def leg(ctx):
            nonlocal timer
            owner, _, _ = self.child(ctx.owners, ctx.readers, self.directory)
            def kill_original():
                try:
                    owner.send(H6["signal"].SIGKILL)
                except (OSError, ValueError):
                    pass
            timer = threading.Timer(1, kill_original)
            timer.start()
            def ptrace(request, pid, *args):
                if request == H6["_PTRACE_SEIZE"]:
                    try:
                        return original_ptrace(request, pid, *args)
                    except OSError as error:
                        if error.errno == 1:
                            self.skipTest("host denies unprivileged seizure of the owned direct child")
                        raise
                self.assertEqual(ctx.traced, [owner], "options failed before ptrace ownership enrollment")
                raise OSError("controlled options acquisition failure")
            with mock.patch.dict(self.globals, {"_ptrace": ptrace}):
                H6["seize_until_exec"](owner.pid, ctx, owner)
        try:
            with self.assertRaisesRegex(OSError, "options acquisition failure"):
                leg(self.ctx)
            self.assert_released()
        finally:
            if timer is not None:
                timer.cancel()
                timer.join(2)

    def test_later_leg_failure_retains_earlier_completed_result(self):
        @H6["owned_leg"]
        def success(ctx):
            self.child(ctx.owners, ctx.readers, self.directory)
            return {"cell": "pid-leader", "leg": "first", "status": "pass", "pass": True}
        @H6["owned_leg"]
        def failure(ctx):
            self.assert_released()
            self.child(ctx.owners, ctx.readers, self.directory)
            raise H6["SetupError"]("controlled later failure")
        def cell(ctx, *_args):
            return [success(ctx), failure(ctx)]
        with mock.patch.dict(H6["CELL_RUNNERS"], {"pid-leader": cell}):
            results = H6["run_cell_backend"](self.ctx, "pid-leader", "singles")
        self.assertEqual([row["pass"] for row in results], [True, False])
        self.assertEqual(results[0]["leg"], "first")
        self.assertIn("controlled later failure", results[1]["errors"][0])
        self.assert_released()

    def test_partial_process_validation_failure_reaps_registered_direct_child(self):
        shared = H6["spawn_owned"].__globals__
        acquired = []
        def validation(_pid, _parent, _uid, popen):
            acquired.append(popen)
            raise OSError("controlled process validation failure")
        @H6["owned_leg"]
        def leg(ctx):
            H6["spawn_owned"](ctx.owners,
                [sys.executable, "-I", "-c", "import sys; sys.stdin.read()"], os.getuid(),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True)
        try:
            with mock.patch.dict(shared, {"OwnedProcess": validation}), \
                    self.assertRaisesRegex(OSError, "process validation failure"):
                leg(self.ctx)
            self.assertIsNotNone(acquired[0].poll())
            self.assertFalse((Path("/proc") / str(acquired[0].pid)).exists())
            self.assertTrue(all(stream.closed for stream in
                (acquired[0].stdin, acquired[0].stdout, acquired[0].stderr)))
        finally:
            for popen in acquired:
                if popen.poll() is None:
                    popen.kill()
                    popen.wait(2)
                for stream in (popen.stdin, popen.stdout, popen.stderr):
                    stream.close()

    def ordinary_group_controls(self):
        # Real directories/held FDs exercise the unchanged ownership checks.
        # Only the cgroup filesystem magic and empty population are injected;
        # no actual cgroup is created or migrated.
        shared = H6["N3HARNESS"]["create_cgroup"].__globals__
        return mock.patch.dict(shared, {"fs_magic": lambda _fd: 0x63677270}), \
            mock.patch.object(H6["N3HARNESS"]["Cgroup"], "members", return_value=[])

    def test_group_removal_follows_reap_reader_and_fd_cleanup(self):
        patch, members = self.ordinary_group_controls()
        removed = []
        path = self.directory / "selected"
        @H6["owned_leg"]
        def leg(ctx):
            self.child(ctx.owners, ctx.readers, self.directory)
            _, wrapper = H6["create_tracked"](ctx, path)
            remove = wrapper.remove
            def after_reap():
                self.assert_released()
                removed.append(True)
                remove()
            wrapper.remove = after_reap
        with patch, members:
            leg(self.ctx)
        self.assertEqual(removed, [True])
        self.assertFalse(path.exists())

    def test_partial_group_acquisition_removes_only_enrolled_directory(self):
        shared = H6["N3HARNESS"]["create_cgroup"].__globals__
        path = self.directory / "selected"
        def acquisition(_path):
            raise OSError("controlled group acquisition failure")
        @H6["owned_leg"]
        def leg(ctx):
            H6["create_tracked"](ctx, path)
        with mock.patch.dict(shared, {"fs_magic": lambda _fd: 0x63677270, "Cgroup": acquisition}), \
                self.assertRaisesRegex(OSError, "group acquisition failure"):
            leg(self.ctx)
        self.assertFalse(path.exists())
        self.assertFalse(self.ctx.cleanup_failed)

    def test_replacement_is_enrolled_before_later_setup_failure(self):
        patch, members = self.ordinary_group_controls()
        path = self.directory / "selected"
        @H6["owned_leg"]
        def leg(ctx):
            selected, wrapper = H6["create_tracked"](ctx, path)
            replacement, new_wrapper, old_ino, new_ino = H6["replace_tracked"](ctx, selected, wrapper)
            self.assertNotEqual(old_ino, new_ino)
            self.assertIn(new_wrapper, ctx.groups)
            raise H6["SetupError"]("controlled failure after replacement")
        with patch, members, self.assertRaisesRegex(H6["SetupError"], "after replacement"):
            leg(self.ctx)
        self.assertFalse(path.exists(), "replacement survived its failed observer leg")
        self.assertFalse(self.ctx.cleanup_failed)

    def test_replacement_refuses_a_foreign_path_without_removing_it(self):
        patch, members = self.ordinary_group_controls()
        path, original = self.directory / "selected", self.directory / "original"
        with patch, members:
            scope = H6["LegContext"](self.ctx)
            selected, wrapper = H6["create_tracked"](scope, path)
            path.rename(original)
            path.mkdir()
            foreign_ino = path.stat().st_ino
            with self.assertRaises(H6["LegCleanupError"]):
                H6["replace_tracked"](scope, selected, wrapper)
            self.assertEqual(path.stat().st_ino, foreign_ino)
            self.assertTrue(original.exists())
            self.assertTrue(self.ctx.cleanup_failed)
            self.assertIsNone(selected.fd)
            H6["cleanup_leg_resources"](scope)

    def test_replacement_preserves_renamed_wrapper_identity_checks(self):
        patch, members = self.ordinary_group_controls()
        top, renamed = self.directory / "top", self.directory / "renamed"
        @H6["owned_leg"]
        def leg(ctx):
            root, root_wrapper = H6["create_tracked"](ctx, top)
            selected, selected_wrapper = H6["create_tracked"](ctx, top / "selected")
            moves = []
            H6["fixup_renamed_wrappers"](moves, root_wrapper, renamed, [(selected_wrapper, "selected")])
            replacement, wrapper, old_ino, new_ino = H6["replace_tracked"](ctx, selected, selected_wrapper)
            self.assertEqual(replacement.path, renamed / "selected")
            self.assertNotEqual(old_ino, new_ino)
            self.assertIn(wrapper, ctx.groups)
            replacement.verify()
        with patch, members:
            leg(self.ctx)
        self.assertFalse(top.exists())
        self.assertFalse(renamed.exists())


class ScriptEntryTest(unittest.TestCase):
    def test_main_entry_sees_all_registered_cell_helpers(self):
        code = textwrap.dedent("""\
            import runpy
            import sys

            class EntryChecked(Exception):
                pass

            def check_entry(frame, event, arg):
                if (event == "call" and frame.f_code.co_name == "main"
                        and frame.f_code.co_filename == sys.argv[1]):
                    helpers = ("spawn_inventory", "wait_inventory_ready",
                               "stop_inventory", "wait_ledger_line",
                               "run_cgroup_stop_before", "run_cgroup_stop_during")
                    missing = [name for name in helpers
                               if not callable(frame.f_globals.get(name))]
                    assert not missing, f"undefined cell helpers at main entry: {missing}"
                    raise EntryChecked
                return check_entry

            sys.settrace(check_entry)
            try:
                runpy.run_path(sys.argv[1], run_name="__main__")
            except EntryChecked:
                print("all cell helpers available before main body")
            else:
                raise AssertionError("script did not invoke main")
            finally:
                sys.settrace(None)
            """)
        result = subprocess.run(
            [sys.executable, "-B", "-c", code,
             str(ROOT / "scripts/qualify-automatic-exec.py")],
            text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(),
                         "all cell helpers available before main body")


class TraceTest(unittest.TestCase):
    maxDiff = 4000

    def test_accept_caller_control(self):
        text, ledger, receipt = caller_inputs()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["calls"], 7)
        self.assertEqual(result["named"], 6)
        self.assertEqual(result["unknown"], 1)
        self.assertEqual(result["false_names"], 0)
        self.assertEqual(result["physical_entered"], 7)
        self.assertEqual(result["api_returned"], 7)
        self.assertEqual(result["measured_calls"], 3)
        self.assertEqual(result["warmup_calls"], 3)
        self.assertEqual(result["order_matched"], 7)

    def test_accept_b_style_control(self):
        text, ledger, receipt = b_style_inputs()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["physical_entered"], 7)
        self.assertEqual(result["api_returned"], 6)
        self.assertEqual(result["completed_operations"], 6)
        self.assertEqual(result["abandoned"], 1)
        self.assertEqual(result["named"], 3)
        self.assertEqual(result["unknown"], 3)

    def test_reject_all_unknown_positive(self):
        text, ledger, receipt = caller_inputs()
        rows = [unknown_row(1000, 1000, fn) for fn in
                ("C_GenerateRandom", "C_GenerateRandom", "C_Initialize",
                 "C_GetSessionInfo", "C_GetSessionInfo", "C_GetSessionInfo")]
        text = trace_text(rows, 6, 6, evidence())
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("no named event" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_wrong_successor_name(self):
        text, ledger, receipt = b_style_inputs()
        rows = text.splitlines()
        rows[7] = named_row(1000, 1000, "/w/evil", "C_Initialize", "CKR_GENERAL_ERROR")
        result = H6["evaluate_trace_h6"]("\n".join(rows) + "\n", ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertEqual(result["false_names"], 1)
        self.assertTrue(any("other than the independently observed image" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_outside_scope_count(self):
        _, ledger, receipt = caller_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["scope_kind"] = "cgroup"
        receipt["owned_pids"] = [1000]
        receipt["scope_intervals"] = [
            {"pid": 1000, "membership": "selected", "t0": READY, "t1": STOP}]
        # An outside-scope call (distinct function, as in the real cgroup
        # legs) whose row wrongly enters the scoped totals. The outside
        # gen1-setup call has no row (kernel scope filter drops it).
        ledger = copy.deepcopy(ledger)
        warm0 = READY + 100_000_000
        ledger.append(target_record(0, "C_GetInfo"))
        ledger.append(call_record(0, "C_GetInfo", 0, "aside", "outside", warm0, warm0 + 10))
        receipt["phases"].append({"image": 0, "fn": "C_GetInfo", "phase": "aside",
                                  "scope": "outside", "count": 1,
                                  "t0": warm0 - 1, "t1": warm0 + 20})
        rows = [
            named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom"),
            named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom"),
            unknown_row(1000, 1000, "C_GetInfo"),
            unknown_row(1000, 1000, "C_GetSessionInfo"),
            named_row(1000, 1000, "/w/caller-b", "C_GetSessionInfo"),
            named_row(1000, 1000, "/w/caller-b", "C_GetSessionInfo"),
        ]
        text = trace_text(rows, 6, 6, evidence())
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("outside-scope or foreign count" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_duplicate_return(self):
        text, ledger, receipt = caller_inputs()
        lines = text.splitlines()
        # Duplicate a completed row and keep terminal counts consistent with
        # the rows: the ledger population check must still catch it.
        dup = next(line for line in lines if "C_GetSessionInfo" in line and "caller-b" in line)
        lines.insert(3, dup)
        rows = [line for line in lines if H6["ROW"].fullmatch(line)]
        body = [line for line in lines if not line.startswith(("COUNT_EVIDENCE", "EVIDENCE"))]
        fixed = "\n".join(body) + "\n" + "\n".join([
            "COUNT_EVIDENCE " + json.dumps(
                {"stats_entered": 7, "stats_returned": 7, "raw_calls": len(rows)}),
            "EVIDENCE " + json.dumps(evidence())]) + "\n"
        result = H6["evaluate_trace_h6"](fixed, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("duplicate return" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_missing_measured_phase(self):
        text, ledger, receipt = caller_inputs()
        del receipt["measured"]
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("missing measured phase" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_manual_rebind_path(self):
        text, ledger, receipt = caller_inputs()
        ledger = copy.deepcopy(ledger)
        ledger.append({"kind": "rebind", "image": 1, "t": READY + 1})
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("rebind" in error for error in result["errors"]),
                        result["errors"])
        receipt = copy.deepcopy(receipt)
        receipt["manual_rebind"] = True
        text2, ledger2, _ = caller_inputs()
        result = H6["evaluate_trace_h6"](text2, ledger2, receipt)
        self.assertFalse(result["pass"])

    def test_accept_order_matched_reused_key(self):
        """Rapid-chain shape: same (pid,tid,fn) in two generations."""
        warm0 = READY + 100_000_000
        meas0 = READY + 500_000_000
        ledger = [
            image_record(0, "/w/chain-a", READY - 500_000_000),
            target_record(0, "C_GenerateRandom"),
            call_record(0, "C_GenerateRandom", 0, "warm", "selected", warm0, warm0 + 10),
            {"kind": "exec", "image": 0, "pid": 1000, "tid": 1000, "start_time": 7777,
             "mode": "leader", "path": "/w/chain-b", "scope": "selected", "t": warm0 + 100},
            image_record(1, "/w/chain-b", warm0 + 200),
            target_record(1, "C_GenerateRandom"),
            call_record(1, "C_GenerateRandom", 0, "measured", "selected", meas0, meas0 + 10),
            call_record(1, "C_GenerateRandom", 0, "measured", "selected", meas0 + 20, meas0 + 30),
        ]
        request = next(row for row in ledger if row["kind"] == "exec")
        receipt = base_receipt(
            cell="rapid-chain",
            images=[image_record(0, "/w/chain-a", READY - 500_000_000),
                    image_record(1, "/w/chain-b", warm0 + 200)],
            exec_transitions=[{"from_image": 0, "to_image": 1, "mode": "leader",
                               "same_path": False, "t0": warm0 + 50, "t1": warm0 + 300,
                               "request": request}],
            phases=[{"image": 0, "fn": "C_GenerateRandom", "phase": "warm",
                     "scope": "selected", "count": 1, "t0": warm0 - 1, "t1": warm0 + 20},
                    {"image": 1, "fn": "C_GenerateRandom", "phase": "measured",
                     "scope": "selected", "count": 2, "t0": meas0 - 1, "t1": meas0 + 40}],
            measured={"label": "stable", "t0": meas0 - 1, "t1": meas0 + 40,
                      "expected_calls": 2, "phases": ["measured"]},
            warmup={"label": "pre", "t0": warm0 - 1, "t1": warm0 + 20,
                    "expected_calls": 1, "phases": ["warm"]},
            require_named=True, require_named_images=[1], first_unknown_images=[1])
        rows = [
            named_row(1000, 1000, "/w/chain-a", "C_GenerateRandom"),
            unknown_row(1000, 1000, "C_GenerateRandom"),
            named_row(1000, 1000, "/w/chain-b", "C_GenerateRandom"),
        ]
        text = trace_text(rows, 3, 3, evidence())
        text, ledger, receipt = add_trace_successor_control(text, ledger, receipt)
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["order_matched"], 4)
        self.assertEqual(result["image_generation_populations"][1], {"named": 3, "unknown": 0})

    def test_reject_ambiguous_reused_key_under_loss(self):
        """Same reused key, but one row lost: no attribution possible."""
        warm0 = READY + 100_000_000
        meas0 = READY + 500_000_000
        ledger = [
            image_record(0, "/w/chain-a", READY - 500_000_000),
            target_record(0, "C_GenerateRandom"),
            call_record(0, "C_GenerateRandom", 0, "warm", "selected", warm0, warm0 + 10),
            {"kind": "exec", "image": 0, "pid": 1000, "tid": 1000, "start_time": 7777,
             "mode": "leader", "path": "/w/chain-b", "scope": "selected", "t": warm0 + 100},
            image_record(1, "/w/chain-b", warm0 + 200),
            target_record(1, "C_GenerateRandom"),
            call_record(1, "C_GenerateRandom", 0, "measured", "selected", meas0, meas0 + 10),
        ]
        request = next(row for row in ledger if row["kind"] == "exec")
        receipt = base_receipt(
            cell="rapid-chain",
            images=[image_record(0, "/w/chain-a", READY - 500_000_000),
                    image_record(1, "/w/chain-b", warm0 + 200)],
            exec_transitions=[{"from_image": 0, "to_image": 1, "mode": "leader",
                               "same_path": False, "t0": warm0 + 50, "t1": warm0 + 300,
                               "request": request}],
            phases=[{"image": 0, "fn": "C_GenerateRandom", "phase": "warm",
                     "scope": "selected", "count": 1, "t0": warm0 - 1, "t1": warm0 + 20},
                    {"image": 1, "fn": "C_GenerateRandom", "phase": "measured",
                     "scope": "selected", "count": 1, "t0": meas0 - 1, "t1": meas0 + 20}],
            measured={"label": "stable", "t0": meas0 - 1, "t1": meas0 + 20,
                      "expected_calls": 1, "phases": ["measured"]},
            warmup={"label": "pre", "t0": warm0 - 1, "t1": warm0 + 20,
                    "expected_calls": 1, "phases": ["warm"]},
            require_named_images=[1])
        rows = [named_row(1000, 1000, "/w/chain-a", "C_GenerateRandom")]
        text = trace_text(rows, 1, 1, evidence(event_loss=1))
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("ambiguous image generation" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_foreign_pid_row(self):
        text, ledger, receipt = caller_inputs()
        lines = text.splitlines()
        lines[3] = named_row(9999, 9999, "/w/caller-a", "C_GenerateRandom")
        result = H6["evaluate_trace_h6"]("\n".join(lines) + "\n", ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("foreign pid" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_abandoned_mismatch(self):
        text, ledger, receipt = b_style_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["abandoned_expected"] = 0
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("abandoned" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_reuse_expected_but_unobserved(self):
        text, ledger, receipt = caller_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["reuse_expected"] = {"session": True, "va": True}
        receipt["session_reuse"] = {"observed": True, "pre": 1, "post": 1}
        receipt["va_reuse"] = {"observed": False}
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("va reuse" in error for error in result["errors"]),
                        result["errors"])

    def test_accept_empty_stop_leg(self):
        text = trace_text([], 0, 0, evidence())
        receipt = {"cell": "cgroup-reentry", "leg": "stop/singles",
                   "expect_empty": True, "observer_rc": 0,
                   "stop_latency_seconds": 0.2, "stop_limit_seconds": 5}
        result = H6["evaluate_trace_h6"](text, [], receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["completed_operations"], 0)

    def test_reject_nonempty_stop_leg(self):
        rows = [unknown_row(1000, 1000, "C_GenerateRandom")]
        text = trace_text(rows, 1, 1, evidence())
        receipt = {"cell": "cgroup-reentry", "leg": "stop/singles",
                   "expect_empty": True, "observer_rc": 0,
                   "stop_latency_seconds": 0.2, "stop_limit_seconds": 5}
        result = H6["evaluate_trace_h6"](text, [], receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("captured rows" in error for error in result["errors"]),
                        result["errors"])


def group_death_inputs():
    """Group-death leg: 2 named pre-death calls, proven death, long dwell."""
    meas0 = READY + 100_000_000
    death = READY + 5_000_000_000
    ledger = [
        image_record(0, "/w/caller-a", READY - 500_000_000),
        target_record(0, "C_GenerateRandom"),
        call_record(0, "C_GenerateRandom", 0, "measured", "selected", meas0, meas0 + 10),
        call_record(0, "C_GenerateRandom", 0, "measured", "selected", meas0 + 20, meas0 + 30),
    ]
    receipt = base_receipt(
        cell="rapid-chain", leg="group-death/singles", caller_rc=-9,
        images=[image_record(0, "/w/caller-a", READY - 500_000_000)],
        phases=[{"image": 0, "fn": "C_GenerateRandom", "phase": "measured",
                 "scope": "selected", "count": 2, "t0": meas0 - 1, "t1": meas0 + 40}],
        measured={"label": "pre-death", "t0": meas0 - 1, "t1": meas0 + 40,
                  "expected_calls": 2, "phases": ["measured"]},
        warmup={"label": "none", "t0": meas0 - 1, "t1": meas0 - 1,
                "expected_calls": 0, "phases": []},
        exec_transitions=[],
        require_named=True, require_named_images=[0], first_unknown_images=[],
        group_death={"kill": "SIGKILL/killpg", "group_size_before": 1,
                     "kill_ns": death - 1000, "death_ns": death,
                     "reaped": True, "proc_gone": True,
                     "manufactured_reuse": False, "replacement_leg": "reuse/singles",
                     "min_dwell_ns": 2_000_000_000,
                     "post_death_checked_ns": STOP,
                     "observer_self_ended": True, "observer_exited_ns": STOP,
                     "observer_exit_limit_ns": 60_000_000_000,
                     "controller_stop": None})
    rows = [named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom"),
            named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom")]
    text = trace_text(rows, 2, 2, evidence())
    return text, ledger, receipt


class GroupDeathTest(unittest.TestCase):
    maxDiff = 4000

    def test_accept_group_death_control(self):
        text, ledger, receipt = group_death_inputs()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["calls"], 2)
        self.assertEqual(result["named"], 2)
        self.assertEqual(result["physical_entered"], 2)
        self.assertEqual(result["api_returned"], 2)

    def test_reject_controller_stopped_observer(self):
        text, ledger, receipt = group_death_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["group_death"]["observer_self_ended"] = False
        receipt["group_death"]["controller_stop"] = "SIGINT/kill-fallback"
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("autonomously" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_missing_natural_exit_receipt(self):
        text, ledger, receipt = group_death_inputs()
        del receipt["group_death"]["observer_exited_ns"]
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("exit timestamp" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_natural_exit_before_kill(self):
        text, ledger, receipt = group_death_inputs()
        receipt["group_death"]["observer_exited_ns"] = READY
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("exit timestamp" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_natural_exit_after_declared_deadline(self):
        text, ledger, receipt = group_death_inputs()
        receipt["group_death"]["observer_exit_limit_ns"] = 1_000_000_000
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("exit deadline" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_forced_signal_even_with_self_ended_flag(self):
        for forced_signal in ("SIGINT", "SIGKILL"):
            with self.subTest(signal=forced_signal):
                text, ledger, receipt = group_death_inputs()
                receipt["group_death"]["controller_stop"] = forced_signal
                result = H6["evaluate_trace_h6"](text, ledger, receipt)
                self.assertFalse(result["pass"])
                self.assertTrue(any("autonomously" in error for error in result["errors"]),
                                result["errors"])

    def test_reject_missing_or_unbounded_exit_deadline(self):
        for limit in (None, 0, -1, 60_000_000_001):
            with self.subTest(limit=limit):
                text, ledger, receipt = group_death_inputs()
                receipt["group_death"]["observer_exit_limit_ns"] = limit
                result = H6["evaluate_trace_h6"](text, ledger, receipt)
                self.assertFalse(result["pass"])
                self.assertTrue(any("exit deadline" in error for error in result["errors"]),
                                result["errors"])

    def test_reject_post_death_row(self):
        _, ledger, receipt = group_death_inputs()
        rows = [named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom"),
                named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom"),
                named_row(1000, 1000, "/w/caller-a", "C_GenerateRandom")]
        text = trace_text(rows, 2, 2, evidence())
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("duplicate return" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_call_at_or_after_death(self):
        _, ledger, receipt = group_death_inputs()
        ledger = copy.deepcopy(ledger)
        receipt = copy.deepcopy(receipt)
        death = receipt["group_death"]["death_ns"]
        receipt["phases"][0]["t1"] = death + 100
        receipt["measured"]["t1"] = death + 100
        ledger[-1]["t1"] = death
        text, _, _ = group_death_inputs()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("at or after the proven death" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_short_dwell(self):
        text, ledger, receipt = group_death_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["group_death"]["post_death_checked_ns"] = (
            receipt["group_death"]["death_ns"] + 1)
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("dwell is too short" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_clean_caller_rc(self):
        text, ledger, receipt = group_death_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["caller_rc"] = 0
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("whole-group SIGKILLed" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_manufactured_reuse(self):
        text, ledger, receipt = group_death_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["group_death"]["manufactured_reuse"] = True
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("never be manufactured" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_unproven_death(self):
        text, ledger, receipt = group_death_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["group_death"]["proc_gone"] = False
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("not proven by waitpid" in error for error in result["errors"]),
                        result["errors"])


class GroupDeathWiringTest(unittest.TestCase):
    """The group-death leg is registered alongside the reuse control."""

    def test_leg_registered_in_rapid_chain(self):
        self.assertIn("run_group_death_leg", H6)
        self.assertEqual(H6["CELL_RUNNERS"]["rapid-chain"], H6["run_rapid_chain"])
        source = inspect.getsource(H6["run_rapid_chain"])
        self.assertIn("run_group_death_leg", source)
        self.assertIn("run_reuse_control", source)
        self.assertEqual(H6["CELLS"],
                         ("pid-leader", "pid-reexec", "pid-nonleader-cold", "pid-failed-exec",
                          "leader-exit-exec", "rapid-chain", "cgroup-reentry", "system-mixed"))

    def test_dwell_bounds(self):
        self.assertGreaterEqual(H6["GROUP_DEATH_DWELL_NS"], H6["GROUP_DEATH_MIN_DWELL_NS"])
        self.assertGreater(H6["GROUP_DEATH_MIN_DWELL_NS"], 0)


class GroupDeathObserverFinishTest(unittest.TestCase):
    def observer(self):
        code = ("import signal, sys; "
                "signal.signal(signal.SIGINT, lambda *_: sys.exit(0)); "
                "print('READY', flush=True); sys.stdin.readline()")
        owners = []
        self.addCleanup(H6["cleanup_processes"], owners)
        owned = H6["spawn_owned"](
            owners, [sys.executable, "-B", "-c", code], os.getuid(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        self.addCleanup(owned.popen.stdout.close)
        self.addCleanup(owned.popen.stdin.close)
        self.assertEqual(owned.popen.stdout.readline(), "READY\n")
        return owned

    def test_records_natural_exit_without_controller_signal(self):
        owned = self.observer()
        death_ns = time.monotonic_ns()
        original_wait = owned.popen.wait

        def finish_when_wait_begins(*args, **kwargs):
            owned.popen.stdin.write("finish\n")
            owned.popen.stdin.flush()
            return original_wait(*args, **kwargs)

        with mock.patch.object(owned.popen, "wait", side_effect=finish_when_wait_begins):
            result = H6["finish_group_death_observer"](owned, death_ns, limit_seconds=1)
        self.assertEqual(result["rc"], 0)
        self.assertTrue(result["self_ended"])
        self.assertIsNone(result["controller_stop"])
        self.assertGreaterEqual(result["exited_ns"], death_ns)
        self.assertEqual(result["stopped_ns"], result["exited_ns"])

    def test_refuses_exit_between_pre_kill_guard_and_death_proof(self):
        owned = self.observer()
        self.assertIsNone(owned.popen.poll())
        owned.popen.stdin.write("finish\n")
        owned.popen.stdin.flush()
        self.assertEqual(owned.popen.wait(timeout=2), 0)
        death_ns = time.monotonic_ns()
        with self.assertRaisesRegex(H6["SetupError"], "exit ordering"):
            H6["finish_group_death_observer"](owned, death_ns, limit_seconds=1)

    def test_clean_sigint_cleanup_cannot_qualify_as_natural_exit(self):
        owned = self.observer()
        result = H6["finish_group_death_observer"](
            owned, time.monotonic_ns(), limit_seconds=0.05)
        self.assertEqual(result["rc"], 0)
        self.assertFalse(result["self_ended"])
        self.assertIsNone(result["exited_ns"])
        self.assertEqual(result["controller_stop"], "SIGINT/kill-fallback")


def profile_doc(functions, mode="profile", scope="pid"):
    schema = ("p11scope/observed-profile/v3-metrics" if mode == "metrics"
              else "p11scope/observed-profile/v3")
    doc = {"schema": schema, "lane": mode,
           "capture": {"mode": mode, "scope": scope,
                       "privacy_mode": "aggregate-only" if mode == "metrics" else "allowlisted",
                       "modules": [{"path": "/w/lib.so", "ino": 111, "sha256": "0" * 64}]},
           "functions": functions,
           "evidence": {"attach_failures": [],
                        "attach_backend": {"selection": "singles", "fallback": None}}}
    if mode == "profile":
        doc.update({"cgroups": [], "sessions": {}, "mechanisms": [],
                    "templates": {}, "logins": {}})
    return doc


def profile_function(name, calls, errors=0, in_flight=0):
    return {"names": [name], "calls": calls, "errors": errors, "in_flight": in_flight,
            "ordinals": [{"ordinal": 0, "table_file_offset": 4096}],
            "module": {"dev": [8, 1], "ino": 111, "sha256": "0" * 64}}


def profile_stdout(completed, errors, in_flight):
    return (f"FUNCTION CALLS\n{completed} completed calls; {errors} returned errors; "
            f"{in_flight} entries without an observed return.\n")


def profile_inputs():
    _, ledger, receipt = b_style_inputs()
    receipt = copy.deepcopy(receipt)
    receipt["leg"] = "profile/singles"
    receipt["abandoned_by_fn"] = {"C_Initialize": 1}
    # Ledger: 3 pre (1 failed) + 2 post (1 failed), 1 abandoned.
    doc = profile_doc([profile_function("C_Initialize", 5, 2, 1),
                       profile_function("C_GetInfo", 1), profile_function("C_Finalize", 0)])
    stdout = (live_frame([("C_Initialize", 3, 1, 1)])
              + live_frame([("C_Initialize", 3, 1, 1), ("C_GetInfo", 1, 0, 0)])
              + live_frame([("C_Initialize", 5, 2, 1), ("C_GetInfo", 1, 0, 0)]))
    frames = H6["parse_live_frames"](stdout)
    proof = receipt["successor_ready"][0]
    proof.update(proof_kind="live-counter", baseline=frames[0], snapshot=frames[1],
                 output_cursor=frames[0]["cursor"], proof_cursor=frames[1]["cursor"])
    return doc, stdout, ledger, receipt


class AggregateReadinessTest(unittest.TestCase):
    def early_population(self, observed_calls, observed_errors, expected_errors=1):
        doc, _, ledger, receipt = profile_inputs()
        early = [row for row in ledger if row["kind"] == "call" and row.get("phase") == "pre"]
        for index, call in enumerate(early):
            call["rv"] = 5 if index < expected_errors else 0
        stdout = (live_frame([("C_Initialize", observed_calls, observed_errors, 1)])
                  + live_frame([("C_Initialize", observed_calls, observed_errors, 1), ("C_GetInfo", 1, 0, 0)])
                  + live_frame([("C_Initialize", observed_calls + 2, observed_errors + 1, 1),
                                ("C_GetInfo", 1, 0, 0)]))
        frames = H6["parse_live_frames"](stdout)
        receipt["successor_ready"][0].update(baseline=frames[0], snapshot=frames[1],
            output_cursor=frames[0]["cursor"], proof_cursor=frames[1]["cursor"])
        doc["functions"][0].update(calls=observed_calls + 2, errors=observed_errors + 1)
        return doc, stdout, ledger, receipt

    def test_exact_early_population_cannot_change_an_error_into_success(self):
        doc, stdout, ledger, receipt = self.early_population(3, 0)
        for mode in ("profile", "metrics"):
            with self.subTest(mode=mode):
                result = H6[f"evaluate_{mode}_h6"](
                    profile_doc(doc["functions"], mode=mode), stdout, ledger, receipt)
                self.assertFalse(result["pass"], result)
                self.assertEqual(result["early_coverage"]["deficit"], 0)
                self.assertTrue(any("early aggregate" in error for error in result["errors"]), result)

    def test_disclosed_early_deficit_accepts_only_feasible_return_subsets(self):
        # Three independent early calls: F failures and 3-F successes.
        # Seeing two returns permits only the literal success/error subsets below.
        for expected_errors, observed_errors, passes in (
                (1, 0, True), (1, 1, True), (1, 2, False),
                (2, 0, False), (2, 1, True), (2, 2, True)):
            for mode in ("profile", "metrics"):
                with self.subTest(expected_errors=expected_errors, observed_errors=observed_errors, mode=mode):
                    doc, stdout, ledger, receipt = self.early_population(2, observed_errors, expected_errors)
                    doc = profile_doc(doc["functions"], mode=mode)
                    doc["evidence"].update(real_early_gap())
                    result = H6[f"evaluate_{mode}_h6"](doc, stdout, ledger, receipt)
                    self.assertEqual(result["pass"], passes, result)
                    self.assertEqual(result["early_coverage"]["deficit"], 1)

    def test_warm_and_measured_function_overlap_is_ambiguous(self):
        doc, _, ledger, receipt = profile_inputs()
        for row in [*ledger, *receipt["phases"]]:
            if row.get("phase") == "successor-marker":
                row["fn"] = "C_Initialize"
        stdout = (live_frame([("C_Initialize", 3, 1, 1)])
                  + live_frame([("C_Initialize", 4, 1, 1)])
                  + live_frame([("C_Initialize", 6, 2, 1)]))
        frames = H6["parse_live_frames"](stdout)
        receipt["successor_ready"][0].update(marker_fn="C_Initialize", baseline=frames[0], snapshot=frames[1],
            output_cursor=frames[0]["cursor"], proof_cursor=frames[1]["cursor"])
        doc["functions"] = [profile_function("C_Initialize", 6, 2, 1)]
        for mode in ("profile", "metrics"):
            with self.subTest(mode=mode):
                result = H6[f"evaluate_{mode}_h6"](
                    profile_doc(doc["functions"], mode=mode), stdout, ledger, receipt)
                self.assertFalse(result["pass"], result)
                self.assertTrue(any("warm" in error and "measured" in error for error in result["errors"]), result)

    def test_final_warm_counters_cannot_disappear_or_exceed_their_return_population(self):
        for count, returned_errors in ((0, 0), (2, 0), (1, 1)):
            for mode in ("profile", "metrics"):
                with self.subTest(count=count, returned_errors=returned_errors, mode=mode):
                    doc, stdout, ledger, receipt = profile_inputs()
                    doc["functions"][1].update(calls=count, errors=returned_errors)
                    stdout = stdout[:receipt["successor_ready"][0]["proof_cursor"]]
                    rows = [("C_Initialize", 5, 2, 1)]
                    if count:
                        rows.append(("C_GetInfo", count, returned_errors, 0))
                    stdout += live_frame(rows)
                    doc = profile_doc(doc["functions"], mode=mode)
                    # Even a real observation-gap disclosure cannot justify
                    # regressing a cumulative counter or creating extra RVs.
                    doc["evidence"].update(real_early_gap())
                    result = H6[f"evaluate_{mode}_h6"](doc, stdout, ledger, receipt)
                    self.assertFalse(result["pass"], result)

    def test_native_loss_is_red_even_with_exact_measured_counters(self):
        doc, stdout, ledger, receipt = profile_inputs()
        doc["evidence"]["event_loss"] = 1
        result = H6["evaluate_profile_h6"](doc, stdout, ledger, receipt)
        self.assertFalse(result["pass"], result)
        self.assertTrue(any("loss" in error for error in result["errors"]), result)

    def test_saved_snapshot_and_last_complete_frame_are_both_required(self):
        for change in ("stale", "forged", "last-frame"):
            with self.subTest(change=change):
                doc, stdout, ledger, receipt = profile_inputs()
                proof = receipt["successor_ready"][0]
                if change == "stale":
                    proof["snapshot"] = proof["baseline"]
                    proof["proof_cursor"] = proof["output_cursor"]
                elif change == "forged":
                    proof["snapshot"] = copy.deepcopy(proof["snapshot"])
                    proof["snapshot"]["functions"]["C_GetInfo"]["calls"] += 1
                else:
                    stdout += live_frame([("C_Initialize", 4, 2, 1), ("C_GetInfo", 1, 0, 0)])
                self.assertFalse(H6["evaluate_profile_h6"](doc, stdout, ledger, receipt)["pass"])

    def test_cumulative_redraws_are_not_added_together(self):
        doc, stdout, ledger, receipt = profile_inputs()
        stdout += live_frame([("C_Initialize", 5, 2, 1), ("C_GetInfo", 1, 0, 0)])
        result = H6["evaluate_profile_h6"](doc, stdout, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["completed_calls"], 6)

    def test_early_deficit_uses_observed_baseline_and_real_gap(self):
        for disclose in (True, False):
            with self.subTest(disclose=disclose):
                doc, stdout, ledger, receipt = profile_inputs()
                proof = receipt["successor_ready"][0]
                call = next(row for row in ledger if row["kind"] == "call" and row.get("phase") == "successor-marker")
                missed = dict(call, phase="successor-missed", t0=call["t0"] - 20, t1=call["t0"] - 10)
                ledger.append(missed)
                proof.update(started_ns=missed["t0"], attempts=2, phases=[missed["phase"], call["phase"]])
                receipt["warmup"]["phases"].append(missed["phase"])
                receipt["warmup"]["expected_calls"] += 1
                if disclose: doc["evidence"].update(real_early_gap())
                result = H6["evaluate_profile_h6"](doc, stdout, ledger, receipt)
                self.assertEqual(result["pass"], disclose, result["errors"])
                self.assertEqual(result["early_coverage"]["deficit"], 1)
                self.assertEqual(result["measured_calls"], 2)

    def test_dropped_duplicate_zero_and_unknown_stable_aggregates_are_red(self):
        for count in (0, 1, 3):
            doc, stdout, ledger, receipt = profile_inputs()
            doc["functions"][0]["calls"] = 3 + count
            result = H6["evaluate_profile_h6"](doc, stdout, ledger, receipt)
            self.assertFalse(result["pass"])
            self.assertTrue(any("stable measured" in error for error in result["errors"]), result)
        doc, stdout, ledger, receipt = profile_inputs()
        doc["functions"][0]["names"] = ["unknown"]
        self.assertFalse(H6["evaluate_profile_h6"](doc, stdout, ledger, receipt)["pass"])


class AggregateTest(unittest.TestCase):
    maxDiff = 4000

    def test_accept_profile_control(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        result = H6["evaluate_profile_h6"](doc, stdout_text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["completed_calls"], 6)
        self.assertEqual(result["returned_errors"], 2)
        self.assertEqual(result["in_flight"], 1)
        self.assertEqual(result["named_calls"], 6)
        self.assertEqual(result["unknown_calls"], 0)
        self.assertEqual(result["physical_entered"], 7)

    def test_accept_metrics_control(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        doc = profile_doc([profile_function("C_Initialize", 5, 2, 1), profile_function("C_GetInfo", 1)], mode="metrics")
        receipt = copy.deepcopy(receipt)
        receipt["leg"] = "metrics/singles"
        result = H6["evaluate_metrics_h6"](doc, stdout_text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])

    def test_reject_profile_outside_count(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        # Cgroup scope with one outside call: totals must exclude it.
        receipt = copy.deepcopy(receipt)
        receipt["scope_kind"] = "cgroup"
        receipt["owned_pids"] = [1000]
        receipt["scope_intervals"] = [
            {"pid": 1000, "membership": "selected", "t0": READY, "t1": STOP}]
        ledger = copy.deepcopy(ledger)
        for call in ledger:
            if call.get("phase") == "pre":
                call["scope"] = "outside"
                break
        doc = copy.deepcopy(doc)
        doc["capture"]["scope"] = "cgroup"
        result = H6["evaluate_profile_h6"](doc, stdout_text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("duplicate return" in error or "population disagrees" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_profile_missing_measured(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        del receipt["measured"]
        result = H6["evaluate_profile_h6"](doc, stdout_text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("missing measured phase" in error for error in result["errors"]),
                        result["errors"])

    def test_metrics_lane_omits_backend_selection(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        doc = copy.deepcopy(doc)
        doc["evidence"].pop("attach_backend", None)
        receipt = copy.deepcopy(receipt)
        receipt["requested_backend"] = "singles"
        result = H6["evaluate_metrics_h6"](doc, stdout_text, ledger, receipt)
        self.assertTrue(all("backend differs" not in error for error in result["errors"]),
                        result["errors"])

    def test_reject_metrics_identity_leak(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        doc = profile_doc([profile_function("C_Initialize", 5, 2, 1), profile_function("C_GetInfo", 1)], mode="metrics")
        doc["sessions"] = {"opened": 1}
        receipt = copy.deepcopy(receipt)
        receipt["leg"] = "metrics/singles"
        result = H6["evaluate_metrics_h6"](doc, stdout_text, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("non-aggregate" in error for error in result["errors"]),
                        result["errors"])


INV_OUT = """IDENT cell=PX pid=1000 start=7777 gen=0 exe=/w/ledger
MAPPED cell=PX pid=1000 start=7777 gen=0 exe=/w/ledger module=/w/libA.so ino=201
LEDGER cell=PX pid=1000 start=7777 gen=0 exe=/w/ledger module=/w/libA.so fn=C_GetFunctionList mech=- n=1 bad=0 phase=setup t0={s0} t1={s1}
LEDGER cell=PX pid=1000 start=7777 gen=0 exe=/w/ledger module=/w/libA.so fn=C_DigestInit mech=0x250 n=4 bad=0 phase=main t0={m0} t1={m1}
LEDGER cell=PX pid=1000 start=7777 gen=0 exe=/w/ledger module=/w/libA.so fn=C_Digest mech=0x250 n=4 bad=1 phase=main t0={m0} t1={m1}
EXEC cell=PX pid=1000 start=7777 gen=0 exe=/w/ledger how=leader next=/w/ledger2
DONE cell=PX pid=1000 start=7777 gen=0 exe=/w/ledger status=ok
IDENT cell=PX pid=1000 start=7777 gen=1 exe=/w/ledger2
MAPPED cell=PX pid=1000 start=7777 gen=1 exe=/w/ledger2 module=/w/libA.so ino=201
LEDGER cell=PX pid=1000 start=7777 gen=1 exe=/w/ledger2 module=/w/libA.so fn=C_GetFunctionList mech=- n=1 bad=0 phase=setup t0={g0} t1={g1}
LEDGER cell=PX pid=1000 start=7777 gen=1 exe=/w/ledger2 module=/w/libA.so fn=C_DigestInit mech=0x250 n=10 bad=0 phase=main t0={h0} t1={h1}
LEDGER cell=PX pid=1000 start=7777 gen=1 exe=/w/ledger2 module=/w/libA.so fn=C_Digest mech=0x250 n=10 bad=0 phase=main t0={h0} t1={h1}
DONE cell=PX pid=1000 start=7777 gen=1 exe=/w/ledger2 status=ok
"""


def inventory_inputs(s1_expected=True):
    s0, s1 = START - 20, START - 10
    m0, m1 = READY + 100, READY + 200
    g0, g1 = READY + 300, READY + 310
    h0, h1 = READY + 400, READY + 500
    text = INV_OUT.format(s0=s0, s1=s1, m0=m0, m1=m1, g0=g0, g1=g1, h0=h0, h1=h1)
    ledgers = {"PX": H6["parse_inv_ledger"](text)}
    doc = {
        "schema": "p11scope/inventory/v1", "scope": "pid:1000",
        "callers": [
            {"id": "c0", "pid": 1000, "start_time": 7777, "incarnation": 0,
             "lifecycle": "exec_retired", "retired": True,
             "image": {"exe": {"path": "/w/ledger"}}},
            {"id": "c1", "pid": 1000, "start_time": 7777, "incarnation": 1,
             "lifecycle": "exited", "retired": False,
             "image": {"exe": {"path": "/w/ledger2"}}},
        ],
        "modules": [{"id": "m0", "paths": ["/w/libA.so"],
                     "identity": {"inode": 201, "sha256": "a" * 64}}],
        "edges": [
            {"caller": "c0", "module": "m0",
             "entries": {"count": 8, "coverage": {"state": "counted",
                                                 "lossy": False}},
             "semantics": "observed",
             "mechanisms": [{"mechanism": 0x250, "mechanism_hex": "0x250",
                             "name": None, "operations": ["digest"],
                             "calls": 8, "errors": 1, "last_seen_ns": m1,
                             "evidence": {"functions": ["C_DigestInit", "C_Digest"],
                                          "returns": [{"rv": 0, "rv_hex": "0x0",
                                                       "name": "CKR_OK"}],
                                          "truncated": False}}],
             "operations": {"calls": 8, "started": 4, "completed": 3,
                            "cancelled": 0, "failed": 1, "unknown": 0,
                            "orphans": 0, "dropped": 0, "last_seen_ns": m1,
                            "active": []}},
            {"caller": "c1", "module": "m0",
             "entries": {"count": 20, "coverage": {"state": "counted",
                                                  "lossy": False}},
             "semantics": "observed",
             "mechanisms": [{"mechanism": 0x250, "mechanism_hex": "0x250",
                             "name": None, "operations": ["digest"],
                             "calls": 20, "errors": 0, "last_seen_ns": h1,
                             "evidence": {"functions": ["C_DigestInit", "C_Digest"],
                                          "returns": [{"rv": 0, "rv_hex": "0x0",
                                                       "name": "CKR_OK"}],
                                          "truncated": False}}],
             "operations": {"calls": 20, "started": 10, "completed": 10,
                            "cancelled": 0, "failed": 0, "unknown": 0,
                            "orphans": 0, "dropped": 0, "last_seen_ns": h1,
                            "active": []}},
        ],
        "instances": [{"id": "i0", "caller": "c0", "module": "m0",
                       "state": "active", "reason": None,
                       "first_seen_ns": m0, "last_seen_ns": m1},
                      {"id": "i1", "caller": "c1", "module": "m0",
                       "state": "active", "reason": None,
                       "first_seen_ns": h0, "last_seen_ns": h1}],
        "semantic_edges": [
            {"caller": "c0", "module": "m0", "instance": "i0",
             "entries": {"unit": "api_entries", "count": None,
                        "observation": "unavailable"},
             "api_returns": {"unit": "api_returns", "count": 8,
                             "saturated": False, "historical_only_returns": 0},
             "semantics": "observed", "mechanisms": [],
             "operations": {"completed": 3, "failed": 1},
             "coverage": {"lossy": False, "reasons": []}},
            {"caller": "c1", "module": "m0", "instance": "i1",
             "entries": {"unit": "api_entries", "count": None,
                        "observation": "unavailable"},
             "api_returns": {"unit": "api_returns", "count": 20,
                             "saturated": False, "historical_only_returns": 0},
             "semantics": "observed", "mechanisms": [],
             "operations": {"completed": 10, "failed": 0},
             "coverage": {"lossy": False, "reasons": []}},
        ],
        "gaps": [{"subject": "exact image authority unavailable", "detail": "test"}],
        "observation": {"native_witnesses": {"rows": 4, "bound": 4, "unbound": 0},
                        "attach": {"selection": "singles", "fallback": None}},
    }
    if not s1_expected:
        for edge in doc["edges"]:
            edge["semantics"] = "unknown (semantic capture withheld)"
            edge["mechanisms"] = None
            edge["operations"] = None
        doc["instances"] = []
        doc["semantic_edges"] = []
    receipt = {"cell": "system-mixed", "leg": "inventory/singles", "scope_kind": "system",
               "scope_label": "pid:1000", "owned_pids": [1000],
               "observer_started_ns": START, "observer_ready_ns": READY,
               "observer_stopped_ns": STOP, "observer_rc": 0,
               "manual_rebind": False, "s1_expected": s1_expected,
               "providers": {"A": {"path": "/w/libA.so", "ino": 201, "sha256": "a" * 64}},
               "expected_incarnations": {"1000": {"gens": {
                   "0": {"exe": "/w/ledger", "retired": True},
                   "1": {"exe": "/w/ledger2", "retired": False}}}},
               "expected_edges": {"1000:0:A": {"counted": True, "count": 8},
                                  "1000:1:A": {"counted": True, "count": 20}},
               "measured": {"label": "gen1", "t0": h0 - 1, "t1": h1 + 1,
                            "expected_calls": 20,
                            "phases": ["main:gen1", "teardown:gen1"]},
               "warmup": {"label": "gen0", "t0": m0 - 1, "t1": m1 + 1,
                          "expected_calls": 8,
                          "phases": ["main:gen0", "teardown:gen0"]},
               "allowed_gap_subjects": ["exact image authority unavailable"],
               "cell_endings": {"PX": {"how": "exited", "rc": 0}},
               "requested_backend": "singles"}
    return doc, ledgers, receipt


class InventoryTest(unittest.TestCase):
    maxDiff = 4000

    def test_accept_inventory_control(self):
        doc, ledgers, receipt = inventory_inputs()
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["physical_entered"], 28)
        self.assertEqual(result["physical_counted"], 28)
        self.assertEqual(result["failed_ledgered"], 1)
        self.assertEqual(result["s1"]["instances"], 2)
        self.assertEqual(result["s1"]["semantic_edges"], 2)
        self.assertEqual(result["completed_operations"], 13)
        self.assertEqual(result["s1"]["measured_completed"], 10)

    def test_reject_inventory_outside_count(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["edges"][1]["entries"]["count"] = 99
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("counted entries disagree" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_unowned_instance_caller(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["callers"].append({"id": "c9", "pid": 4242, "start_time": 1, "incarnation": 0,
                               "lifecycle": "mapped", "retired": False,
                               "image": {"exe": {"path": "/w/other"}}})
        doc["instances"][1]["caller"] = "c9"
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("unowned caller" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_unknown_instance_caller(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["instances"][1]["caller"] = "cX"
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("unknown caller" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_zero_completion_on_measured_image(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["edges"][1]["operations"]["completed"] = 0
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("completed operations disagree" in error
                            for error in result["errors"]), result["errors"])
        self.assertTrue(any("fewer than 10" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_wrong_mechanism_totals(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["edges"][1]["mechanisms"][0]["calls"] = 19
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("mechanism call total" in error for error in result["errors"]),
                        result["errors"])
        doc, _, _ = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["edges"][0]["mechanisms"][0]["errors"] = 0
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("mechanism error total" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_unledgered_mechanism(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["edges"][1]["mechanisms"].append(
            {"mechanism": 0x1087, "mechanism_hex": "0x1087", "calls": 2, "errors": 0})
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("outside the ledgered mechanism set" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_stale_incarnation_counts(self):
        # Successor returns leaked onto the retired gen0 row must fail gen0's
        # own group, not hide behind the successor's totals.
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["semantic_edges"][0]["api_returns"]["count"] = 13
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("semantic returns" in error for error in result["errors"]),
                        result["errors"])
        doc, _, _ = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["edges"][0]["operations"]["completed"] = 8
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("completed operations disagree" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_inventory_missing_measured(self):
        doc, ledgers, receipt = inventory_inputs()
        del receipt["measured"]
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("missing measured phase" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_s1_withheld_when_expected(self):
        doc, ledgers, receipt = inventory_inputs(s1_expected=False)
        receipt = copy.deepcopy(receipt)
        receipt["s1_expected"] = True
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("S1 unavailable" in error or "S1 withheld" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_lossy_counted_edge(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["edges"][0]["entries"]["coverage"]["lossy"] = True
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("lossy" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_unadmitted_counted_edge(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["edges"][1]["entries"]["coverage"] = {"state": "unknown",
                                                  "reason": "use_before_admission"}
        doc["edges"][1]["entries"]["count"] = 0
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("never admitted" in error for error in result["errors"]),
                        result["errors"])

    def test_zero_ok_mapping_control(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        receipt = copy.deepcopy(receipt)
        doc["callers"].append({"id": "c2", "pid": 2000, "start_time": 1,
                               "incarnation": 0, "lifecycle": "mapped",
                               "retired": False,
                               "image": {"exe": {"path": "/w/ledger"}}})
        doc["edges"].append({"caller": "c2", "module": "m0",
                             "entries": {"count": 0, "coverage": {
                                 "state": "unknown", "reason": "not_admitted"}}})
        receipt["owned_pids"].append(2000)
        receipt["expected_incarnations"]["2000"] = {
            "gens": {"0": {"exe": "/w/ledger", "retired": False}}}
        receipt["expected_edges"]["2000:0:A"] = {"zero_ok": True}
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        doc["edges"][2]["entries"]["count"] = 5
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("mapping-only control" in error for error in result["errors"]),
                        result["errors"])

    def test_foreign_caller_refusal(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        receipt = copy.deepcopy(receipt)
        doc["callers"].append({"id": "c9", "pid": 4242, "start_time": 1,
                               "incarnation": 0, "lifecycle": "mapped",
                               "retired": False,
                               "image": {"exe": {"path": "/w/ledger"}}})
        doc["edges"].append({"caller": "c9", "module": "m0",
                             "entries": {"count": 0, "coverage": {
                                 "state": "unknown", "reason": "not_admitted"}}})
        receipt["owned_pids"].append(4242)
        receipt["foreign_pids"] = [4242]
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        doc["edges"][2]["entries"]["count"] = 7
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("foreign producer" in error for error in result["errors"]),
                        result["errors"])

    def test_reject_module_identity_mismatch(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        doc["modules"][0]["identity"]["inode"] = 999
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("module identity" in error for error in result["errors"]),
                        result["errors"])

    def test_allow_path_gaps_for_system_scale(self):
        doc, ledgers, receipt = inventory_inputs()
        doc = copy.deepcopy(doc)
        receipt = copy.deepcopy(receipt)
        doc["gaps"].append({"subject": "/usr/lib/libx.so.1 (deleted)", "detail": ""})
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])
        receipt["allow_path_gaps"] = True
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        doc["gaps"].append({"subject": "novel verdict gap", "detail": ""})
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"])


class CallerExecHelperTest(unittest.TestCase):
    """caller_exec must fetch each transition's own from-image record."""

    def _driver(self, plan):
        handle = H6

        class Pipe:
            def __init__(self):
                self.writes = []

            def write(self, text):
                self.writes.append(text)

            def flush(self):
                pass

        class Caller:
            def __init__(self):
                self.popen = type("P", (), {"stdin": Pipe()})()

            def verify(self):
                pass

        class Stdout:
            def __init__(self, records):
                self._records = records

            def record(self, kind, image=0, phase=None, seconds=10):
                for row in self._records:
                    if row.get("kind") == kind and row.get("image") == image \
                            and (phase is None or row.get("phase") == phase):
                        return row
                raise AssertionError(f"no {kind} record for image {image}")

        class Pin:
            def __init__(self, path):
                self.path = path

            def image_receipt(self, record, caller):
                return {"image": record["image"], "path": str(self.path)}

        _ = handle
        return Caller(), Stdout(plan), Pin

    def test_three_exec_chain_returns_distinct_requests(self):
        plan = [
            {"kind": "ready", "image": 1},
            {"kind": "image", "image": 1},
            {"kind": "exec", "image": 0, "path": "/w/caller-b",
             "mode": "leader"},
            {"kind": "ready", "image": 2},
            {"kind": "image", "image": 2},
            {"kind": "exec", "image": 1, "path": "/w/caller-a",
             "mode": "leader"},
            {"kind": "ready", "image": 3},
            {"kind": "image", "image": 3},
            {"kind": "exec", "image": 2, "path": "/w/caller-b",
             "mode": "leader"},
        ]
        caller, stdout, pin_cls = self._driver(plan)
        images = [{"image": 0, "path": "/w/caller-a"}]
        requests = []
        for target in ("/w/caller-b", "/w/caller-a", "/w/caller-b"):
            request, _, _, _ = H6["caller_exec"](
                caller, stdout, images, "exec", pin_cls(target))
            requests.append(request)
        self.assertEqual([row["image"] for row in requests], [0, 1, 2])
        self.assertEqual([row["path"] for row in requests],
                         ["/w/caller-b", "/w/caller-a", "/w/caller-b"])

    def test_exec_record_mismatch_is_setup_error(self):
        plan = [{"kind": "ready", "image": 1},
                {"kind": "image", "image": 1},
                {"kind": "exec", "image": 0, "path": "/w/caller-b",
                 "mode": "leader"}]
        caller, stdout, pin_cls = self._driver(plan)
        images = [{"image": 0, "path": "/w/caller-a"}]
        with self.assertRaises(H6["SetupError"]):
            H6["caller_exec"](caller, stdout, images, "thread-exec",
                              pin_cls("/w/caller-b"))


if __name__ == "__main__":
    unittest.main()
