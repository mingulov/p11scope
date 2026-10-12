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
from collections import Counter
import inspect
import io
import json
import os
import runpy
import signal
import shutil
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


class InventoryExecDeadlineTest(unittest.TestCase):
    def test_exec_stop_cannot_extend_the_existing_image_recovery_deadline(self):
        now = [1_000_000_000]
        budget = H6["LegBudget"](inventory=True, clock=lambda: now[0],
                                 budgets={"successor-recovery": 0.05})
        budget.enter("successor-recovery", 1)
        deadline = budget.phase_deadline_ns
        now[0] = 1_040_000_000
        def stop(_pid, _flags):
            now[0] = 1_060_000_000
            return 1234, (H6["_PTRACE_EVENT_EXEC"] << 16) | (signal.SIGTRAP << 8) | 0x7f
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            with mock.patch.dict(H6["wait_exec_stop"].__globals__, {"monotonic_ns": lambda: now[0]}), \
                    mock.patch.object(os, "waitpid", stop), self.assertRaises(TimeoutError):
                H6["wait_exec_stop"](1234, timeout=0.05, deadline=deadline)
            self.assertNotIn(("successor-recovery", 1234), budget.deadlines)
        finally:
            H6["ACTIVE_LEG"].reset(token)

    def test_exec_stop_before_expiry_preserves_image_key_and_legacy_wait_is_bounded(self):
        for explicit in (True, False):
            with self.subTest(explicit=explicit):
                now = [1_000_000_000]
                budget = H6["LegBudget"](inventory=True, clock=lambda: now[0],
                                         budgets={"successor-recovery": 0.05})
                budget.enter("successor-recovery", 1)
                deadline = budget.phase_deadline_ns
                now[0] = 1_040_000_000
                def stop(_pid, _flags):
                    now[0] = 1_049_000_000
                    return 1234, (H6["_PTRACE_EVENT_EXEC"] << 16) | (signal.SIGTRAP << 8) | 0x7f
                token = H6["ACTIVE_LEG"].set(budget)
                try:
                    with mock.patch.dict(H6["wait_exec_stop"].__globals__, {"monotonic_ns": lambda: now[0]}), \
                            mock.patch.object(os, "waitpid", stop):
                        kwargs = {"deadline": deadline} if explicit else {}
                        self.assertEqual(H6["wait_exec_stop"](1234, timeout=0.05, **kwargs), now[0])
                    self.assertEqual(("successor-recovery", 1234) in budget.deadlines, not explicit)
                finally:
                    H6["ACTIVE_LEG"].reset(token)

    def test_expired_unrelated_trap_cannot_dispatch_continue(self):
        now = [1_000_000_000]
        budget = H6["LegBudget"](inventory=True, clock=lambda: now[0],
                                 budgets={"successor-recovery": 0.05})
        budget.enter("successor-recovery", 1)
        deadline = budget.phase_deadline_ns
        def stop(_pid, _flags):
            now[0] += 60_000_000
            return 1234, (signal.SIGTRAP << 8) | 0x7f
        continuation = mock.Mock()
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            with mock.patch.dict(H6["wait_exec_stop"].__globals__,
                    {"monotonic_ns": lambda: now[0], "_ptrace": continuation}), \
                    mock.patch.object(os, "waitpid", stop), self.assertRaises(TimeoutError):
                H6["wait_exec_stop"](1234, deadline=deadline)
            continuation.assert_not_called()
        finally:
            H6["ACTIVE_LEG"].reset(token)


class BDispatchClockTest(unittest.TestCase):
    def test_expired_leg_prevents_real_pipe_dispatch(self):
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        now = [1_000_000_000]
        budget = H6["LegBudget"](clock=lambda: now[0], budgets={"setup": 0.1})
        driver = H6["BDriver"].__new__(H6["BDriver"])
        driver.stamps = {}
        class Pipe:
            def write(self, byte): os.write(write_fd, byte.encode())
            def flush(self): pass
        driver.owned = SimpleNamespace(verify=lambda: None, popen=SimpleNamespace(stdin=Pipe()))
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            now[0] += 100_000_000
            with self.assertRaises(TimeoutError):
                driver.send("W", "expired")
            with self.assertRaises(BlockingIOError):
                os.read(read_fd, 1)
            self.assertEqual(driver.stamps, {})
        finally:
            H6["ACTIVE_LEG"].reset(token)
            os.close(write_fd)
            os.close(read_fd)

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


class PhaseDeadlineTest(unittest.TestCase):
    def test_open_pipe_and_pty_transports_expire_at_the_leg_bound(self):
        with tempfile.TemporaryDirectory(prefix="h6-transport-deadline-") as directory:
            for kind in ("pipe", "pty"):
                with self.subTest(kind=kind):
                    budget = H6["LegBudget"](leg_seconds=0.05)
                    token = H6["ACTIVE_LEG"].set(budget)
                    stream = None
                    if kind == "pipe":
                        read_fd, held = os.pipe()
                        stream = os.fdopen(read_fd, encoding="utf-8")
                        reader = H6["Reader"](stream, Path(directory) / "pipe.txt")
                    else:
                        master, held = H6["pty"].openpty()
                        reader = H6["PtyCapture"](master, Path(directory) / "pty.txt")
                    H6["ACTIVE_LEG"].reset(token)
                    try:
                        reader.thread.join(0.4)
                        self.assertFalse(reader.thread.is_alive(), "open transport survived its finite leg")
                        self.assertTrue(any("deadline" in error for error in reader.errors), reader.errors)
                    finally:
                        reader.stop.set()
                        os.close(held)
                        reader.thread.join(1)
                        if stream is not None:
                            stream.close()

    def test_reader_cannot_accept_proof_after_its_phase_expires(self):
        now = [1_000_000_000]
        budget = H6["LegBudget"](clock=lambda: now[0], budgets={"setup": 0.1})
        class Updates:
            def get(self, timeout):
                now[0] += 250_000_000  # Scheduling delays do not renew the wait.
        reader = H6["Reader"].__new__(H6["Reader"])
        reader.errors, reader.updates = [], Updates()
        reader.thread = SimpleNamespace(is_alive=lambda: True)
        checked = []
        def predicate(_reader):
            checked.append(True)
            return {"proof": "late"} if len(checked) > 1 else None
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            with mock.patch.dict(H6["Reader"].wait.__globals__, {"monotonic_ns": lambda: now[0]}), \
                    self.assertRaises(TimeoutError):
                reader.wait(predicate, 10)
            self.assertEqual(len(checked), 1, "late proof was examined after the absolute phase limit")
        finally:
            H6["ACTIVE_LEG"].reset(token)

    def test_repeated_waits_and_reentry_consume_one_absolute_phase(self):
        now = [1_000_000_000]
        budget = H6["LegBudget"](clock=lambda: now[0], budgets={"setup": 2})
        self.assertEqual(budget.remaining(10), 2)
        now[0] += 750_000_000
        budget.enter("setup")
        self.assertEqual(budget.remaining(10), 1.25)
        now[0] += 1_250_000_000
        with self.assertRaises(TimeoutError):
            budget.remaining(10)

    def test_recovery_attempts_do_not_renew_phase_or_leg_age(self):
        now = [1_000_000_000]
        budget = H6["LegBudget"](clock=lambda: now[0], budgets={"successor-recovery": 1})
        budget.enter("successor-recovery", key=1)
        original = budget.phase_deadline_ns
        now[0] += 600_000_000
        budget.enter("successor-recovery", key=1)
        self.assertEqual(budget.phase_deadline_ns, original)
        self.assertEqual(budget.remaining(15), 0.4)
        now[0] += 400_000_000
        with self.assertRaises(TimeoutError):
            budget.enter("successor-recovery", key=1)

    def test_short_leg_caps_a_later_phase(self):
        now = [1_000_000_000]
        budget = H6["LegBudget"](clock=lambda: now[0], leg_seconds=1)
        now[0] += 900_000_000
        budget.enter("fixed-measurement")
        self.assertEqual(budget.remaining(60), 0.1)
        now[0] += 100_000_000
        with self.assertRaises(TimeoutError):
            budget.remaining(60)

    def test_stop_wait_and_receipt_use_same_limit(self):
        now = [1_000_000_000]
        class Child:
            def wait(self, timeout):
                now[0] += int(timeout * 1e9) - 1
                return 0
        owner = SimpleNamespace(send=lambda _signal: None, popen=Child())
        globals_ = H6["stop_observer"].__globals__
        with mock.patch.dict(globals_, {"monotonic_ns": lambda: now[0]}):
            rc, stopped, latency = H6["stop_observer"](owner)
        self.assertEqual(rc, 0)
        self.assertLessEqual(latency, 60)
        self.assertEqual(owner.stop_receipt["stop_limit_seconds"], 60)
        self.assertFalse(owner.stop_receipt["forced_cleanup"])
        self.assertEqual(owner.stop_receipt["stop_latency_seconds"], latency)
        self.assertEqual(stopped, now[0])

    def test_forced_stop_is_failed_even_if_cleanup_reaps_zero_status(self):
        now = [1_000_000_000]
        class Child:
            def wait(self, timeout):
                now[0] += int(timeout * 1e9)
                if not getattr(self, "killed", False):
                    raise subprocess.TimeoutExpired("owned child", timeout)
                return 0
        child = Child()
        def send(signum):
            if signum == H6["signal"].SIGKILL:
                child.killed = True
        owner = SimpleNamespace(send=send, popen=child)
        globals_ = H6["stop_inventory"].__globals__
        with mock.patch.dict(globals_, {"monotonic_ns": lambda: now[0]}):
            rc, _, latency = H6["stop_inventory"](owner)
        self.assertEqual(rc, 0)
        self.assertEqual(latency, 30)
        self.assertTrue(owner.stop_receipt["forced_cleanup"])
        self.assertEqual(owner.stop_receipt["cleanup_latency_seconds"], 5)
        text, ledger, receipt = b_style_inputs()
        receipt.update(owner.stop_receipt)
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertFalse(result["pass"], result)
        self.assertTrue(any("forced" in error for error in result["errors"]), result)

    def test_forced_cleanup_refuses_aggregate_and_inventory_zero_status(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        receipt["forced_cleanup"] = True
        result = H6["evaluate_profile_h6"](doc, stdout_text, ledger, receipt)
        self.assertFalse(result["pass"], result)
        self.assertTrue(any("forced" in error for error in result["errors"]), result)
        doc, ledgers, receipt = inventory_inputs()
        receipt["forced_cleanup"] = True
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"], result)
        self.assertTrue(any("forced" in error for error in result["errors"]), result)


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
                            ("before", []), ("after", ["-DDETAILED_EXEC_AFTER"]),
                            ("before-short", ["-DDETAILED_EXEC_LEGACY_WAIT_NS=50000000UL"]),
                            ("after-short", ["-DDETAILED_EXEC_AFTER", "-DDETAILED_EXEC_LEGACY_WAIT_NS=50000000UL"])):
            result = subprocess.run(["cc", *H6["B_CFLAGS"], *flags, str(source), "-ldl",
                                     "-o", str(cls.directory / name)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stderr)

    def child(self, after=True, warm=False, failed=False, deadlines=None, short=False,
              delay_ms=0, before_name="before", mode=None, provider_name="provider.so"):
        provider = str(self.directory / provider_name)
        suffix = "-short" if short else ""
        argv = ([str(self.directory / ("after" + suffix)), provider, str(os.getpid()), "43"] if after
                else [str(self.directory / (before_name + suffix)), provider, str(self.directory / "after"),
                      str(self.directory / "absent"), str(os.getpid()), "43", mode or ("1" if failed else "0")])
        if warm or deadlines:
            argv += ["17", str(delay_ms), "1" if warm else "0"]
        if deadlines:
            argv += [str(value) for value in deadlines]
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
        proc.h6_reader = reader
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

    def deadline_args(self, hold_ms=500, recovery_ms=500, setup_ms=500, measurement_ms=500):
        now = time.monotonic_ns()
        return [now + 2_000_000_000, now + setup_ms * 1_000_000,
                recovery_ms, measurement_ms, hold_ms]

    def test_opt_in_mode2_has_no_real_provider_call_before_zombie_release(self):
        # Instrument the real provider entry, so an early partial batch cannot
        # hide behind a missing WORKER_DONE. The driver and clone stay real.
        source = (ROOT / "tests/fixtures/detailed-nonleader-exec.c").read_text()
        source = source.replace("    struct request *request = argument;",
            "    struct request *request = argument;\n"
            "    if (request->operation == 0) emit(\"CAPABILITY_CALL\", NULL, 0);", 1)
        result = subprocess.run(["cc", *H6["B_CFLAGS"], "-DDETAILED_EXEC_PROVIDER", "-fPIC", "-shared",
                                 "-x", "c", "-", "-ldl", "-o", str(self.directory / "provider-counted.so")],
                                input=source, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        proc, expect, send = self.child(after=False, mode="2", deadlines=self.deadline_args(),
                                        provider_name="provider-counted.so")
        expect("READY")
        send("G")
        thread = expect("THREAD")
        expect("LEADER_EXIT")
        deadline = time.monotonic() + 0.3
        while H6["proc_task_states"](proc.pid).get(proc.pid) != "Z":
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.001)
        states = H6["proc_task_states"](proc.pid)
        self.assertIn(states.get(int(thread[2])), ("R", "S"))
        with self.assertRaises(TimeoutError, msg="real capability entry occurred before controller release"):
            H6["expect_line"](proc.h6_reader, 0, "CAPABILITY_CALL", 0.04)
        waiting = expect("WORKER_WAIT")
        self.assertEqual(waiting[1:3], thread[1:3])
        released_ns = time.monotonic_ns()
        send("B")
        released = expect("WORKER_RELEASE")
        self.assertEqual(released[1:3], thread[1:3])
        self.assertGreaterEqual(int(released[-1]), released_ns)
        for _ in range(11):
            self.assertGreaterEqual(int(expect("CAPABILITY_CALL")[-1]), int(released[-1]))
        self.assertEqual([int(v) for v in expect("WORKER_DONE")[3:6]], [11, 6, 5])
        expect("EXEC_BODY")
        send("X")
        expect("NEW_READY")
        send("P")
        expect("POST_BODY")
        send("R")
        self.assertEqual([int(v) for v in expect("NEW_DONE")[3:6]], [17, 9, 8])
        send("F")
        self.assertEqual(proc.wait(timeout=2), 0)

    def mode2_driver(self, before_name="before"):
        proc, expect, _send = self.child(after=False, mode="2", before_name=before_name,
                                         deadlines=self.deadline_args(setup_ms=1500))
        expect("READY")
        driver = H6["BDriver"].__new__(H6["BDriver"])
        driver.pid, driver.mode = proc.pid, "2"
        driver.owned = H6["OwnedProcess"](proc.pid, os.getpid(), os.getuid(), proc)
        self.addCleanup(driver.owned.close)
        driver.birth = driver.owned.identity["start_time"]
        driver.stdout, driver.index = proc.h6_reader, 0
        driver.stamps, driver.lines, driver.tasks = {}, {}, {}
        return proc, driver

    def test_mode2_driver_proves_original_zombie_and_releases_exact_worker(self):
        proc, driver = self.mode2_driver()
        driver.start_worker()
        self.assertIn("B", driver.stamps, "controller never released the opt-in worker")
        proof = driver.worker_barrier
        self.assertEqual(proof["tasks"][proc.pid], "Z")
        self.assertIn(proof["tasks"][driver.worker_tid], ("R", "S"))
        self.assertEqual(proof["worker"]["tid"], driver.worker_tid)
        self.assertEqual(proof["worker"]["tgid"], proc.pid)
        self.assertGreater(proof["worker"]["start_time"], 0)
        self.assertEqual(proof["worker"]["pid_namespace"], driver.owned.identity["pid_namespace"])
        self.assertLessEqual(proof["observed_ns"], proof["released_ns"])
        self.assertLessEqual(proof["released_ns"], proof["worker_release_ns"])
        driver.pre_exec()
        # X dispatch must also work while /proc/<zombie leader>/ns is gone.
        driver.send("X", "X")
        driver.expect("NEW_READY")

    def delayed_mode2_driver(self):
        # A controlled pipe holds the original leader after LEADER_EXIT.
        # The worker's barrier ack is real, and no deadline is lengthened.
        source = (ROOT / "tests/fixtures/detailed-nonleader-exec.c").read_text()
        source = source.replace("        (void)raw6(SYS_exit, 0, 0, 0, 0, 0, 0);",
            "        char leader_gate;\n"
            "        if (raw6(SYS_read, 3, (long)&leader_gate, 1, 0, 0, 0) != 1) fail(109);\n"
            "        (void)raw6(SYS_exit, 0, 0, 0, 0, 0, 0);", 1)
        # FD3 is prepared by the test's child before exec, without preexec_fn.
        result = subprocess.run(["cc", *H6["B_CFLAGS"], "-x", "c", "-", "-ldl",
                                 "-o", str(self.directory / "before-leader-held")],
                                input=source, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        popen = subprocess.Popen
        def spawn(argv, **kwargs):
            script = "import os,sys; os.dup2(int(sys.argv[1]),3); os.set_inheritable(3,True); os.execv(sys.argv[2],sys.argv[2:])"
            return popen([sys.executable, "-I", "-c", script, str(read_fd), *argv],
                         pass_fds=(read_fd,), **kwargs)
        try:
            with mock.patch.object(subprocess, "Popen", spawn):
                proc, driver = self.mode2_driver("before-leader-held")
        finally:
            os.close(read_fd)
        return proc, driver, write_fd

    def test_mode2_delayed_actual_leader_exit_is_polled(self):
        proc, driver, leader_gate = self.delayed_mode2_driver()
        observations = []
        snapshot = H6["proc_task_states"]
        def observe(pid):
            states = snapshot(pid)
            observations.append(states.get(pid))
            if len(observations) == 2:
                os.write(leader_gate, b"E")
            return states
        with mock.patch.dict(driver.start_worker.__globals__, {"proc_task_states": observe}):
            try:
                driver.start_worker()
            except AssertionError as error:
                self.fail(f"LEADER_EXIT intent was mistaken for actual exit: {error}")
        self.assertGreaterEqual(len(observations), 3)
        self.assertIn(observations[0], ("R", "S"))
        self.assertEqual(observations[-1], "Z")
        self.assertIn("B", driver.stamps)
        self.assertIsNone(proc.poll())

    def test_mode2_live_leader_at_expiry_refuses_release(self):
        _proc, driver, _leader_gate = self.delayed_mode2_driver()
        budget = H6["LegBudget"](budgets={"setup": 0.08})
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            with self.assertRaises((TimeoutError, H6["SetupError"])):
                driver.start_worker()
        finally:
            H6["ACTIVE_LEG"].reset(token)
        self.assertNotIn("B", driver.stamps)

    def test_mode2_missing_worker_and_dead_group_refuse_release(self):
        for state in ("missing", "zombie", "dead-group"):
            with self.subTest(state=state):
                proc, driver = self.mode2_driver()
                snapshot = H6["proc_task_states"]
                def observe(pid):
                    states = snapshot(pid)
                    if state == "missing":
                        states.pop(driver.worker_tid, None)
                    elif state == "zombie":
                        states[driver.worker_tid] = "Z"
                    else:
                        proc.kill()
                        proc.wait(timeout=2)
                    return states
                with mock.patch.dict(driver.start_worker.__globals__, {"proc_task_states": observe}):
                    try:
                        with self.assertRaises((H6["SetupError"], OSError, ValueError)):
                            driver.start_worker()
                    except AssertionError as error:
                        self.fail(f"worker refusal was an unclassified snapshot assertion: {error}")
                self.assertNotIn("B", driver.stamps)

    def test_mode2_changed_worker_birth_group_or_namespace_refuses_release(self):
        for field in ("start_time", "tgid", "pid_namespace", "time_namespace"):
            with self.subTest(field=field):
                _proc, driver = self.mode2_driver()
                calls = []
                read = H6["proc_worker_identity"]
                def changed(pid, tid):
                    identity = read(pid, tid)
                    calls.append(identity)
                    if len(calls) > 1:
                        identity[field] += 1
                    return identity
                with mock.patch.dict(driver.start_worker.__globals__, {"proc_worker_identity": changed}):
                    with self.assertRaises(H6["SetupError"]):
                        driver.start_worker()
                self.assertNotIn("B", driver.stamps)

    def test_mode2_vanished_worker_or_wrong_original_leader_refuses_release(self):
        for broken in ("vanished", "leader-birth", "leader-parent", "leader-uid"):
            with self.subTest(broken=broken):
                _proc, driver = self.mode2_driver()
                worker_read, leader_read = H6["proc_worker_identity"], H6["proc_leader_identity"]
                calls = []
                def worker(pid, tid):
                    calls.append(True)
                    if broken == "vanished" and len(calls) > 1:
                        raise FileNotFoundError("controlled exact worker disappearance")
                    return worker_read(pid, tid)
                def leader(pid):
                    identity = leader_read(pid)
                    if broken != "vanished":
                        field = {"leader-birth": "start_time", "leader-parent": "ppid", "leader-uid": "uid"}[broken]
                        identity[field] += 1
                    return identity
                with mock.patch.dict(driver.start_worker.__globals__, {
                        "proc_worker_identity": worker, "proc_leader_identity": leader}):
                    with self.assertRaises((H6["SetupError"], FileNotFoundError)):
                        driver.start_worker()
                self.assertNotIn("B", driver.stamps)

    def test_mode2_cleanup_reaps_the_owned_zombie_leader_group(self):
        proc, driver = self.mode2_driver()
        driver.start_worker()
        driver.pre_exec()
        ctx = H6["Case"](SimpleNamespace(out=self.directory))
        ctx.owners.append(driver.owned)
        ctx.readers.append(driver.stdout)
        try:
            H6["cleanup_leg_resources"](ctx)
        except H6["LegCleanupError"] as error:
            self.fail(f"zombie leader custody prevented owned-group cleanup: {error}")
        self.assertEqual(proc.returncode, -9)
        self.assertIsNone(driver.owned.pidfd)
        self.assertFalse(driver.stdout.thread.is_alive())
        self.assertEqual(ctx.owners, [])

    def test_legacy_mode2_keeps_its_ungated_worker_protocol(self):
        proc, expect, send = self.child(after=False, mode="2")
        expect("READY")
        send("G")
        expect("THREAD")
        # Legacy W and WORKER_DONE may race LEADER_EXIT; no barrier B exists.
        done, _ = H6["expect_line"](proc.h6_reader, 0, "WORKER_DONE", 2)
        self.assertEqual([int(v) for v in done.split()[3:6]], [11, 6, 5])
        expect("EXEC_BODY")
        send("X")
        expect("NEW_READY")
        send("P")
        expect("POST_BODY")
        send("R")
        self.assertEqual([int(v) for v in expect("NEW_DONE")[3:6]], [17, 9, 8])
        send("F")
        self.assertEqual(proc.wait(timeout=2), 0)

    def test_opt_in_initial_g_expires_at_absolute_setup_bound(self):
        proc, expect, _send = self.child(after=False, short=True, deadlines=self.deadline_args(setup_ms=150))
        expect("READY")
        time.sleep(0.08)
        self.assertIsNone(proc.poll(), "H6 G wait still used the independent legacy bound")
        self.assertEqual(proc.wait(timeout=1), 92)

    def test_opt_in_pre_exec_x_wait_uses_recovery_phase_bound(self):
        for failed in (False, True):
            with self.subTest(failed=failed):
                proc, expect, send = self.child(after=False, failed=failed,
                    deadlines=self.deadline_args(recovery_ms=60, measurement_ms=60))
                expect("READY")
                send("G")
                expect("THREAD")
                expect("WORKER_DONE")
                expect("EXEC_BODY")
                try:
                    status = proc.wait(timeout=0.18)
                except subprocess.TimeoutExpired:
                    self.fail("X wait survived 180 ms despite its 60 ms recovery limit (2 s leg)")
                self.assertEqual(status, 92)

    def test_opt_in_failed_exec_r_wait_uses_fixed_post_phase_bound(self):
        proc, expect, send = self.child(after=False, failed=True,
            deadlines=self.deadline_args(recovery_ms=60, measurement_ms=60))
        expect("READY")
        send("G")
        thread = expect("THREAD")
        expect("WORKER_DONE")
        expect("EXEC_BODY")
        send("X")
        failed = expect("EXEC_FAILED")
        self.assertEqual(failed[1:3], thread[1:3])
        try:
            status = proc.wait(timeout=0.18)
        except subprocess.TimeoutExpired:
            self.fail("failed-exec R wait survived 180 ms despite 60 ms recovery and measurement limits (2 s leg)")
        self.assertEqual(status, 92)

    def test_opt_in_failed_post_deadline_survives_actual_return_before_remaining_calls(self):
        # Advance only the driver's clock after the real matched RV5. A reset
        # after return would grant another 60 ms and permit the remaining calls.
        source = (ROOT / "tests/fixtures/detailed-nonleader-exec.c").read_text()
        source = source.replace("static unsigned long clock_ns(void) {",
            "static unsigned long clock_shift_ns;\nstatic unsigned long clock_ns(void) {")
        source = source.replace("return (unsigned long)now.tv_sec * 1000000000UL",
            "return clock_shift_ns + (unsigned long)now.tv_sec * 1000000000UL")
        source = source.replace("    ++errors;\n", "    clock_shift_ns = 200000000UL;\n    ++errors;\n", 1)
        result = subprocess.run(["cc", *H6["B_CFLAGS"], "-x", "c", "-", "-ldl",
                                 "-o", str(self.directory / "before-clock")],
                                input=source, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        proc, expect, send = self.child(after=False, failed=True, before_name="before-clock",
            deadlines=self.deadline_args(recovery_ms=60, measurement_ms=60))
        expect("READY")
        send("G")
        expect("THREAD")
        expect("WORKER_DONE")
        expect("EXEC_BODY")
        send("X")
        expect("EXEC_FAILED")
        send("RF")
        self.assertEqual(proc.wait(timeout=1), 92,
            "failed-post measurement renewed after the original matched return")

    def test_opt_in_terminal_hold_survives_delayed_stop_then_expires(self):
        for finish in (True, False):
            with self.subTest(finish=finish):
                proc, expect, send = self.child(short=True, deadlines=self.deadline_args(hold_ms=200))
                expect("NEW_READY")
                send("P")
                expect("POST_BODY")
                send("R")
                expect("NEW_DONE")
                time.sleep(0.1)
                self.assertIsNone(proc.poll(), "fixture died inside permitted observer stop")
                if finish:
                    send("F")
                self.assertEqual(proc.wait(timeout=1), 0 if finish else 92)

    def test_opt_in_failed_join_covers_same_terminal_hold_and_exact_counts(self):
        proc, expect, send = self.child(after=False, failed=True, short=True,
                                       deadlines=self.deadline_args(hold_ms=300))
        ready = expect("READY")
        send("G")
        thread = expect("THREAD")
        expect("WORKER_DONE")
        expect("EXEC_BODY")
        send("X")
        failed = expect("EXEC_FAILED")
        self.assertEqual(failed[1:3], thread[1:3])
        self.assertEqual(ready[1], failed[1])
        send("R")
        self.assertEqual([int(v) for v in expect("DONE")[3:7]], [29, 15, 14, 5])
        time.sleep(0.15)
        self.assertIsNone(proc.poll(), "failed-exec join ended before permitted terminal hold")
        send("F")
        self.assertEqual(proc.wait(timeout=1), 0)

    def test_legacy_terminal_hold_retains_its_independent_default_bound(self):
        proc, expect, send = self.child(short=True)
        expect("NEW_READY")
        send("P")
        expect("POST_BODY")
        send("R")
        expect("NEW_DONE")
        self.assertEqual(proc.wait(timeout=1), 92)

    def test_opt_in_warm_commands_do_not_renew_recovery_deadline(self):
        proc, expect, send = self.child(warm=True, short=True, deadlines=self.deadline_args(recovery_ms=180))
        expect("NEW_READY")
        for sequence in (1, 2, 3):
            send("W")
            self.assertEqual(int(expect("WARM_DONE")[3]), sequence)
            time.sleep(0.04)
        self.assertEqual(proc.wait(timeout=0.1), 92)

    def test_opt_in_measurement_pacing_cannot_dispatch_past_phase_bound(self):
        deadlines = self.deadline_args()
        deadlines[3] = 60
        proc, expect, send = self.child(deadlines=deadlines, delay_ms=100)
        expect("NEW_READY")
        send("P")
        expect("POST_BODY")
        send("R")
        self.assertEqual(proc.wait(timeout=1), 92)


class WorkerCapabilityTest(unittest.TestCase):
    def inputs(self, captured=11):
        leader = {"pid": 1000, "ppid": 900, "start_time": 7777, "uid": 1001,
                  "pid_namespace": 1, "time_namespace": 2}
        worker = {"tid": 1001, "tgid": 1000, "ppid": 900, "start_time": 8888,
                  "uid": 1001, "pid_namespace": 1, "time_namespace": 2}
        proof = {"proof_kind": "zombie-leader-worker-gate", "leader": leader, "worker": worker,
                 "tasks": {1000: "Z", 1001: "S"}, "pidfd_live": True,
                 "started_ns": READY + 10, "thread_ns": READY + 20, "intent_ns": READY + 30,
                 "wait_ns": READY + 40, "observed_ns": READY + 50, "released_ns": READY + 60,
                 "worker_release_ns": READY + 70, "deadline_ns": READY + 100_000_000}
        lines = {"THREAD": f"THREAD 1000 1001 1001 {READY + 20}",
                 "LEADER_EXIT": f"LEADER_EXIT 1000 1001 {READY + 30}",
                 "WORKER_WAIT": f"WORKER_WAIT 1000 1001 {READY + 40}",
                 "WORKER_RELEASE": f"WORKER_RELEASE 1000 1001 {READY + 70}",
                 "WORKER_DONE": f"WORKER_DONE 1000 1001 11 6 5 {READY + 80}"}
        receipt = base_receipt(images=[image_record(0, "/w/before", READY - 10)],
            known_tids=[1000, 1001], b_setup={"mode": "2", "worker_identity": dict(worker),
                "worker_barrier": proof, "lines": lines,
                "stamps": {"G": READY + 10, "B": READY + 60, "WORKER_DONE": READY + 90}},
            phases=[{"image": 0, "phase": "pre", "count": 11, "t0": READY + 60, "t1": READY + 90}])
        ev = evidence()
        if captured != 11:
            ev.update(real_early_gap())
        result = {"pass": True, "status": "pass", "cell": "leader-exit-exec", "leg": "trace/singles",
                  "phase_populations": {"pre": {"named": captured}},
                  "image_generation_populations": {0: {"named": captured}},
                  "capability_early_coverage": {"expected": 11, "observed_named": captured, "observed_unknown": 0,
                                                "deficit": 11 - captured, "errors": []},
                  "early_coverage": {"expected": 12, "observed_named": captured + 1, "observed_unknown": 0,
                                     "deficit": 11 - captured}, "evidence": [ev], "errors": []}
        return result, receipt

    def test_capability_counts_only_exact_worker_rows_and_rejects_false_names(self):
        _result, receipt = self.inputs()
        rows = H6["N3_PARSE_TRACE"](trace_text([
            named_row(1000, 1001, "/w/before", "C_Initialize"),
            unknown_row(1000, 1001, "C_Initialize", rv="CKR_GENERAL_ERROR"),
            named_row(4242, 1001, "/w/before", "C_Initialize"),
            named_row(1000, 4242, "/w/before", "C_Initialize"),
            named_row(1000, 1000, "/w/after", "C_Initialize"),
        ], 5, 5, evidence()))[0]
        population = H6.get("worker_early_population")
        self.assertTrue(callable(population), "capability has no independent exact-worker population check")
        got = population(rows, receipt, {0: receipt["images"][0]}, {index: 0 for index in range(5)})
        self.assertEqual(got, {"expected": 11, "observed_named": 1, "observed_unknown": 1, "deficit": 9,
                              "errors": []})
        rows[0]["path"] = "/w/impostor"
        self.assertTrue(population(rows, receipt, {0: receipt["images"][0]}, {0: 0, 1: 0})["errors"])

    def run_capability(self, result, receipt, backend="singles"):
        with tempfile.TemporaryDirectory(prefix="h6-capability-") as directory:
            def leg(ctx, cell, backend, kind, leg_dir, mode):
                Path(leg_dir).mkdir(parents=True)
                if receipt is not None:
                    H6["write_json"](Path(leg_dir) / "receipt.json", receipt)
                return result
            runner = H6["run_leader_exit_exec"]
            with mock.patch.dict(runner.__globals__, {"run_b_leg": leg}):
                return runner(None, directory, backend)

    def test_valid_barrier_records_capability_deficit_separately(self):
        for captured, status in ((11, "demonstrated"), (4, "demonstrated"), (0, "limitation")):
            with self.subTest(captured=captured):
                result, receipt = self.inputs(captured)
                rows = self.run_capability(result, receipt)
                self.assertIs(rows[0], result)
                cap = rows[1]
                self.assertEqual(cap["status"], status)
                self.assertIsNone(cap["pass"])
                self.assertEqual(cap.get("early_coverage"), {"expected": 11, "observed_named": captured,
                                                       "observed_unknown": 0, "deficit": 11 - captured})

    def test_backend_mismatch_or_fallback_cannot_demonstrate_capability(self):
        for backend in ("singles", "multi"):
            other = "multi" if backend == "singles" else "singles"
            for refused in ("selection", "fallback", "request", "missing-selection"):
                with self.subTest(backend=backend, refused=refused):
                    result, receipt = self.inputs()
                    receipt["requested_backend"] = backend
                    result.update(leg=f"trace/{backend}", status="fail", **{"pass": False})
                    attach = result["evidence"][0]["attach_backend"]
                    attach["selection"] = backend
                    if refused == "selection": attach["selection"] = other
                    elif refused == "fallback": attach["fallback"] = other
                    elif refused == "request": receipt["requested_backend"] = other
                    else: del attach["selection"]
                    rows = self.run_capability(result, receipt, backend)
                    self.assertIs(rows[0], result)
                    self.assertIs(rows[0]["pass"], False)
                    self.assertEqual(rows[1]["status"], "error")
                    self.assertIs(rows[1]["pass"], False)
                    self.assertTrue(rows[1]["errors"])

    def test_valid_backend_capability_survives_a_later_recovery_failure(self):
        for backend in ("singles", "multi"):
            with self.subTest(backend=backend):
                result, receipt = self.inputs(4)
                receipt["requested_backend"] = backend
                result["evidence"][0]["attach_backend"]["selection"] = backend
                result.update(leg=f"trace/{backend}", status="fail", errors=["post-exec successor rows missing"],
                              **{"pass": False})
                rows = self.run_capability(result, receipt, backend)
                self.assertIs(rows[0], result)
                self.assertIs(rows[0]["pass"], False)
                cap = rows[1]
                self.assertEqual((cap["leg"], cap["status"], cap["pre_exec_captured"], cap["early_coverage"]["deficit"]),
                                 (f"capability-preexec/{backend}", "demonstrated", 4, 7))
                self.assertIsNone(cap["pass"])
                self.assertEqual(cap["errors"], [])

    def test_missing_or_insufficient_barrier_cannot_demonstrate_capability(self):
        for broken in ("absent", "live-leader", "missing-worker", "dead-worker", "wrong-birth",
                       "wrong-namespace", "no-pidfd", "missing-ack", "before-release", "expired", "no-evidence", "setup-error"):
            with self.subTest(broken=broken):
                result, receipt = self.inputs()
                proof = receipt["b_setup"]["worker_barrier"]
                if broken == "absent":
                    del receipt["b_setup"]["worker_barrier"]
                elif broken == "live-leader": proof["tasks"][1000] = "S"
                elif broken == "missing-worker": del proof["tasks"][1001]
                elif broken == "dead-worker": proof["tasks"][1001] = "Z"
                elif broken == "wrong-birth": proof["worker"]["start_time"] += 1
                elif broken == "wrong-namespace": proof["worker"]["pid_namespace"] += 1
                elif broken == "no-pidfd": proof["pidfd_live"] = False
                elif broken == "missing-ack": del receipt["b_setup"]["lines"]["WORKER_WAIT"]
                elif broken == "before-release": proof["worker_release_ns"] = READY + 59
                elif broken == "expired": proof["deadline_ns"] = READY + 49
                elif broken == "no-evidence": result["evidence"] = []
                else: result.update(status="error", **{"pass": False})
                cap = self.run_capability(result, receipt)[1]
                self.assertEqual(cap["status"], "error")
                self.assertIs(cap["pass"], False)
                self.assertTrue(cap["errors"])

    def test_backend_refusal_before_receipt_keeps_its_negative_classification(self):
        refusal = {"pass": False, "status": "negative", "leg": "trace/singles",
                   "negative_reason": "unsupported backend", "errors": ["backend refused"]}
        try:
            rows = self.run_capability(refusal, None)
        except FileNotFoundError as error:
            self.fail(f"backend refusal became a fabricated missing-receipt error: {error}")
        self.assertEqual(rows, [refusal])


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

    def test_expired_cleanup_still_cancels_reader_and_marks_custody_failed(self):
        scope = H6["LegContext"](self.ctx)
        owner, reader, _errors = self.child(scope.owners, scope.readers, self.directory)
        now = [1_000_000_000]
        budget = H6["LegBudget"](clock=lambda: now[0], budgets={"cleanup": 0.1})
        budget.enter("cleanup")
        now[0] += 100_000_000
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            with self.assertRaises(H6["LegCleanupError"]):
                H6["cleanup_leg_resources"](scope)
            self.assertTrue(reader.stop.is_set(), "deadline expiry bypassed sticky reader cancellation")
            self.assertTrue(self.ctx.cleanup_failed)
            self.assertTrue(any("deadline" in error for error in self.ctx.cleanup_errors))
        finally:
            H6["ACTIVE_LEG"].reset(token)
        reader.thread.join(1)
        try:
            H6["cleanup_leg_resources"](scope)
        except H6["LegCleanupError"]:
            pass  # The original cancellation remains an honest failed outcome.
        self.assertIsNotNone(owner.popen.poll())
        self.assertIsNone(owner.pidfd)

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

    def matrix(self, runner, *, pin_close_failure=False, cells=("pid-leader",),
               backends=("singles", "multi")):
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
        self.matrix_count = getattr(self, "matrix_count", 0) + 1
        out = self.directory / f"matrix-{self.matrix_count}"
        argv = ["--binary", str(self.case_pin.path), "--provider", str(self.case_pin.path),
                "--discover", str(self.case_pin.path), "--source-revision", "0" * 40,
                "--uid", "1001", "--gid", "1001", "--cells", ",".join(cells),
                "--backends", ",".join(backends), "--out", str(out)]
        def cell(ctx, directory, backend):
            rows = runner(ctx, directory, backend)
            return rows if isinstance(rows, list) else [rows]
        try:
            with mock.patch.dict(self.globals, {"FilePin": pin,
                    "compile_case_fixtures": lambda *_args: {}, "symbol_file_offset": lambda *_args: 0}), \
                    mock.patch.dict(H6["CELL_RUNNERS"], {name: cell for name in cells}), \
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

    def test_informational_capability_neither_passes_nor_fails_required_matrix(self):
        def runner(ctx, directory, backend):
            return [{"pass": True, "status": "pass", "leg": f"trace/{backend}"},
                    {"pass": None, "status": "demonstrated", "leg": f"capability-preexec/{backend}"}]
        rc, summary, _ = self.matrix(runner, cells=("leader-exit-exec",))
        self.assertEqual((rc, summary["passed"], summary["failed"]), (0, 2, 0))
        self.assertEqual((summary["negative"], summary["informational"]), (0, 2))
        self.assertTrue(summary["required_complete"])

    def test_positive_backend_cannot_mask_an_empty_or_informational_backend(self):
        for multi in ([], [{"pass": None, "status": "demonstrated", "leg": "capability-preexec/multi"}]):
            with self.subTest(multi=multi):
                def runner(ctx, directory, backend):
                    return [{"pass": True, "status": "pass", "leg": "trace/singles"}] if backend == "singles" else multi
                rc, summary, _ = self.matrix(runner, cells=("leader-exit-exec",))
                self.assertEqual((summary["passed"], summary["failed"], summary["negative"]), (1, 0, 0))
                self.assertEqual(summary["informational"], len(multi))
                self.assertEqual(rc, 1, "one backend's positive filled the other's required recovery result")
                self.assertFalse(summary["required_complete"])
                self.assertFalse(summary["complete"])
                self.assertEqual(summary["required_coverage"]["missing"],
                                 [{"cell": "leader-exit-exec", "leg": "trace/multi"}])

    def test_every_requested_cell_requires_each_distinct_recovery_leg(self):
        required = {"pid-leader": ("trace", "profile", "metrics"),
                    "pid-reexec": ("trace", "profile", "metrics"),
                    "pid-nonleader-cold": ("trace", "profile", "metrics"),
                    "pid-failed-exec": ("trace",), "leader-exit-exec": ("trace",),
                    "rapid-chain": ("trace", "reuse", "group-death"),
                    "cgroup-reentry": ("trace", "replacement", "stop-before", "stop-during", "inventory"),
                    "system-mixed": ("inventory",)}
        for cell, kinds in required.items():
            for missing in kinds:
                with self.subTest(cell=cell, missing=missing):
                    def runner(ctx, directory, backend):
                        present = kinds if backend == "singles" else [kind for kind in kinds if kind != missing]
                        return [{"pass": True, "status": "pass", "leg": f"{kind}/{backend}"} for kind in present]
                    rc, summary, _ = self.matrix(runner, cells=(cell,))
                    self.assertEqual((summary["failed"], summary["negative"]), (0, 0))
                    self.assertGreater(summary["passed"], 0)
                    self.assertEqual(rc, 1, "other positive legs filled an omitted recovery leg")
                    self.assertFalse(summary["required_complete"])
                    self.assertEqual(summary["required_coverage"]["missing"],
                                     [{"cell": cell, "leg": f"{missing}/multi"}])

    def test_duplicate_and_wrong_result_identities_cannot_complete_matrix(self):
        for wrong in ("duplicate", "cell", "backend", "kind"):
            with self.subTest(wrong=wrong):
                def runner(ctx, directory, backend):
                    rows = [{"pass": True, "status": "pass", "leg": f"{kind}/{backend}"}
                            for kind in ("trace", "profile", "metrics")]
                    if backend == "multi":
                        if wrong == "duplicate": rows.append(dict(rows[-1]))
                        elif wrong == "cell": rows[-1]["cell"] = "pid-reexec"
                        elif wrong == "backend": rows[-1]["leg"] = "metrics/singles"
                        else: rows[-1]["leg"] = "inventory/multi"
                    return rows
                rc, summary, _ = self.matrix(runner)
                self.assertEqual((summary["failed"], summary["negative"]), (0, 0))
                self.assertEqual(rc, 1, "duplicate/wrong recovery identity was accepted")
                self.assertFalse(summary["required_complete"])

    def test_rows_from_another_invocation_cannot_fill_required_identity(self):
        for swapped in ("cell", "backend"):
            with self.subTest(swapped=swapped):
                def runner(ctx, directory, backend):
                    cell = {"pid-leader": "pid-reexec", "pid-reexec": "pid-leader"}[directory.name] if swapped == "cell" else directory.name
                    selected = {"singles": "multi", "multi": "singles"}[backend] if swapped == "backend" else backend
                    return [{"cell": cell, "leg": f"{kind}/{selected}", "pass": True, "status": "pass"}
                            for kind in ("trace", "profile", "metrics")]
                rc, summary, _ = self.matrix(runner, cells=("pid-leader", "pid-reexec"))
                self.assertEqual((summary["passed"], summary["failed"], summary["negative"]), (12, 0, 0))
                self.assertEqual(rc, 1, "rows were credited to a different cell/backend invocation")
                self.assertFalse(summary["required_complete"])

    def test_all_selected_names_cannot_claim_complete_with_an_empty_cell(self):
        def runner(ctx, directory, backend):
            if directory.name == "system-mixed":
                return []
            kinds = {"pid-leader": ("trace", "profile", "metrics"),
                     "pid-reexec": ("trace", "profile", "metrics"),
                     "pid-nonleader-cold": ("trace", "profile", "metrics"),
                     "pid-failed-exec": ("trace",), "leader-exit-exec": ("trace",),
                     "rapid-chain": ("trace", "reuse", "group-death"),
                     "cgroup-reentry": ("trace", "replacement", "stop-before", "stop-during", "inventory")}
            return [{"pass": True, "status": "pass", "leg": f"{kind}/{backend}"} for kind in kinds[directory.name]]
        rc, summary, _ = self.matrix(runner, cells=H6["CELLS"])
        self.assertEqual((summary["failed"], summary["negative"]), (0, 0))
        self.assertEqual(rc, 1)
        self.assertFalse(summary["required_complete"])
        self.assertFalse(summary["complete"])

    def test_all_required_cell_backend_leg_results_complete_matrix(self):
        def runner(ctx, directory, backend):
            kinds = {"pid-leader": ("trace", "profile", "metrics"),
                     "pid-reexec": ("trace", "profile", "metrics"),
                     "pid-nonleader-cold": ("trace", "profile", "metrics"),
                     "pid-failed-exec": ("trace",), "leader-exit-exec": ("trace",),
                     "rapid-chain": ("trace", "reuse", "group-death"),
                     "cgroup-reentry": ("trace", "replacement", "stop-before", "stop-during", "inventory"),
                     "system-mixed": ("inventory",)}
            rows = [{"pass": True, "status": "pass", "leg": f"{kind}/{backend}"} for kind in kinds[directory.name]]
            if directory.name == "leader-exit-exec":
                rows.append({"pass": None, "status": "limitation", "leg": f"capability-preexec/{backend}"})
            return rows
        rc, summary, _ = self.matrix(runner, cells=H6["CELLS"])
        self.assertEqual((rc, summary["passed"], summary["failed"], summary["negative"], summary["informational"]),
                         (0, 40, 0, 0, 2))
        self.assertTrue(summary["required_complete"])
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["required_coverage"], {"required": 40, "positive": 40, "missing": [],
                          "nonpositive": [], "duplicates": [], "unexpected": [], "complete": True})

    def test_informational_only_population_cannot_complete_h6(self):
        rc, summary, _ = self.matrix(lambda ctx, directory, backend: {
            "pass": None, "status": "limitation", "leg": f"capability-preexec/{backend}"},
            cells=("leader-exit-exec",))
        self.assertEqual((summary["passed"], summary["failed"]), (0, 0))
        self.assertEqual(summary["informational"], 2)
        self.assertEqual(rc, 1)
        self.assertFalse(summary["required_complete"])
        self.assertFalse(summary["complete"])

    def test_required_failure_and_backend_refusal_are_separate_nonpositives(self):
        def runner(ctx, directory, backend):
            return {"pass": False, "status": "fail" if backend == "singles" else "negative",
                    "leg": f"trace/{backend}"}
        rc, summary, _ = self.matrix(runner, cells=("leader-exit-exec",))
        self.assertEqual((rc, summary["passed"], summary["failed"], summary.get("negative", -1)), (1, 0, 1, 1))
        self.assertFalse(summary["required_complete"])
        self.assertEqual(summary["required_coverage"]["missing"], [])
        self.assertEqual(summary["required_coverage"]["nonpositive"], [
            {"cell": "leader-exit-exec", "leg": "trace/multi", "pass": False, "status": "negative"},
            {"cell": "leader-exit-exec", "leg": "trace/singles", "pass": False, "status": "fail"}])

    def test_truthy_nonboolean_and_failed_status_cannot_count_as_positive(self):
        def runner(ctx, directory, backend):
            return {"pass": 1 if backend == "singles" else True,
                    "status": "pass" if backend == "singles" else "error", "leg": backend}
        rc, summary, _ = self.matrix(runner)
        self.assertEqual((rc, summary["passed"], summary["failed"]), (1, 0, 2))

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
            return {"leg": f"trace/{backend}", "status": "pass", "pass": True}
        rc, summary, cleanup = self.matrix(runner, pin_close_failure=True, cells=("pid-failed-exec",))
        self.assertEqual(rc, 1, "main decided success before final cleanup")
        self.assertGreater(summary["failed"], 0)
        self.assertTrue(any("controlled final pin cleanup failure" in error for error in cleanup["errors"]))
        self.assert_released()

    def test_child_exit_between_poll_and_signal_is_reaped_before_next_leg(self):
        started, races = [], []
        @H6["owned_leg"]
        def runner(ctx, directory, backend):
            # Reading returncode has no wait side effect; Popen.poll would
            # itself reap the zombie and hide the production cleanup race.
            for previous, _ in self.spawned:
                self.assertIsNotNone(previous.popen.returncode, "previous child lacked a terminal reap")
                self.assertFalse((Path("/proc") / str(previous.pid)).exists())
                self.assertIsNone(previous.pidfd)
            started.append(backend)
            owner, _, _ = self.child(ctx.owners, ctx.readers, directory)
            send = owner.send
            def exit_during_signal(signum):
                owner.popen.stdin.close()
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    if "Z" in H6["proc_task_states"](owner.pid).values():
                        break
                    time.sleep(0.01)
                else:
                    self.fail("owned child did not naturally exit before verified signal")
                try:
                    return send(signum)
                except FileNotFoundError:
                    races.append(backend)
                    raise
            owner.send = exit_during_signal
            return {"leg": f"trace/{backend}", "status": "pass", "pass": True}
        rc, summary, cleanup = self.matrix(runner, cells=("pid-failed-exec",))
        self.assertEqual(rc, 0, "the next leg saw an unreaped previous child")
        self.assertEqual(started, ["singles", "multi"])
        self.assertEqual(races, ["singles", "multi"])
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(cleanup["errors"], [])
        for owner, _ in self.spawned:
            self.assertEqual(owner.popen.returncode, 0)
        self.assert_released()

    def cancellation_during_normal_finish(self, kind):
        started, readers = [], []
        held = []
        @H6["owned_leg"]
        def runner(ctx, directory, backend):
            started.append(backend)
            if backend != "singles":
                return {"cell": "pid-leader", "leg": backend, "pass": True}
            if kind == "pipe":
                read_fd, write_fd = os.pipe()
                stream, writer = os.fdopen(read_fd, encoding="utf-8"), os.fdopen(write_fd, "w")
                held.append(writer)
                reader = H6["owned_reader"](ctx.readers, H6["Reader"], stream, directory / "held-pipe.txt")
            else:
                master, slave = H6["pty"].openpty()
                held.append(slave)
                reader = H6["owned_reader"](ctx.readers, H6["PtyCapture"], master, directory / "held-pty.txt")
            readers.append(reader)
            join = reader.thread.join
            calls = []
            def short_first_join(timeout=None):
                calls.append(True)
                return join(0.02 if len(calls) == 1 else timeout)
            with mock.patch.object(reader.thread, "join", side_effect=short_first_join):
                H6["finish_readers"]([reader])
            self.fail("forced reader cancellation unexpectedly returned normally")
        try:
            rc, summary, cleanup = self.matrix(runner)
            self.assertEqual(rc, 1)
            self.assertEqual(started, ["singles"], "reader cleanup failure allowed the next backend")
            self.assertTrue(any("reader" in error for error in cleanup["errors"]))
            self.assertTrue(any("primary" in error for row in summary["legs"] for error in row["errors"]))
            reader = readers[0]
            self.assertTrue(reader.stop.is_set())
            self.assertFalse(reader.thread.is_alive())
            if kind == "pipe":
                self.assertTrue(reader.stream.closed)
                self.assertFalse(held[0].closed)
            else:
                self.assertIsNone(reader.master)
                os.fstat(held[0])
            with self.assertRaises((ValueError, TimeoutError)):
                reader.finish()
        finally:
            for writer in held:
                if isinstance(writer, int):
                    os.close(writer)
                else:
                    writer.close()
            for reader in readers:
                reader.stop.set()
                reader.thread.join(2)
                if getattr(reader, "stream", None) is not None:
                    reader.stream.close()

    def test_pipe_cancellation_during_normal_finish_stops_matrix(self):
        self.cancellation_during_normal_finish("pipe")

    def test_pty_cancellation_during_normal_finish_stops_matrix(self):
        self.cancellation_during_normal_finish("pty")

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
        shared = H6["N3HARNESS"]["spawn_owned"].__globals__
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
            pin = H6["leg_pin"](ctx, self.case_pin.path)
            self.local_pins.append(pin)
            pin_fd = pin.fd
            _, wrapper = H6["create_tracked"](ctx, path)
            remove = wrapper.remove
            def after_reap():
                try:
                    self.assert_released()
                    self.assertIsNone(pin.fd, "local pin remained held when group removal began")
                    with self.assertRaises(OSError):
                        os.fstat(pin_fd)
                    removed.append(True)
                finally:
                    remove()
            wrapper.remove = after_reap
        with patch, members:
            leg(self.ctx)
        self.assertEqual(removed, [True])
        self.assertFalse(path.exists())

    def test_failed_terminal_wait_retains_owner_and_group_for_final_backstop(self):
        patch, members = self.ordinary_group_controls()
        scope = H6["LegContext"](self.ctx)
        path = self.directory / "selected"
        with patch, members:
            owner = H6["spawn_owned"](scope.owners,
                [sys.executable, "-I", "-c", "import sys; sys.stdin.read()"], os.getuid(),
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                text=True, start_new_session=True)
            self.spawned.append((owner, []))
            group, wrapper = H6["create_tracked"](scope, path)
            removed = []
            remove = wrapper.remove
            def record_removal():
                removed.append(True)
                remove()
            wrapper.remove = record_removal
            def failed_signal(_owner):
                raise OSError("controlled signal failure")
            def failed_wait(_owner):
                raise TimeoutError("controlled terminal wait failure")
            with mock.patch.dict(self.globals, {"terminate_owned": failed_signal,
                                                "wait_terminal_child": failed_wait}), \
                    self.assertRaises(H6["LegCleanupError"]):
                H6["cleanup_leg_resources"](scope)
            self.assertEqual(scope.owners, [owner], "failed terminal wait discarded child ownership")
            self.assertEqual(scope.groups, [wrapper])
            os.fstat(owner.pidfd)
            os.fstat(group.fd)
            self.assertEqual(removed, [], "group was removed before owned-child terminal proof")
            self.assertTrue(self.ctx.cleanup_failed)
            self.assertEqual(self.ctx.cleanup_totals["processes"], 0)
            self.assertEqual(self.ctx.cleanup_totals["cgroups"], 0)
            errors = list(self.ctx.cleanup_errors)
            H6["cleanup_leg_resources"](scope)
            self.assert_released()
            self.assertFalse(path.exists())
            self.assertEqual(removed, [True])
            self.assertEqual(self.ctx.cleanup_errors, errors)
            self.assertEqual(self.ctx.cleanup_totals["processes"], 1)
            self.assertEqual(self.ctx.cleanup_totals["cgroups"], 1)
            totals = dict(self.ctx.cleanup_totals)
            H6["cleanup_leg_resources"](scope)
            self.assertEqual(self.ctx.cleanup_totals, totals)
            self.assertTrue(self.ctx.cleanup_failed)

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


class ControlledInventoryObserver:
    """Unprivileged public-event seam fed by independently ledgered real children.

    This simulates observer publication, never native/BPF qualification. The
    production controller and event reader still own every gate and deadline.
    """
    def __init__(self, ctx, path, doc_path, provider, providers, membership=None, fault=None):
        self.ctx, self.path, self.doc_path = ctx, path, doc_path
        self.provider, self.providers, self.membership, self.fault = provider, providers, membership, fault
        self.stop = threading.Event()
        self.records, self.callers, self.last, self.instances, self.semantic = [], {}, {}, {}, {}
        self.passed, self.previous_counts = -1, {}
        self.last_acks = {}
        self.module_ids = {value["path"]: f"m{index}" for index, value in enumerate(providers.values())}
        self.started = time.monotonic_ns()
        self.emit("started", {"scope": "system" if membership is None else "cgroup",
            "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"}, "started_ns": self.started})
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def emit(self, kind, event):
        record = {"schema": "p11scope/inventory-events/v1", "seq": len(self.records),
                  "at_ns": time.monotonic_ns(), "kind": kind, "event": event}
        self.records.append(record)
        with self.path.open("a") as stream:
            stream.write(json.dumps(record) + "\n")

    def context(self, owner, ident, caller_id):
        info = os.stat(ident["exe"])
        return {"id": caller_id, "pid": owner.pid, "start_time": owner.identity["start_time"],
            "incarnation": ident["gen"], "authority": "native_exact", "lifecycle": "mapped", "status": "observed",
            "executable": {"path": ident["exe"], "dev": info.st_dev, "ino": info.st_ino,
                "mtime_secs": info.st_mtime_ns // 1_000_000_000,
                "mtime_nanos": info.st_mtime_ns % 1_000_000_000}}

    def snapshot(self):
        rows = [{"id": value["id"], "pid": value["pid"], "start_time": value["start_time"],
            "incarnation": value["incarnation"], "lifecycle": value["lifecycle"],
            "retired": value["lifecycle"] == "exec_retired", "image": {"exe": {"path": value["executable"]["path"]}}}
            for value in self.callers.values()]
        return {"schema": "p11scope/inventory/v1", "scope": "system" if self.membership is None else "cgroup",
            "callers": rows, "modules": [{"id": self.module_ids[pin["path"]], "paths": [pin["path"]],
                "identity": {"inode": pin["ino"], "sha256": pin["sha256"]}} for pin in self.providers.values()],
            "edges": [{key: value for key, value in row.items() if key != "identity_context"}
                      for row in self.last.values()], "instances": list(self.instances.values()),
            "semantic_edges": list(self.semantic.values()), "gaps": [],
            "observation": {"attach": {"selection": "singles", "fallback": None}}}

    def sweep(self, final=False):
        written = Counter()
        for owner in list(self.ctx.owners):
            reader = getattr(owner, "h6_test_reader", None)
            if reader is None:
                continue
            parsed = H6["parse_inv_ledger"]("".join(reader.lines))
            idents = parsed["idents"]
            if not idents or idents[-1]["cell"] == "MF":
                continue
            if self.membership is not None and "/selected" not in self.membership.get(owner.pid, ""):
                continue
            for ident in idents:
                caller_key = owner.pid, ident["gen"]
                if caller_key not in self.callers:
                    caller_id = f"c{len(self.callers)}"
                    context = self.context(owner, ident, caller_id)
                    old = self.callers.get((owner.pid, ident["gen"] - 1))
                    self.callers[caller_key] = context
                    if old:
                        old["lifecycle"] = "exec_retired"
                        self.emit("caller_event", {"event": "exec_retired", "old": old["id"], "new": caller_id,
                            "identity_context": {"version": 1, "old": dict(old), "new": context}})
                    else:
                        self.emit("caller_event", {"event": "admitted", "caller": caller_id,
                            "identity_context": {"version": 1, "caller": context}})
                context = self.callers[caller_key]
                ack = max((row for row in parsed["acks"] if row["gen"] == ident["gen"]),
                          key=lambda row: row["t1"], default=None)
                if self.fault in ("initial-no-calls", "history-prefix") and not final:
                    ack = min((row for row in parsed["acks"] if row["gen"] == ident["gen"]
                               and row["seq"] > self.last_acks.get(caller_key, 0)),
                              key=lambda row: row["seq"], default=ack)
                pending_no_calls = False
                batches = [row for row in parsed["batches"] if row["gen"] == ident["gen"]
                           and ack is not None and row["t1"] <= ack["t1"]]
                for module_path, module_id in self.module_ids.items():
                    if not any(row["gen"] == ident["gen"] and row["module"] == module_path for row in parsed["mapped"]):
                        continue
                    pin = next(pin for pin in self.providers.values() if pin["path"] == module_path)
                    key = owner.pid, ident["gen"], module_path
                    totals = H6["ledger_s1_totals"](batches, 0)
                    count = totals[5].get(key, 0)
                    last_seen = max((row["t1"] for row in batches if row["module"] == module_path), default=None)
                    edge = {"caller": context["id"], "module": module_id, "mapping": {"state": "mapped"},
                        "entries": {"count": count, "last_seen_ns": last_seen, "saturated": False,
                                    "coverage": {"state": "counted" if count else "armed", "lossy": False}},
                        "semantics": "unknown (semantic capture withheld)", "mechanisms": None, "operations": None,
                        "identity_context": {"version": 1, "caller": dict(context), "module": {
                            "id": module_id, "device_major": pin["mapping"]["dev"][0],
                            "device_minor": pin["mapping"]["dev"][1], "inode": pin["ino"],
                            "path": module_path, "status": "observed"}}}
                    if module_path == self.provider["path"] and count:
                        instance_id = f"i{context['id'][1:]}"
                        mechanisms = [{"mechanism_hex": mech, "calls": value,
                            "errors": totals[1].get(key + (mech,), 0)} for (*group, mech), value in totals[0].items()
                            if tuple(group) == key]
                        ops = {"calls": totals[4].get(key, 0), "completed": totals[2].get(key, 0),
                            "failed": totals[3].get(key, 0), "unknown": 0, "orphans": 0, "dropped": 0,
                            "last_seen_ns": last_seen}
                        edge.update(semantics="observed", mechanisms=mechanisms, operations=ops)
                        instance = {"id": instance_id, "caller": context["id"], "module": module_id,
                            "state": "observed", "reason": None,
                            "first_seen_ns": self.instances.get(instance_id, {}).get("first_seen_ns", last_seen),
                            "last_seen_ns": last_seen}
                        semantic = {"caller": context["id"], "module": module_id, "instance": instance_id,
                            "entries": {"unit": "api_entries", "count": None, "observation": "unavailable"},
                            "api_returns": {"count": count, "saturated": False, "historical_only_returns": 0},
                            "semantics": "observed", "mechanisms": mechanisms, "operations": ops,
                            "coverage": {"lossy": False, "reasons": []}}
                        if self.fault == "initial-no-calls" and instance_id not in self.instances and not final:
                            # Registration can publish before admitted returns.
                            # Serve this same independently ledgered ACK next pass.
                            semantic.update(semantics="unknown (no calls observed)", mechanisms=None,
                                            operations=None, coverage={"lossy": False, "reasons": ["no_calls"]})
                            semantic["api_returns"]["count"] = None
                            pending_no_calls = True
                        retired = context["lifecycle"] == "exec_retired"
                        if retired:
                            instance.update(state="retired", reason="instance_retired")
                            semantic["coverage"] = {"lossy": True, "reasons": ["instance_retired"]}
                        if final:
                            if not retired:
                                instance.update(state="uncertain", reason="semantic_loss")
                            semantic["coverage"] = {"lossy": True, "reasons": sorted(
                                set(semantic["coverage"]["reasons"]) | {"capture_stopped", "semantic_loss"})}
                        if ident["gen"] == 1:
                            if self.fault == "admission-only":
                                edge["entries"]["coverage"]["state"] = "armed"
                            elif self.fault == "attachment-only":
                                semantic.update(semantics="unknown", mechanisms=None, operations=None)
                                semantic["api_returns"]["count"] = None
                            elif self.fault == "wrong-birth":
                                edge["identity_context"]["caller"]["start_time"] += 1
                        if self.instances.get(instance_id) != instance:
                            self.emit("instance_observed", instance)
                            written["instance_events"] += 1
                            self.instances[instance_id] = instance
                        if self.semantic.get(instance_id) != semantic:
                            self.emit("semantic_edge_observed", semantic)
                            written["semantic_edge_events"] += 1
                            self.semantic[instance_id] = semantic
                    pair = context["id"], module_id
                    if self.last.get(pair) != edge:
                        self.emit("edge_observed", edge)
                        written["edge_events"] += 1
                        self.last[pair] = edge
                if ack is not None and not pending_no_calls:
                    self.last_acks[caller_key] = ack["seq"]
        if not final:
            self.passed += 1
        self.emit("pass_committed", {"pass": self.passed, "final": final,
            **{key: written[key] for key in ("edge_events", "instance_events", "semantic_edge_events")},
            "edge_events_deferred": 0, "instance_events_deferred": 0, "semantic_edge_events_deferred": 0})

    def run(self):
        while not self.stop.wait(0.01):
            self.sweep()

    def finish(self):
        self.stop.set()
        self.thread.join(2)
        self.sweep(final=True)
        self.emit("ended", {"ended_ns": time.monotonic_ns(), "edges_unretained": 0, "instances_unretained": 0,
            "semantic_edges_unretained": 0, "edge_events": 0, "instance_events": 0,
            "semantic_edge_events": 0})
        self.doc_path.write_text(json.dumps(self.snapshot()))
        return 0, time.monotonic_ns(), 0


class InventoryFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = Path("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
        if not cls.provider.is_file() or not shutil.which("softhsm2-util"):
            raise unittest.SkipTest("SoftHSM fixture dependencies unavailable")
        cls.temporary = tempfile.TemporaryDirectory(prefix="h6-inventory-fixture-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.binary = cls.directory / "ledger"
        cls.successor = cls.directory / "ledger2"
        result = subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
            "-std=gnu11", str(ROOT / "tests/fixtures/public-cli/inventory-ledger.c"),
            "-ldl", "-pthread", "-o", str(cls.binary)], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)
        shutil.copyfile(cls.binary, cls.successor)
        cls.successor.chmod(0o755)
        tokens = cls.directory / "tokens"
        tokens.mkdir(mode=0o700)
        config = cls.directory / "softhsm2.conf"
        config.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
        cls.env = dict(os.environ, SOFTHSM2_CONF=str(config))
        result = subprocess.run(["softhsm2-util", "--init-token", "--free", "--label",
            "h6-control", "--so-pin", "5678", "--pin", "1234"], env=cls.env,
            capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise AssertionError(result.stderr)

    def child(self, mode="exec-chain", seconds=3, extra=(), controlled=True):
        deadline = time.monotonic_ns() + int(seconds * 1e9)
        control = ["--h6-control", "--h6-deadline", str(deadline),
                   "--h6-leg-deadline", str(deadline)] if controlled else []
        proc = subprocess.Popen([str(self.binary), mode, "--cell", "TEST",
            "--module", str(self.provider), *control, *extra], env=self.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        reader = H6["Reader"](proc.stdout, self.directory / f"child-{proc.pid}.out")
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(2)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
            reader.thread.join(2)
        self.addCleanup(cleanup)
        return proc, reader, deadline

    def command(self, proc, reader, command, seq, deadline, gen=0, attempt=0):
        proc.stdin.write(f"{command} {gen} {seq} {time.monotonic_ns()} {deadline} {attempt}\n")
        proc.stdin.flush()
        reader.wait(lambda r: any(line.startswith("ACK ") and f" seq={seq} " in line
                    and f" gen={gen} " in line for line in r.lines), 2)
        return H6["parse_inv_ledger"]("".join(reader.lines))

    def test_control_holds_before_loading_and_flushes_each_actual_phase(self):
        proc, reader, deadline = self.child()
        reader.wait(lambda r: any(line.startswith("H6_READY ") for line in r.lines), 2)
        self.assertFalse(H6["parse_inv_ledger"]("".join(reader.lines))["mapped"])
        for attempt in (1, 2):
            ledger = self.command(proc, reader, "W", attempt, deadline, attempt=attempt)
            rows = [row for row in ledger["batches"] if row["phase"] == f"h6-warm{attempt}"]
            self.assertEqual(sum(row["n"] for row in rows), 10)
        ledger = self.command(proc, reader, "M", 3, deadline)
        measured = [row for row in ledger["batches"] if row["phase"] == "h6-measured"]
        self.assertEqual(sum(row["n"] for row in measured), 20)
        failed = [row for row in ledger["batches"] if row["phase"] == "h6-failed"]
        self.assertEqual([(row["fn"], row["n"], row["bad"]) for row in failed],
                         [("C_VerifyInit", 1, 0), ("C_Verify", 1, 1)])
        self.assertEqual(ledger["acks"][-1]["rv"], 0xc0)
        self.assertIsNone(proc.poll())
        self.command(proc, reader, "T", 4, deadline)
        self.command(proc, reader, "F", 5, deadline)
        self.assertEqual(proc.wait(2), 0)

    def test_eof_and_initial_absolute_bound_end_the_actual_child(self):
        for eof in (True, False):
            with self.subTest(eof=eof):
                proc, reader, _deadline = self.child(seconds=0.2)
                reader.wait(lambda r: any(line.startswith("H6_READY ") for line in r.lines), 2)
                if eof:
                    proc.stdin.close()
                self.assertEqual(proc.wait(2), 1)

    def test_generation_bound_exec_successor_stays_idle_until_its_warmup(self):
        proc, reader, deadline = self.child(extra=("--chain", f"leader:{self.successor}"))
        reader.wait(lambda r: any(line.startswith("H6_READY ") for line in r.lines), 2)
        self.command(proc, reader, "W", 1, deadline, attempt=1)
        self.command(proc, reader, "T", 2, deadline)
        self.command(proc, reader, "X", 3, deadline)
        reader.wait(lambda r: any(line.startswith("H6_READY ") and " gen=1 " in line
                                  for line in r.lines), 2)
        ledger = H6["parse_inv_ledger"]("".join(reader.lines))
        self.assertFalse([row for row in ledger["batches"] if row["gen"] == 1])
        self.assertFalse([row for row in ledger["mapped"] if row["gen"] == 1])
        self.command(proc, reader, "W", 1, deadline, gen=1, attempt=1)
        self.command(proc, reader, "M", 2, deadline, gen=1)
        self.command(proc, reader, "T", 3, deadline, gen=1)
        self.command(proc, reader, "F", 4, deadline, gen=1)
        self.assertEqual(proc.wait(2), 0)

    def test_stale_duplicate_out_of_order_and_renewed_bounds_refuse(self):
        controls = ("stale", "duplicate", "measure-before-warm", "renewed", "attempt")
        for control in controls:
            with self.subTest(control=control):
                proc, reader, deadline = self.child()
                reader.wait(lambda r: any(line.startswith("H6_READY ") for line in r.lines), 2)
                first_bound = deadline - 1_000_000_000 if control == "renewed" else deadline
                if control not in ("stale", "measure-before-warm"):
                    self.command(proc, reader, "W", 1, first_bound, attempt=1)
                gen = 1 if control == "stale" else 0
                seq = 1 if control in ("stale", "duplicate", "measure-before-warm") else 2
                attempt = 3 if control == "attempt" else 2
                command = "M" if control == "measure-before-warm" else "W"
                proc.stdin.write(f"{command} {gen} {seq} {time.monotonic_ns()} {deadline} {attempt}\n")
                proc.stdin.flush()
                self.assertEqual(proc.wait(2), 1)

    def test_fixed_measurement_cannot_repeat_and_terminal_idle_eof_is_bounded(self):
        proc, reader, deadline = self.child()
        reader.wait(lambda r: any(line.startswith("H6_READY ") for line in r.lines), 2)
        self.command(proc, reader, "W", 1, deadline, attempt=1)
        self.command(proc, reader, "M", 2, deadline)
        proc.stdin.write(f"M 0 3 {time.monotonic_ns()} {deadline} 0\n")
        proc.stdin.flush()
        self.assertEqual(proc.wait(2), 1)

    def test_legacy_staged_late_single_call_and_second_gate_are_preserved(self):
        second = self.directory / f"legacy-B-{time.monotonic_ns()}.so"
        shutil.copyfile(self.provider, second)
        gate = self.directory / f"legacy-gate-{time.monotonic_ns()}"
        gate2 = self.directory / f"legacy-gate2-{time.monotonic_ns()}"
        proc, reader, _deadline = self.child(mode="mech", controlled=False,
            extra=("--module", str(second), "--iters", "1", "--late-from", "1",
                   "--single-call", "1", "--gate", str(gate), "--gate2", str(gate2)))
        reader.wait(lambda r: any(line.startswith("READY ") for line in r.lines), 2)
        self.assertFalse([row for row in H6["parse_inv_ledger"]("".join(reader.lines))["mapped"]
                          if row["module"] == str(second)])
        gate.touch()
        reader.wait(lambda r: any(" fn=C_Initialize " in line and f" module={second} " in line
                                  for line in r.lines), 2)
        ledger = H6["parse_inv_ledger"]("".join(reader.lines))
        staged = [row for row in ledger["batches"] if row["module"] == str(second)]
        self.assertEqual([(row["fn"], row["n"]) for row in staged],
                         [("C_GetFunctionList", 1), ("C_Initialize", 1)])
        self.assertIsNone(proc.poll())
        gate2.touch()
        self.assertEqual(proc.wait(2), 0)
        reader.finish()
        ledger = H6["parse_inv_ledger"]("".join(reader.lines))
        self.assertFalse(ledger["controls"])
        self.assertEqual(sum(row["n"] for row in ledger["batches"]
            if row["module"] == str(second) and row["phase"] == "main"), 20)

    def run_inventory_route(self, cell="system-mixed", fault=None):
        owners, readers, pins = [], [], []
        provider_pin = H6["FilePin"](self.provider)
        self.addCleanup(provider_pin.close)
        ctx = SimpleNamespace(args=SimpleNamespace(uid=os.getuid(), gid=os.getgid()),
            owners=owners, readers=readers, groups=[], leg_pins=pins, traced=[],
            pins={"ledger": SimpleNamespace(path=self.binary)}, provider_pin=provider_pin,
            discover_pin=None)
        ctx.scopes, ctx.completed_results, ctx.cleanup_errors = [], [], []
        ctx.cleanup_failed = False
        ctx.cleanup_totals = {"processes": 0, "readers": 0, "cgroups": 0, "pins": 0}
        observers = []
        membership, events, exec_deadline = {}, [], []
        real_pin = H6["leg_pin"]
        def pinned(scope, path):
            pin = real_pin(scope, path)
            actual_verify = pin.verify
            def verify():
                actual_verify()
                if pin.path.name == "ledger2" and exec_deadline and (
                        fault == "late-reentry" or fault == "late-resume" and "sub" in events):
                    time.sleep(max(0, (exec_deadline[0] - time.monotonic_ns()) / 1e9) + 0.005)
            pin.verify = verify
            return pin
        def ordinary(owned, argv, uid, **kwargs):
            for key in ("user", "group", "extra_groups"):
                kwargs.pop(key, None)
            return H6["N3HARNESS"]["spawn_owned"](owned, argv, uid, **kwargs)
        real_ledger = H6["spawn_ledger"]
        def ledger(*args):
            owner, stdout, stderr = real_ledger(*args)
            owner.h6_test_reader = stdout
            if owner not in owners:
                owners.append(owner)
                readers.extend((stdout, stderr))
            return owner, stdout, stderr
        def observer(_ctx, leg_dir, *_args):
            log, doc = leg_dir / "events.jsonl", leg_dir / "inventory.json"
            log.write_text("")
            a = H6["provider_receipt"](provider_pin)
            providers = {"A": a}
            if cell == "system-mixed":
                b_pin = H6["FilePin"](leg_dir / "provider-B.so")
                try:
                    providers["B"] = H6["provider_receipt"](b_pin)
                finally:
                    b_pin.close()
            injected = ControlledInventoryObserver(_ctx, log, doc, a, providers,
                membership=None if cell == "system-mixed" else membership, fault=fault)
            observers.append(injected)
            return injected, None, None, injected.started, doc, log
        def exec_stop(pid, **kwargs):
            deadline = time.monotonic() + 2
            while not os.readlink(f"/proc/{pid}/exe").endswith("/ledger2"):
                if time.monotonic() >= deadline:
                    self.fail("actual child did not exec its held successor")
                time.sleep(0.001)
            owner = next(owner for owner in owners if owner.pid == pid)
            owner.send(signal.SIGSTOP)
            exec_deadline.append(kwargs["deadline"])
            if fault == "late-stop":
                time.sleep(max(0, (exec_deadline[0] - time.monotonic_ns()) / 1e9) + 0.005)
            return time.monotonic_ns()
        def group(_ctx, path):
            path = Path(path)
            def move(owner):
                if path.name == "sub" and fault == "failed-move":
                    raise H6["SetupError"]("controlled failed descendant verification")
                membership[owner.pid] = str(path)
                events.append(path.name)
            return SimpleNamespace(path=path, move=move), None
        def resume(pid):
            if cell != "system-mixed":
                self.assertTrue(membership[pid].endswith("/selected/sub"))
            events.append("resume")
            next(owner for owner in owners if owner.pid == pid).send(signal.SIGCONT)
        patches = {"init_token": lambda *_args: self.env, "build_manifest": lambda *_args: None, "leg_pin": pinned,
            "spawn_owned": ordinary, "spawn_ledger": ledger, "spawn_inventory": observer,
            "wait_inventory_ready": lambda *_args: time.monotonic_ns(),
            "wait_passes": lambda *_args: 2,
            "seize_until_exec": lambda _pid, scope, owner: scope.traced.append(owner),
            "wait_exec_stop": exec_stop,
            "ptrace_continue": resume, "create_tracked": group, "cgroup_of": lambda pid: membership[pid],
            "ptrace_detach": lambda pid, scope: scope.traced.remove(
                next(owner for owner in scope.traced if owner.pid == pid)),
            "stop_inventory": lambda injected: injected.finish(),
            "stop_receipt": lambda *_args: {},
            "finish_readers": lambda rows: [row.finish() for row in rows if row is not None],
            "evaluate_inventory_h6": lambda doc, ledgers, receipt: (doc, ledgers, receipt)}
        actual_budget = H6["LegBudget"]
        patches["LegBudget"] = lambda **_kwargs: actual_budget(inventory=True, budgets={"setup": 3,
            "successor-recovery": 0.4 if fault not in (None, "failed-move", "initial-no-calls", "history-prefix") else 3,
            "fixed-measurement": 8, "normal-stop": 2, "cleanup": 2}, leg_seconds=15)
        self.route_events, self.route_owners, self.route_case = events, owners, ctx
        try:
            budget = H6["LegBudget"](inventory=True, budgets={"setup": 3,
                "successor-recovery": 3, "fixed-measurement": 8, "normal-stop": 2, "cleanup": 2},
                leg_seconds=15)
            token = H6["ACTIVE_LEG"].set(budget)
            function = H6["run_system_mixed" if cell == "system-mixed" else "run_cgroup_inventory_r5"]
            with mock.patch.dict(function.__globals__, patches):
                doc, ledgers, receipt = function(ctx,
                    self.directory / f"mixed-{time.monotonic_ns()}", "singles")
            self.route_events, self.route_owners = events, owners
            return doc, ledgers, receipt
        finally:
            H6["ACTIVE_LEG"].reset(token)
            for observer in observers:
                observer.stop.set()
                observer.thread.join(2)
            for owner in owners:
                if owner.popen.poll() is None:
                    owner.popen.kill()
                owner.popen.wait(2)
                for stream in (owner.popen.stdin, owner.popen.stdout, owner.popen.stderr):
                    if stream is not None:
                        stream.close()
                owner.close()
            for reader in readers:
                reader.thread.join(2)
            for pin in pins:
                pin.close()

    def test_system_mixed_real_sibling_calls_overlap_target_measurement(self):
        doc, ledgers, receipt = self.run_inventory_route()
        measured = receipt["measured"]
        for module in ("A", "B"):
            path = receipt["providers"][module]["path"]
            overlap = [row for row in ledgers["MS"]["batches"]
                if row["module"] == path and row["fn"] != "C_GetFunctionList"
                and row["t0"] <= measured["t1"] and row["t1"] >= measured["t0"]]
            self.assertTrue(overlap, f"no real MS {module} calls overlap target fixed measurement")
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["s1"]["measured_completed"], 20)
        self.assertEqual(result["s1"]["measured_failed"], 2)
        sibling = result["s1"]["sibling_instances"][0]
        self.assertEqual((sibling["api_returns"], sibling["ledger_api_returns"]), (47, 47))
        self.assertEqual(sibling["operations"]["completed"], 22)

    def test_r5_real_owned_target_reenters_before_resuming_and_measuring(self):
        doc, ledgers, receipt = self.run_inventory_route(cell="cgroup-reentry")
        self.assertLess(self.route_events.index("sub"), self.route_events.index("resume"))
        self.assertEqual(receipt["scope_intervals"][1]["t0"], receipt["freeze"]["reentry_ns"])
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])

    def change_semantic_tail(self, doc, receipt, instance_id, coverage, state=None, *, earlier=False):
        """Publish changed public rows with exact final parity/accounting."""
        semantic = next(row for row in doc["semantic_edges"] if row["instance"] == instance_id)
        semantic["coverage"] = coverage
        additions = [("semantic_edge_observed", copy.deepcopy(semantic))]
        if state is not None:
            instance = next(row for row in doc["instances"] if row["id"] == instance_id)
            instance.update(state=state, reason="semantic_loss")
            additions.insert(0, ("instance_observed", copy.deepcopy(instance)))
        records = receipt["inventory_control"]["final_records"]
        index = next(i for i in reversed(range(len(records)))
                     if records[i]["kind"] == "pass_committed" and records[i]["event"].get("final"))
        terminal = records[index]
        rows = [{"schema": terminal["schema"], "kind": kind, "at_ns": terminal["at_ns"],
                 "event": row} for kind, row in additions]
        counts = Counter(kind for kind, _row in additions)
        if earlier:
            event = dict(terminal["event"], final=False)
            for kind, field in (("instance_observed", "instance_events"),
                                ("semantic_edge_observed", "semantic_edge_events")):
                event[field] = counts[kind]
            rows.append({"schema": terminal["schema"], "kind": "pass_committed",
                         "at_ns": terminal["at_ns"], "event": event})
        else:
            terminal["event"]["instance_events"] += counts["instance_observed"]
            terminal["event"]["semantic_edge_events"] += counts["semantic_edge_observed"]
        records[index:index] = rows
        for seq, row in enumerate(records):
            row["seq"] = seq

    def test_producer_normal_stop_retains_history_and_ends_uncertain(self):
        doc, ledgers, receipt = self.run_inventory_route(cell="cgroup-reentry")
        instance = receipt["inventory_control"]["measurements"][-1]["proof"]["instance"]
        self.change_semantic_tail(doc, receipt, instance,
            {"lossy": True, "reasons": ["capture_stopped", "semantic_loss"]}, "uncertain")
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])

    def test_unexplained_or_early_final_semantic_loss_cannot_pass(self):
        original = self.run_inventory_route(cell="cgroup-reentry")
        for coverage, state, earlier in (
                ({"lossy": True, "reasons": ["semantic_loss"]}, None, False),
                ({"lossy": True, "reasons": ["capture_stopped", "semantic_loss"]}, "uncertain", True),
                ({"lossy": True, "reasons": ["capture_stopped", "semantic_loss", "task_retired"]},
                 "uncertain", False)):
            with self.subTest(coverage=coverage, earlier=earlier):
                doc, ledgers, receipt = copy.deepcopy(original)
                instance = receipt["inventory_control"]["measurements"][-1]["proof"]["instance"]
                self.change_semantic_tail(doc, receipt, instance, coverage, state, earlier=earlier)
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertFalse(result["pass"], result)

    def test_final_semantic_history_cannot_disappear_after_measured_end(self):
        doc, ledgers, receipt = self.run_inventory_route()
        proof = receipt["inventory_control"]["measurements"][-1]["proof"]
        semantic = next(row for row in doc["semantic_edges"] if row["instance"] == proof["instance"])
        semantic["api_returns"]["count"] = 0
        records = receipt["inventory_control"]["final_records"]
        terminal = records[-2]
        records.insert(len(records) - 2, {"schema": "p11scope/inventory-events/v1",
            "seq": terminal["seq"], "at_ns": terminal["at_ns"],
            "kind": "semantic_edge_observed", "event": copy.deepcopy(semantic)})
        terminal["event"]["semantic_edge_events"] += 1
        for seq, row in enumerate(records):
            row["seq"] = seq
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"], result)
        self.assertTrue(any("historical" in error for error in result["errors"]), result["errors"])

    def test_target_history_cannot_rewind_or_erase_loss_across_measured_end(self):
        for cell in ("cgroup-reentry", "system-mixed"):
            original = self.run_inventory_route(cell=cell, fault="history-prefix")
            for fault in ("rewind-after-end", "pre-baseline-loss", "retirement-reason-erasure"):
                with self.subTest(cell=cell, fault=fault):
                    doc, ledgers, receipt = copy.deepcopy(original)
                    phase = receipt["inventory_control"]["measurements"][0]
                    proof = phase["proof"]
                    rows = [row for row in receipt["inventory_control"]["final_records"]
                            if row["kind"] == "semantic_edge_observed"
                            and row["event"]["instance"] == proof["instance"]]
                    early = next(row for row in rows if row["event"]["api_returns"]["count"] == 17
                                 and row["seq"] < proof["baseline"]["semantic"]["seq"])
                    final = next(row for row in doc["semantic_edges"] if row["instance"] == proof["instance"])
                    self.assertEqual((early["event"]["api_returns"]["count"],
                        phase["end"]["counts"]["api"], final["api_returns"]["count"]), (17, 49, 53))
                    if fault == "rewind-after-end":
                        later = [row for row in rows if row["seq"] > phase["end"]["pass"]["seq"]]
                        self.assertGreaterEqual(len(later), 2)
                        later[0]["event"] = copy.deepcopy(early["event"])
                    elif fault == "pre-baseline-loss":
                        early["event"]["coverage"] = {"lossy": True, "reasons": ["semantic_loss"]}
                    else:
                        for row in (final, rows[-1]["event"]):
                            self.assertIn("instance_retired", row["coverage"]["reasons"])
                            row["coverage"]["reasons"].remove("instance_retired")
                    result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                    self.assertFalse(result["pass"], (cell, fault, result["errors"]))

    def test_target_initial_no_calls_remains_valid_through_measurement_and_stop(self):
        for cell in ("cgroup-reentry", "system-mixed"):
            with self.subTest(cell=cell):
                doc, ledgers, receipt = self.run_inventory_route(cell=cell, fault="initial-no-calls")
                for phase in receipt["inventory_control"]["measurements"]:
                    proof = phase["proof"]
                    rows = [row for row in receipt["inventory_control"]["final_records"]
                        if row["kind"] == "semantic_edge_observed" and row["event"]["instance"] == proof["instance"]]
                    self.assertIsNone(rows[0]["event"]["api_returns"]["count"])
                    self.assertLess(rows[0]["seq"], proof["baseline"]["semantic"]["seq"])
                    self.assertEqual(rows[0]["event"]["coverage"], {"lossy": False, "reasons": ["no_calls"]})
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertTrue(result["pass"], (cell, result["errors"]))

                # The public serializer also supports admitted API returns
                # before operation evidence; this prefix claims no completions.
                for phase in receipt["inventory_control"]["measurements"]:
                    instance = phase["proof"]["instance"]
                    row = next(row["event"] for row in receipt["inventory_control"]["final_records"]
                        if row["kind"] == "semantic_edge_observed" and row["event"]["instance"] == instance)
                    row.update(semantics="unknown (no operation evidence)", coverage={"lossy": False, "reasons": []})
                    row["api_returns"]["count"] = 4  # Initialize, GetSlotList, OpenSession, Login
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertTrue(result["pass"], (cell, "API-only prefix", result["errors"]))

    def test_target_api_and_s1_authority_survive_history_and_final_stop(self):
        for cell in ("cgroup-reentry", "system-mixed"):
            original = self.run_inventory_route(cell=cell, fault="history-prefix")
            for position in ("prefix", "final"):
                for fault in ("historical", "saturation", "label"):
                    with self.subTest(cell=cell, position=position, fault=fault):
                        doc, ledgers, receipt = copy.deepcopy(original)
                        phase = receipt["inventory_control"]["measurements"][0 if position == "prefix" else -1]
                        instance = phase["proof"]["instance"]
                        matching = [row["event"] for row in receipt["inventory_control"]["final_records"]
                            if row["kind"] == "semantic_edge_observed" and row["event"]["instance"] == instance]
                        rows = [matching[0]] if position == "prefix" else [matching[-1],
                            next(row for row in doc["semantic_edges"] if row["instance"] == instance)]
                        for row in rows:
                            if fault == "historical":
                                row["api_returns"]["historical_only_returns"] = 1
                            elif fault == "saturation":
                                row["api_returns"]["saturated"] = True
                            else:
                                row["semantics"] = "unknown (no operation evidence)"
                        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                        self.assertFalse(result["pass"], (cell, position, fault, result["errors"]))

    def test_target_counter_fields_cannot_disappear_before_during_or_after_measurement(self):
        for cell in ("cgroup-reentry", "system-mixed"):
            original = self.run_inventory_route(cell=cell, fault="history-prefix")
            for position in ("prefix", "measured", "post-measured"):
                for field in ("operation", "mechanism"):
                    with self.subTest(cell=cell, position=position, field=field):
                        doc, ledgers, receipt = copy.deepcopy(original)
                        phase = receipt["inventory_control"]["measurements"][0]
                        rows = [row for row in receipt["inventory_control"]["final_records"]
                            if row["kind"] == "semantic_edge_observed"
                            and row["event"]["instance"] == phase["proof"]["instance"]]
                        if position == "prefix":
                            changed = rows[0]["event"]
                        elif position == "measured":
                            changed = next(row["event"] for row in rows
                                           if row["seq"] == phase["end"]["semantic"]["seq"])
                        else:
                            later = [row for row in rows if row["seq"] > phase["end"]["pass"]["seq"]]
                            self.assertGreaterEqual(len(later), 2)
                            changed = later[0]["event"]
                        if field == "operation":
                            del changed["operations"]["completed"]
                        else:
                            del changed["mechanisms"][0]["calls"]
                        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                        self.assertFalse(result["pass"], (cell, position, field, result["errors"]))

    def test_sibling_duplicate_api_returns_cannot_borrow_target_s1_proof(self):
        doc, ledgers, receipt = self.run_inventory_route()
        pid = ledgers["MS"]["idents"][0]["pid"]
        caller = next(row["id"] for row in doc["callers"] if row["pid"] == pid)
        module = next(row["id"] for row in doc["modules"]
                      if receipt["providers"]["A"]["path"] in row["paths"])
        for row in doc["semantic_edges"]:
            if (row["caller"], row["module"]) == (caller, module):
                row["api_returns"]["count"] += 100
        for record in receipt["inventory_control"]["final_records"]:
            row = record["event"]
            if record["kind"] == "semantic_edge_observed" and (row["caller"], row["module"]) == (caller, module):
                row["api_returns"]["count"] += 100
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertFalse(result["pass"], result)

    def test_sibling_history_instance_and_count_only_withholding_twins(self):
        original = self.run_inventory_route()
        for fault in ("mechanism", "operation", "orphans", "unknown", "dropped", "historical",
                      "earlier-loss", "final-loss", "birth", "extra-instance", "orphan-instance",
                      "duplicate-instance", "duplicate-semantic", "count-only-api"):
            with self.subTest(fault=fault):
                doc, ledgers, receipt = copy.deepcopy(original)
                pid = ledgers["MS"]["idents"][0]["pid"]
                caller = next(row for row in doc["callers"] if row["pid"] == pid)
                semantic = next(row for row in doc["semantic_edges"] if row["caller"] == caller["id"])
                instance = next(row for row in doc["instances"] if row["id"] == semantic["instance"])
                records = receipt["inventory_control"]["final_records"]
                matching = [row["event"] for row in records if row["kind"] == "semantic_edge_observed"
                            and row["event"]["instance"] == semantic["instance"]]
                rows = [semantic, *matching]
                additions = []
                if fault == "mechanism":
                    for row in rows:
                        row["mechanisms"][0]["calls"] += 1
                elif fault == "operation":
                    for row in rows:
                        row["operations"]["completed"] += 1
                elif fault in ("orphans", "unknown", "dropped"):
                    for row in rows:
                        row["operations"][fault] += 1
                elif fault == "historical":
                    for row in rows:
                        row["api_returns"]["historical_only_returns"] += 1
                elif fault == "earlier-loss":
                    matching[0]["coverage"] = {"lossy": True, "reasons": ["semantic_loss"]}
                elif fault == "final-loss":
                    semantic["coverage"] = matching[-1]["coverage"] = {"lossy": True, "reasons": ["semantic_loss"]}
                elif fault == "birth":
                    caller["start_time"] += 1
                elif fault == "duplicate-instance":
                    doc["instances"].append(copy.deepcopy(instance))
                elif fault == "duplicate-semantic":
                    doc["semantic_edges"].append(copy.deepcopy(semantic))
                elif fault == "extra-instance":
                    extra = dict(instance, id="i999")
                    doc["instances"].append(extra)
                    additions.append(("instance_observed", extra))
                elif fault == "orphan-instance":
                    extra = dict(semantic, instance="i999")
                    doc["semantic_edges"].append(extra)
                    additions.append(("semantic_edge_observed", extra))
                elif fault == "count-only-api":
                    module = next(row["id"] for row in doc["modules"]
                                  if receipt["providers"]["B"]["path"] in row["paths"])
                    extra = {**semantic, "instance": "i999", "module": module,
                             "semantics": "unknown (semantic capture withheld)", "mechanisms": None, "operations": None}
                    doc["semantic_edges"].append(extra)
                    additions.append(("semantic_edge_observed", extra))
                if additions:
                    index = next(i for i in reversed(range(len(records)))
                        if records[i]["kind"] == "pass_committed" and records[i]["event"].get("final"))
                    terminal = records[index]
                    for kind, row in additions:
                        field = "instance_events" if kind == "instance_observed" else "semantic_edge_events"
                        terminal["event"][field] += 1
                    records[index:index] = [{"schema": terminal["schema"], "kind": kind,
                        "at_ns": terminal["at_ns"], "event": copy.deepcopy(row)} for kind, row in additions]
                    for seq, row in enumerate(records):
                        row["seq"] = seq
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertFalse(result["pass"], (fault, result))
                self.assertTrue(any("sibling" in error or "duplicate final" in error or "count-only" in error
                                    for error in result["errors"]), (fault, result["errors"]))

    def test_sibling_no_call_prefix_is_supported_but_positive_history_cannot_regress(self):
        original = self.run_inventory_route()
        for fault in ("initial-no-calls", "later-no-calls", "duplicate-prefix"):
            with self.subTest(fault=fault):
                doc, ledgers, receipt = copy.deepcopy(original)
                pid = ledgers["MS"]["idents"][0]["pid"]
                caller = next(row["id"] for row in doc["callers"] if row["pid"] == pid)
                rows = [row["event"] for row in receipt["inventory_control"]["final_records"]
                        if row["kind"] == "semantic_edge_observed" and row["event"]["caller"] == caller]
                if fault == "duplicate-prefix":
                    rows[0]["api_returns"]["count"] += 100
                else:
                    row = rows[0 if fault == "initial-no-calls" else 1]
                    row.update(semantics="unknown (no calls observed)", mechanisms=None, operations=None,
                               coverage={"lossy": False, "reasons": ["no_calls"]})
                    row["api_returns"]["count"] = None
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertEqual(result["pass"], fault == "initial-no-calls", (fault, result["errors"]))

    def test_controlled_oracle_refuses_proof_phase_history_and_parity_twins(self):
        original = self.run_inventory_route(cell="cgroup-reentry")
        for fault in ("before-proof", "wrong-birth", "wrong-provider", "wrong-instance",
                      "unretained", "missing-ended", "parity", "outside", "late-growth", "new-loss"):
            with self.subTest(fault=fault):
                doc, ledgers, receipt = copy.deepcopy(original)
                control = receipt["inventory_control"]
                phase = control["measurements"][-1]
                proof, end = phase["proof"], phase["end"]
                if fault == "before-proof":
                    proof["observed_ns"] = phase["marker"]["ack"]["t0"] + 1
                elif fault == "wrong-birth":
                    proof["image"]["start_time"] += 1
                elif fault == "wrong-provider":
                    proof["provider"]["mapping"]["ino"] += 1
                elif fault == "wrong-instance":
                    proof["instance"] = "i999"
                elif fault == "unretained":
                    control["final_records"][-1]["event"]["semantic_edges_unretained"] = 1
                elif fault == "missing-ended":
                    control["final_records"].pop()
                elif fault == "parity":
                    doc["edges"][-1]["entries"]["count"] += 1
                elif fault == "outside":
                    receipt["scope_intervals"][1]["t0"] = phase["marker"]["ack"]["t1"] + 1
                elif fault == "late-growth":
                    end["counts"]["physical"] += 1
                elif fault == "new-loss":
                    end["semantic"]["event"]["coverage"]["lossy"] = True
                result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
                self.assertFalse(result["pass"], (fault, result))
                self.assertTrue(result["errors"])

    def test_actual_routes_do_not_measure_without_attachment_or_s1_and_reap(self):
        for cell in ("system-mixed", "cgroup-reentry"):
            for fault in ("admission-only", "attachment-only", "wrong-birth"):
                with self.subTest(cell=cell, fault=fault):
                    with self.assertRaises((H6["SetupError"], TimeoutError)):
                        self.run_inventory_route(cell=cell, fault=fault)
                    self.assertFalse(self.route_case.cleanup_failed, self.route_case.cleanup_errors)

    def test_expired_exec_stop_reentry_or_resume_do_not_dispatch_and_reap(self):
        for fault in ("late-stop", "late-reentry", "late-resume"):
            with self.subTest(fault=fault):
                with self.assertRaises(TimeoutError):
                    self.run_inventory_route(cell="cgroup-reentry", fault=fault)
                self.assertNotIn("resume", self.route_events)
                self.assertEqual("sub" in self.route_events, fault == "late-resume")
                self.assertFalse(self.route_case.cleanup_failed, self.route_case.cleanup_errors)
                for owner in self.route_owners:
                    self.assertIsNotNone(owner.popen.poll())
                    self.assertIsNone(owner.pidfd)
                    for owner in self.route_owners:
                        self.assertFalse(Path(f"/proc/{owner.pid}").exists())
                        parsed = H6["parse_inv_ledger"]("".join(owner.h6_test_reader.lines))
                        self.assertFalse([row for row in parsed["acks"]
                            if row["gen"] == 1 and row["command"] == "M"])

    def test_actual_r5_failed_descendant_verification_never_resumes_and_reaps(self):
        with self.assertRaisesRegex(H6["SetupError"], "failed descendant verification"):
            self.run_inventory_route(cell="cgroup-reentry", fault="failed-move")
        self.assertNotIn("resume", self.route_events)
        self.assertFalse(self.route_case.cleanup_failed, self.route_case.cleanup_errors)
        self.assertTrue(all(not Path(f"/proc/{owner.pid}").exists() for owner in self.route_owners))



class R5OrderingTest(unittest.TestCase):
    """Exercise the real R5 route with ordinary cgroup/ptrace seams."""
    def run_route(self, failed_move=False):
        temporary = tempfile.TemporaryDirectory(prefix="h6-r5-order-")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = directory / "source"
        source.write_bytes(b"controlled executable")
        source.chmod(0o755)
        state = {"stopped": False, "membership": {}, "events": [], "resumes": 0}
        self.state = state
        owners, pins = [], []
        ctx = SimpleNamespace(args=SimpleNamespace(uid=os.getuid(), gid=os.getgid()),
            owners=owners, readers=[], groups=[], leg_pins=pins, traced=[],
            pins={"ledger": SimpleNamespace(path=source)},
            provider_pin=SimpleNamespace(path=source), discover_pin=None)
        def group(_ctx, path):
            path = Path(path)
            def move(owner):
                if path.name == "sub":
                    self.assertTrue(state["stopped"], "descendant migration released user code")
                    if failed_move:
                        raise H6["SetupError"]("controlled failed descendant verification")
                    state["events"].append("verified-reentry")
                state["membership"][owner.pid] = str(path)
            return SimpleNamespace(path=path, move=move), None
        def ledger(_owners, _readers, _leg_dir, _argv, _env, _uid, _gid, tag):
            owner = SimpleNamespace(pid=1000 + len(owners),
                identity={"pid": 1000 + len(owners), "start_time": 7777},
                verify=lambda: None, popen=SimpleNamespace(send_signal=lambda _sig: None))
            owners.append(owner)
            reader = SimpleNamespace(lines=[], wait=lambda *_args: None)
            return owner, reader, reader
        def observer(_ctx, leg_dir, *_args):
            log_path, doc_path = leg_dir / "events.jsonl", leg_dir / "inventory.json"
            log_path.write_text("")
            doc_path.write_text("{}")
            return SimpleNamespace(), None, None, 10, doc_path, log_path
        def stop(_pid, **_kwargs):
            state["stopped"] = True
            state["events"].append("exec-stop")
            return time.monotonic_ns()
        def resume(_pid):
            self.assertTrue(state["stopped"])
            self.assertTrue(state["membership"][1000].endswith("/selected/sub"))
            state["stopped"] = False
            state["resumes"] += 1
            state["events"].append("resume")
        def admission(*_args, **_kwargs):
            self.assertTrue(state["membership"][1000].endswith("/selected/sub"),
                            "R5 attempted admission while outside selected descendants")
            self.assertFalse(state["stopped"], "R5 attempted admission before resume")
            state["events"].append("fresh-admission")
            return {"caller": "c1", "incarnation": 1, "seq": 4, "at_ns": 40,
                    "completed_pass": {"seq": 5, "at_ns": 50, "pass": 3}}
        def checkpoint(*_args):
            state["events"].append("checkpoint")
            return SimpleNamespace(seq=2, retired_caller="c0", retired_incarnation=0,
                completed_pass={"seq": 2, "pass": 1},
                receipt=lambda: {"seq": 2, "retired_caller": "c0", "retired_incarnation": 0})
        class Protocol:
            def __init__(self, owner, reader, executable):
                self.owner, self.image = owner, 0
            def ready(self, _deadline, *, image=None, executable=None):
                if image is not None:
                    self.image = image
            def command(self, command, _deadline, attempt=0):
                if command == "T" and self.image == 0:
                    self.assert_inside()
                if command == "X":
                    assert state["membership"][self.owner.pid].endswith("/outside")
                return {"batches": [], "ack": {"t0": 30, "t1": 40}}
            def assert_inside(self):
                assert state["membership"][self.owner.pid].endswith("/selected")
            def warm(self, attempt, deadline):
                return self.command("W", deadline, attempt)
            def ledger(self):
                return {"batches": []}
            def dispatch(self, command, deadline, **_kwargs):
                return self.command(command, deadline)
            def complete(self, pending):
                return pending
        def image(pin, _row, owner):
            pin.verify()
            owner.verify()
            return {"pid": owner.pid, "start_time": 7777, **pin.metadata()}
        patches = {"init_token": lambda *_args: {}, "build_manifest": lambda *_args: None,
            "create_tracked": group, "spawn_ledger": ledger, "spawn_inventory": observer,
            "wait_ledger_line": lambda *_args, **_kwargs: None,
            "wait_inventory_ready": lambda *_args: 20, "wait_passes": lambda *_args: 2,
            "seize_until_exec": lambda *_args: None, "wait_exec_stop": stop,
            "ptrace_continue": resume, "ptrace_detach": lambda *_args: None,
            "wait_caller_admitted": admission, "wait_r5_successor_admitted": admission,
            "r5_admission_checkpoint": checkpoint,
            "wait_inventory_original_checkpoint": checkpoint,
            "InventoryController": Protocol,
            "wait_inventory_s1_ready": lambda _owner, _exe, _provider, admitted, *_args, **_kwargs:
                {"incarnation": admitted["incarnation"], "observed_ns": time.monotonic_ns(),
                 "deadline_ns": time.monotonic_ns() + 90_000_000_000, "provider": {}},
            "wait_inventory_measured_boundary": lambda *_args, **_kwargs: {},
            "inventory_final_records": lambda *_args: [],
            "cgroup_of": lambda pid: state["membership"][pid],
            "stop_inventory": lambda *_args: (0, time.monotonic_ns(), 0),
            "stop_receipt": lambda *_args: {}, "wait_process": lambda *_args: 0,
            "finish_readers": lambda *_args: None,
            "parse_inv_ledger": lambda *_args: {"batches": []},
            "counted_totals": lambda *_args: {}, "phase_window": lambda *_args: (30, 40, 1),
            "provider_entry": lambda *_args: {}, "provider_receipt": lambda *_args: {},
            "evaluate_inventory_h6": lambda _doc, _ledgers, receipt: receipt}
        try:
            with mock.patch.dict(H6["run_cgroup_inventory_r5"].__globals__, patches), \
                    mock.patch.object(H6["FilePin"], "image_receipt", image):
                return H6["run_cgroup_inventory_r5"].__wrapped__(ctx, directory, "singles")
        finally:
            for pin in pins:
                pin.close()

    def test_r5_reenters_while_exec_stopped_before_admission(self):
        receipt = self.run_route()
        self.assertEqual(self.state["events"],
                         ["checkpoint", "checkpoint", "exec-stop", "verified-reentry", "resume", "fresh-admission"])
        self.assertEqual(self.state["resumes"], 1)
        edge = next(move["t"] for move in receipt["moves"] if move["note"] == "X-descendant-reentry")
        self.assertEqual(receipt["scope_intervals"][1]["t0"], edge)
        self.assertEqual(receipt["freeze"]["checkpoint"]["retired_caller"], "c0")
        self.assertEqual(receipt["freeze"]["admitted"]["completed_pass"]["pass"], 3)

    def test_r5_failed_descendant_verification_never_resumes(self):
        with self.assertRaisesRegex(H6["SetupError"], "failed descendant verification"):
            self.run_route(failed_move=True)
        self.assertEqual(self.state["resumes"], 0)


class R5FreshAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="h6-r5-admission-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.owner = H6["spawn_owned"]([], [sys.executable, "-I", "-c",
            "import os,sys; target=sys.stdin.readline().strip(); "
            "os.execve(target, [target,'-S','-c','import sys;print(\"successor-ready\",flush=True);sys.stdin.read()'], "
            "{'PYTHONHOME':sys.prefix}) if target else None"],
            os.getuid(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.release)
        self.pin = H6["FilePin"](Path(sys.executable))
        self.ctx = SimpleNamespace(leg_pins=[])
        self.log = self.directory / "events.jsonl"
        self.prefix = [self.record(0, "started", {}), self.admission(1, "c0", 0),
                       self.record(2, "pass_committed", {"pass": 0})]
        self.write(self.prefix)
        self.cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)

    def release(self):
        self.owner.popen.kill()
        self.owner.popen.wait(2)
        self.owner.popen.stdin.close()
        self.owner.popen.stdout.close()
        self.owner.popen.stderr.close()
        self.owner.close()
        if hasattr(self, "pin"):
            self.pin.close()
        if hasattr(self, "ctx"):
            for cursor in self.ctx.leg_pins:
                cursor.close()

    def record(self, seq, kind, event):
        # Serialized shapes from started_payload/pass_payload and emit_commit
        # (inventory_events.rs / inventory.rs), including the additive fields.
        if kind == "started":
            event = {"scope": "cgroup:/controlled/selected",
                     "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
                     "started_ns": 100, "limits": {"callers": 4096, "modules": 4096,
                         "edges": 32768, "endpoints": 1048576, "inventory_endpoints": 4096,
                         "inventory_attach_modules": 4096, "semantic_state": 32768,
                         "instance_semantic_resources": 1048576, "retained_history": 1024}, **event}
        elif kind == "pass_committed":
            event = {"scanned": 1, "maps_matched": 0, "native_callers": 0, "scan_callers": 1,
                     "totals": {"callers": 1, "modules": 1, "edges": 1}, "new_gaps": 0,
                     "suppressed_delta": 0, "gaps_suppressed": 0, "edge_events": 0,
                     "edge_events_deferred": 0, "instance_events": 0, "instance_events_deferred": 0,
                     "semantic_edge_events": 0, "semantic_edge_events_deferred": 0,
                     "unbound_rows": [], "unbound_rows_truncated": 0, **event}
        return {"schema": "p11scope/inventory-events/v1", "seq": seq,
                "at_ns": 100 + seq, "kind": kind, "event": event}

    def admission(self, seq, caller_id, incarnation):
        info = self.pin.initial
        caller = {"id": caller_id, "pid": self.owner.pid,
                  "start_time": self.owner.identity["start_time"], "incarnation": incarnation,
                  "authority": "native_exact", "lifecycle": "mapped", "status": "observed",
                  "executable": {"path": str(self.pin.path), "dev": info.st_dev,
                      "ino": info.st_ino, "mtime_secs": info.st_mtime_ns // 1_000_000_000,
                      "mtime_nanos": info.st_mtime_ns % 1_000_000_000}}
        return self.record(seq, "caller_event", {"event": "admitted", "caller": caller_id,
                              "identity_context": {"version": 1, "caller": caller}})

    def write(self, records, tail=b""):
        self.log.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in records) + tail)

    def reset_cursor(self):
        self.cursor.close()
        self.write(self.prefix)
        self.cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)

    def wait(self, timeout=2):
        return H6["wait_r5_successor_admitted"](self.log, self.owner, self.pin, self.cursor,
                                               not_before_ns=103, timeout=timeout)

    def fresh(self):
        return [self.admission(3, "c1", 1), self.record(4, "pass_committed", {"pass": 1})]

    def turnover(self):
        old = copy.deepcopy(self.prefix[1]["event"]["identity_context"]["caller"])
        old["lifecycle"] = "exec_retired"
        new = self.admission(4, "c1", 1)["event"]["identity_context"]["caller"]
        new["authority"] = "scan_pinned"
        retired = self.record(3, "caller_event", {"event": "retired", "caller": "c0",
            "reason": "caller retired", "identity_context": {"version": 1, "caller": old}})
        committed = self.record(4, "caller_event", {"event": "exec_retired", "old": "c0", "new": "c1",
            "identity_context": {"version": 1, "old": old, "new": new}})
        return [retired, committed, self.record(5, "pass_committed", {"pass": 1})]

    def successor_turnover(self, new_pid):
        old = copy.deepcopy(self.fresh()[0]["event"]["identity_context"]["caller"])
        old["lifecycle"] = "exec_retired"
        if new_pid is None:
            new = {"id": "c2", "pid": None, "incarnation": None, "start_time": None,
                   "authority": None, "lifecycle": None, "executable": None, "status": "unavailable"}
        else:
            new = self.admission(4, "c2", 2)["event"]["identity_context"]["caller"]
            new["pid"] = new_pid
        return self.record(4, "caller_event", {"event": "exec_retired", "old": "c1", "new": "c2",
            "identity_context": {"version": 1, "old": old, "new": new}})

    def test_selected_successor_turnover_refuses_unavailable_new_context(self):
        self.write(self.prefix + [self.fresh()[0], self.successor_turnover(None),
                                  self.record(5, "pass_committed", {"pass": 1})])
        with self.assertRaisesRegex(H6["SetupError"], "successor retired before admission completion"):
            self.wait()

    def test_selected_successor_turnover_refuses_conflicting_new_pid(self):
        self.write(self.prefix + [self.fresh()[0], self.successor_turnover(self.owner.pid + 1),
                                  self.record(5, "pass_committed", {"pass": 1})])
        with self.assertRaisesRegex(H6["SetupError"], "successor retired before admission completion"):
            self.wait()

    def test_unrelated_turnover_does_not_retire_selected_successor(self):
        for new_pid in (None, self.owner.pid + 1):
            with self.subTest(new_pid=new_pid):
                self.reset_cursor()
                row = self.successor_turnover(new_pid)
                row["event"]["old"] = "c9"
                row["event"]["identity_context"]["old"] = {
                    "id": "c9", "pid": None, "incarnation": None, "start_time": None,
                    "authority": None, "lifecycle": None, "executable": None, "status": "unavailable"}
                self.write(self.prefix + [self.fresh()[0], row,
                                          self.record(5, "pass_committed", {"pass": 1})])
                result = self.wait()
                self.assertEqual((result["caller"], result["incarnation"], result["completed_pass"]["seq"]),
                                 ("c1", 1, 5))

    def test_checkpoint_accepts_producer_initial_live_pass_zero_then_one(self):
        self.cursor.close()
        rows = copy.deepcopy(self.prefix)
        rows[2]["event"]["pass"] = 0
        self.write(rows + [self.record(3, "pass_committed", {"pass": 1})])
        cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)
        self.assertEqual(cursor.receipt()["completed_pass"], {"seq": 3, "at_ns": 103, "pass": 1})
        self.assertEqual(cursor.receipt()["retired_incarnation"], 0)

    def test_producer_scoped_exec_retired_handoff_is_fresh_admission(self):
        self.write(self.prefix + self.turnover())
        result = self.wait(timeout=0.5)
        self.assertEqual((result["caller"], result["incarnation"], result["seq"]), ("c1", 1, 4))
        self.assertEqual(result["completed_pass"], {"seq": 5, "at_ns": 105, "pass": 1})
        self.assertEqual(result["publication"], "exec_retired")

    def test_checkpoint_refuses_invalid_or_terminal_initial_pass(self):
        for payload in ({"pass": -1}, {"pass": True}, {"pass": 0.5}, {}, {"pass": 0, "final": True}):
            with self.subTest(payload=payload):
                rows = self.prefix[:2] + [self.record(2, "pass_committed", payload)]
                self.write(rows)
                with self.assertRaisesRegex(H6["SetupError"], "live completing pass"):
                    H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)

    def test_checkpoint_partial_pass_zero_has_no_authority(self):
        self.write(self.prefix[:2], json.dumps(self.prefix[2]).encode())
        with self.assertRaisesRegex(H6["SetupError"], "admission/pass"):
            H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)

    def test_successor_pass_must_be_a_later_nonnegative_live_integer(self):
        for payload in ({"pass": 0}, {"pass": -1}, {"pass": True}, {"pass": 0.5}, {},
                        {"pass": 1, "final": True}):
            with self.subTest(payload=payload):
                self.reset_cursor()
                self.write(self.prefix + [self.fresh()[0], self.record(4, "pass_committed", payload)])
                self.assert_refused()

    def test_scoped_turnover_requires_exact_saved_old_subject(self):
        mutations = (("id", "c9"), ("pid", self.owner.pid + 1),
                     ("start_time", self.owner.identity["start_time"] + 1),
                     ("incarnation", 1), ("authority", "scan_pinned"),
                     ("lifecycle", "mapped"), ("status", "context_budget"),
                     ("executable", {"path": "/wrong"}))
        for field, value in mutations:
            with self.subTest(field=field):
                self.reset_cursor()
                rows = self.turnover()
                rows[1]["event"]["identity_context"]["old"][field] = value
                self.write(self.prefix + rows)
                self.assert_refused()
        self.reset_cursor()
        rows = self.turnover()
        rows[1]["event"]["old"] = "c9"
        rows[1]["event"]["identity_context"]["old"]["id"] = "c9"
        self.write(self.prefix + rows)
        self.assert_refused()

    def test_scoped_turnover_validates_new_join_birth_executable_and_incarnation(self):
        for field, value in (("id", "c9"), ("pid", self.owner.pid + 1),
                             ("start_time", self.owner.identity["start_time"] + 1),
                             ("incarnation", 0), ("executable", {"path": "/wrong"}),
                             ("lifecycle", "exec_retired"), ("authority", "unknown")):
            with self.subTest(field=field):
                self.reset_cursor()
                rows = self.turnover()
                rows[1]["event"]["identity_context"]["new"][field] = value
                self.write(self.prefix + rows)
                self.assert_refused()
        self.reset_cursor()
        rows = self.turnover()
        rows[1]["event"]["new"] = "c9"
        self.write(self.prefix + rows)
        self.assert_refused()

    def test_scoped_turnover_refuses_stale_or_incomplete_context_and_clock(self):
        for mutation in ("old-missing", "new-missing", "version", "sequence", "time"):
            with self.subTest(mutation=mutation):
                self.reset_cursor()
                rows = self.turnover()
                record, event = rows[1], rows[1]["event"]
                if mutation.endswith("-missing"):
                    event["identity_context"].pop(mutation.removesuffix("-missing"))
                elif mutation == "version":
                    event["identity_context"]["version"] = 2
                elif mutation == "sequence":
                    record["seq"] = 2
                else:
                    record["at_ns"] = 102
                self.write(self.prefix + rows)
                self.assert_refused()

    def test_deferred_retirement_only_cannot_complete_successor_admission(self):
        rows = self.turnover()
        self.write(self.prefix + [rows[0], self.record(4, "pass_committed", {"pass": 1})])
        self.assert_refused(expiry=True)

    def test_scoped_committed_turnover_requires_complete_following_pass(self):
        rows = self.turnover()
        self.write(self.prefix + rows[:2])
        self.assert_refused(expiry=True)
        self.reset_cursor()
        self.write(self.prefix + rows[:2], json.dumps(rows[2]).encode())
        self.assert_refused(expiry=True)

    def test_oversize_stream_refuses_before_read_allocation(self):
        self.write(self.prefix, b"x" * 1_048_576)
        reads, pread = [], os.pread
        def read(fd, count, offset):
            reads.append(count)
            return pread(fd, count, offset)
        with mock.patch.object(os, "pread", read), self.assertRaises(H6["SetupError"]):
            self.cursor.read()
        self.assertEqual(reads, [], "oversized stream allocated bytes before refusal")

    def test_record_ceiling_refuses_a_small_record_flood(self):
        rows = [self.record(seq, "snapshot", {}) for seq in range(3, 8192)]
        with self.log.open("a") as stream:
            stream.write("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))
        self.assertLess(self.log.stat().st_size, 1_048_576)
        records, complete = self.cursor.read()
        self.assertTrue(complete)
        self.assertEqual(len(records), 8189)
        with self.log.open("a") as stream:
            stream.write(json.dumps(self.record(8192, "snapshot", {})) + "\n")
        with self.assertRaisesRegex(H6["SetupError"], "record.*budget"):
            self.cursor.read()

    def test_line_ceiling_refuses_complete_and_partial_rows(self):
        for newline in (b"\n", b""):
            with self.subTest(newline=bool(newline)):
                self.reset_cursor()
                row = self.record(3, "snapshot", {"oversize": "x" * 67_584})
                self.write(self.prefix, json.dumps(row).encode() + newline)
                with self.assertRaisesRegex(H6["SetupError"], "line.*budget"):
                    self.cursor.read()

    def test_reads_never_allocate_the_full_stream(self):
        self.write(self.prefix + [self.record(seq, "snapshot", {}) for seq in range(3, 1003)])
        reads, pread = [], os.pread
        def read(fd, count, offset):
            reads.append(count)
            return pread(fd, count, offset)
        with mock.patch.object(os, "pread", read):
            self.cursor.read()
        self.assertGreater(len(reads), 1)
        self.assertLessEqual(max(reads), 16_384)

    def test_deadline_interrupts_read_hash_and_parse_work(self):
        for stage in ("read", "hash", "parse"):
            with self.subTest(stage=stage):
                self.reset_cursor()
                self.write(self.prefix + [self.record(seq, "snapshot", {}) for seq in range(3, 23)])
                now, decoded = [1_000_000_000], []
                budget = H6["LegBudget"](inventory=True, clock=lambda: now[0],
                                          budgets={"successor-recovery": 1})
                budget.enter("successor-recovery", self.owner.pid)
                loads, pread, sha256 = json.loads, os.pread, H6["hashlib"].sha256
                def decode(*args, **kwargs):
                    result = loads(*args, **kwargs)
                    decoded.append(True)
                    if stage == "parse":
                        now[0] += 1_000_000_000
                    return result
                def read(*args):
                    result = pread(*args)
                    if stage == "read":
                        now[0] += 1_000_000_000
                    return result
                class Hash:
                    def __init__(self, data=b""):
                        self.inner = sha256(data)
                        if data and stage == "hash":
                            now[0] += 1_000_000_000
                    def update(self, data):
                        self.inner.update(data)
                        if stage == "hash":
                            now[0] += 1_000_000_000
                    def digest(self):
                        return self.inner.digest()
                token = H6["ACTIVE_LEG"].set(budget)
                try:
                    with mock.patch.object(json, "loads", decode), mock.patch.object(os, "pread", read), \
                            mock.patch.object(H6["hashlib"], "sha256", Hash), \
                            self.assertRaisesRegex(TimeoutError, "deadline"):
                        self.cursor.read()
                finally:
                    H6["ACTIVE_LEG"].reset(token)
                self.assertEqual(len(decoded), 1 if stage == "parse" else 0,
                                 "stream work continued after the phase expired")

    def test_helper_timeout_interrupts_parsing_without_an_active_leg(self):
        self.write(self.prefix + self.fresh())
        now, decoded, loads = [1_000_000_000], [], json.loads
        def decode(*args, **kwargs):
            result = loads(*args, **kwargs)
            decoded.append(True)
            now[0] += 1_000_000_000
            return result
        with mock.patch.dict(H6["wait_r5_successor_admitted"].__globals__, {"monotonic_ns": lambda: now[0]}), \
                mock.patch.object(json, "loads", decode), self.assertRaises(TimeoutError):
            self.wait(timeout=1)
        self.assertEqual(len(decoded), 1)

    def test_deadline_interrupts_admission_traversal_before_the_next_pass(self):
        self.write(self.prefix + self.fresh())
        now, passes = [1_000_000_000], []
        budget = H6["LegBudget"](inventory=True, clock=lambda: now[0],
                                  budgets={"successor-recovery": 1})
        budget.enter("successor-recovery", self.owner.pid)
        validate, pass_receipt = H6["r5_caller_context"], H6["r5_pass_receipt"]
        def caller(*args, **kwargs):
            result = validate(*args, **kwargs)
            now[0] += 1_000_000_000
            return result
        def marker(record):
            passes.append(record["seq"])
            return pass_receipt(record)
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            with mock.patch.dict(H6["wait_r5_successor_admitted"].__globals__,
                    {"r5_caller_context": caller, "r5_pass_receipt": marker}), \
                    self.assertRaisesRegex(TimeoutError, "deadline"):
                self.wait()
        finally:
            H6["ACTIVE_LEG"].reset(token)
        self.assertEqual(passes, [], "traversal processed a pass after expiry")

    def test_row_at_line_budget_is_accepted_without_overflow(self):
        row = self.record(3, "snapshot", {"padding": ""})
        row["event"]["padding"] = "x" * (67_584 - len(json.dumps(row).encode()) - 1)
        encoded = json.dumps(row).encode() + b"\n"
        self.assertEqual(len(encoded), 67_584)
        self.write(self.prefix, encoded)
        records, complete = self.cursor.read()
        self.assertTrue(complete)
        self.assertEqual([record["seq"] for record in records], [3])

    def test_split_utf8_row_is_parsed_only_after_bounded_chunks_complete(self):
        row = self.record(3, "snapshot", {"text": "€" * 18_000})
        self.write(self.prefix, json.dumps(row, ensure_ascii=False).encode() + b"\n")
        records, complete = self.cursor.read()
        self.assertTrue(complete)
        self.assertEqual(records[0]["event"]["text"], "€" * 18_000)

    def test_scoped_turnover_binds_distinct_held_original_and_actual_successor(self):
        # These three independently derived cursors precede a real ordinary
        # Python exec. No ptrace, cgroup, provider, or native observer runs.
        old_cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)
        new_cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)
        path = self.directory / "successor-python"
        shutil.copyfile(self.pin.path, path)
        path.chmod(0o755)
        successor = H6["FilePin"](path)
        self.addCleanup(successor.close)
        self.owner.popen.stdin.write((str(path) + "\n").encode())
        self.owner.popen.stdin.flush()
        readable, _, _ = H6["select"].select([self.owner.popen.stdout], [], [], 2)
        self.assertTrue(readable, "owned successor produced no startup acknowledgement")
        if self.owner.popen.stdout.readline() != b"successor-ready\n":
            self.fail(self.owner.popen.stderr.read().decode())
        deadline = time.monotonic() + 2
        while True:
            try:
                image = successor.image_receipt({"image": 1}, self.owner)
                break
            except (ValueError, FileNotFoundError):
                if self.owner.popen.poll() is not None:
                    self.fail(self.owner.popen.stderr.read().decode())
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.005)
        self.assertNotEqual(image["ino"], self.cursor.original_image["ino"])
        rows = self.turnover()
        executable = {"path": image["path"], "dev": image["dev"], "ino": image["ino"],
                      "mtime_secs": image["mtime_ns"] // 1_000_000_000,
                      "mtime_nanos": image["mtime_ns"] % 1_000_000_000}
        rows[1]["event"]["identity_context"]["new"]["executable"] = executable
        for subject, cursor in (("old", old_cursor), ("new", new_cursor)):
            bad = copy.deepcopy(rows)
            context = bad[1]["event"]["identity_context"]
            context[subject]["executable"] = copy.deepcopy(context["new" if subject == "old" else "old"]["executable"])
            self.write(self.prefix + bad)
            with self.assertRaisesRegex(H6["SetupError"], "held actual owned image"):
                H6["wait_r5_successor_admitted"](self.log, self.owner, successor, cursor,
                                               not_before_ns=103, timeout=2)
        self.write(self.prefix + rows)
        result = H6["wait_r5_successor_admitted"](self.log, self.owner, successor, self.cursor,
                                                not_before_ns=103, timeout=2)
        self.assertEqual(result["image"], image)
        self.assertEqual(result["publication"], "exec_retired")

    def assert_refused(self, expiry=False):
        expected = TimeoutError if expiry else (H6["SetupError"], ValueError)
        with self.assertRaises(expected):
            self.wait(timeout=0.1 if expiry else 2)

    def test_fresh_owned_successor_requires_and_records_completing_pass(self):
        self.write(self.prefix + self.fresh())
        result = self.wait()
        self.assertEqual((result["caller"], result["incarnation"], result["seq"], result["at_ns"]),
                         ("c1", 1, 3, 103))
        self.assertEqual(result["completed_pass"], {"seq": 4, "at_ns": 104, "pass": 1})
        self.assertEqual(self.cursor.receipt()["retired_caller"], "c0")
        self.assertEqual(self.cursor.receipt()["retired_incarnation"], 0)

    def test_scan_pinned_complete_identity_is_admission(self):
        rows = self.fresh()
        rows[0]["event"]["identity_context"]["caller"]["authority"] = "scan_pinned"
        self.write(self.prefix + rows)
        self.assertEqual(self.wait()["caller"], "c1")

    def test_old_same_pid_path_prefix_never_satisfies_fresh_gate(self):
        self.assert_refused(expiry=True)

    def test_old_caller_or_incarnation_beyond_cursor_is_refused(self):
        for caller, incarnation in (("c0", 1), ("c1", 0), ("c0", 0)):
            with self.subTest(caller=caller, incarnation=incarnation):
                self.reset_cursor()
                self.write(self.prefix + [self.admission(3, caller, incarnation), self.fresh()[1]])
                self.assert_refused()

    def test_wrong_birth_or_executable_physical_metadata_is_refused(self):
        for field in ("start_time", "pid", "dev", "ino", "mtime_secs", "mtime_nanos", "path"):
            with self.subTest(field=field):
                self.reset_cursor()
                rows = self.fresh()
                caller = rows[0]["event"]["identity_context"]["caller"]
                target = caller if field in ("start_time", "pid") else caller["executable"]
                target[field] = target[field] + 1 if isinstance(target[field], int) else "/wrong/path"
                self.write(self.prefix + rows)
                self.assert_refused(expiry=field == "pid")

    def test_wrong_caller_context_authority_or_lifecycle_is_refused(self):
        for field, value in (("id", "c9"), ("authority", "unknown"), ("lifecycle", "exec_retired"),
                             ("status", "context_budget"), ("incarnation", True)):
            with self.subTest(field=field):
                self.reset_cursor()
                rows = self.fresh()
                rows[0]["event"]["identity_context"]["caller"][field] = value
                self.write(self.prefix + rows)
                self.assert_refused()

    def test_unknown_identity_context_version_is_refused(self):
        rows = self.fresh()
        rows[0]["event"]["identity_context"]["version"] = 2
        self.write(self.prefix + rows)
        self.assert_refused()

    def test_malformed_identity_context_is_a_clear_setup_refusal(self):
        rows = self.fresh()
        rows[0]["event"]["identity_context"] = ["malformed"]
        self.write(self.prefix + rows)
        with self.assertRaises(H6["SetupError"]):
            self.wait()

    def test_gate_keeps_original_owner_and_stream_custody(self):
        self.write(self.prefix + self.fresh())
        impostor = SimpleNamespace(pid=self.owner.pid, identity=dict(self.owner.identity))
        with self.assertRaisesRegex(H6["SetupError"], "original owner"):
            H6["wait_r5_successor_admitted"](self.log, impostor, self.pin, self.cursor,
                                           not_before_ns=103, timeout=2)
        with self.assertRaisesRegex(H6["SetupError"], "observer stream"):
            H6["wait_r5_successor_admitted"](self.directory / "other.jsonl", self.owner,
                                           self.pin, self.cursor, not_before_ns=103, timeout=2)

    def test_completing_a_partial_pass_can_unlock_only_after_newline(self):
        rows = self.fresh()
        self.write(self.prefix + rows[:1], json.dumps(rows[1]).encode())
        def complete(_deadline, _interval):
            with self.log.open("ab") as stream:
                stream.write(b"\n")
        with mock.patch.dict(H6["wait_r5_successor_admitted"].__globals__, {"pause_until": complete}):
            self.assertEqual(self.wait()["completed_pass"]["seq"], 4)

    def test_cursor_derives_retired_identity_only_from_committed_owned_records(self):
        self.cursor.close()
        self.write(self.prefix[:2])
        with self.assertRaisesRegex(H6["SetupError"], "admission/pass"):
            H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)

    def test_stream_rotation_marker_and_terminal_pass_are_refused(self):
        self.write(self.prefix + [self.record(3, "rotated", {})])
        self.assert_refused()
        self.reset_cursor()
        rows = self.fresh()
        rows[1]["event"]["final"] = True
        self.write(self.prefix + rows)
        self.assert_refused()

    def test_gate_error_reaps_stopped_child_and_releases_stream_fd(self):
        case = H6["Case"](SimpleNamespace(out=self.directory, uid=os.getuid(), gid=os.getgid()))
        acquired = []
        @H6["owned_leg"](inventory=True)
        def leg(ctx):
            owner = H6["spawn_owned"](ctx.owners,
                [sys.executable, "-I", "-c", "import time; time.sleep(30)"], os.getuid(),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log = self.directory / "cleanup-events.jsonl"
            rows = copy.deepcopy(self.prefix)
            rows[1]["event"]["identity_context"]["caller"]["pid"] = owner.pid
            rows[1]["event"]["identity_context"]["caller"]["start_time"] = owner.identity["start_time"]
            log.write_text("".join(json.dumps(row) + "\n" for row in rows))
            cursor = H6["r5_admission_checkpoint"](ctx, log, owner, self.pin)
            acquired.extend((owner, cursor))
            owner.send(signal.SIGSTOP)
            os.waitpid(owner.pid, os.WUNTRACED)
            with log.open("a") as stream:
                stream.write("{malformed}\n")
            H6["wait_r5_successor_admitted"](log, owner, self.pin, cursor,
                                           not_before_ns=103, timeout=2)
        with self.assertRaisesRegex(H6["SetupError"], "malformed"):
            leg(case)
        owner, cursor = acquired
        self.assertIsNotNone(owner.popen.poll())
        self.assertFalse((Path("/proc") / str(owner.pid)).exists())
        self.assertIsNone(owner.pidfd)
        self.assertIsNone(cursor.fd)
        os.fstat(self.pin.fd)

    def test_partial_last_line_cannot_complete_admission(self):
        rows = self.fresh()
        self.write(self.prefix + rows[:1], json.dumps(rows[1]).encode())
        self.assert_refused(expiry=True)

    def test_complete_pass_alone_cannot_borrow_stale_prefix_admission(self):
        self.write(self.prefix + [self.fresh()[1] | {"seq": 3}])
        self.assert_refused(expiry=True)

    def test_admission_without_completing_pass_expires(self):
        self.write(self.prefix + self.fresh()[:1])
        self.assert_refused(expiry=True)

    def test_malformed_complete_record_and_unknown_schema_are_refused(self):
        self.write(self.prefix, b"{broken}\n")
        self.assert_refused()
        self.reset_cursor()
        rows = self.fresh()
        rows[0]["schema"] = "p11scope/inventory-events/v999"
        self.write(self.prefix + rows)
        self.assert_refused()

    def test_rotated_or_truncated_stream_cannot_restart_at_zero(self):
        self.log.rename(self.directory / "prior.jsonl")
        self.write(self.prefix + self.fresh())
        self.assert_refused()

    def test_truncated_original_stream_is_refused(self):
        self.write(self.prefix[:1])
        self.assert_refused()

    def test_rewritten_prefix_and_sequence_discontinuity_are_refused(self):
        changed = copy.deepcopy(self.prefix)
        changed[0]["at_ns"] = 99
        self.write(changed + self.fresh())
        self.assert_refused()
        self.reset_cursor()
        rows = self.fresh()
        rows[0]["seq"] = 99
        self.write(self.prefix + rows)
        self.assert_refused()

    def test_admission_before_verified_reentry_is_refused(self):
        rows = self.fresh()
        rows[0]["at_ns"] = 102
        self.write(self.prefix + rows)
        self.assert_refused()

    def test_retirement_before_completing_pass_is_refused(self):
        old = self.successor_turnover(None)["event"]["identity_context"]["old"]
        self.write(self.prefix + [self.fresh()[0], self.record(4, "caller_event",
            {"event": "retired", "caller": "c1", "reason": "caller retired",
             "identity_context": {"version": 1, "caller": old}}),
            self.record(5, "pass_committed", {"pass": 2})])
        with self.assertRaisesRegex(H6["SetupError"], "successor retired before admission completion"):
            self.wait()

    def test_actual_owned_executable_mismatch_prevents_admission(self):
        other = self.directory / "other-executable"
        other.write_bytes(b"different executable")
        pin = H6["FilePin"](other)
        self.addCleanup(pin.close)
        self.write(self.prefix + self.fresh())
        with self.assertRaisesRegex(ValueError, "actual owned process executable"):
            H6["wait_r5_successor_admitted"](self.log, self.owner, pin, self.cursor,
                                           not_before_ns=103, timeout=2)

    def test_original_recovery_deadline_is_not_renewed_by_admission_wait(self):
        self.write(self.prefix + self.fresh())
        now = [1_000_000_000]
        budget = H6["LegBudget"](inventory=True, clock=lambda: now[0],
                                  budgets={"successor-recovery": 0.01})
        budget.enter("successor-recovery", self.owner.pid)
        now[0] += 10_000_000
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            with self.assertRaisesRegex(TimeoutError, "deadline"):
                self.wait(timeout=90)
        finally:
            H6["ACTIVE_LEG"].reset(token)

    def test_expiry_during_final_file_verification_cannot_return_admission(self):
        self.write(self.prefix + self.fresh())
        now = [1_000_000_000]
        budget = H6["LegBudget"](inventory=True, clock=lambda: now[0],
                                  budgets={"successor-recovery": 1})
        budget.enter("successor-recovery", self.owner.pid)
        verify, calls = self.pin.verify, []
        def expire():
            verify()
            calls.append(True)
            if len(calls) == 2:
                now[0] += 1_000_000_000
        token = H6["ACTIVE_LEG"].set(budget)
        try:
            with mock.patch.object(self.pin, "verify", expire), \
                    self.assertRaisesRegex(TimeoutError, "deadline"):
                self.wait()
        finally:
            H6["ACTIVE_LEG"].reset(token)


class InventoryReadinessTest(unittest.TestCase):
    setUp = R5FreshAdmissionTest.setUp
    release = R5FreshAdmissionTest.release
    record = R5FreshAdmissionTest.record
    admission = R5FreshAdmissionTest.admission
    write = R5FreshAdmissionTest.write

    def prepare(self, mutation=None, *, partial=False, missing_pass=False, delayed=False,
                deficit=0, gap=False, early=0, unrelated_gap=False, deferred=False):
        fresh = [self.admission(3, "c1", 1), self.record(4, "pass_committed", {"pass": 1})]
        self.write(self.prefix + fresh)
        self.accepted = H6["wait_r5_successor_admitted"](self.log, self.owner, self.pin,
            self.cursor, not_before_ns=103, timeout=1)
        self.provider = H6["provider_receipt"](self.pin)
        self.markers = []
        self.sequence = 5
        self.next_pass = 2
        def attempt(number, deadline):
            t = time.monotonic_ns()
            batches = [{"cell": "RX", "pid": self.owner.pid,
                "start": self.owner.identity["start_time"], "gen": 1, "exe": str(self.pin.path),
                "module": str(self.pin.path), "fn": fn, "mech": "0x250", "n": 5,
                "bad": 0, "phase": f"h6-warm{number}", "t0": t - 500, "t1": t - 100}
                for fn in ("C_DigestInit", "C_Digest")]
            ack = {"command": "W", "gen": 1, "attempt": number, "seq": number,
                   "pid": self.owner.pid, "start": self.owner.identity["start_time"],
                   "exe": str(self.pin.path), "t0": t - 600, "t1": t, "deadline": deadline,
                   "idle": 1, "rv": 0}
            caller = copy.deepcopy(fresh[0]["event"]["identity_context"]["caller"])
            module = {"id": "m0", "device_major": self.provider["mapping"]["dev"][0],
                "device_minor": self.provider["mapping"]["dev"][1], "inode": self.provider["ino"],
                "path": str(self.pin.path), "status": "observed"}
            count = number * 10 + early - deficit
            physical = {"caller": "c1", "module": "m0", "mapping": {"state": "mapped"},
                "entries": {"count": count, "last_seen_ns": t, "saturated": False,
                            "coverage": {"state": "counted", "lossy": False}},
                "identity_context": {"version": 1, "caller": caller, "module": module}}
            instance = {"id": "i1", "caller": "c1", "module": "m0", "state": "observed", "reason": None}
            semantic = {"caller": "c1", "module": "m0", "instance": "i1", "semantics": "observed",
                "entries": {"unit": "api_entries", "count": None, "observation": "unavailable"},
                "api_returns": {"count": count, "saturated": False, "historical_only_returns": 0},
                "mechanisms": [{"mechanism_hex": "0x250", "calls": count, "errors": 0}],
                "operations": {"calls": count, "completed": count // 2, "failed": 0,
                               "unknown": 0, "orphans": 0, "dropped": 0, "last_seen_ns": t - 100},
                "coverage": {"lossy": False, "reasons": []}}
            if delayed and number == 1:
                physical["entries"].update(count=8, last_seen_ns=t - 1000)
            if mutation:
                mutation(physical, instance, semantic)
            payloads = [("edge_observed", physical), ("instance_observed", instance),
                        ("semantic_edge_observed", semantic)]
            if gap:
                payloads.insert(0, ("gap_recorded", {"caller": "c9" if unrelated_gap else "c1", "module": "m0",
                    "pid": self.owner.pid + 1 if unrelated_gap else self.owner.pid,
                    "subject": "exact image authority unavailable" if unrelated_gap else "early coverage",
                    "reason": "use_before_admission"}))
            if not missing_pass:
                payloads.append(("pass_committed", {"pass": self.next_pass,
                    "edge_events": 1, "instance_events": 1, "semantic_edge_events": 1,
                    "semantic_edge_events_deferred": 1 if deferred else 0}))
                self.next_pass += 1
            records = []
            for kind, event in payloads:
                row = self.record(self.sequence, kind, event)
                row["at_ns"] = t + self.sequence
                records.append(row)
                self.sequence += 1
            with self.log.open("ab") as stream:
                for index, row in enumerate(records):
                    stream.write(json.dumps(row).encode() + (b"" if partial and index == len(records) - 1 else b"\n"))
            self.markers.append({"ack": ack, "batches": batches})
            return self.markers[-1]
        return attempt

    def gate(self, callback, timeout=2, **kwargs):
        return H6["wait_inventory_s1_ready"](self.owner, self.pin, self.pin,
            self.accepted, self.cursor, callback, time.monotonic_ns() + int(timeout * 1e9), **kwargs)

    def test_same_observer_physical_instance_s1_and_complete_pass_release(self):
        result = self.gate(self.prepare())
        self.assertEqual((result["caller"], result["module"], result["instance"]), ("c1", "m0", "i1"))
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(result["baseline"]["physical"]["event"]["entries"]["count"], 10)
        self.assertGreater(result["baseline"]["pass"]["seq"], result["baseline"]["semantic"]["seq"])

    def test_unmapped_unattached_unknown_and_wrong_subjects_cannot_release(self):
        def wrong_birth(p, _i, _s): p["identity_context"]["caller"]["start_time"] += 1
        def wrong_incarnation(p, _i, _s): p["identity_context"]["caller"]["incarnation"] = 0
        def wrong_provider(p, _i, _s): p["identity_context"]["module"]["inode"] += 1
        def wrong_instance(_p, i, s): s["instance"] = "i9"
        controls = [lambda p, _i, _s: p["mapping"].update(state="unknown"),
            lambda p, _i, _s: p["entries"]["coverage"].update(state="armed"),
            lambda _p, _i, s: s.update(semantics="unknown", mechanisms=None, operations=None),
            lambda _p, i, _s: i.update(state="retired"),
            lambda _p, _i, s: s["api_returns"].update(count=None),
            lambda _p, _i, s: s["api_returns"].update(count=1),
            wrong_birth, wrong_incarnation, wrong_provider, wrong_instance,
            lambda _p, _i, s: s.update(caller="c9")]
        for mutation in controls:
            with self.subTest(mutation=mutation):
                self.cursor.close()
                self.write(self.prefix)
                self.cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)
                callback = self.prepare(mutation)
                with self.assertRaises((TimeoutError, H6["SetupError"])):
                    self.gate(callback, timeout=0.2)
                self.assertTrue(self.markers, "refusal control never executed its real attempt callback")

    def test_partial_line_missing_pass_and_expired_proof_do_not_release(self):
        for kwargs in ({"partial": True}, {"missing_pass": True}):
            self.cursor.close()
            self.write(self.prefix)
            self.cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)
            with self.assertRaises(TimeoutError):
                self.gate(self.prepare(**kwargs), timeout=0.2)
            self.assertTrue(self.markers)
        with self.assertRaises(TimeoutError):
            H6["wait_inventory_s1_ready"](self.owner, self.pin, self.pin, self.accepted,
                self.cursor, lambda *_args: self.fail("expired gate dispatched work"), time.monotonic_ns() - 1)

    def test_delayed_physical_baseline_needs_actual_marker_work(self):
        result = self.gate(self.prepare(delayed=True), timeout=3)
        self.assertGreater(result["attempts"], 1)
        self.assertEqual(result["baseline"]["physical"]["event"]["entries"]["count"], 20)

    def test_honest_early_deficit_requires_physically_joined_finite_gap(self):
        for gap in (True, False):
            with self.subTest(gap=gap):
                self.cursor.close()
                self.write(self.prefix)
                self.cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)
                callback = self.prepare(early=10, deficit=2, gap=gap)
                t = time.monotonic_ns() - 1000000
                prefix = [{"cell": "RX", "pid": self.owner.pid, "gen": 1,
                    "module": str(self.pin.path), "fn": fn, "mech": "0x250", "n": 5,
                    "bad": 0, "phase": "h6-setup", "t0": t, "t1": t + 10}
                    for fn in ("C_DigestInit", "C_Digest")]
                if gap:
                    proof = self.gate(callback, prefix_batches=prefix)
                    early = proof["baseline"]["early"]
                    self.assertEqual((early["physical_expected"], early["physical_observed"],
                                      early["physical_missed"]), (20, 18, 2))
                    self.assertEqual(early["api_missed"], 2)
                    self.assertTrue(early["gaps"])
                    self.assertIsNone(early["populations"]["setup"]["observed_physical"])
                    self.assertEqual(early["populations"]["warmup"]["expected"], 10)
                else:
                    with self.assertRaises(TimeoutError):
                        self.gate(callback, timeout=0.2, prefix_batches=prefix)
                    self.assertTrue(self.markers)

    def test_cumulative_redraws_replace_the_same_instance_counters(self):
        callback = self.prepare()
        def redraw(number, deadline):
            marker = callback(number, deadline)
            rows = [json.loads(line) for line in self.log.read_text().splitlines()]
            physical = next(row["event"] for row in reversed(rows) if row["kind"] == "edge_observed")
            semantic = next(row["event"] for row in reversed(rows) if row["kind"] == "semantic_edge_observed")
            t = time.monotonic_ns()
            additions = [("edge_observed", physical), ("semantic_edge_observed", semantic),
                ("pass_committed", {"pass": 3, "edge_events": 1, "instance_events": 0,
                                    "semantic_edge_events": 1})]
            with self.log.open("a") as stream:
                for offset, (kind, event) in enumerate(additions):
                    row = self.record(len(rows) + offset, kind, event)
                    row["at_ns"] = t + offset
                    stream.write(json.dumps(row) + "\n")
            return marker
        result = self.gate(redraw)
        self.assertEqual(result["baseline"]["counts"]["physical"], 10)
        self.assertEqual(result["baseline"]["counts"]["api"], 10)
        self.assertEqual(result["baseline"]["counts"]["completed"], 5)

    def test_old_caller_gap_cannot_excuse_current_image_deficit_at_the_same_pid(self):
        callback = self.prepare(early=10, deficit=2, gap=True)
        def old_gap(number, deadline):
            marker = callback(number, deadline)
            rows = [json.loads(line) for line in self.log.read_text().splitlines()]
            for row in rows:
                if row["kind"] == "gap_recorded":
                    row["event"]["caller"] = "c0"
            self.write(rows)
            return marker
        t = time.monotonic_ns() - 1000000
        prefix = [{"cell": "RX", "pid": self.owner.pid, "gen": 1,
            "module": str(self.pin.path), "fn": fn, "mech": "0x250", "n": 5,
            "bad": 0, "phase": "h6-setup", "t0": t, "t1": t + 10}
            for fn in ("C_DigestInit", "C_Digest")]
        with self.assertRaises((TimeoutError, H6["SetupError"])):
            self.gate(old_gap, timeout=0.2, prefix_batches=prefix)
        self.assertTrue(self.markers, "wrong-caller refusal never attempted the real warmup callback")

    def test_pid_only_gap_requires_current_admission_and_early_call_interval(self):
        for stale in (False, True):
            with self.subTest(stale=stale):
                self.cursor.close()
                self.write(self.prefix)
                self.cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)
                callback = self.prepare(early=10, deficit=2, gap=True)
                def pid_gap(number, deadline):
                    marker = callback(number, deadline)
                    rows = [json.loads(line) for line in self.log.read_text().splitlines()]
                    for row in rows:
                        if row["kind"] == "gap_recorded":
                            row["event"]["caller"] = None
                            if stale:
                                row["at_ns"] = 105  # after admission, before this image's actual calls
                    self.write(rows)
                    return marker
                t = time.monotonic_ns() - 1000000
                prefix = [{"cell": "RX", "pid": self.owner.pid, "gen": 1,
                    "module": str(self.pin.path), "fn": fn, "mech": "0x250", "n": 5,
                    "bad": 0, "phase": "h6-setup", "t0": t, "t1": t + 10}
                    for fn in ("C_DigestInit", "C_Digest")]
                if stale:
                    with self.assertRaises((TimeoutError, H6["SetupError"])):
                        self.gate(pid_gap, timeout=0.2, prefix_batches=prefix)
                else:
                    proof = self.gate(pid_gap, prefix_batches=prefix)
                    self.assertEqual(proof["baseline"]["early"]["physical_missed"], 2)
                self.assertTrue(self.markers)

    def test_pass_cannot_claim_zero_emissions_for_the_actual_proof_rows(self):
        callback = self.prepare()
        def invalid_accounting(number, deadline):
            marker = callback(number, deadline)
            rows = [json.loads(line) for line in self.log.read_text().splitlines()]
            rows[-1]["event"].update(edge_events=0, instance_events=0, semantic_edge_events=0)
            self.write(rows)
            return marker
        with self.assertRaisesRegex(H6["SetupError"], "accounting"):
            self.gate(invalid_accounting)

    def test_deferred_pass_and_unrelated_gap_cannot_release(self):
        for kwargs in ({"deferred": True}, {"gap": True, "unrelated_gap": True,
                                              "early": 10, "deficit": 2}):
            with self.subTest(kwargs=kwargs):
                self.cursor.close()
                self.write(self.prefix)
                self.cursor = H6["r5_admission_checkpoint"](self.ctx, self.log, self.owner, self.pin)
                callback = self.prepare(**kwargs)
                prefix = []
                if kwargs.get("early"):
                    t = time.monotonic_ns() - 1000000
                    prefix = [{"cell": "RX", "pid": self.owner.pid, "gen": 1,
                        "module": str(self.pin.path), "fn": fn, "mech": "0x250", "n": 5,
                        "bad": 0, "phase": "h6-setup", "t0": t, "t1": t + 10}
                        for fn in ("C_DigestInit", "C_Digest")]
                with self.assertRaises(TimeoutError):
                    self.gate(callback, timeout=0.2, prefix_batches=prefix)
                self.assertTrue(self.markers)

    def test_release_rechecks_expired_proof_and_actual_held_provider_custody(self):
        provider_path = self.directory / "release-provider"
        provider_path.write_bytes(b"owned held provider")
        provider = H6["FilePin"](provider_path)
        self.addCleanup(provider.close)
        held = H6["provider_receipt"](provider)
        controller = SimpleNamespace(dispatch=mock.Mock(), complete=mock.Mock())
        proof = {"provider": held, "deadline_ns": time.monotonic_ns() - 1}
        with self.assertRaises(TimeoutError):
            H6["release_inventory_measurement"](controller, provider, proof,
                time.monotonic_ns() + 1000000000)
        controller.dispatch.assert_not_called()
        proof["deadline_ns"] = time.monotonic_ns() + 1000000000
        provider_path.write_bytes(b"changed held provider")
        with self.assertRaises(ValueError):
            H6["release_inventory_measurement"](controller, provider, proof, proof["deadline_ns"])
        controller.dispatch.assert_not_called()


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

    def test_worker_prefix_population_cannot_borrow_post_exec_named_calls(self):
        text, ledger, receipt = b_style_inputs()
        receipt.update(cell="leader-exit-exec", b_setup={"worker_identity": {"tid": 1042}})
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["capability_early_coverage"], {
            "expected": 11, "observed_named": 0, "observed_unknown": 3, "deficit": 8, "errors": []})
        self.assertEqual(result["named"], 3)

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
LEDGER cell=PX pid=1000 start=7777 gen=1 exe=/w/ledger2 module=/w/libA.so fn=C_DigestInit mech=0x250 n=11 bad=0 phase=main t0={h0} t1={h1}
LEDGER cell=PX pid=1000 start=7777 gen=1 exe=/w/ledger2 module=/w/libA.so fn=C_Digest mech=0x250 n=11 bad=1 phase=main t0={h0} t1={h1}
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
             "entries": {"count": 22, "coverage": {"state": "counted",
                                                  "lossy": False}},
             "semantics": "observed",
             "mechanisms": [{"mechanism": 0x250, "mechanism_hex": "0x250",
                             "name": None, "operations": ["digest"],
                             "calls": 22, "errors": 1, "last_seen_ns": h1,
                             "evidence": {"functions": ["C_DigestInit", "C_Digest"],
                                          "returns": [{"rv": 0, "rv_hex": "0x0",
                                                       "name": "CKR_OK"}],
                                          "truncated": False}}],
             "operations": {"calls": 22, "started": 10, "completed": 10,
                            "cancelled": 0, "failed": 1, "unknown": 0,
                            "orphans": 0, "dropped": 0, "last_seen_ns": h1,
                            "active": []}},
        ],
        "instances": [{"id": "i0", "caller": "c0", "module": "m0",
                       "state": "observed", "reason": None,
                       "first_seen_ns": m0, "last_seen_ns": m1},
                      {"id": "i1", "caller": "c1", "module": "m0",
                       "state": "observed", "reason": None,
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
             "api_returns": {"unit": "api_returns", "count": 22,
                             "saturated": False, "historical_only_returns": 0},
             "semantics": "observed", "mechanisms": [],
             "operations": {"completed": 10, "failed": 1},
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
                                  "1000:1:A": {"counted": True, "count": 22}},
               "measured": {"label": "gen1", "t0": h0 - 1, "t1": h1 + 1,
                            "expected_calls": 22,
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

    def measured_sibling_control(self, target_success=9, target_failed=1):
        doc, ledgers, receipt = inventory_inputs()
        target = doc["edges"][1]
        count = 2 * (target_success + target_failed)
        target["entries"]["count"] = count
        target["mechanisms"][0].update(calls=count, errors=target_failed)
        target["operations"].update(calls=count, completed=target_success,
                                    failed=target_failed)
        doc["semantic_edges"][1]["api_returns"]["count"] = count
        doc["semantic_edges"][1]["operations"].update(
            completed=target_success, failed=target_failed)
        target_batches = [batch for batch in ledgers["PX"]["batches"] if batch["gen"] == 1]
        for batch in target_batches:
            batch["n"] = target_success + target_failed
            batch["bad"] = target_failed if batch["fn"] == "C_Digest" else 0
        sibling = copy.deepcopy(doc["callers"][1])
        sibling.update(id="c2", pid=2000, start_time=8888)
        doc["callers"].append(sibling)
        sibling_edge = copy.deepcopy(target)
        sibling_edge.update(caller="c2")
        sibling_edge["entries"]["count"] = 22
        sibling_edge["mechanisms"][0].update(calls=22, errors=1)
        sibling_edge["operations"].update(calls=22, completed=10, failed=1)
        doc["edges"].append(sibling_edge)
        sibling_instance = copy.deepcopy(doc["instances"][1])
        sibling_instance.update(id="i2", caller="c2")
        doc["instances"].append(sibling_instance)
        sibling_semantic = copy.deepcopy(doc["semantic_edges"][1])
        sibling_semantic.update(caller="c2", instance="i2")
        sibling_semantic["api_returns"]["count"] = 22
        sibling_semantic["operations"].update(completed=10, failed=1)
        doc["semantic_edges"].append(sibling_semantic)
        sibling_ledger = H6["parse_inv_ledger"]("")
        for original in target_batches:
            batch = dict(original, pid=2000, start=8888, n=11,
                         bad=1 if original["fn"] == "C_Digest" else 0)
            sibling_ledger["batches"].append(batch)
        ledgers["MS"] = sibling_ledger
        receipt["owned_pids"].append(2000)
        receipt["expected_incarnations"]["2000"] = {
            "gens": {"1": {"exe": sibling["image"]["exe"]["path"], "retired": False}}}
        receipt["expected_edges"].update({"1000:1:A": {"counted": True, "count": count},
                                          "2000:1:A": {"counted": True, "count": 22}})
        receipt["measured"]["expected_calls"] = count + 22
        return doc, ledgers, receipt

    def test_reject_nine_target_completions_despite_ten_sibling_completions(self):
        result = H6["evaluate_inventory_h6"](*self.measured_sibling_control())
        self.assertFalse(result["pass"], result)
        self.assertTrue(any("pid 1000 gen 1" in error and "fewer than 10" in error
                            for error in result["errors"]), result["errors"])

    def test_reject_target_without_failed_returns_despite_sibling_failures(self):
        result = H6["evaluate_inventory_h6"](
            *self.measured_sibling_control(target_success=10, target_failed=0))
        self.assertFalse(result["pass"], result)
        self.assertTrue(any("pid 1000 gen 1" in error and "failed return" in error
                            for error in result["errors"]), result["errors"])

    def test_accept_inventory_control(self):
        doc, ledgers, receipt = inventory_inputs()
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["physical_entered"], 30)
        self.assertEqual(result["physical_counted"], 30)
        self.assertEqual(result["failed_ledgered"], 2)
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
