#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Adversarial controls for the H6 installed-acceptance oracle.

Loads scripts/qualify-automatic-exec.py (the oracle under test) via runpy
and proves each H6 verdict leg both ways: the required rejects
(all-unknown "positive", wrong successor name, outside-scope count,
duplicate return, missing measured phase, manual-rebind path) and the
nonempty ledger-matched accept, plus order-attribution, purity,
abandoned-accounting, reuse, profile/metrics and inventory legs.

No privilege, no fixtures, no observer: every input is synthetic.
"""

import copy
import inspect
import json
import runpy
import sys
import unittest
from pathlib import Path

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
               "manual_rebind": False, "abandoned_expected": 0,
               "reuse_expected": {}, "requested_backend": "singles"}
    receipt.update(over)
    return receipt


def caller_inputs():
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
    return text, ledger, receipt


def b_style_inputs():
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
    return text, ledger, receipt


class TraceTest(unittest.TestCase):
    maxDiff = 4000

    def test_accept_caller_control(self):
        text, ledger, receipt = caller_inputs()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["calls"], 6)
        self.assertEqual(result["named"], 4)
        self.assertEqual(result["unknown"], 2)
        self.assertEqual(result["false_names"], 0)
        self.assertEqual(result["physical_entered"], 6)
        self.assertEqual(result["api_returned"], 6)
        self.assertEqual(result["measured_calls"], 3)
        self.assertEqual(result["warmup_calls"], 2)
        self.assertEqual(result["order_matched"], 6)

    def test_accept_b_style_control(self):
        text, ledger, receipt = b_style_inputs()
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["physical_entered"], 6)
        self.assertEqual(result["api_returned"], 5)
        self.assertEqual(result["completed_operations"], 5)
        self.assertEqual(result["abandoned"], 1)
        self.assertEqual(result["named"], 1)
        self.assertEqual(result["unknown"], 4)

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
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["order_matched"], 3)
        self.assertEqual(result["image_generation_populations"][1], {"named": 1, "unknown": 1})

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
                     "min_dwell_ns": 2_000_000_000, "observer_self_ended": False})
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

    def test_accept_self_ended_observer(self):
        text, ledger, receipt = group_death_inputs()
        receipt = copy.deepcopy(receipt)
        receipt["group_death"]["observer_self_ended"] = True
        result = H6["evaluate_trace_h6"](text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])

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
        receipt["group_death"]["kill_ns"] = STOP - 2
        receipt["group_death"]["death_ns"] = STOP - 1
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
                       profile_function("C_Finalize", 0, 0, 0)])
    return doc, profile_stdout(5, 2, 1), ledger, receipt


class AggregateTest(unittest.TestCase):
    maxDiff = 4000

    def test_accept_profile_control(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        result = H6["evaluate_profile_h6"](doc, stdout_text, ledger, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["completed_calls"], 5)
        self.assertEqual(result["returned_errors"], 2)
        self.assertEqual(result["in_flight"], 1)
        self.assertEqual(result["named_calls"], 5)
        self.assertEqual(result["unknown_calls"], 0)
        self.assertEqual(result["physical_entered"], 6)

    def test_accept_metrics_control(self):
        doc, stdout_text, ledger, receipt = profile_inputs()
        doc = profile_doc([profile_function("C_Initialize", 5, 2, 1)], mode="metrics")
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
        pre0 = READY + 100_000_000
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
        doc = profile_doc([profile_function("C_Initialize", 5, 2, 1)], mode="metrics")
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
