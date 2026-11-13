# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Inventory MT-exact oracle controls; every assertion has a failing twin."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


def ledger_payload(ledger):
    for line in ledger:
        if line.startswith("LEDGER "):
            return json.loads(line[len("LEDGER "):])
    raise AssertionError("no LEDGER line")


def replace_ledger(ledger, payload):
    for i, line in enumerate(ledger):
        if line.startswith("LEDGER "):
            ledger[i] = "LEDGER " + json.dumps(payload)
            return
    raise AssertionError("no LEDGER line")

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/inventory-mt-oracle.py"
GATE = ROOT / "scripts/inventory-mt-gate.py"
MT_NAMES = ("C_GenerateRandom", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal",
            "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetSessionInfo")
OWNED_SHA = "a" * 64


def provider_pin():
    return {"dev": [8, 1], "ino": 71, "sha256": OWNED_SHA,
            "file_identity": {"dev": [0, 38], "ino": 71, "size": 8192,
                              "mtime_ns": 123, "ctime_ns": 456},
            "mapping": {"dev": [8, 1], "ino": 71, "file_offset": 0,
                        "length": 4096, "permissions": "r--p"}}


def ledger_lines(pids, calls=24):
    lines = ["TARGET " + json.dumps({"name": name, "dev": [8, 1], "ino": 71,
                                     "file_offset": 4096 + i * 16})
             for i, name in enumerate(MT_NAMES)]
    lines.append("READY pid=%d" % pids[0])
    for pid in pids[1:]:
        lines.append("CHILD pid=%d" % pid)
    lines.append("LEDGER " + json.dumps({
        "schema": "p11scope/public-cli-ledger/v2", "pid": pids[0], "complete": True,
        "functions": [{"name": name, "attempts": calls, "successful": calls,
                       "rv_counts": {"0x0000000000000000": calls}} for name in MT_NAMES]}))
    lines.append("SCAFFOLD " + json.dumps(
        {"opens_attempted": 8, "opens_ok": 8, "closes": 8, "finalizes": 1}))
    return lines


def receipt(cell, scope, pids):
    return {"schema": "p11scope/public-cli-receipt/v1", "cell": cell,
            "scope": scope, "count_domain": "owned-provider",
            "launched_pid": pids[0], "generation": 456,
            "ready_pid": pids[0], "ready_generation": 456,
            "workload_ready": True, "capture_ready": True, "gate_released": True,
            "observer_exit": 0, "workload_exit": 0, "ledger_complete": True,
            "provider_before": provider_pin(), "provider_after": provider_pin()}


def edge_row(caller, module, count):
    return {"caller": caller, "module": module,
            "mapping": {"state": "mapped"},
            "entries": {"count": count, "observation": "observed",
                        "coverage": {"state": "counted", "lossy": False, "reason": None}}}


def inputs(cell, pids=(123,), calls=24):
    short = "system" if cell == "inventory-mt-system" else "pid"
    scope = short if short == "system" else "pid:%d" % pids[0]
    per = len(MT_NAMES) * calls
    if len(pids) == 1:
        # Single edge: mixed calls + 8 opens + 8 closes + 1 finalize.
        counts = [per + 17]
    else:
        # Parent edge carries only its Finalize; each child its share.
        counts = [1] + [(per + 16) // (len(pids) - 1)] * (len(pids) - 1)
    report = {"schema": "p11scope/inventory/v1", "scope": scope,
              "modules": [{"id": "m1", "admission": {"state": "admitted"},
                           "identity": {"device": {"major": 8, "minor": 1},
                                        "inode": 71, "sha256": OWNED_SHA}}],
              "callers": [{"id": "c%d" % i, "pid": pid} for i, pid in enumerate(pids)],
              "edges": [edge_row("c%d" % i, "m1", count)
                        for i, count in enumerate(counts)],
              "gaps": []}
    events = [{"seq": 1, "kind": "started", "event": {"scope": scope}}]
    seq = 2
    for row in report["edges"]:
        events.append({"seq": seq, "kind": "edge_observed",
                         "event": copy.deepcopy(row)})
        seq += 1
    events.append({"seq": seq, "kind": "ended", "event": {}})
    return report, ledger_lines(pids, calls), receipt(cell, short, pids), events


class InventoryMtOracleTests(unittest.TestCase):
    def run_case(self, mutate=None, *, cell="inventory-mt-pid", want=0,
                 pids=(123,), calls=24):
        report, ledger, receipt_value, events = inputs(cell, pids, calls)
        if cell == "inventory-mt-system" and pids == (123,):
            pids = (123, 124, 125, 126, 127)
            report, ledger, receipt_value, events = inputs(cell, pids, calls)
        if mutate:
            mutate(report, ledger, receipt_value, events)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {}
            for key, value in (("report", report), ("receipt", receipt_value)):
                paths[key] = tmp / key
                paths[key].write_text(json.dumps(value))
            paths["ledger"] = tmp / "ledger"
            paths["ledger"].write_text("\n".join(ledger) + "\n")
            paths["event-log"] = tmp / "events"
            paths["event-log"].write_text("\n".join(json.dumps(row) for row in events) + "\n")
            args = [sys.executable, "-I", str(ORACLE), "--cell", cell,
                    *sum((["--" + key, str(path)] for key, path in paths.items()), [])]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["cell"], cell)
        self.assertEqual(result["pass"], want == 0)
        return result

    def test_pid_healthy_passes(self):
        result = self.run_case(cell="inventory-mt-pid")
        self.assertEqual(result["qualification"], "owned-edge-usage-counts")

    def test_system_healthy_passes(self):
        result = self.run_case(cell="inventory-mt-system")
        self.assertEqual(result["qualification"], "owned-edge-usage-counts")

    def test_snapshot_undercount_fails(self):
        result = self.run_case(lambda d, l, r, e: d["edges"][0]["entries"].update(count=208),
                               cell="inventory-mt-pid", want=1)
        self.assertIn("differs from the independent ledger total", result["detail"])

    def test_snapshot_overcount_fails(self):
        self.run_case(lambda d, l, r, e: d["edges"][0]["entries"].update(count=210),
                      cell="inventory-mt-pid", want=1)

    def test_missing_scaffold_fails(self):
        def mutate(d, l, r, e):
            l[:] = [line for line in l if not line.startswith("SCAFFOLD ")]
        self.run_case(mutate, cell="inventory-mt-pid", want=1)

    def test_inconsistent_scaffold_fails(self):
        def mutate(d, l, r, e):
            for i, line in enumerate(l):
                if line.startswith("SCAFFOLD "):
                    l[i] = "SCAFFOLD " + json.dumps(
                        {"opens_attempted": 7, "opens_ok": 8, "closes": 8, "finalizes": 1})
        self.run_case(mutate, cell="inventory-mt-pid", want=1)

    def test_ledger_plus_one_fails(self):
        def mutate(d, l, r, e):
            payload = ledger_payload(l)
            payload["functions"][2].update(attempts=25, successful=25,
                                           rv_counts={"0x0000000000000000": 25})
            replace_ledger(l, payload)
        result = self.run_case(mutate, cell="inventory-mt-pid", want=1)
        self.assertIn("differs from the independent ledger total", result["detail"])

    def test_lossy_coverage_fails(self):
        self.run_case(lambda d, l, r, e: d["edges"][0]["entries"]["coverage"].update(lossy=True),
                      cell="inventory-mt-pid", want=1)

    def test_uncounted_coverage_fails(self):
        self.run_case(lambda d, l, r, e: d["edges"][0]["entries"]["coverage"].update(state="witnessed"),
                      cell="inventory-mt-pid", want=1)

    def test_unobserved_edge_fails(self):
        self.run_case(lambda d, l, r, e: d["edges"][0]["entries"].update(
            observation="unknown (usage observation lossy)"), cell="inventory-mt-pid", want=1)

    def test_missing_caller_edge_fails(self):
        self.run_case(lambda d, l, r, e: d["edges"].pop(), cell="inventory-mt-system", want=1)

    def test_missing_child_caller_fails(self):
        def mutate(d, l, r, e):
            d["callers"] = [c for c in d["callers"] if c["pid"] != 126]
            d["edges"] = [row for row in d["edges"] if row["caller"] != "c3"]
        self.run_case(mutate, cell="inventory-mt-system", want=1)

    def test_owned_module_gap_fails(self):
        self.run_case(lambda d, l, r, e: d["gaps"].append({"module": "m1", "reason": "x"}),
                      cell="inventory-mt-pid", want=1)

    def test_stream_missing_ended_fails(self):
        self.run_case(lambda d, l, r, e: e.pop(), cell="inventory-mt-pid", want=1)

    def test_stream_edge_total_drift_fails(self):
        def mutate(d, l, r, e):
            e[1]["event"]["entries"]["count"] = 100
        result = self.run_case(mutate, cell="inventory-mt-pid", want=1)
        self.assertIn("differs from the snapshot row", result["detail"])

    def test_stream_missing_edge_fails(self):
        def mutate(d, l, r, e):
            del e[1]
        self.run_case(mutate, cell="inventory-mt-pid", want=1)

    def test_v1_ledger_refused(self):
        def mutate(d, l, r, e):
            payload = ledger_payload(l)
            payload["schema"] = "p11scope/public-cli-ledger/v1"
            for row in payload["functions"]:
                row.pop("rv_counts", None)
            replace_ledger(l, payload)
        self.run_case(mutate, cell="inventory-mt-pid", want=1)

    def test_wrong_cell_fails(self):
        self.run_case(cell="inventory-mt-pid-typo", want=1)

    def test_scope_pid_mismatch_fails(self):
        self.run_case(lambda d, l, r, e: d.update(scope="pid:999"),
                      cell="inventory-mt-pid", want=1)


def gate_event(pid, state, dev=(8, 1), ino=71):
    return {"kind": "edge_observed",
            "event": {"caller": "c0", "module": "m0",
                      "identity_context": {
                          "caller": {"pid": pid},
                          "module": {"device_major": dev[0], "device_minor": dev[1],
                                     "inode": ino}},
                      "entries": {"coverage": {"state": state}}}}


def gate_pass(seq):
    return {"seq": seq, "kind": "pass_committed", "at_ns": seq * 1_000_000_000,
            "event": {"pass": seq - 1}}


def gate_started():
    return {"seq": 0, "kind": "started", "at_ns": 0, "event": {}}


def gate_ended(seq):
    return {"seq": seq, "kind": "ended", "at_ns": seq * 1_000_000_000,
            "event": {}}


class ScriptedEventLog:
    """Append event-log records on a scripted timeline (writer thread).

    script: [(delay_after_previous_seconds, [record, ...]), ...].
    stop() halts the timeline early; join() waits for the thread.
    """

    def __init__(self, path, script):
        self._path = path
        self._script = script
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self):
        with open(self._path, "a", encoding="utf-8") as handle:
            for delay, records in self._script:
                if self._stop.wait(delay):
                    break
                for record in records:
                    handle.write(json.dumps(record) + "\n")
                handle.flush()

    def stop(self):
        self._stop.set()

    def join(self, timeout=30):
        self._thread.join(timeout)


class InventoryMtGateTests(unittest.TestCase):
    def run_gate(self, wl_lines, events, timeout=2):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wl = tmp / "wl"
            wl.write_text("\n".join(wl_lines) + "\n")
            log = tmp / "log"
            log.write_text("\n".join(json.dumps(row) for row in events) + "\n")
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log), "--wl", str(wl),
                                   "--timeout", str(timeout)],
                                  capture_output=True, text=True, timeout=15)
        return proc.returncode

    def wl(self):
        return (["TARGET " + json.dumps({"name": "C_GenerateRandom", "dev": [8, 1], "ino": 71})] +
                ["READY pid=123", "CHILD pid=124"])

    def test_all_matched_passes(self):
        events = [gate_event(123, "unknown"), gate_event(124, "watched_no_use"),
                  gate_event(123, "counted")]
        self.assertEqual(self.run_gate(self.wl(), events), 0)

    def test_missing_pid_times_out(self):
        # Static log, no passes: the overall backstop (not the stall,
        # which clocks from the first pass) fails the unmatchable wait.
        events = [gate_event(123, "counted")]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wl = tmp / "wl"
            wl.write_text("\n".join(self.wl()) + "\n")
            log = tmp / "log"
            log.write_text("\n".join(json.dumps(row) for row in events) + "\n")
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log), "--wl", str(wl),
                                   "--timeout", "0.2",
                                   "--overall-timeout", "0.3"],
                                  capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 1)

    def test_wrong_module_ignored(self):
        events = [gate_event(123, "counted", ino=72), gate_event(124, "counted", ino=72)]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wl = tmp / "wl"
            wl.write_text("\n".join(self.wl()) + "\n")
            log = tmp / "log"
            log.write_text("\n".join(json.dumps(row) for row in events) + "\n")
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log), "--wl", str(wl),
                                   "--timeout", "0.2",
                                   "--overall-timeout", "0.3"],
                                  capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 1)

    def test_malformed_lines_skipped(self):
        events = [gate_event(123, "counted"), gate_event(124, "counted")]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wl = tmp / "wl"
            wl.write_text("\n".join(self.wl()) + "\n")
            log = tmp / "log"
            log.write_text("not json\n" + "\n".join(json.dumps(row) for row in events) + "\n")
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log), "--wl", str(wl),
                                   "--timeout", "2"],
                                  capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0)

    def test_missing_wl_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(tmp / "log"),
                                   "--wl", str(tmp / "absent"),
                                   "--timeout", "0.2"],
                                  capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 2)

    def wl_single(self):
        return ["TARGET " + json.dumps({"name": "C_GenerateRandom",
                                        "dev": [8, 1], "ino": 71}),
                "READY pid=123"]

    def run_gate_scripted(self, wl_lines, script, timeout, extra=()):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            args = [sys.executable, "-I", str(GATE),
                    "--event-log", str(tmp / "log"), "--timeout", str(timeout)]
            if wl_lines is not None:
                wl = tmp / "wl"
                wl.write_text("\n".join(wl_lines) + "\n")
                args += ["--wl", str(wl)]
            args += list(extra)
            writer = ScriptedEventLog(tmp / "log", script).start()
            try:
                start = time.monotonic()
                proc = subprocess.run(args, capture_output=True, text=True,
                                      timeout=30)
                elapsed = time.monotonic() - start
            finally:
                writer.stop()
                writer.join()
        return proc.returncode, proc.stderr, elapsed

    def test_slow_but_progressing_match_passes(self):
        # The loaded-runner shape: passes arrive steadily but the
        # qualifying edge lands after the old wall budget. The gate must
        # wait while the product progresses, not fail on wall time.
        script = [(0.0, [gate_started(), gate_pass(1),
                         gate_event(123, "unknown")]),
                  (0.4, [gate_pass(2), gate_event(123, "unknown")]),
                  (0.4, [gate_pass(3), gate_event(123, "unknown")]),
                  (0.4, [gate_pass(4), gate_event(123, "unknown")]),
                  (0.4, [gate_pass(5), gate_event(123, "watched_no_use")])]
        code, err, _ = self.run_gate_scripted(self.wl_single(), script, 1.5)
        self.assertEqual(code, 0)
        self.assertIn("released: all", err)

    def test_progress_then_stall_fails_with_stall_message(self):
        # Passes arrive, then stop without a match: a wedged product
        # must fail on the stall, measured from the last pass.
        script = [(0.0, [gate_started(), gate_pass(1),
                         gate_event(123, "unknown")]),
                  (0.4, [gate_pass(2), gate_event(123, "unknown")]),
                  (0.4, [gate_pass(3), gate_event(123, "unknown")])]
        code, err, _ = self.run_gate_scripted(self.wl_single(), script, 1.0)
        self.assertEqual(code, 1)
        self.assertIn("stalled:", err)
        self.assertIn("unmatched workload edges for pids [123]", err)

    def test_no_passes_waits_for_overall(self):
        # No pass ever arrives (wedged before the first one): the stall
        # clocks from the first pass, so only the overall backstop fails
        # this wait, and it names the overall budget.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wl = tmp / "wl"
            wl.write_text("\n".join(self.wl_single()) + "\n")
            log = tmp / "log"
            log.write_text(json.dumps(gate_started()) + "\n")
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log), "--wl", str(wl),
                                   "--timeout", "0.4",
                                   "--overall-timeout", "1.0"],
                                  capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("overall budget exhausted", proc.stderr)

    def test_overall_backstop_bounds_endless_progress(self):
        # Passes flow forever but no edge ever qualifies: the overall
        # backstop bounds the wait even while progressing.
        script = [(0.0, [gate_started(), gate_pass(1),
                         gate_event(123, "unknown")])]
        script += [(0.2, [gate_pass(seq), gate_event(123, "unknown")])
                   for seq in range(2, 22)]
        code, err, _ = self.run_gate_scripted(
            self.wl_single(), script, 2, ["--overall-timeout", "1.0"])
        self.assertEqual(code, 1)
        self.assertIn("overall budget exhausted", err)
        self.assertIn("unmatched workload edges for pids [123]", err)

    def test_ended_without_match_fails_fast(self):
        # The stream ended with no qualifying edge: no further pass can
        # arrive, so the gate fails at once instead of idling to stall.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wl = tmp / "wl"
            wl.write_text("\n".join(self.wl_single()) + "\n")
            log = tmp / "log"
            events = [gate_started(), gate_pass(1),
                      gate_event(123, "unknown"), gate_ended(2)]
            log.write_text("\n".join(json.dumps(row) for row in events) + "\n")
            start = time.monotonic()
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log), "--wl", str(wl),
                                   "--timeout", "3"],
                                  capture_output=True, text=True, timeout=15)
            elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 1)
        self.assertIn("ended without match", proc.stderr)
        self.assertLess(elapsed, 2.0)

    def test_settle_waits_for_further_passes(self):
        # Settle mode waits for N more passes past the gate start, so a
        # post-LEDGER stop lets the product count on its own cadence.
        script = [(0.3, [gate_pass(11)]), (0.3, [gate_pass(12)])]
        code, err, _ = self.run_gate_scripted(
            None, script, 2, ["--settle-passes", "2"])
        self.assertEqual(code, 0)
        self.assertIn("settled:", err)

    def test_settle_stall_fails(self):
        # Settle mode fails when the further passes stop arriving.
        script = [(0.2, [gate_pass(11)])]
        code, err, _ = self.run_gate_scripted(
            None, script, 0.8, ["--settle-passes", "2"])
        self.assertEqual(code, 1)
        self.assertIn("stalled:", err)

    def test_settle_overall_exhausted_fails(self):
        # Settle mode with no further pass ever arriving: like the
        # release twin, only the overall backstop fails this wait.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            log = tmp / "log"
            log.write_text(json.dumps(gate_started()) + "\n")
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log),
                                   "--settle-passes", "2",
                                   "--timeout", "0.4",
                                   "--overall-timeout", "1.0"],
                                  capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("overall budget exhausted", proc.stderr)

    def test_settle_ended_early_fails_fast(self):
        # The stream ended before the further passes arrived: no pass
        # can follow, so settle fails at once instead of idling.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            log = tmp / "log"
            events = [gate_started(), gate_pass(11), gate_ended(12)]
            log.write_text("\n".join(json.dumps(row) for row in events) + "\n")
            start = time.monotonic()
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log),
                                   "--settle-passes", "2",
                                   "--timeout", "3"],
                                  capture_output=True, text=True, timeout=15)
            elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 1)
        self.assertIn("ended after", proc.stderr)
        self.assertLess(elapsed, 2.0)

    def dead_pid(self):
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        pid = child.pid
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return pid
        self.fail("reaped child pid %d unexpectedly alive" % pid)

    def test_dead_observer_fails_fast(self):
        # The observer crashed without writing `ended`: with its pid
        # passed in, the gate must fail at once with a named reason
        # instead of idling out the long overall backstop.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wl = tmp / "wl"
            wl.write_text("\n".join(self.wl_single()) + "\n")
            log = tmp / "log"
            log.write_text(json.dumps(gate_started()) + "\n")
            start = time.monotonic()
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log), "--wl", str(wl),
                                   "--timeout", "3",
                                   "--overall-timeout", "30",
                                   "--observer-pid", str(self.dead_pid())],
                                  capture_output=True, text=True, timeout=15)
            elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 1)
        self.assertIn("observer exited", proc.stderr)
        self.assertIn("unmatched workload edges for pids [123]", proc.stderr)
        self.assertLess(elapsed, 5.0)

    def test_live_observer_pid_still_releases(self):
        # A live observer pid must not trip the liveness fail-fast:
        # the qualifying edges still release the gate.
        events = [gate_event(123, "counted")]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wl = tmp / "wl"
            wl.write_text("\n".join(self.wl_single()) + "\n")
            log = tmp / "log"
            log.write_text("\n".join(json.dumps(row) for row in events) + "\n")
            proc = subprocess.run([sys.executable, "-I", str(GATE),
                                   "--event-log", str(log), "--wl", str(wl),
                                   "--timeout", "2",
                                   "--observer-pid", str(os.getpid())],
                                  capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0)


def load_gate_module():
    spec = importlib.util.spec_from_file_location("inventory_mt_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InventoryMtEventTailTests(unittest.TestCase):
    def test_torn_record_across_polls_is_buffered(self):
        # A record split across two polls (half-written line at the
        # first read) must be buffered until its newline arrives,
        # not dropped as two malformed lines.
        gate = load_gate_module()
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "log"
            line = json.dumps(gate_pass(1)) + "\n"
            head, tail = line[:len(line) // 2], line[len(line) // 2:]
            log.write_text(head)
            tail_reader = gate.EventTail(str(log))
            self.assertEqual(tail_reader.poll(), [])
            self.assertEqual(tail_reader.passes, 0)
            with open(log, "a", encoding="utf-8") as handle:
                handle.write(tail)
            records = tail_reader.poll()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["kind"], "pass_committed")
            self.assertEqual(tail_reader.passes, 1)


if __name__ == "__main__":
    unittest.main()
