# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Inventory MT-exact oracle controls; every assertion has a failing twin."""

import copy
import json
import subprocess
import sys
import tempfile
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
        events = [gate_event(123, "counted")]
        self.assertEqual(self.run_gate(self.wl(), events, timeout=0.2), 1)

    def test_wrong_module_ignored(self):
        events = [gate_event(123, "counted", ino=72), gate_event(124, "counted", ino=72)]
        self.assertEqual(self.run_gate(self.wl(), events, timeout=0.2), 1)

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


if __name__ == "__main__":
    unittest.main()
