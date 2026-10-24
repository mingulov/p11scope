#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""R2 T0 per-call ledger fixture/oracle foundation twins.

The oracle (scripts/joint-ledger-oracle.py) validates the independent
per-call ledger emitted by tests/fixtures/joint-ledger/per-call-ledger.c:
E17-pattern rows (ready, call{seq,fn,rv,pid,tid,t0,t1}, ack) on a declared
CLOCK_MONOTONIC/ns basis, plus the ledger<->events settlement join where
latency is the JSONL event at_ns minus the ledger END t1.

Healthy and mutation twins run unignored; the live-emission tests build the
tracked live-discovery-provider.c fixture and the ledger emitter with gcc
and validate the real emitted ledger.
"""

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "scripts" / "joint-ledger-oracle.py"
FIXTURE_SRC = ROOT / "tests" / "fixtures" / "joint-ledger" / "per-call-ledger.c"
PROVIDER_SRC = ROOT / "tests" / "fixtures" / "live-discovery-provider.c"

try:
    _SPEC = importlib.util.spec_from_file_location(
        "joint_ledger_oracle", ORACLE_PATH
    )
    ORACLE = importlib.util.module_from_spec(_SPEC)
    _SPEC.loader.exec_module(ORACLE)
except OSError:
    ORACLE = None


def require_oracle(test):
    """Fail naming the missing production file (RED) or return the oracle."""
    if ORACLE is None:
        test.fail(f"oracle missing: {ORACLE_PATH} (T0 implementation not present)")
    return ORACLE


def healthy_rows(calls=25, pid=4242, tid=4242, rv=0):
    """Canned E17-pattern ledger: ready, N calls, ack; t0<=t1 in-window."""
    rows = [{"kind": "ready", "pid": pid, "tid": tid, "t": 1_000,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    tick = 1_000
    for seq in range(1, calls + 1):
        start = tick + 10
        end = start + 5
        rows.append({"kind": "call", "seq": seq, "fn": "table[4]",
                     "rv": rv, "pid": pid, "tid": tid,
                     "t0": start, "t1": end})
        tick = end
    rows.append({"kind": "ack", "issued": calls, "t": tick + 10})
    return rows


def healthy_events(rows, delay_ns=1_000):
    """One settled event per call seq, latency delay_ns after END t1."""
    return [{"at_ns": row["t1"] + delay_ns, "ledger_seq": row["seq"]}
            for row in rows if row["kind"] == "call"]


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


class LedgerOracleTwins(unittest.TestCase):
    def test_healthy_ledger_passes(self):
        oracle = require_oracle(self)
        summary = oracle.validate_ledger(healthy_rows())
        self.assertEqual(summary["issued"], 25)
        self.assertEqual(summary["calls"], 25)

    def test_healthy_ledger_passes_through_cli(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            write_jsonl(ledger, healthy_rows())
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["issued"], 25)

    def test_mutation_dropped_call_rejected(self):
        oracle = require_oracle(self)
        rows = [row for row in healthy_rows() if row.get("seq") != 7]
        with self.assertRaisesRegex(oracle.LedgerError, "issued"):
            oracle.validate_ledger(rows)

    def test_mutation_extra_call_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[-1] = {"kind": "ack", "issued": 24, "t": rows[-1]["t"]}
        with self.assertRaisesRegex(oracle.LedgerError, "issued"):
            oracle.validate_ledger(rows)

    def test_mutation_reversed_timestamps_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[3]["t0"], rows[3]["t1"] = rows[3]["t1"], rows[3]["t0"]
        with self.assertRaisesRegex(oracle.LedgerError, "t1"):
            oracle.validate_ledger(rows)

    def test_mutation_foreign_pid_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[5]["pid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "pid"):
            oracle.validate_ledger(rows)

    def test_mutation_non_integer_rv_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[2]["rv"] = "CKR_OK"
        with self.assertRaisesRegex(oracle.LedgerError, "rv"):
            oracle.validate_ledger(rows)

    def test_mutation_duplicate_seq_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[4]["seq"] = rows[3]["seq"]
        with self.assertRaisesRegex(oracle.LedgerError, "seq"):
            oracle.validate_ledger(rows)

    def test_mutation_call_outside_window_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[1]["t0"] = rows[0]["t"] - 1
        rows[1]["t1"] = rows[0]["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "window"):
            oracle.validate_ledger(rows)

    def test_settlement_join_healthy(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        events = healthy_events(rows, delay_ns=1_000)
        result = oracle.compare_settlement(
            rows, events, p99_ns=250_000_000, min_rate_per_s=1)
        self.assertEqual(result["settled"], 25)
        self.assertEqual(result["loss"], 0)
        self.assertEqual(result["p99_ns"], 1_000)

    def test_settlement_join_loss_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        events = [row for row in healthy_events(rows) if row["ledger_seq"] != 9]
        with self.assertRaisesRegex(oracle.LedgerError, "loss"):
            oracle.compare_settlement(
                rows, events, p99_ns=250_000_000, min_rate_per_s=1)

    def test_settlement_join_p99_over_budget_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        events = healthy_events(rows, delay_ns=1_000)
        events[0]["at_ns"] += 1_000_000_000
        with self.assertRaisesRegex(oracle.LedgerError, "p99"):
            oracle.compare_settlement(
                rows, events, p99_ns=250_000_000, min_rate_per_s=1)

    def test_settlement_join_rate_shortfall_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        events = healthy_events(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "rate"):
            oracle.compare_settlement(
                rows, events, p99_ns=250_000_000, min_rate_per_s=10**18)


class LedgerEmissionTests(unittest.TestCase):
    def build_pair(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (T0 implementation not present)")
        provider = Path(tmp) / "provider.so"
        fixture = Path(tmp) / "per-call-ledger"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-fPIC", "-DP11SCOPE_EXPORT_TABLES=1", "-shared", "-Wl,-z,defs",
             "-o", str(provider), str(PROVIDER_SRC)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(FIXTURE_SRC), "-ldl", "-o", str(fixture)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return provider, fixture

    def test_fixture_emits_valid_ledger(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            child = subprocess.Popen(
                [str(fixture), str(provider), "4", "25", str(ledger)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = child.communicate(timeout=60)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertIn(f"READY pid={child.pid}", stdout)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual(summary["issued"], 25)
            calls = [row for row in rows if row["kind"] == "call"]
            self.assertEqual(len(calls), 25)
            for row in calls:
                self.assertEqual(row["rv"], 0)
                self.assertEqual((row["pid"], row["tid"]), (child.pid, child.pid))

    def test_fixture_gated_run_completes(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            gate = Path(tmp) / "GO"
            gate.touch()
            completed = subprocess.run(
                [str(fixture), str(provider), "4", "5", str(ledger), str(gate)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 5)

    def test_fixture_refuses_bad_argv(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture)], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            completed = subprocess.run(
                [str(fixture), str(provider), "104", "5", str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(ledger.exists())


if __name__ == "__main__":
    unittest.main()
