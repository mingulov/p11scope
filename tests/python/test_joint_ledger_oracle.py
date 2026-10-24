#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-call ledger fixture/oracle foundation twins.

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
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
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
        test.fail(f"oracle missing: {ORACLE_PATH} (implementation not present)")
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


COUNTING_PROVIDER = """/* Test-only counting stub: one-pointer-arg entries plus the marker export. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} CountTable;
int P11ScopeSlot68;
static unsigned long count_calls(void **out) {
    (void)out;
    const char *path = getenv("P11SCOPE_LEDGER_COUNT_PATH");
    if (path != NULL) {
        FILE *sink = fopen(path, "a");
        if (sink != NULL) {
            fputc('.', sink);
            fclose(sink);
        }
    }
    return 0;
}
static unsigned long count_noop(void **out) {
    (void)out;
    return 0;
}
static CountTable count_table;
__attribute__((constructor)) static void count_init(void) {
    count_table.major = 3;
    count_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        count_table.functions[i] = (void *)count_noop;
    }
    count_table.functions[4] = (void *)count_calls;
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &count_table;
    return 0;
}
"""

REFUSAL_PROVIDER = """/* Test-only non-stub provider: no marker export, so the stub-only emitter refuses it. */
#define _GNU_SOURCE
#include <stddef.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} PlainTable;
static unsigned long plain_noop(void **out) {
    (void)out;
    return 0;
}
static PlainTable plain_table;
__attribute__((constructor)) static void plain_init(void) {
    plain_table.major = 2;
    plain_table.minor = 40;
    for (int i = 0; i < 104; i++) {
        plain_table.functions[i] = (void *)plain_noop;
    }
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &plain_table;
    return 0;
}
"""

SLOW_PROVIDER = """/* Test-only slow stub: the entry sleeps, so t1-t0 proves post-call stamping. */
#define _GNU_SOURCE
#include <stddef.h>
#include <time.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} SlowTable;
int P11ScopeSlot68;
static unsigned long slow_call(void **out) {
    (void)out;
    struct timespec delay = {0, 5000000};
    while (nanosleep(&delay, &delay) != 0) {
    }
    return 0;
}
static unsigned long slow_noop(void **out) {
    (void)out;
    return 0;
}
static SlowTable slow_table;
__attribute__((constructor)) static void slow_init(void) {
    slow_table.major = 3;
    slow_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        slow_table.functions[i] = (void *)slow_noop;
    }
    slow_table.functions[4] = (void *)slow_call;
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &slow_table;
    return 0;
}
"""


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

    def test_mutation_t1_after_ack_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[2]["t0"] = rows[-1]["t"]
        rows[2]["t1"] = rows[-1]["t"] + 1
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

    def test_mutation_duplicate_event_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        events = healthy_events(rows)
        events.append(dict(events[0]))
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate event"):
            oracle.compare_settlement(rows, events)

    def test_mutation_unknown_event_seq_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        events = healthy_events(rows)
        events[0]["ledger_seq"] = 999
        with self.assertRaisesRegex(oracle.LedgerError, "unknown seq"):
            oracle.compare_settlement(rows, events)

    def test_mutation_negative_latency_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        events = healthy_events(rows)
        calls = [row for row in rows if row["kind"] == "call"]
        events[0]["at_ns"] = calls[0]["t1"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "precedes END t1"):
            oracle.compare_settlement(rows, events)

    def test_mutation_tid_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[5]["tid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "tid"):
            oracle.validate_ledger(rows)

    def test_mutation_clock_basis_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[0]["clock"] = "CLOCK_REALTIME"
        with self.assertRaisesRegex(oracle.LedgerError, "clock basis"):
            oracle.validate_ledger(rows)
        rows = healthy_rows()
        rows[0]["unit"] = "ms"
        with self.assertRaisesRegex(oracle.LedgerError, "clock unit"):
            oracle.validate_ledger(rows)

    def test_mutation_non_call_row_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[3] = {"kind": "gap", "index": 0}
        with self.assertRaisesRegex(oracle.LedgerError, "non-call"):
            oracle.validate_ledger(rows)

    def test_mutation_ack_before_ready_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[-1]["t"] = rows[0]["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "ack precedes"):
            oracle.validate_ledger(rows)

    def test_mutation_non_object_frame_row_refused(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[0] = ["ready"]
        with self.assertRaisesRegex(oracle.LedgerError, "first row must be ready"):
            oracle.validate_ledger(rows)
        rows = healthy_rows()
        rows[-1] = ["ack"]
        with self.assertRaisesRegex(oracle.LedgerError, "last row must be ack"):
            oracle.validate_ledger(rows)

    def test_mutation_duplicate_json_key_rejected(self):
        oracle = require_oracle(self)
        line = ('{"kind": "ready", "pid": 1, "tid": 1, "t": 2,'
                ' "clock": "CLOCK_MONOTONIC", "unit": "ns", "pid": 2}\n')
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate JSON key"):
            oracle.read_ledger(io.StringIO(line))

    def test_mutation_fn_label_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[2]["fn"] = "table[4];id"
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows)
        rows = healthy_rows()
        rows[2]["fn"] = ""
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows)

    def test_mutation_rv_out_of_range_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_rows()
        rows[2]["rv"] = 2 ** 64
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_rows()
        rows[2]["rv"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_line_byte_limit_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "byte limit"):
            oracle.read_ledger(io.StringIO("x" * 4097 + "\n"))

    def test_boundary_count_200000_passes(self):
        oracle = require_oracle(self)
        rows = healthy_rows(calls=200000)
        text = "\n".join(json.dumps(row) for row in rows) + "\n"
        with io.StringIO(text) as stream:
            read = oracle.read_ledger(stream)
        summary = oracle.validate_ledger(read)
        self.assertEqual(summary["issued"], 200000)
        self.assertEqual(summary["calls"], 200000)

    def test_mutation_row_limit_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "row limit"):
            oracle.read_ledger(io.StringIO("{}\n" * 200003))

    def test_cli_refusal_reports_p99_numbers(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            events_path = Path(tmp) / "events.jsonl"
            write_jsonl(ledger, healthy_rows())
            write_jsonl(events_path, healthy_events(healthy_rows()))
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger), str(events_path),
                 "--p99-ns", "500"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertRegex(completed.stderr,
                             r"ledger refused: p99 1000 exceeds budget 500")

    def test_cli_refusal_reports_reason(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            rows = healthy_rows()
            rows[-1] = {"kind": "ack", "issued": 24, "t": rows[-1]["t"]}
            write_jsonl(ledger, rows)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("issued 24 disagrees with 25 call rows", completed.stderr)

    def test_cli_string_payload_not_echoed(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            rows = healthy_rows()
            rows[5]["pid"] = "PIN=1234-secret"
            write_jsonl(ledger, rows)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("ledger refused: pid string disagrees with ready pid",
                          completed.stderr)
            self.assertNotIn("PIN=1234-secret", completed.stderr)

    def test_cli_non_object_first_row_refused_without_traceback(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            rows = healthy_rows()
            rows[0] = ["ready"]
            write_jsonl(ledger, rows)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("ledger refused: first row must be ready", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)


class LedgerEmissionTests(unittest.TestCase):
    def build_pair(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
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

    def build_fixture(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
        fixture = Path(tmp) / "per-call-ledger"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(FIXTURE_SRC), "-ldl", "-o", str(fixture)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return fixture

    def build_inline_provider(self, tmp, name, source):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        provider_c = Path(tmp) / (name + ".c")
        provider = Path(tmp) / (name + ".so")
        provider_c.write_text(source, encoding="utf-8")
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-fPIC", "-shared", "-Wl,-z,defs",
             "-o", str(provider), str(provider_c)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return provider

    def test_fixture_calls_provider_for_every_row(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "count", COUNTING_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            witness = Path(tmp) / "count"
            env = dict(os.environ, P11SCOPE_LEDGER_COUNT_PATH=str(witness))
            completed = subprocess.run(
                [str(fixture), str(provider), "4", "5", str(ledger)],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 5)
            self.assertEqual(witness.stat().st_size, 5)

    def test_fixture_slow_provider_call_duration(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "slow", SLOW_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), "4", "5", str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual(summary["issued"], 5)
            for row in rows:
                if row.get("kind") != "call":
                    continue
                self.assertGreaterEqual(row["t1"] - row["t0"], 1_000_000)

    def test_fixture_waits_for_go(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            gate = Path(tmp) / "GO"
            child = subprocess.Popen(
                [str(fixture), str(provider), "4", "5", str(ledger), str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stderr = ""
            try:
                line = child.stdout.readline()
                self.assertIn(f"READY pid={child.pid}", line)
                time.sleep(0.5)
                self.assertFalse(ledger.exists())
                gate.touch()
                _, stderr = child.communicate(timeout=60)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 5)

    def test_fixture_refuses_nonstub_provider(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "plain", REFUSAL_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), "4", "5", str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("stub", completed.stderr)
            self.assertFalse(ledger.exists())

    def test_fixture_stop_flag_interrupts_wait(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            gate = Path(tmp) / "GO"
            child = subprocess.Popen(
                [str(fixture), str(provider), "4", "5", str(ledger), str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stderr = ""
            try:
                line = child.stdout.readline()
                self.assertIn(f"READY pid={child.pid}", line)
                self.assertFalse(ledger.exists())
                child.terminate()
                _, stderr = child.communicate(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)
            self.assertEqual(child.returncode, 2)
            self.assertIn("gate", stderr)
            self.assertFalse(ledger.exists())


if __name__ == "__main__":
    unittest.main()
