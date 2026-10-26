#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""S1 throughput harness twins: compare script and gen-calls driver.

The harness (R2 T1 narrowed to the S1 path by R-53/N3) lets the
controller prove sustained PKCS#11 throughput on the plain semantic
path: the driver (tests/fixtures/joint-throughput/gen-calls.c) issues
paced SoftHSM digest calls behind a READY/GO gate and writes one
T0-shaped per-call ledger per worker thread; the comparison script
(scripts/s1-throughput-compare.py) checks that ledger against the
observer's --event-log and inventory JSON for a --pid-scoped run.

Gates (all must pass): every full 1 s window aligned to ready.t holds
at least --min-rate (default 10,000) ledgered calls (a burst followed
by idle fails; the partial tail is reported, never gated); per-function
API results equal the ledger (exact totals plus per-mechanism calls /
errors plus function and return-code set equality); zero event loss
(ring_loss == 0, unrouted S1 returns == 0, a proven full drain, no loss
gap or lossy coverage, a complete event stream); and the S1-active gate
(object_observations unavailable with reason journal_unavailable, the
semantic lane past disabled). S1 publish latency (coarse per-call
edge-count publication delay) is recorded as p50/p99 with its sample
count, never gated.

Healthy and mutation twins run unignored; the driver tests build the
tracked gen-calls.c fixture with gcc and drive a test-only in-suite
stub provider (real PKCS#11 entry signatures, counting-free immediate
OK returns), so they need no SoftHSM install.
"""

import importlib.util
import json
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
S1_PATH = ROOT / "scripts" / "s1-throughput-compare.py"
T0_PATH = ROOT / "scripts" / "joint-ledger-oracle.py"
DRIVER_SRC = ROOT / "tests" / "fixtures" / "joint-throughput" / "gen-calls.c"


def _load(name, path):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except OSError:
        return None


S1 = _load("s1_throughput_compare", S1_PATH)
T0 = _load("joint_ledger_oracle", T0_PATH)


def require_s1(test):
    """Fail naming the missing script (RED) or return the module."""
    if S1 is None:
        test.fail(f"compare script missing: {S1_PATH} (implementation not present)")
    return S1


def require_t0(test):
    """Fail naming the missing T0 core or return the module."""
    if T0 is None:
        test.fail(f"T0 oracle missing: {T0_PATH} (foundation not present)")
    return T0


PID = 4242
R0 = 10_000_000_000
FN_INIT = "C_DigestInit"
FN_DO = "C_Digest"
FNS = (FN_INIT, FN_DO)
MECH_SHA256 = 0x250
MECH_NAME = "CKM_SHA_256"
FULL_RATE = 10000


def uniform_ledger(count, per_s, pid=PID, tid=PID, start_ns=R0,
                   fns=FNS, rv=0, ack_ns=None):
    """Ledger with `count` calls evenly spaced at `per_s`/s from start_ns.

    Call t1 stamps pack exactly per_s per 1 s window; t0 trails t1 by
    500 ns; functions alternate through `fns` starting with fns[0].
    """
    rows = [{"kind": "ready", "pid": pid, "tid": tid, "t": start_ns,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    step = 1_000_000_000 // per_s
    last = start_ns
    for seq in range(1, count + 1):
        end = start_ns + (seq - 1) * step + 1000
        rows.append({"kind": "call", "seq": seq, "fn": fns[(seq - 1) % len(fns)],
                     "rv": rv, "pid": pid, "tid": tid,
                     "t0": end - 500, "t1": end})
        last = end
    rows.append({"kind": "ack", "issued": count,
                 "t": last + 500 if ack_ns is None else ack_ns})
    return rows


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def write_json(path, doc):
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(doc, stream)


def mechanism_row(calls, errors=0, fns=FNS, rvs=(0,)):
    return {"mechanism": MECH_SHA256, "mechanism_hex": hex(MECH_SHA256),
            "name": MECH_NAME, "operations": ["digest"],
            "calls": calls, "errors": errors,
            "last_seen_ns": R0 + 2_000_000_000,
            "evidence": {
                "functions": sorted(fns),
                "returns": [{"rv": rv, "rv_hex": hex(rv),
                             "name": "CKR_OK" if rv == 0 else None}
                            for rv in sorted(rvs)],
                "truncated": False}}


def driver_edge(count, errors=0, fns=FNS, rvs=(0,), caller="c0", module="m0",
                coverage_state="counted", lossy=False, operations_calls=None,
                mechanisms=True):
    return {
        "caller": caller, "module": module,
        "mapping": {"state": "mapped", "evidence": "deep_scan",
                    "reason": None, "first_seen_ns": R0,
                    "last_seen_ns": R0 + 2_000_000_000, "interruptions": 0},
        "entries": {"count": count, "saturated": False, "cap": 2 ** 63 - 1,
                    "first_seen_ns": R0, "last_seen_ns": R0 + 2_000_000_000,
                    "in_flight": False, "observation": "observed",
                    "coverage": {"state": coverage_state, "since_ns": R0,
                                 "until_ns": None, "first_ns": None,
                                 "lossy": lossy if coverage_state == "counted" else None,
                                 "reason": None, "detail": None}},
        "semantics": "observed",
        "mechanisms": ([mechanism_row(count, errors, fns, rvs)]
                       if mechanisms else None),
        "operations": {"calls": count if operations_calls is None else operations_calls,
                       "started": count // 2, "completed": count // 2,
                       "cancelled": 0, "failed": 0, "unknown": 0, "orphans": 0,
                       "dropped": 0, "last_seen_ns": R0 + 2_000_000_000,
                       "active": [],
                       "evidence": {"state_reconciliations": 0,
                                    "session_cancel_ambiguities": 0,
                                    "session_cancel_unknown_flags": 0,
                                    "operation_state_imports": 0,
                                    "auth_state_ambiguities": 0,
                                    "semantic_capture_failures": 0,
                                    "async_duplicates": 0,
                                    "async_evictions": 0,
                                    "unmatched_closes": 0}},
    }


def semantic_row(edge, api_count, lossy=False):
    return {"caller": edge["caller"], "module": edge["module"],
            "instance": "i0",
            "entries": {"unit": "api_entries", "count": None,
                        "observation": "unavailable"},
            "api_returns": {"unit": "api_returns", "count": api_count,
                            "saturated": False, "historical_only_returns": 0},
            "semantics": edge["semantics"],
            "mechanisms": edge["mechanisms"],
            "operations": edge["operations"],
            "coverage": {"lossy": lossy, "reasons": []}}


def inventory_doc(edge, sem_rows, pid=PID, ring_loss=0, unrouted=0,
                  quiescence="quiesced", drain=True, lane_status="stopped",
                  obs_status="unavailable", obs_reason="journal_unavailable",
                  gaps=(), suppressed=0):
    return {
        "callers": [{"id": "c0", "pid": pid}],
        "modules": [{"id": "m0"}],
        "edges": [edge],
        "instances": [{"id": "i0", "caller": "c0", "module": "m0"}],
        "semantic_edges": list(sem_rows),
        "object_observations": {
            "version": 1, "revision": 0, "status": obs_status,
            "reason": obs_reason, "sessions": [], "objects": [],
            "key_operations": [], "unknown_key_operations": [],
            "gaps": {"rows": [], "suppressed": 0},
            "budgets": {"key_rows": {"limit": 65536, "occupied": 0, "refused": 0},
                        "object_rows": {"limit": 65536, "occupied": 0, "refused": 0},
                        "unknown_rows": {"occupied": 0}, "encoded_bytes": 0,
                        "allocation_refused": False, "refusal_reason": "none"}},
        "observation": {
            "lane": "native",
            "lifecycle": {"records": 3, "ring_loss": ring_loss,
                          "malformed": 0, "failed_quanta": 0,
                          "recovery_rescans": 0},
            "semantic_capture": {"status": lane_status,
                                 "admitted_endpoints": 2,
                                 "refused_endpoints": 0,
                                 "continuity_cuts": 0,
                                 "unrouted_returns": unrouted,
                                 "stop_quiescence": quiescence,
                                 "final_drain": drain}},
        "gaps": [{"caller": None, "module": None, "pid": None,
                  "subject": subject, "reason": reason, "budget": None,
                  "repeats": 1} for subject, reason in gaps],
        "budgets": {"retained_history": {"limit": 1024, "retained": 0,
                                         "suppressed": suppressed}},
    }


def event_envelope(seq, at_ns, kind, event):
    return {"schema": "p11scope/inventory-events/v1", "seq": seq,
            "at_ns": at_ns, "kind": kind, "event": event}


def events_doc(edge_final, series, pid=PID, scope=None,
               basis="CLOCK_MONOTONIC", unit="ns", started_ns=R0,
               unretained=0, gaps_suppressed=0, gap_events=(),
               evicted=False, with_ended=True):
    """Event log: started, one edge_observed per series point, ended."""
    rows = [event_envelope(0, started_ns, "started",
                           {"scope": f"pid:{pid}" if scope is None else scope,
                            "clock": {"basis": basis, "unit": unit},
                            "started_ns": started_ns, "limits": {}})]
    seq = 1
    for at_ns, count in series:
        edge = dict(edge_final)
        edge["entries"] = dict(edge_final["entries"])
        edge["entries"]["count"] = count
        record = dict(edge)
        record["presence"] = "mapped"
        record["capture"] = "armed"
        record["activity"] = "recently observed"
        record["identity_context"] = {"version": 1}
        rows.append(event_envelope(seq, at_ns, "edge_observed", record))
        seq += 1
    for index, (subject, reason) in enumerate(gap_events):
        rows.append(event_envelope(
            seq, started_ns + 1_000, "gap_recorded",
            {"index": index, "caller": None, "module": None, "pid": None,
             "subject": subject, "reason": reason, "budget": None}))
        seq += 1
    if evicted:
        rows.append(event_envelope(
            seq, started_ns + 2_000, "retention_evicted",
            {"evicted_file": "events.jsonl.1", "evicted_events": 4,
             "evicted_bytes": 400, "covered_events": 0,
             "covered_bytes": 0, "reason": "retention"}))
        seq += 1
    if with_ended:
        rows.append(event_envelope(
            seq, started_ns + 3_000_000_000, "ended",
            {"ended_ns": started_ns + 3_000_000_000, "passes": 3,
             "budgets": {}, "gaps_suppressed": gaps_suppressed,
             "stream": {"rotations": 0, "evicted_events": 0,
                        "evicted_bytes": 0},
             "edge_events": len(series), "edges_unretained": unretained,
             "instance_events": 0, "instances_unretained": 0,
             "semantic_edge_events": 0, "semantic_edges_unretained": 0,
             "key_operation_events": 0, "key_operations_unretained": 0}))
    return rows


def healthy_triple(workdir, count=20000, per_s=FULL_RATE, pid=PID,
                   latency_step_ns=1_000_000, ack_ns=None,
                   **inventory_kwargs):
    """Write a fully passing ledger + events + inventory triple."""
    ledger = uniform_ledger(count, per_s, pid=pid, ack_ns=ack_ns)
    last_t1 = max(row["t1"] for row in ledger if row["kind"] == "call")
    edge = driver_edge(count)
    sem = semantic_row(edge, count)
    inventory = inventory_doc(edge, [sem], pid=pid, **inventory_kwargs)
    mid = count // 2
    series = [(last_t1 + latency_step_ns, mid),
              (last_t1 + 2 * latency_step_ns, count)]
    events = events_doc(edge, series, pid=pid)
    ledger_path = workdir / "ledger.jsonl"
    events_path = workdir / "events.jsonl"
    inventory_path = workdir / "inventory.json"
    write_jsonl(ledger_path, ledger)
    write_jsonl(events_path, events)
    write_json(inventory_path, inventory)
    return ledger_path, events_path, inventory_path


def rewrite_events_for_edge(workdir, edge, last_t1, pid=PID):
    """Rebuild the events file so its records embed the (mutated) edge.

    Mutation twins change the snapshot edge; without this the
    stream/snapshot divergence check would fire before the intended
    gate. The final record count follows the edge's entries.count.
    """
    final = edge["entries"]["count"]
    series = [(last_t1 + 1_000_000, final // 2),
              (last_t1 + 2_000_000, final)]
    write_jsonl(workdir / "events.jsonl", events_doc(edge, series, pid=pid))


def ledger_last_t1(ledger_path):
    with open(ledger_path, encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    return max(row["t1"] for row in rows if row["kind"] == "call")


class HealthyTwin(unittest.TestCase):
    def test_healthy_10k_passes_with_recorded_windows_and_latency(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-healthy-") as tmp:
            workdir = Path(tmp)
            ledger, events, inventory = healthy_triple(
                workdir, ack_ns=R0 + 2_000_000_000 + 500)
            result = s1.compare([str(ledger)], [str(events)], str(inventory),
                                FULL_RATE)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["issued"], 20000)
            self.assertEqual(len(result["windows"]), 2)
            self.assertTrue(all(window["count"] == 10000
                                for window in result["windows"]),
                            result["windows"])
            self.assertEqual(result["tail"]["count"], 0)
            latency = result["latency"]
            self.assertEqual(latency["samples"], 20000)
            self.assertGreater(latency["p50_ns"], 0)
            self.assertGreaterEqual(latency["p99_ns"], latency["p50_ns"])

    def test_healthy_small_baseline_passes(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-small-") as tmp:
            workdir = Path(tmp)
            ledger, events, inventory = healthy_triple(
                workdir, count=25, per_s=21)
            result = s1.compare([str(ledger)], [str(events)], str(inventory),
                                10)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["issued"], 25)
            self.assertEqual(len(result["windows"]), 1)


class RateGate(unittest.TestCase):
    def run_case(self, ledger_rows, min_rate=FULL_RATE):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-rate-") as tmp:
            workdir = Path(tmp)
            count = sum(1 for row in ledger_rows if row["kind"] == "call")
            last_t1 = max(row["t1"] for row in ledger_rows
                          if row["kind"] == "call")
            edge = driver_edge(count)
            sem = semantic_row(edge, count)
            ledger_path = workdir / "ledger.jsonl"
            events_path = workdir / "events.jsonl"
            inventory_path = workdir / "inventory.json"
            write_jsonl(ledger_path, ledger_rows)
            write_jsonl(events_path, events_doc(
                edge, [(last_t1 + 1_000_000, count)]))
            write_json(inventory_path, inventory_doc(edge, [sem]))
            return s1.compare([str(ledger_path)], [str(events_path)],
                              str(inventory_path), min_rate)

    def test_one_full_window_under_10k_fails(self):
        ledger = uniform_ledger(19999, FULL_RATE,
                                ack_ns=R0 + 2_000_000_000 + 500)
        with self.assertRaises(ValueError) as ctx:
            self.run_case(ledger)
        self.assertIn("below minimum", str(ctx.exception))

    def test_burst_then_idle_fails(self):
        ledger = uniform_ledger(10000, FULL_RATE,
                                ack_ns=R0 + 2_000_000_000 + 500)
        with self.assertRaises(ValueError) as ctx:
            self.run_case(ledger)
        self.assertIn("below minimum", str(ctx.exception))

    def test_partial_tail_never_fails(self):
        ledger = uniform_ledger(10003, FULL_RATE, ack_ns=R0 + 1_000_201_500)
        result = self.run_case(ledger)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(len(result["windows"]), 1)
        self.assertEqual(result["tail"]["count"], 3)

    def test_no_full_window_fails(self):
        ledger = uniform_ledger(5000, 20000, ack_ns=R0 + 500_000_000)
        with self.assertRaises(ValueError) as ctx:
            self.run_case(ledger)
        self.assertIn("no full 1 s window", str(ctx.exception))

    def test_empty_run_fails(self):
        s1 = require_s1(self)
        ledger = [{"kind": "ready", "pid": PID, "tid": PID, "t": R0,
                   "clock": "CLOCK_MONOTONIC", "unit": "ns"},
                  {"kind": "ack", "issued": 0, "t": R0 + 2_000_000_000}]
        with tempfile.TemporaryDirectory(prefix="s1tp-empty-") as tmp:
            workdir = Path(tmp)
            edge = driver_edge(0)
            ledger_path = workdir / "ledger.jsonl"
            events_path = workdir / "events.jsonl"
            inventory_path = workdir / "inventory.json"
            write_jsonl(ledger_path, ledger)
            write_jsonl(events_path, events_doc(edge, []))
            write_json(inventory_path,
                       inventory_doc(edge, [semantic_row(edge, 0)]))
            with self.assertRaises(ValueError) as ctx:
                s1.compare([str(ledger_path)], [str(events_path)],
                           str(inventory_path), 0)
            self.assertIn("no calls", str(ctx.exception))

    def test_min_rate_zero_records_windows_without_gating(self):
        ledger = uniform_ledger(25, 21)
        result = self.run_case(ledger, min_rate=0)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(len(result["windows"]), 1)
        self.assertEqual(result["windows"][0]["count"], 21)

    def test_two_thread_ledgers_merge(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-merge-") as tmp:
            workdir = Path(tmp)
            first = uniform_ledger(600, 1000, tid=1111, start_ns=R0)
            second = uniform_ledger(600, 1000, tid=2222,
                                    start_ns=R0 + 600_000_000)
            first_path = workdir / "ledger.t0.jsonl"
            second_path = workdir / "ledger.t1.jsonl"
            write_jsonl(first_path, first)
            write_jsonl(second_path, second)
            edge = driver_edge(1200)
            sem = semantic_row(edge, 1200)
            events_path = workdir / "events.jsonl"
            inventory_path = workdir / "inventory.json"
            write_jsonl(events_path, events_doc(
                edge, [(R0 + 2_000_000_000, 1200)]))
            write_json(inventory_path, inventory_doc(edge, [sem]))
            result = s1.compare([str(first_path), str(second_path)],
                                [str(events_path)], str(inventory_path), 900)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["issued"], 1200)
            self.assertEqual(result["ledgers"], 2)

    def test_mixed_pid_ledgers_fail(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-pid-") as tmp:
            workdir = Path(tmp)
            first_path = workdir / "ledger.t0.jsonl"
            second_path = workdir / "ledger.t1.jsonl"
            write_jsonl(first_path, uniform_ledger(25, 21, pid=PID))
            write_jsonl(second_path, uniform_ledger(25, 21, pid=PID + 1))
            edge = driver_edge(50)
            events_path = workdir / "events.jsonl"
            inventory_path = workdir / "inventory.json"
            write_jsonl(events_path, events_doc(edge, []))
            write_json(inventory_path, inventory_doc(edge, []))
            with self.assertRaises(ValueError) as ctx:
                s1.compare([str(first_path), str(second_path)],
                           [str(events_path)], str(inventory_path), 10)
            self.assertIn("disagrees", str(ctx.exception))

    def test_duplicate_ledger_path_fails(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-dup-") as tmp:
            workdir = Path(tmp)
            ledger, events, inventory = healthy_triple(
                workdir, count=25, per_s=21)
            with self.assertRaises(ValueError) as ctx:
                s1.compare([str(ledger), str(ledger)], [str(events)],
                           str(inventory), 10)
            self.assertIn("duplicate", str(ctx.exception))


class ConservationGate(unittest.TestCase):
    """Small triples (25 calls, --min-rate 10) with one observed field off."""

    def run_mutation(self, mutate):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-cons-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21)
            with open(inventory_path, encoding="utf-8") as stream:
                inventory = json.load(stream)
            mutate(inventory)
            write_json(inventory_path, inventory)
            if inventory["edges"]:
                rewrite_events_for_edge(workdir, inventory["edges"][0],
                                        ledger_last_t1(ledger_path))
            return s1.compare([str(ledger_path)], [str(events_path)],
                              str(inventory_path), 10)

    def test_one_call_missing_for_a_function_fails(self):
        def mutate(inventory):
            inventory["edges"][0]["entries"]["count"] = 24
            inventory["edges"][0]["mechanisms"][0]["calls"] = 24
            inventory["semantic_edges"][0]["mechanisms"][0]["calls"] = 24
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("entries.count 24 != issued 25", str(ctx.exception))

    def test_wrong_return_code_count_fails(self):
        def mutate(inventory):
            inventory["edges"][0]["mechanisms"][0]["errors"] = 1
            inventory["semantic_edges"][0]["mechanisms"][0]["errors"] = 1
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("errors", str(ctx.exception))

    def test_operations_calls_short_fails(self):
        def mutate(inventory):
            inventory["edges"][0]["operations"]["calls"] = 24
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("operations.calls 24 != issued 25", str(ctx.exception))

    def test_api_returns_short_fails(self):
        def mutate(inventory):
            inventory["semantic_edges"][0]["api_returns"]["count"] = 24
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("api_returns 24 != issued 25", str(ctx.exception))

    def test_phantom_function_fails(self):
        def mutate(inventory):
            row = inventory["edges"][0]["mechanisms"][0]
            row["evidence"]["functions"].append("C_Phantom")
            row["evidence"]["functions"].sort()
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("absent from ledger", str(ctx.exception))

    def test_unobserved_function_fails(self):
        def mutate(inventory):
            row = inventory["edges"][0]["mechanisms"][0]
            row["evidence"]["functions"] = [FN_INIT]
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("missing from observed evidence", str(ctx.exception))

    def test_phantom_return_code_fails(self):
        def mutate(inventory):
            row = inventory["edges"][0]["mechanisms"][0]
            row["evidence"]["returns"].append(
                {"rv": 1, "rv_hex": "0x1", "name": None})
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("absent from ledger", str(ctx.exception))

    def test_missing_mechanism_row_fails(self):
        def mutate(inventory):
            inventory["edges"][0]["mechanisms"] = None
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("mechanism", str(ctx.exception))

    def test_no_driver_edge_fails(self):
        def mutate(inventory):
            inventory["edges"] = []
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("0 edges", str(ctx.exception))

    def test_no_semantic_rows_fails(self):
        def mutate(inventory):
            inventory["semantic_edges"] = []
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("semantic_edges", str(ctx.exception))

    def test_scan_lane_fails(self):
        def mutate(inventory):
            inventory["observation"]["lane"] = "scan"
            del inventory["observation"]["lifecycle"]
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("native", str(ctx.exception))

    def test_stream_snapshot_divergence_fails(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-div-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21)
            with open(events_path, encoding="utf-8") as stream:
                events = [json.loads(line) for line in stream if line.strip()]
            for row in events:
                if row["kind"] == "edge_observed":
                    row["event"]["entries"]["count"] = 19
            write_jsonl(events_path, events)
            with self.assertRaises(ValueError) as ctx:
                s1.compare([str(ledger_path)], [str(events_path)],
                           str(inventory_path), 10)
            self.assertIn("divergence", str(ctx.exception))


class LossGate(unittest.TestCase):
    def run_mutation(self, mutate_inventory=None, mutate_events=None):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-loss-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21)
            if mutate_inventory is not None:
                with open(inventory_path, encoding="utf-8") as stream:
                    inventory = json.load(stream)
                mutate_inventory(inventory)
                write_json(inventory_path, inventory)
                if inventory["edges"]:
                    rewrite_events_for_edge(
                        workdir, inventory["edges"][0],
                        ledger_last_t1(ledger_path))
            if mutate_events is not None:
                with open(events_path, encoding="utf-8") as stream:
                    events = [json.loads(line) for line in stream
                              if line.strip()]
                mutate_events(events)
                write_jsonl(events_path, events)
            return s1.compare([str(ledger_path)], [str(events_path)],
                              str(inventory_path), 10)

    def test_events_lost_1_fails(self):
        def mutate(inventory):
            inventory["observation"]["semantic_capture"][
                "unrouted_returns"] = 1
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("events_lost 1", str(ctx.exception))

    def test_ring_loss_1_fails(self):
        def mutate(inventory):
            inventory["observation"]["lifecycle"]["ring_loss"] = 1
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("ring_loss 1", str(ctx.exception))

    def test_unproven_drain_fails(self):
        def mutate(inventory):
            capture = inventory["observation"]["semantic_capture"]
            capture["final_drain"] = False
            capture["stop_quiescence"] = "unproven"
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("full drain", str(ctx.exception))

    def test_loss_gap_fails(self):
        def mutate_inventory(inventory):
            inventory["gaps"].append(
                {"caller": "c0", "module": "m0", "pid": PID,
                 "subject": "semantic capture loss",
                 "reason": "Detailed event overflow", "budget": None,
                 "repeats": 1})

        def mutate_events(events):
            ended = events[-1]
            assert ended["kind"] == "ended"
            gap = event_envelope(ended["seq"], R0 + 1_000, "gap_recorded",
                                 {"index": 0, "caller": "c0", "module": "m0",
                                  "pid": None,
                                  "subject": "semantic capture loss",
                                  "reason": "Detailed event overflow",
                                  "budget": None})
            events.insert(-1, gap)
            ended["seq"] += 1

        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory, mutate_events)
        self.assertIn("loss gap", str(ctx.exception))

    def test_tolerated_journal_disclosure_passes(self):
        def mutate_inventory(inventory):
            inventory["gaps"].append(
                {"caller": None, "module": None, "pid": None,
                 "subject": "semantic lane disclosure",
                 "reason": "joint_journal_unavailable", "budget": None,
                 "repeats": 1})
        result = self.run_mutation(mutate_inventory)
        self.assertEqual(result["verdict"], "pass")

    def test_lossy_coverage_fails(self):
        def mutate(inventory):
            inventory["edges"][0]["entries"]["coverage"]["lossy"] = True
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("loss-free", str(ctx.exception))

    def test_unretained_edges_fail(self):
        def mutate(events):
            self.assertEqual(events[-1]["kind"], "ended")
            events[-1]["event"]["edges_unretained"] = 1
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_events=mutate)
        self.assertIn("incomplete", str(ctx.exception))

    def test_missing_ended_fails(self):
        def mutate(events):
            self.assertEqual(events[-1]["kind"], "ended")
            del events[-1]
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_events=mutate)
        self.assertIn("incomplete", str(ctx.exception))

    def test_suppressed_gaps_fail(self):
        def mutate(events):
            self.assertEqual(events[-1]["kind"], "ended")
            events[-1]["event"]["gaps_suppressed"] = 2
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_events=mutate)
        self.assertIn("incomplete", str(ctx.exception))


class S1ActiveGate(unittest.TestCase):
    def run_mutation(self, mutate):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-s1-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21)
            with open(inventory_path, encoding="utf-8") as stream:
                inventory = json.load(stream)
            mutate(inventory)
            write_json(inventory_path, inventory)
            return s1.compare([str(ledger_path)], [str(events_path)],
                              str(inventory_path), 10)

    def test_populated_object_observations_fails(self):
        def mutate(inventory):
            inventory["object_observations"]["status"] = "populated"
            inventory["object_observations"]["reason"] = "none"
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("populated", str(ctx.exception))

    def test_bootstrap_reason_fails(self):
        def mutate(inventory):
            inventory["object_observations"]["reason"] = \
                "bootstrap_unavailable"
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("bootstrap_unavailable", str(ctx.exception))

    def test_disabled_lane_fails(self):
        def mutate(inventory):
            inventory["observation"]["semantic_capture"]["status"] = \
                "disabled"
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("disabled", str(ctx.exception))


class PublishLatency(unittest.TestCase):
    def test_latency_values_are_exact_on_a_tiny_series(self):
        s1 = require_s1(self)
        calls = [{"kind": "ready", "pid": PID, "tid": PID, "t": R0,
                  "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
        for seq in range(1, 5):
            end = R0 + seq * 100_000_000
            calls.append({"kind": "call", "seq": seq, "fn": FNS[seq % 2],
                          "rv": 0, "pid": PID, "tid": PID,
                          "t0": end - 500, "t1": end})
        calls.append({"kind": "ack", "issued": 4,
                      "t": R0 + 1_500_000_000})
        with tempfile.TemporaryDirectory(prefix="s1tp-lat-") as tmp:
            workdir = Path(tmp)
            edge = driver_edge(4)
            sem = semantic_row(edge, 4)
            ledger_path = workdir / "ledger.jsonl"
            events_path = workdir / "events.jsonl"
            inventory_path = workdir / "inventory.json"
            write_jsonl(ledger_path, calls)
            # Two records: calls 1-2 published 10 ms after t1_2, calls
            # 3-4 published 30 ms after t1_4.
            series = [(R0 + 210_000_000, 2), (R0 + 430_000_000, 4)]
            write_jsonl(events_path, events_doc(edge, series))
            write_json(inventory_path, inventory_doc(edge, [sem]))
            result = s1.compare([str(ledger_path)], [str(events_path)],
                                str(inventory_path), 1)
            self.assertEqual(result["verdict"], "pass")
            latency = result["latency"]
            self.assertEqual(latency["samples"], 4)
            # Samples: 110/10/130/30 ms -> sorted 10/30/110/130.
            self.assertEqual(latency["p50_ns"], 30_000_000)
            self.assertEqual(latency["p99_ns"], 130_000_000)
            self.assertEqual(latency["max_ns"], 130_000_000)
            self.assertEqual(latency["unmapped"], 0)

    def test_huge_latency_is_recorded_never_gated(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-late-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21, latency_step_ns=5_000_000_000)
            result = s1.compare([str(ledger_path)], [str(events_path)],
                                str(inventory_path), 10)
            self.assertEqual(result["verdict"], "pass")
            self.assertGreaterEqual(result["latency"]["p99_ns"],
                                    5_000_000_000)


class ScopeAndClock(unittest.TestCase):
    def test_foreign_scope_fails(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-scope-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21)
            with open(events_path, encoding="utf-8") as stream:
                events = [json.loads(line) for line in stream if line.strip()]
            events[0]["event"]["scope"] = "system"
            write_jsonl(events_path, events)
            with self.assertRaises(ValueError) as ctx:
                s1.compare([str(ledger_path)], [str(events_path)],
                           str(inventory_path), 10)
            self.assertIn("scope", str(ctx.exception))

    def test_clock_basis_mismatch_fails(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-clock-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21)
            with open(events_path, encoding="utf-8") as stream:
                events = [json.loads(line) for line in stream if line.strip()]
            events[0]["event"]["clock"]["basis"] = "CLOCK_REALTIME"
            write_jsonl(events_path, events)
            with self.assertRaises(ValueError) as ctx:
                s1.compare([str(ledger_path)], [str(events_path)],
                           str(inventory_path), 10)
            self.assertIn("clock", str(ctx.exception))


STUB_PROVIDER = r"""/* Test-only stub provider: immediate OK returns, real entry shapes. */
typedef unsigned long CK_RV;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef void (*CK_NOTIFY)(void);
#define CKR_OK 0
typedef struct { unsigned long mechanism; void *pParameter; unsigned long ulParameterLen; } CK_MECHANISM;
static unsigned long next_session = 100;
CK_RV C_Initialize(void *init_args) { (void)init_args; return CKR_OK; }
CK_RV C_Finalize(void *reserved) { (void)reserved; return CKR_OK; }
CK_RV C_GetSlotList(unsigned char token_present, CK_SLOT_ID *slot_list, CK_ULONG *count) {
    (void)token_present;
    if (count == 0) return 1;
    if (slot_list == 0) { *count = 1; return CKR_OK; }
    if (*count < 1) { *count = 1; return 1; }
    slot_list[0] = 7;
    *count = 1;
    return CKR_OK;
}
CK_RV C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session) {
    (void)slot; (void)flags; (void)application; (void)notify;
    if (session == 0) return 1;
    *session = next_session++;
    return CKR_OK;
}
CK_RV C_CloseSession(CK_SESSION_HANDLE session) { (void)session; return CKR_OK; }
CK_RV C_DigestInit(CK_SESSION_HANDLE session, CK_MECHANISM *mechanism) {
    (void)session; (void)mechanism;
    return CKR_OK;
}
CK_RV C_Digest(CK_SESSION_HANDLE session, CK_BYTE *data, CK_ULONG data_len, CK_BYTE *digest, CK_ULONG *digest_len) {
    (void)session; (void)data; (void)data_len;
    if (digest_len == 0) return 1;
    if (digest != 0 && *digest_len >= 4) {
        digest[0] = 1; digest[1] = 2; digest[2] = 3; digest[3] = 4;
    }
    *digest_len = 4;
    return CKR_OK;
}
"""

GCC_FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]


def build_c(test, sources, output, extra=()):
    test.assertTrue(shutil.which("gcc"), "gcc unavailable")
    cmd = ["gcc", *GCC_FLAGS, *extra, "-o", str(output),
           *[str(source) for source in sources]]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    test.assertEqual(proc.returncode, 0,
                     f"gcc failed: {proc.stderr[-2000:]}")


@unittest.skipUnless(shutil.which("gcc"), "gcc unavailable")
class DriverFixture(unittest.TestCase):
    def build_driver(self, workdir):
        self.assertTrue(DRIVER_SRC.exists(),
                        f"driver missing: {DRIVER_SRC}")
        driver = workdir / "gen-calls"
        build_c(self, [DRIVER_SRC], driver, extra=["-ldl"])
        return driver

    def build_stub(self, workdir):
        stub_src = workdir / "stub.c"
        stub_src.write_text(STUB_PROVIDER, encoding="utf-8")
        stub = workdir / "stub.so"
        build_c(self, [stub_src], stub, extra=["-shared", "-fPIC"])
        return stub

    def test_driver_builds_clean(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-gcc-") as tmp:
            self.build_driver(Path(tmp))

    def test_driver_help_needs_no_provider(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-help-") as tmp:
            driver = self.build_driver(Path(tmp))
            proc = subprocess.run([str(driver), "--help"], capture_output=True,
                                  text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("usage:", proc.stdout)
            self.assertIn("RATE", proc.stdout)

    def test_driver_usage_errors_are_exit_2(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-usage-") as tmp:
            driver = self.build_driver(Path(tmp))
            for argv in ([], ["only"], ["/nope.so", "single", "bogus", "1",
                                        "ledger.jsonl"]):
                proc = subprocess.run([str(driver), *argv],
                                      capture_output=True, text=True,
                                      timeout=30)
                self.assertEqual(proc.returncode, 2, argv)

    def test_driver_dry_run_needs_no_provider(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-dry-") as tmp:
            driver = self.build_driver(Path(tmp))
            proc = subprocess.run(
                [str(driver), "--dry-run", "/no-provider.so", "single",
                 "10k", "5", "ledger.jsonl"], capture_output=True, text=True,
                timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("50000 calls", proc.stdout)

    def test_driver_stub_run_emits_a_valid_1k_ledger(self):
        t0 = require_t0(self)
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-live-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_stub(workdir)
            ledger = workdir / "ledger.jsonl"
            gate = workdir / "go"
            gate.touch()
            proc = subprocess.run(
                [str(driver), str(stub), "single", "1k", "2", str(ledger),
                 str(gate)], capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0,
                             f"rc={proc.returncode}: {proc.stderr[-2000:]}")
            self.assertIn("READY pid=", proc.stdout)
            with open(ledger, encoding="utf-8") as stream:
                rows = t0.read_ledger(stream)
            summary = t0.validate_ledger(rows)
            self.assertEqual(summary, {"issued": 2000, "calls": 2000})
            view = s1.load_ledgers([str(ledger)])
            windows = s1.check_windows(view, 1000)
            self.assertEqual(view["issued"], 2000)
            self.assertGreaterEqual(len(windows["windows"]), 1)
            self.assertTrue(all(window["count"] >= 1000
                                for window in windows["windows"]),
                            windows["windows"])

    def test_driver_waits_for_the_go_gate(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-go-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_stub(workdir)
            ledger = workdir / "ledger.jsonl"
            gate = workdir / "go"
            proc = subprocess.Popen(
                [str(driver), str(stub), "single", "1k", "1", str(ledger),
                 str(gate)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)
            try:
                ready = ""
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    chunk = proc.stdout.read(1)
                    if not chunk:
                        break
                    ready += chunk
                    if "\n" in ready:
                        break
                self.assertIn("READY pid=", ready)
                time.sleep(0.5)
                self.assertIsNone(proc.poll())
                self.assertFalse(ledger.exists())
                gate.touch()
                rc = proc.wait(timeout=30)
                self.assertEqual(rc, 0)
                self.assertTrue(ledger.exists())
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
                    proc.wait(timeout=10)

    def test_driver_churn_run_emits_one_ledger_per_thread(self):
        t0 = require_t0(self)
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-churn-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_stub(workdir)
            prefix = workdir / "churn"
            proc = subprocess.run(
                [str(driver), str(stub), "churn", "1k", "2", str(prefix)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0,
                             f"rc={proc.returncode}: {proc.stderr[-2000:]}")
            ledgers = sorted(workdir.glob("churn.t*.jsonl"))
            self.assertGreater(len(ledgers), 1)
            total = 0
            for path in ledgers:
                with open(path, encoding="utf-8") as stream:
                    rows = t0.read_ledger(stream)
                total += t0.validate_ledger(rows)["issued"]
            self.assertEqual(total, 2000)
            view = s1.load_ledgers([str(path) for path in ledgers])
            self.assertEqual(view["issued"], 2000)
            windows = s1.check_windows(view, 1000)
            self.assertGreaterEqual(len(windows["windows"]), 1)


if __name__ == "__main__":
    unittest.main()

