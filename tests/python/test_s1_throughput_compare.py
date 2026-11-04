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
by idle fails; the partial tail is reported, never gated); exact call
and error totals per mechanism (edge and operation totals plus
per-mechanism calls / errors, with function and return-code set
equality over the hot loop; the driver's ledgered teardown calls are
conserved in the exact totals but claim no mechanism row); zero event
loss (ring_loss == 0, unrouted S1 returns == 0, a proven full drain, no
loss gap, clean physical coverage and only clean or exact terminal R59
semantic coverage, a complete event stream); and the
S1-active gate (object_observations unavailable with reason
journal_unavailable, the semantic lane past disabled). S1 publish
latency (coarse per-call edge-count publication delay) is recorded as
p50/p99 with its sample count, never gated.

Healthy and mutation twins run unignored; the driver tests build the
tracked gen-calls.c fixture with gcc and drive a test-only in-suite
stub provider (real PKCS#11 entry signatures, counting-free immediate
OK returns, with optional test-only call tracing), so they need no
SoftHSM install. The optional FINISH phase preserves the original
process/provider after closed ledgers; its signal-interruptible wait has
no internal timeout, so the controller's absolute 30 s lifetime bound
must include GO, work, DONE and FINISH. This active-target rate mode does
not qualify immediate-exit coverage. Actual Multi, identity-bound
Detailed EVENTS loss == 0, and exact collected/joined/shed stop receipts
remain mandatory independent live-wrapper proofs.
"""

import contextlib
import copy
import importlib.util
import io
import json
import os
import select
import shutil
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
MECH_NAME = "CKM_SHA256"
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


def ledger_with_teardown(count, per_s, pid=PID, teardown_rv=0):
    """uniform_ledger plus the two ledgered teardown calls.

    C_CloseSession then C_Finalize land after the last hot-loop END, so
    they sit in the partial tail, never in a gated full window.
    """
    rows = uniform_ledger(count, per_s, pid=pid)
    ack = rows.pop()
    assert ack["kind"] == "ack"
    last = max(row["t1"] for row in rows if row["kind"] == "call")
    seq = count
    for fn in ("C_CloseSession", "C_Finalize"):
        seq += 1
        end = last + (seq - count) * 1000
        rows.append({"kind": "call", "seq": seq, "fn": fn,
                     "rv": teardown_rv, "pid": pid, "tid": pid,
                     "t0": end - 500, "t1": end})
        last = end
    rows.append({"kind": "ack", "issued": seq, "t": last + 500})
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


def driver_edge(count, caller="c0", module="m0",
                coverage_state="counted", lossy=False):
    # Physical edges deliberately withhold per-instance semantic summaries.
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
        "semantics": "unknown (per-edge summary withheld; see semantic children)",
        "mechanisms": None,
        "operations": None,
    }


def semantic_row(edge, api_count, lossy=False):
    return {"caller": edge["caller"], "module": edge["module"],
            "instance": "i0",
            "entries": {"unit": "api_entries", "count": None,
                        "observation": "unavailable"},
            "api_returns": {"unit": "api_returns", "count": api_count,
                            "saturated": False, "historical_only_returns": 0},
            "semantics": "observed",
            "mechanisms": [mechanism_row(api_count)],
            "operations": {"calls": api_count,
                       "started": (api_count + 1) // 2, "completed": api_count // 2,
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
            "coverage": {"lossy": lossy, "reasons": (
                ["capture_stopped", "semantic_loss"] if lossy else [])}}


def inventory_doc(edge, sem_rows, pid=PID, ring_loss=0, unrouted=0,
                  quiescence="quiesced", drain=True, lane_status="stopped",
                  obs_status="unavailable", obs_reason="journal_unavailable",
                  gaps=(), suppressed=0):
    return {
        "schema": "p11scope/inventory/v1", "scope": f"pid:{pid}",
        "callers": [{"id": "c0", "pid": pid, "start_time": 12345,
                     "retired": False}],
        "modules": [{"id": "m0", "lifecycle": "mapped", "unloaded_observed": False,
                     "admission": {"state": "admitted", "class": "operator",
                                   "endpoints": 68, "reasons": []}}],
        "edges": [edge],
        "instances": [{"id": "i0", "caller": "c0", "module": "m0",
                       "state": "observed", "reason": None}],
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
                                 "events_lost": 0,
                                 "stop_quiescence": quiescence,
                                 "final_drain": drain}},
        "gaps": [{"caller": None, "module": None, "pid": None,
                  "subject": subject, "reason": reason, "budget": None,
                  "repeats": 1} for subject, reason in gaps],
        "gaps_suppressed": 0,
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


JOINT_SIGN_MECH = 0x251
JOINT_SIGN_NAME = "CKM_SHA256_HMAC"
JOINT_GEN_MECH = 0x350
JOINT_GEN_NAME = "CKM_GENERIC_SECRET_KEY_GEN"


def joint_hot_ledger(ops, per_s, pid=PID, tid=PID, start_ns=R0, rv=0):
    """One key file: GenerateKey + ops x (SignInit, Sign) + DestroyObject.

    Call t1 stamps pack exactly per_s per 1 s window from start_ns,
    like uniform_ledger; t0 trails t1 by 500 ns.
    """
    rows = [{"kind": "ready", "pid": pid, "tid": tid, "t": start_ns,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    step = 1_000_000_000 // per_s
    fns = (["C_GenerateKey"] + ["C_SignInit", "C_Sign"] * ops
           + ["C_DestroyObject"])
    last = start_ns
    for seq, fn in enumerate(fns, start=1):
        end = start_ns + (seq - 1) * step + 1000
        rows.append({"kind": "call", "seq": seq, "fn": fn,
                     "rv": rv, "pid": pid, "tid": tid,
                     "t0": end - 500, "t1": end})
        last = end
    rows.append({"kind": "ack", "issued": len(fns), "t": last + 500})
    return rows


def joint_setup_ledger(sessions=1, pid=PID, start_ns=R0):
    """The keyed setup file: Initialize, two slot probes, one open each."""
    rows = [{"kind": "ready", "pid": pid, "tid": pid, "t": start_ns,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    fns = (["C_Initialize", "C_GetSlotList", "C_GetSlotList"]
           + ["C_OpenSession"] * sessions)
    for seq, fn in enumerate(fns, start=1):
        end = start_ns + seq * 1000
        rows.append({"kind": "call", "seq": seq, "fn": fn,
                     "rv": 0, "pid": pid, "tid": pid,
                     "t0": end - 500, "t1": end})
    rows.append({"kind": "ack", "issued": len(fns),
                 "t": start_ns + (len(fns) + 1) * 1000})
    return rows


def joint_teardown_ledger(sessions=1, pid=PID, start_ns=R0 + 2_000_001_000):
    """The keyed teardown file: one close per session, then finalize."""
    rows = [{"kind": "ready", "pid": pid, "tid": pid, "t": start_ns,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    fns = ["C_CloseSession"] * sessions + ["C_Finalize"]
    for seq, fn in enumerate(fns, start=1):
        end = start_ns + seq * 1000
        rows.append({"kind": "call", "seq": seq, "fn": fn,
                     "rv": 0, "pid": pid, "tid": pid,
                     "t0": end - 500, "t1": end})
    rows.append({"kind": "ack", "issued": len(fns),
                 "t": start_ns + (len(fns) + 1) * 1000})
    return rows


def joint_mechanism_rows(sign_calls, keygen_calls, sign_errors=0,
                         keygen_errors=0):
    """The two pinned Joint mechanism rows: HMAC sign plus keygen."""
    return [
        {"mechanism": JOINT_SIGN_MECH,
         "mechanism_hex": hex(JOINT_SIGN_MECH), "name": JOINT_SIGN_NAME,
         "operations": ["sign"], "calls": sign_calls,
         "errors": sign_errors,
         "last_seen_ns": R0 + 2_000_000_000,
         "evidence": {
             "functions": ["C_Sign", "C_SignInit"],
             "returns": [{"rv": 0, "rv_hex": "0x0", "name": "CKR_OK"}],
             "truncated": False}},
        {"mechanism": JOINT_GEN_MECH,
         "mechanism_hex": hex(JOINT_GEN_MECH), "name": JOINT_GEN_NAME,
         "operations": ["generate_key"], "calls": keygen_calls,
         "errors": keygen_errors,
         "last_seen_ns": R0 + 2_000_000_000,
         "evidence": {
             "functions": ["C_GenerateKey"],
             "returns": [{"rv": 0, "rv_hex": "0x0", "name": "CKR_OK"}],
             "truncated": False}},
    ]


def joint_semantic_row(edge, issued, sign_calls, keygen_calls, lossy=False):
    """The driver's semantic child: two Joint mechanism rows, exact totals."""
    started = sign_calls // 2 + keygen_calls
    return {"caller": edge["caller"], "module": edge["module"],
            "instance": "i0",
            "entries": {"unit": "api_entries", "count": None,
                        "observation": "unavailable"},
            "api_returns": {"unit": "api_returns", "count": issued,
                            "saturated": False, "historical_only_returns": 0},
            "semantics": "observed",
            "mechanisms": joint_mechanism_rows(sign_calls, keygen_calls),
            "operations": {"calls": issued,
                       "started": started, "completed": started,
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
            "coverage": {"lossy": lossy, "reasons": (
                ["capture_stopped", "semantic_loss"] if lossy else [])}}


def joint_key_row(instance, object_id, ops):
    return {"instance": instance, "object": object_id, "category": "sign",
            "role": "key", "metadata_at_use": None, "unit": "operations",
            "started": ops, "completed": ops, "failed": 0, "cancelled": 0,
            "unknown": 0, "active": 0, "key_join_lost": 0}


def joint_unknown_row(category, reason, completed):
    return {"category": category, "reason": reason, "unit": "operations",
            "completed": completed, "failed": 0, "cancelled": 0,
            "unknown": 0, "active": 0}


def joint_object_view(object_id, session=1, birth_start=R0 + 500,
                     birth_end=R0 + 1500, origin="created",
                     creation="generate", lifetime="destroyed", key_refs=2):
    blank = {"status": "unknown", "value": None}
    value = {"status": "value", "value": 0}
    return {"object": object_id, "session": session, "origin": origin,
            "creation": creation,
            "birth": {"start_ns": birth_start, "end_ns": birth_end},
            "lifetime": lifetime, "lifetime_reason": None,
            "attribution": "valid", "attribution_reason": None,
            "requested": {"class": value, "key_type": value, "token": value,
                          "value_len": blank, "modulus_bits": blank,
                          "ec_params": blank},
            "established": {"class": value, "key_type": value,
                            "token": value, "value_len": blank,
                            "modulus_bits": blank, "ec_params": blank},
            "queries": {"class": "established", "key_type": "established",
                        "token": "established", "value_len": "not_queried",
                        "modulus_bits": "not_queried",
                        "ec_params": "not_queried"},
            "label": None, "successful_references": key_refs + 1,
            "successful_key_references": key_refs, "accessing_sessions": 1}


def joint_object_observations(ops_per_key, sessions=1, instance="i0",
                              status="populated", reason="none"):
    """A populated section: one created+destroyed view and one sign row
    per key, in window births, closed sessions, no unknown rows."""
    return {
        "version": 1, "revision": 4, "status": status, "reason": reason,
        "sessions": [{"session": number + 1, "origin": "opened",
                      "status": "closed"} for number in range(sessions)],
        "objects": [joint_object_view(11 + index, session=1 + (index % sessions),
                                      key_refs=ops)
                    for index, ops in enumerate(ops_per_key)],
        "key_operations": [joint_key_row(instance, 11 + index, ops)
                           for index, ops in enumerate(ops_per_key)],
        # One not_applicable generation per created key, as the product
        # always reports for C_GenerateKey.
        "unknown_key_operations": [joint_unknown_row(
            "generate_key", "not_applicable", len(ops_per_key))],
        "gaps": {"rows": [], "suppressed": 0},
        "budgets": {"key_rows": {"limit": 65536,
                                 "occupied": len(ops_per_key), "refused": 0},
                    "object_rows": {"limit": 65536,
                                    "occupied": len(ops_per_key),
                                    "refused": 0},
                    "unknown_rows": {"occupied": 1}, "encoded_bytes": 410,
                    "allocation_refused": False, "refusal_reason": "none"},
    }


def joint_inventory_doc(edge, sem_rows, observations, pid=PID,
                        ring_loss=0, unrouted=0, quiescence="quiesced",
                        drain=True, lane_status="stopped",
                        refused_endpoints=0, continuity_cuts=0,
                        gaps=(), suppressed=0, foreign_edge=None):
    """A --system snapshot: the driver's owned graph, foreign rows first."""
    edges = [foreign_edge] if foreign_edge is not None else []
    edges.append(edge)
    return {
        "schema": "p11scope/inventory/v1", "scope": "system",
        "callers": [{"id": "c0", "pid": 999, "start_time": 999,
                     "retired": False},
                    {"id": "c1", "pid": pid, "start_time": 12345,
                     "retired": False}],
        "modules": [{"id": "m0", "lifecycle": "mapped", "unloaded_observed": False,
                     "admission": {"state": "admitted", "class": "operator",
                                   "endpoints": 68, "reasons": []}}],
        "edges": edges,
        "instances": [{"id": "i0", "caller": "c1", "module": "m0",
                       "state": "observed", "reason": None}],
        "semantic_edges": list(sem_rows),
        "object_observations": observations,
        "observation": {
            "lane": "native",
            "lifecycle": {"records": 3, "ring_loss": ring_loss,
                          "malformed": 0, "failed_quanta": 0,
                          "recovery_rescans": 0},
            "semantic_capture": {"status": lane_status,
                                 "admitted_endpoints": 68,
                                 "refused_endpoints": refused_endpoints,
                                 "continuity_cuts": continuity_cuts,
                                 "unrouted_returns": unrouted,
                                 "events_lost": 0,
                                 "stop_quiescence": quiescence,
                                 "final_drain": drain}},
        "gaps": [{"caller": None, "module": None, "pid": None,
                  "subject": subject, "reason": reason, "budget": None,
                  "repeats": 1} for subject, reason in gaps],
        "gaps_suppressed": 0,
        "budgets": {"retained_history": {"limit": 1024, "retained": 0,
                                         "suppressed": suppressed}},
    }


def joint_events_doc(edge_final, series, foreign_series=(),
                     basis="CLOCK_MONOTONIC", unit="ns", started_ns=R0,
                     unretained=0, gaps_suppressed=0, gap_events=(),
                     evicted=False, with_ended=True):
    """A --system event log: started, driver records, ended."""
    rows = [event_envelope(0, started_ns, "started",
                           {"scope": "system",
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
    for at_ns, count in foreign_series:
        edge = driver_edge(count, caller="c0", module="m0")
        edge["entries"]["count"] = count
        rows.append(event_envelope(seq, at_ns, "edge_observed", edge))
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
             "edge_events": len(series) + len(foreign_series),
             "edges_unretained": unretained,
             "instance_events": 0, "instances_unretained": 0,
             "semantic_edge_events": 0, "semantic_edges_unretained": 0,
             "key_operation_events": 0, "key_operations_unretained": 0}))
    return rows


def healthy_joint_triple(workdir, ops_per_key=(9999,), per_s=FULL_RATE,
                         pid=PID, sessions=1, latency_step_ns=1_000_000,
                         **inventory_kwargs):
    """Write a fully passing Joint ledger set + events + inventory."""
    ledger_paths = []
    setup = joint_setup_ledger(sessions=sessions, pid=pid)
    setup_path = workdir / "setup.jsonl"
    write_jsonl(setup_path, setup)
    ledger_paths.append(setup_path)
    last_t1 = 0
    for index, ops in enumerate(ops_per_key):
        hot = joint_hot_ledger(ops, per_s, pid=pid, tid=pid + index)
        if len(ops_per_key) == 1:
            hot_path = workdir / "hot.jsonl"
        else:
            hot_path = workdir / f"hot.t{index}.jsonl"
        write_jsonl(hot_path, hot)
        ledger_paths.append(hot_path)
        last_t1 = max(last_t1, max(row["t1"] for row in hot
                                  if row["kind"] == "call"))
    teardown = joint_teardown_ledger(sessions=sessions, pid=pid)
    teardown_path = workdir / "teardown.jsonl"
    write_jsonl(teardown_path, teardown)
    ledger_paths.append(teardown_path)
    issued = sum(1 for path in ledger_paths for row in
                 json.loads(f"[{','.join(path.read_text().splitlines())}]")
                 if row["kind"] == "call")
    edge = driver_edge(issued, caller="c1", module="m0")
    sign_calls = 2 * sum(ops_per_key)
    sem = joint_semantic_row(edge, issued, sign_calls, len(ops_per_key))
    observations = joint_object_observations(ops_per_key, sessions=sessions)
    foreign = driver_edge(0, caller="c0", module="m0")
    inventory = joint_inventory_doc(edge, [sem], observations, pid=pid,
                                    foreign_edge=foreign, **inventory_kwargs)
    mid = issued // 2
    series = [(last_t1 + latency_step_ns, mid),
              (last_t1 + 2 * latency_step_ns, issued)]
    events = joint_events_doc(edge, series,
                              foreign_series=[(last_t1 + 500_000, 0)])
    events_path = workdir / "events.jsonl"
    inventory_path = workdir / "inventory.json"
    write_jsonl(events_path, events)
    write_json(inventory_path, inventory)
    return ledger_paths, events_path, inventory_path


def rewrite_joint_events_for_edge(workdir, edge, last_t1):
    """Rebuild the Joint events file around the (mutated) driver edge."""
    final = edge["entries"]["count"]
    series = [(last_t1 + 1_000_000, final // 2),
              (last_t1 + 2_000_000, final)]
    write_jsonl(workdir / "events.jsonl",
                joint_events_doc(edge, series,
                                 foreign_series=[(last_t1 + 500_000, 0)]))


def joint_hot_last_t1(ledger_paths):
    last = 0
    for path in ledger_paths:
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("kind") == "call":
                    last = max(last, row["t1"])
    return last


OTHER_UNROUTED = "semantic calls unrouted from other callers"


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
            edges = inventory.get("edges")
            if type(edges) is list and edges:
                rewrite_events_for_edge(workdir, edges[0],
                                        ledger_last_t1(ledger_path))
            return s1.compare([str(ledger_path)], [str(events_path)],
                              str(inventory_path), 10)

    def test_one_call_missing_for_a_function_fails(self):
        def mutate(inventory):
            inventory["edges"][0]["entries"]["count"] = 24
            inventory["semantic_edges"][0]["mechanisms"][0]["calls"] = 24
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("entries.count 24 != issued 25", str(ctx.exception))

    def test_wrong_return_code_count_fails(self):
        def mutate(inventory):
            inventory["semantic_edges"][0]["mechanisms"][0]["errors"] = 1
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("errors", str(ctx.exception))

    def test_operations_calls_short_fails(self):
        def mutate(inventory):
            inventory["semantic_edges"][0]["operations"]["calls"] = 24
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("operations.calls 24 != issued 25", str(ctx.exception))

    def test_api_returns_short_fails(self):
        def mutate(inventory):
            inventory["semantic_edges"][0]["api_returns"]["count"] = 24
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("api_returns 24 != issued 25", str(ctx.exception))

    def test_slot_refused_setup_conserved(self):
        def mutate(inventory):
            child = inventory["semantic_edges"][0]
            child["operations"]["calls"] = 24
            child["api_returns"]["count"] = 24
            inventory["gaps"].append(
                {"caller": "c0", "module": None, "pid": None,
                 "subject": "semantic input refused", "reason": "slot",
                 "budget": None, "repeats": 1})
        result = self.run_mutation(mutate)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["conservation"]["slot_refused"], 1)

    def test_slot_refused_short_without_gap_fails(self):
        def mutate(inventory):
            child = inventory["semantic_edges"][0]
            child["operations"]["calls"] = 24
            child["api_returns"]["count"] = 24
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("minus slot-refused 0", str(ctx.exception))

    def test_slot_refused_overcounted_fails(self):
        def mutate(inventory):
            inventory["gaps"].append(
                {"caller": "c0", "module": None, "pid": None,
                 "subject": "semantic input refused", "reason": "slot",
                 "budget": None, "repeats": 1})
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("minus slot-refused 1", str(ctx.exception))

    def test_slot_refused_foreign_scope_ignored(self):
        # A foreign-scoped slot row never dilutes the driver's exact
        # totals: conservation fails closed on its own term first.
        def mutate(inventory):
            child = inventory["semantic_edges"][0]
            child["operations"]["calls"] = 24
            child["api_returns"]["count"] = 24
            inventory["gaps"].append(
                {"caller": "c9", "module": None, "pid": None,
                 "subject": "semantic input refused", "reason": "slot",
                 "budget": None, "repeats": 1})
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("minus slot-refused 0", str(ctx.exception))

    def run_rsa_tally_confusion(self, mutate, token):
        # 6.08 phase 1 (S2): the throughput denominator is all-issued from
        # the per-thread T0 ledgers. The 65-call RSA semantic tally is a
        # different cell's number and must never satisfy conservation.
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-cons65-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, ack_ns=R0 + 2_000_000_000 + 500)
            with open(inventory_path, encoding="utf-8") as stream:
                inventory = json.load(stream)
            mutate(inventory)
            write_json(inventory_path, inventory)
            with self.assertRaises(ValueError) as ctx:
                s1.compare([str(ledger_path)], [str(events_path)],
                           str(inventory_path), FULL_RATE)
            self.assertIn(token, str(ctx.exception))

    def test_rsa_semantic_calls_tally_is_not_the_throughput_denominator(self):
        def mutate(inventory):
            inventory["semantic_edges"][0]["operations"]["calls"] = 65
        self.run_rsa_tally_confusion(
            mutate, "operations.calls 65 != issued 20000")

    def test_rsa_api_returns_tally_is_not_the_throughput_denominator(self):
        def mutate(inventory):
            inventory["semantic_edges"][0]["api_returns"]["count"] = 65
        self.run_rsa_tally_confusion(
            mutate, "api_returns 65 != issued 20000")

    def test_phantom_function_fails(self):
        def mutate(inventory):
            row = inventory["semantic_edges"][0]["mechanisms"][0]
            row["evidence"]["functions"].append("C_Phantom")
            row["evidence"]["functions"].sort()
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("absent from ledger", str(ctx.exception))

    def test_unobserved_function_fails(self):
        def mutate(inventory):
            row = inventory["semantic_edges"][0]["mechanisms"][0]
            row["evidence"]["functions"] = [FN_INIT]
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("missing from observed evidence", str(ctx.exception))

    def test_phantom_return_code_fails(self):
        def mutate(inventory):
            row = inventory["semantic_edges"][0]["mechanisms"][0]
            row["evidence"]["returns"].append(
                {"rv": 1, "rv_hex": "0x1", "name": None})
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("absent from ledger", str(ctx.exception))

    def test_missing_mechanism_row_fails(self):
        def mutate(inventory):
            inventory["semantic_edges"][0]["mechanisms"] = None
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("mechanism", str(ctx.exception))

    def test_no_driver_edge_fails(self):
        def mutate(inventory):
            inventory["edges"] = []
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate)
        self.assertIn("edges", str(ctx.exception))

    def test_current_topology_rejects_duplicates_missing_or_foreign_rows(self):
        cases = []
        for key in ("callers", "modules", "edges", "instances", "semantic_edges"):
            cases.extend(((key + " duplicate", lambda d, k=key: d[k].append(copy.deepcopy(d[k][0]))),
                          (key + " absent", lambda d, k=key: d.pop(k)),
                          (key + " null", lambda d, k=key: d.__setitem__(k, None))))
        for key in ("edges", "instances", "semantic_edges"):
            for ref in ("caller", "module"):
                cases.append((key + " wrong " + ref,
                              lambda d, k=key, r=ref: d[k][0].__setitem__(r, "foreign")))
        cases.extend((
            ("wrong PID", lambda d: d["callers"][0].__setitem__("pid", PID + 1)),
            ("wrong scope", lambda d: d.__setitem__("scope", "system")),
            ("missing start", lambda d: d["callers"][0].pop("start_time")),
            ("retired caller", lambda d: d["callers"][0].__setitem__("retired", True)),
            ("wrong instance", lambda d: d["semantic_edges"][0].__setitem__("instance", "i9")),
            ("unloaded module", lambda d: d["modules"][0].__setitem__("lifecycle", "unloaded")),
            ("unload observed", lambda d: d["modules"][0].__setitem__("unloaded_observed", True)),
            ("manifest refused", lambda d: d["modules"][0]["admission"].__setitem__("state", "refused")),
            ("manifest unproven", lambda d: d["modules"][0]["admission"].__setitem__("class", "heuristic")),
            ("interrupted mapping", lambda d: d["edges"][0]["mapping"].__setitem__("interruptions", 1)),
            ("unknown parent only", lambda d: d["semantic_edges"][0].__setitem__("semantics", "unknown")),
            ("parent promotion", lambda d: d["edges"][0].__setitem__("operations", d["semantic_edges"][0]["operations"])),
        ))
        for name, mutate in cases:
            with self.subTest(name=name), self.assertRaises(S1.S1Error):
                self.run_mutation(mutate)

    def test_current_count_authority_flags_are_required(self):
        for section, key, value in (
                ("physical", "saturated", True), ("physical", "in_flight", True),
                ("physical", "observation", "unknown"),
                ("returns", "unit", "api_entries"), ("returns", "saturated", True),
                ("returns", "historical_only_returns", 1), ("returns", "count", True),
                ("entries", "count", 25), ("entries", "observation", "observed")):
            def mutate(doc, s=section, k=key, v=value):
                row = (doc["edges"][0]["entries"] if s == "physical" else
                       doc["semantic_edges"][0]["api_returns" if s == "returns" else "entries"])
                row[k] = v
            with self.subTest(section=section, key=key), self.assertRaises(S1.S1Error):
                self.run_mutation(mutate)

    def test_duplicate_or_truncated_mechanism_evidence_fails(self):
        for mutate in (
                lambda d: d["semantic_edges"][0]["mechanisms"].append(
                    copy.deepcopy(d["semantic_edges"][0]["mechanisms"][0])),
                lambda d: d["semantic_edges"][0]["mechanisms"][0]["evidence"].__setitem__("truncated", True),
                lambda d: d["semantic_edges"][0]["mechanisms"][0]["evidence"]["functions"].append(FN_DO)):
            with self.subTest(mutate=mutate), self.assertRaises(S1.S1Error):
                self.run_mutation(mutate)

    def test_mechanism_identity_and_duplicate_return_evidence_are_hard(self):
        for mutate_row in (
                lambda r: r.__setitem__("mechanism", 0x251),
                lambda r: r.__setitem__("name", "CKM_SHA_256"),
                lambda r: r.__setitem__("operations", ["sign"]),
                lambda r: r["evidence"]["returns"].append(copy.deepcopy(r["evidence"]["returns"][0]))):
            with self.subTest(mutate=mutate_row), self.assertRaises(S1.S1Error):
                self.run_mutation(lambda d: mutate_row(d["semantic_edges"][0]["mechanisms"][0]))

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

    def run_teardown_triple(self, teardown_rv=0, row_calls=25, stopped=False):
        """Ledger with teardown vs observer totals that include it.

        The mechanism row keeps the hot-loop calls only: teardown claims
        no mechanism row. Returns the pass verdict or raises.
        """
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-teardown-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21)
            rows = ledger_with_teardown(25, 21, teardown_rv=teardown_rv)
            write_jsonl(ledger_path, rows)
            last_t1 = max(row["t1"] for row in rows
                          if row["kind"] == "call")
            with open(inventory_path, encoding="utf-8") as stream:
                inventory = json.load(stream)
            edge = inventory["edges"][0]
            edge["entries"]["count"] = 27
            inventory["semantic_edges"][0]["operations"]["calls"] = 27
            inventory["semantic_edges"][0]["mechanisms"][0]["calls"] = \
                row_calls
            inventory["semantic_edges"][0]["api_returns"]["count"] = 27
            if stopped:
                inventory["instances"][0].update(state="uncertain", reason="semantic_loss")
                inventory["semantic_edges"][0]["coverage"] = {
                    "lossy": True, "reasons": ["capture_stopped", "semantic_loss"]}
            write_json(inventory_path, inventory)
            rewrite_events_for_edge(workdir, edge, last_t1)
            return s1.compare([str(ledger_path)], [str(events_path)],
                              str(inventory_path), 10)

    def test_ledgered_teardown_conserves_in_the_exact_totals(self):
        result = self.run_teardown_triple()
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["issued"], 27)
        self.assertEqual(result["conservation"]["teardown"]["calls"], 2)
        self.assertEqual(result["conservation"]["teardown"]["errors"], 0)

    def test_R59_stopped_child_still_requires_every_hot_and_teardown_call(self):
        result = self.run_teardown_triple(stopped=True)
        self.assertEqual(result["issued"], 27)
        for name in ("entries", "api_returns", "operations"):
            self.assertEqual(result["conservation"][name], 27)
        self.assertEqual(result["conservation"]["mechanisms"][0]["calls"], 25)

    def test_teardown_inside_a_mechanism_row_fails(self):
        with self.assertRaises(ValueError) as ctx:
            self.run_teardown_triple(row_calls=27)
        self.assertIn("calls 27 != ledger 25", str(ctx.exception))

    def test_teardown_only_return_code_is_exempt_from_the_rv_set(self):
        result = self.run_teardown_triple(teardown_rv=1)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["issued"], 27)
        self.assertEqual(result["conservation"]["teardown"]["errors"], 2)


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

    def test_other_caller_unrouted_gap_fails_outside_joint(self):
        # Without a bound Joint caller nothing separates the loss.
        def mutate(inventory):
            inventory["gaps"].append(
                {"caller": None, "module": None, "pid": None,
                 "subject": OTHER_UNROUTED,
                 "reason": "3 calls shed without a route (unobserved=3) "
                           "from callers other than the 0 bound callers",
                 "budget": None, "repeats": 1})
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("loss gap", str(ctx.exception))

    def test_unrouted_returns_1_fails(self):
        def mutate(inventory):
            inventory["observation"]["semantic_capture"][
                "unrouted_returns"] = 1
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("unrouted_returns 1", str(ctx.exception))

    def test_events_lost_1_fails(self):
        def mutate(inventory):
            inventory["observation"]["semantic_capture"]["events_lost"] = 1
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("events_lost 1", str(ctx.exception))

    def test_events_lost_missing_fails(self):
        def mutate(inventory):
            del inventory["observation"]["semantic_capture"]["events_lost"]
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("events_lost missing", str(ctx.exception))

    def test_events_lost_out_of_range_fails(self):
        def mutate(inventory):
            inventory["observation"]["semantic_capture"]["events_lost"] = -1
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("events_lost missing or out of range",
                      str(ctx.exception))

    def test_native_capture_events_loss_unknown_gap_fails(self):
        reason = ("the EVENTS ring-loss counter could not be read; "
                  "events_lost may undercount until a later good read "
                  "restores the exact cumulative total")

        def mutate_inventory(inventory):
            inventory["gaps"].append(
                {"caller": None, "module": None, "pid": None,
                 "subject": "native capture events loss unknown",
                 "reason": reason, "budget": None, "repeats": 1})

        def mutate_events(events):
            ended = events[-1]
            assert ended["kind"] == "ended"
            gap = event_envelope(ended["seq"], R0 + 1_000, "gap_recorded",
                                 {"index": 0, "caller": None, "module": None,
                                  "pid": None,
                                  "subject": "native capture events loss unknown",
                                  "reason": reason,
                                  "budget": None})
            events.insert(-1, gap)
            ended["seq"] += 1

        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory, mutate_events)
        self.assertIn("loss gap", str(ctx.exception))

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

    def test_joint_machine_unavailable_reason_fails(self):
        def mutate(inventory):
            inventory["gaps"].append(
                {"caller": None, "module": None, "pid": None,
                 "subject": "S1 lane stopped",
                 "reason": "joint machine unavailable", "budget": None,
                 "repeats": 1})
        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory=mutate)
        self.assertIn("loss gap", str(ctx.exception))

    def test_joint_machine_unavailable_subject_fails(self):
        def mutate_inventory(inventory):
            inventory["gaps"].append(
                {"caller": None, "module": None, "pid": None,
                 "subject": "joint machine unavailable",
                 "reason": "S1 lane stopped", "budget": None,
                 "repeats": 1})

        def mutate_events(events):
            ended = events[-1]
            assert ended["kind"] == "ended"
            gap = event_envelope(ended["seq"], R0 + 1_000, "gap_recorded",
                                 {"index": 0, "caller": None, "module": None,
                                  "pid": None,
                                  "subject": "joint machine unavailable",
                                  "reason": "S1 lane stopped",
                                  "budget": None})
            events.insert(-1, gap)
            ended["seq"] += 1

        with self.assertRaises(ValueError) as ctx:
            self.run_mutation(mutate_inventory, mutate_events)
        self.assertIn("loss gap", str(ctx.exception))

    def test_native_capture_events_lost_gap_fails(self):
        reason = ("the EVENTS ring was full; the kernel refused records "
                  "before the drain could read them (kernel reserve "
                  "failures; exact count in events_lost)")

        def mutate_inventory(inventory):
            inventory["gaps"].append(
                {"caller": None, "module": None, "pid": None,
                 "subject": "native capture events lost",
                 "reason": reason, "budget": None,
                 "repeats": 1})

        def mutate_events(events):
            ended = events[-1]
            assert ended["kind"] == "ended"
            gap = event_envelope(ended["seq"], R0 + 1_000, "gap_recorded",
                                 {"index": 0, "caller": None, "module": None,
                                  "pid": None,
                                  "subject": "native capture events lost",
                                  "reason": reason,
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

    def test_exact_R59_terminal_disclosure_preserves_all_call_denominators(self):
        def mutate(doc):
            doc["instances"][0].update(state="uncertain", reason="semantic_loss")
            doc["semantic_edges"][0]["coverage"] = {
                "lossy": True, "reasons": ["capture_stopped", "semantic_loss"]}
        result = self.run_mutation(mutate_inventory=mutate)
        self.assertEqual(result["conservation"]["entries"], 25)
        self.assertEqual(result["conservation"]["operations"], 25)
        self.assertEqual(result["conservation"]["api_returns"], 25)

    def test_R59_does_not_waive_retirement_history_or_real_loss(self):
        cases = [
            lambda d: d["instances"][0].update(state="retired", reason="task_retired"),
            lambda d: d["semantic_edges"][0]["coverage"]["reasons"].append("task_retired"),
            lambda d: d["semantic_edges"][0]["coverage"]["reasons"].append("instance_retired"),
            lambda d: d["semantic_edges"][0]["coverage"]["reasons"].append("semantic_loss"),
            lambda d: d["semantic_edges"][0]["coverage"].__setitem__("reasons", ["capture_stopped"]),
            lambda d: d["semantic_edges"][0]["api_returns"].__setitem__("historical_only_returns", 1),
            lambda d: d["observation"]["semantic_capture"].__setitem__("status", "active"),
            lambda d: d["observation"]["semantic_capture"].__setitem__("final_drain", False),
            lambda d: d["observation"]["semantic_capture"].__setitem__("stop_quiescence", "unproven"),
        ]
        for key in ("continuity_cuts", "refused_endpoints", "unrouted_returns"):
            cases.append(lambda d, k=key: d["observation"]["semantic_capture"].__setitem__(k, 1))
        for key in ("malformed", "failed_quanta"):
            cases.append(lambda d, k=key: d["observation"]["lifecycle"].__setitem__(k, 1))
        for mutate in cases:
            def stopped_mutation(doc):
                doc["instances"][0].update(state="uncertain", reason="semantic_loss")
                doc["semantic_edges"][0]["coverage"] = {
                    "lossy": True, "reasons": ["capture_stopped", "semantic_loss"]}
                mutate(doc)
            with self.subTest(mutate=mutate), self.assertRaises(S1.S1Error):
                self.run_mutation(mutate_inventory=stopped_mutation)

    def test_published_loss_and_suppression_never_hide_behind_R50(self):
        for subject in ("semantic capture loss", "native capture retirement unsettled",
                        "native capture scope custody unproven", "native capture refused an extend",
                        "rejected demoted count", "semantic admission refused", "semantic calls unrouted"):
            def mutate(doc):
                doc["gaps"].append({"caller": None, "module": None, "pid": None,
                                    "subject": subject, "reason": "joint_journal_unavailable",
                                    "repeats": 1})
            with self.subTest(subject=subject), self.assertRaises(S1.S1Error):
                self.run_mutation(mutate_inventory=mutate)
        for value in (1, None, True):
            with self.subTest(suppressed=value), self.assertRaises(S1.S1Error):
                self.run_mutation(mutate_inventory=lambda d: d.__setitem__("gaps_suppressed", value))

    def test_gap_rows_are_scoped_readable_and_never_echo_untrusted_labels(self):
        base = {"caller": None, "module": None, "pid": None,
                "subject": "disclosure", "reason": "before_semantic_boundary", "repeats": 1}
        for key, value in (("caller", "c8"), ("module", "m8"), ("pid", PID + 1),
                           ("repeats", 0), ("repeats", True), ("reason", None), ("subject", "")):
            def mutate(d, k=key, v=value):
                gap = dict(base)
                gap[k] = v
                d["gaps"].append(gap)
            with self.subTest(key=key, value=value), self.assertRaises(S1.S1Error):
                self.run_mutation(mutate_inventory=mutate)
        secret = "untrusted-private-label"
        def mutate(d):
            d["gaps"].append(dict(base, subject="semantic capture loss", reason=secret))
        with self.assertRaises(S1.S1Error) as failure:
            self.run_mutation(mutate_inventory=mutate)
        self.assertNotIn(secret, str(failure.exception))

    def test_missing_duplicate_or_unaccounted_rotations_refuse(self):
        mutations = (
            lambda e: e.pop(1),
            lambda e: e.insert(1, copy.deepcopy(e[1])),
            lambda e: e[-1]["event"]["stream"].__setitem__("rotations", 1),
            lambda e: e[-1]["event"]["stream"].__setitem__("evicted_events", 1),
            lambda e: e[-1]["event"]["stream"].__setitem__("evicted_bytes", 1),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises(S1.S1Error):
                self.run_mutation(mutate_events=mutate)

    def test_retained_rotation_files_are_merged_without_losing_a_row(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-rotation-") as tmp:
            workdir = Path(tmp)
            ledger, events_path, inventory = healthy_triple(workdir, count=25, per_s=21)
            rows = [json.loads(line) for line in events_path.read_text().splitlines()]
            prior = workdir / "events.jsonl.1"
            write_jsonl(prior, rows[:2])
            marker = event_envelope(2, R0 + 1_000_000, "rotated", {
                "prior_file": prior.name, "prior_events": 2,
                "prior_bytes": prior.stat().st_size, "rotation_seq": 1})
            tail = [marker, *rows[2:]]
            for seq, row in enumerate(tail, start=2):
                row["seq"] = seq
            tail[-1]["event"]["stream"]["rotations"] = 1
            write_jsonl(events_path, tail)
            result = S1.compare([ledger], [events_path, prior], inventory, 10)
            self.assertEqual(result["verdict"], "pass")

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


class MalformedLedgerCLI(unittest.TestCase):
    def test_malformed_ledger_cli_prints_a_json_fail_verdict(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-badledger-") as tmp:
            workdir = Path(tmp)
            ledger_path, events_path, inventory_path = healthy_triple(
                workdir, count=25, per_s=21)
            ledger_path.write_text("{not a json row\n", encoding="utf-8")
            out = io.StringIO()
            err = io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                rc = s1.main(["--ledger", str(ledger_path),
                              "--events", str(events_path),
                              "--inventory", str(inventory_path),
                              "--min-rate", "10"])
            self.assertEqual(rc, 1)
            verdict = json.loads(out.getvalue())
            self.assertEqual(verdict["verdict"], "fail")
            self.assertIn("ledger", verdict["reason"])
            self.assertNotIn("Traceback", err.getvalue())


STUB_PROVIDER = r"""/* Test-only stub provider: immediate OK returns, real entry shapes. */
#include <stdio.h>
#include <stdlib.h>
static void record(const char *function) {
    const char *path = getenv("S1TP_STUB_CALLS");
    if (path == NULL) return;
    FILE *stream = fopen(path, "a");
    if (stream == NULL) abort();
    if (fprintf(stream, "%s\n", function) < 0 || fclose(stream) != 0) abort();
}
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
CK_RV C_Initialize(void *init_args) { (void)init_args; record("C_Initialize"); return CKR_OK; }
CK_RV C_Finalize(void *reserved) { (void)reserved; record("C_Finalize"); return CKR_OK; }
CK_RV C_GetSlotList(unsigned char token_present, CK_SLOT_ID *slot_list, CK_ULONG *count) {
    record("C_GetSlotList");
    (void)token_present;
    if (count == 0) return 1;
    if (slot_list == 0) { *count = 1; return CKR_OK; }
    if (*count < 1) { *count = 1; return 1; }
    slot_list[0] = 7;
    *count = 1;
    return CKR_OK;
}
CK_RV C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session) {
    record("C_OpenSession");
    (void)slot; (void)flags; (void)application; (void)notify;
    if (session == 0) return 1;
    *session = next_session++;
    return CKR_OK;
}
CK_RV C_CloseSession(CK_SESSION_HANDLE session) { (void)session; record("C_CloseSession"); return CKR_OK; }
CK_RV C_DigestInit(CK_SESSION_HANDLE session, CK_MECHANISM *mechanism) {
    record("C_DigestInit");
    (void)session; (void)mechanism;
    return CKR_OK;
}
CK_RV C_Digest(CK_SESSION_HANDLE session, CK_BYTE *data, CK_ULONG data_len, CK_BYTE *digest, CK_ULONG *digest_len) {
    record("C_Digest");
    (void)session; (void)data; (void)data_len;
    if (digest_len == 0) return 1;
    if (digest != 0 && *digest_len >= 4) {
        digest[0] = 1; digest[1] = 2; digest[2] = 3; digest[3] = 4;
    }
    *digest_len = 4;
    return getenv("S1TP_STUB_FAIL_DIGEST") == NULL ? CKR_OK : 5;
}
"""

KEYED_STUB_ENTRIES = r"""/* Keyed entries for the keyed/keyed-churn modes (same record style). */
typedef unsigned long CK_OBJECT_HANDLE;
typedef struct { unsigned long type; void *value; unsigned long value_len; } CK_ATTRIBUTE;
static unsigned long next_object = 500;
CK_RV C_GenerateKey(CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_ATTRIBUTE *templ, CK_ULONG count, CK_OBJECT_HANDLE *key) {
    record("C_GenerateKey");
    (void)session; (void)mechanism; (void)templ; (void)count;
    if (key == 0) return 1;
    *key = next_object++;
    return CKR_OK;
}
CK_RV C_SignInit(CK_SESSION_HANDLE session, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {
    record("C_SignInit");
    (void)session; (void)mechanism; (void)key;
    return CKR_OK;
}
CK_RV C_Sign(CK_SESSION_HANDLE session, CK_BYTE *data, CK_ULONG data_len, CK_BYTE *sig, CK_ULONG *sig_len) {
    record("C_Sign");
    (void)session; (void)data; (void)data_len;
    if (sig_len == 0) return 1;
    if (sig != 0 && *sig_len >= 4) {
        sig[0] = 5; sig[1] = 6; sig[2] = 7; sig[3] = 8;
    }
    *sig_len = 4;
    return CKR_OK;
}
CK_RV C_DestroyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object) {
    (void)session; (void)object; record("C_DestroyObject"); return CKR_OK;
}
"""

KEYED_STUB_PROVIDER = STUB_PROVIDER + KEYED_STUB_ENTRIES

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
    @classmethod
    def setUpClass(cls):
        cls.build_root = tempfile.TemporaryDirectory(prefix="s1tp-compiled-")
        cls.addClassCleanup(cls.build_root.cleanup)
        cls.compiled = Path(cls.build_root.name)

    def build_driver(self, workdir):
        self.assertTrue(DRIVER_SRC.exists(),
                        f"driver missing: {DRIVER_SRC}")
        driver = self.compiled / "gen-calls"
        if not driver.exists():
            build_c(self, [DRIVER_SRC], driver, extra=["-ldl", "-pthread"])
        return driver

    def build_stub(self, workdir):
        stub_src = self.compiled / "stub.c"
        stub = self.compiled / "stub.so"
        if not stub.exists():
            stub_src.write_text(STUB_PROVIDER, encoding="utf-8")
            build_c(self, [stub_src], stub, extra=["-shared", "-fPIC"])
        return stub

    def build_keyed_stub(self, workdir):
        stub_src = self.compiled / "keyed-stub.c"
        stub = self.compiled / "keyed-stub.so"
        if not stub.exists():
            stub_src.write_text(KEYED_STUB_PROVIDER, encoding="utf-8")
            build_c(self, [stub_src], stub, extra=["-shared", "-fPIC"])
        return stub

    def finish_process(self, workdir, ledger=None, finish=None, fail_digest=False):
        driver = self.build_driver(workdir)
        stub = self.build_stub(workdir)
        go = workdir / "go"
        finish = finish or workdir / "finish"
        ledger = ledger or workdir / "ledger.jsonl"
        calls = workdir / "provider-calls"
        env = dict(os.environ, S1TP_STUB_CALLS=str(calls))
        if fail_digest:
            env["S1TP_STUB_FAIL_DIGEST"] = "1"
        # One absolute supervisor deadline starts before Popen, covering GO,
        # hot work, DONE and FINISH. It is never renewed at a phase boundary.
        deadline = time.monotonic() + 30
        proc = subprocess.Popen(
            [str(driver), str(stub), "single", "1k", "1", str(ledger),
             str(go), str(finish)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env)
        return proc, go, finish, ledger, calls, deadline

    def read_phase(self, proc, prefix, deadline):
        line = bytearray()
        while time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [],
                                         max(0, deadline - time.monotonic()))
            if not ready:
                break
            part = os.read(proc.stdout.fileno(), 1)
            if not part:
                break
            line.extend(part)
            if part == b"\n":
                break
        self.assertEqual(line.decode(), f"{prefix} pid={proc.pid}\n")

    def reap(self, proc):
        if proc.poll() is None:
            proc.terminate()
        proc.communicate(timeout=5)

    def test_finish_keeps_original_pid_mapping_and_closed_ledgers_without_calls(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-finish-") as tmp:
            workdir = Path(tmp)
            proc, go, finish, ledger, calls, deadline = self.finish_process(workdir)
            try:
                self.read_phase(proc, "READY", deadline)
                start = Path(f"/proc/{proc.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                go.touch()
                self.read_phase(proc, "DONE", deadline)
                self.assertIsNone(proc.poll())
                self.assertIn(str(self.compiled / "stub.so"), Path(f"/proc/{proc.pid}/maps").read_text())
                self.assertEqual(start, Path(f"/proc/{proc.pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
                teardown = workdir / "ledger-teardown.jsonl"
                before = (ledger.read_bytes(), teardown.read_bytes(), calls.read_bytes())
                self.assertEqual(S1.load_ledgers([ledger, teardown])["issued"], 1002)
                recorded = calls.read_text().splitlines()
                self.assertEqual(recorded.count("C_DigestInit"), 500)
                self.assertEqual(recorded.count("C_Digest"), 500)
                self.assertEqual(recorded.count("C_CloseSession"), 1)
                self.assertEqual(recorded.count("C_Finalize"), 1)
                time.sleep(0.08)
                self.assertEqual(before, (ledger.read_bytes(), teardown.read_bytes(), calls.read_bytes()))
                finish.touch()
                out, err = proc.communicate(timeout=max(0.01, deadline - time.monotonic()))
                self.assertEqual(proc.returncode, 0, err)
                self.assertEqual(out, "")
                self.assertEqual(before, (ledger.read_bytes(), teardown.read_bytes(), calls.read_bytes()))
            finally:
                self.reap(proc)

    def test_missing_finish_supervisor_terminates_and_reaps_without_double_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-finish-missing-") as tmp:
            short_deadline = time.monotonic() + 3
            proc, go, _, _, calls, deadline = self.finish_process(Path(tmp))
            # A shortened test supervisor exercises the same absolute bound;
            # the actual qualification supervisor uses the existing 30 s.
            deadline = min(deadline, short_deadline)
            try:
                self.read_phase(proc, "READY", deadline)
                go.touch()
                self.read_phase(proc, "DONE", deadline)
                before = calls.read_bytes()
                with self.assertRaises(subprocess.TimeoutExpired):
                    proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                proc.terminate()
                out, err = proc.communicate(timeout=5)
                self.assertNotEqual(proc.returncode, 0, (out, err))
                self.assertIn("finish", err)
                self.assertEqual(calls.read_bytes(), before)
            finally:
                self.reap(proc)

    def test_preexisting_or_bad_finish_never_enters_healthy_hold(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-finish-bad-") as tmp:
            workdir = Path(tmp)
            for label in ("preexisting", "inaccessible"):
                with self.subTest(label=label):
                    cell = workdir / label
                    cell.mkdir()
                    barrier = cell / "barrier"
                    barrier.touch()
                    finish = barrier if label == "preexisting" else barrier / "finish"
                    proc, _, _, _, calls, deadline = self.finish_process(cell, finish=finish)
                    try:
                        out, err = proc.communicate(timeout=max(0.01, deadline - time.monotonic()))
                        self.assertEqual(proc.returncode, 2, err)
                        self.assertNotIn("DONE", out)
                        self.assertFalse(calls.exists())
                    finally:
                        self.reap(proc)

    def test_early_finish_cannot_claim_a_held_phase(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-finish-early-") as tmp:
            proc, go, finish, _, calls, deadline = self.finish_process(Path(tmp))
            try:
                self.read_phase(proc, "READY", deadline)
                finish.touch()
                go.touch()
                out, err = proc.communicate(timeout=max(0.01, deadline - time.monotonic()))
                self.assertEqual(proc.returncode, 2, err)
                self.assertNotIn("DONE", out)
                self.assertEqual(calls.read_text().splitlines().count("C_Finalize"), 1)
            finally:
                self.reap(proc)

    def test_unhealthy_or_unwritten_ledger_cannot_emit_healthy_done(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-finish-unhealthy-") as tmp:
            for unhealthy in (True, False):
                with self.subTest(unhealthy=unhealthy):
                    cell = Path(tmp) / str(unhealthy)
                    cell.mkdir()
                    ledger = cell / "ledger.jsonl" if unhealthy else cell / "missing" / "ledger.jsonl"
                    proc, go, _, _, calls, deadline = self.finish_process(
                        cell, ledger=ledger, fail_digest=unhealthy)
                    try:
                        self.read_phase(proc, "READY", deadline)
                        go.touch()
                        out, err = proc.communicate(timeout=max(0.01, deadline - time.monotonic()))
                        self.assertEqual(proc.returncode, 1 if unhealthy else 2, err)
                        self.assertNotIn("DONE", out)
                        recorded = calls.read_text().splitlines()
                        self.assertEqual(recorded.count("C_CloseSession"), 1)
                        self.assertEqual(recorded.count("C_Finalize"), 1)
                    finally:
                        self.reap(proc)

    def test_done_flush_failure_never_becomes_a_successful_hold(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-finish-pipe-") as tmp:
            proc, go, _, _, calls, deadline = self.finish_process(Path(tmp))
            try:
                self.read_phase(proc, "READY", deadline)
                proc.stdout.close()
                go.touch()
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                self.assertNotEqual(proc.returncode, 0)
                recorded = calls.read_text().splitlines()
                self.assertEqual(recorded.count("C_CloseSession"), 1)
                self.assertEqual(recorded.count("C_Finalize"), 1)
            finally:
                self.reap(proc)

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

    def test_driver_help_names_the_gated_minimum_duration(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-min-") as tmp:
            driver = self.build_driver(Path(tmp))
            proc = subprocess.run([str(driver), "--help"], capture_output=True,
                                  text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(">= 2", proc.stdout)
            self.assertIn("smoke only", proc.stdout)
            self.assertIn("FINISH_FILE", proc.stdout)
            self.assertIn("absolute 30 s", proc.stdout)
            self.assertIn("No internal deadline", proc.stdout)

    def test_driver_dry_run_names_the_teardown_ledger(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-tddry-") as tmp:
            driver = self.build_driver(Path(tmp))
            for mode, ledger, expect in (
                    ("single", "ledger.jsonl", "ledger-teardown.jsonl"),
                    ("churn", "churn", "churn-teardown.jsonl")):
                proc = subprocess.run(
                    [str(driver), "--dry-run", "/no-provider.so", mode,
                     "1k", "2", ledger], capture_output=True, text=True,
                    timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(expect, proc.stdout)

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
            self.assertNotIn("DONE", proc.stdout)
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
            deadline = time.monotonic() + 30
            proc = subprocess.Popen(
                [str(driver), str(stub), "single", "1k", "1", str(ledger),
                 str(gate)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)
            try:
                self.read_phase(proc, "READY", deadline)
                time.sleep(0.5)
                self.assertIsNone(proc.poll())
                self.assertFalse(ledger.exists())
                gate.touch()
                out, err = proc.communicate(timeout=max(0.01, deadline - time.monotonic()))
                self.assertEqual(proc.returncode, 0, err)
                self.assertNotIn("DONE", out)
                self.assertTrue(ledger.exists())
            finally:
                self.reap(proc)

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
            self.assertTrue(all(window["count"] >= 1000
                                for window in windows["windows"]),
                            windows["windows"])

    def test_driver_single_run_ledgers_teardown_beside_the_hot_ledger(self):
        t0 = require_t0(self)
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-td1-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_stub(workdir)
            ledger = workdir / "ledger.jsonl"
            proc = subprocess.run(
                [str(driver), str(stub), "single", "1k", "2", str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0,
                             f"rc={proc.returncode}: {proc.stderr[-2000:]}")
            teardown = workdir / "ledger-teardown.jsonl"
            self.assertTrue(
                teardown.exists(),
                "teardown ledger missing beside the hot ledger")
            with open(teardown, encoding="utf-8") as stream:
                rows = t0.read_ledger(stream)
            summary = t0.validate_ledger(rows)
            self.assertEqual(summary, {"issued": 2, "calls": 2})
            fns = [row["fn"] for row in rows if row.get("kind") == "call"]
            self.assertEqual(fns, ["C_CloseSession", "C_Finalize"])
            view = s1.load_ledgers([str(ledger), str(teardown)])
            self.assertEqual(view["issued"], 2002)
            windows = s1.check_windows(view, 1000)
            self.assertTrue(all(window["count"] >= 1000
                                for window in windows["windows"]),
                            windows["windows"])

    def test_driver_churn_run_ledgers_teardown_in_its_own_file(self):
        t0 = require_t0(self)
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-tdc-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_stub(workdir)
            prefix = workdir / "churn"
            proc = subprocess.run(
                [str(driver), str(stub), "churn", "1k", "2", str(prefix)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0,
                             f"rc={proc.returncode}: {proc.stderr[-2000:]}")
            teardown = workdir / "churn-teardown.jsonl"
            self.assertTrue(teardown.exists(),
                            "churn teardown ledger missing")
            with open(teardown, encoding="utf-8") as stream:
                rows = t0.read_ledger(stream)
            summary = t0.validate_ledger(rows)
            self.assertEqual(summary, {"issued": 9, "calls": 9})
            fns = [row["fn"] for row in rows if row.get("kind") == "call"]
            self.assertEqual(fns, ["C_CloseSession"] * 8 + ["C_Finalize"])
            ledgers = sorted(workdir.glob("churn.t*.jsonl"))
            view = s1.load_ledgers(
                [str(path) for path in ledgers] + [str(teardown)])
            self.assertEqual(view["issued"], 2009)

    def test_keyed_help_names_the_keyed_modes(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-khelp-") as tmp:
            driver = self.build_driver(Path(tmp))
            proc = subprocess.run([str(driver), "--help"], capture_output=True,
                                  text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("keyed / keyed-churn", proc.stdout)
            self.assertIn("CKM_SHA256_HMAC", proc.stdout)
            self.assertIn("4 calls keyed, 11", proc.stdout)

    def test_keyed_dry_run_pins_the_keyed_plan(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-kdry-") as tmp:
            driver = self.build_driver(Path(tmp))
            cases = (
                (["--dry-run", "/no-provider.so", "keyed", "1k", "2",
                  "ledger.jsonl"],
                 "gen-calls dry run: provider=/no-provider.so mode=keyed "
                 "rate=1000/s duration=2s 2000 calls 999 ops threads=1 "
                 "key=generic-secret-hmac-sha256 ledgers=ledger.jsonl "
                 "setup=ledger-setup.jsonl (4 calls) "
                 "teardown=ledger-teardown.jsonl (2 calls)"),
                (["--dry-run", "/no-provider.so", "keyed-churn", "1k", "2",
                  "churn"],
                 "gen-calls dry run: provider=/no-provider.so "
                 "mode=keyed-churn rate=1000/s duration=2s 2000 calls "
                 "968 ops threads=32 waves=4 "
                 "key=generic-secret-hmac-sha256 "
                 "ledgers=churn.t<nn>.jsonl setup=churn-setup.jsonl "
                 "(11 calls) teardown=churn-teardown.jsonl (9 calls)"),
            )
            for argv, expect in cases:
                proc = subprocess.run([str(driver), *argv],
                                      capture_output=True, text=True,
                                      timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout.strip(), expect)

    def test_keyed_plan_refuses_beyond_the_ledger_ceiling(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-kceil-") as tmp:
            driver = self.build_driver(Path(tmp))
            exact = subprocess.run(
                [str(driver), "--dry-run", "/no-provider.so", "keyed",
                 "10k", "20", "ledger.jsonl"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(exact.returncode, 0, exact.stderr)
            self.assertIn("200000 calls 99999 ops", exact.stdout)
            refused = subprocess.run(
                [str(driver), "--dry-run", "/no-provider.so", "keyed",
                 "100k", "8", "ledger.jsonl"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(refused.returncode, 2)
            self.assertIn("ledger ceiling", refused.stderr)

    def test_keyed_mode_names_all_four_modes_on_mistake(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-kmode-") as tmp:
            driver = self.build_driver(Path(tmp))
            proc = subprocess.run(
                [str(driver), "/no-provider.so", "Keyed", "1k", "2",
                 "ledger.jsonl"], capture_output=True, text=True,
                timeout=30)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("single, churn, keyed or keyed-churn", proc.stderr)

    def test_setup_gate_opens_a_mapping_window_before_first_use(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-mapped-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_keyed_stub(workdir)
            gate = workdir / "setup-go"
            gate.touch()
            env = dict(os.environ, GEN_CALLS_SETUP_GATE=str(gate))
            proc = subprocess.run(
                [str(driver), str(stub), "keyed", "1k", "1",
                 str(workdir / "ledger.jsonl")],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(proc.returncode, 0,
                             f"rc={proc.returncode}: {proc.stderr[-2000:]}")
            mapped = proc.stdout.index("MAPPED pid=")
            ready = proc.stdout.index("READY pid=")
            self.assertLess(mapped, ready)

    def test_unset_setup_gate_prints_no_mapped(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-nomapped-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_keyed_stub(workdir)
            env = {key: value for key, value in os.environ.items()
                   if key != "GEN_CALLS_SETUP_GATE"}
            proc = subprocess.run(
                [str(driver), str(stub), "keyed", "1k", "1",
                 str(workdir / "ledger.jsonl")],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(proc.returncode, 0,
                             f"rc={proc.returncode}: {proc.stderr[-2000:]}")
            self.assertNotIn("MAPPED", proc.stdout)
            self.assertIn("READY pid=", proc.stdout)

    def test_keyed_mode_requires_the_keyed_entry_points(self):
        with tempfile.TemporaryDirectory(prefix="s1tp-kreq-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_stub(workdir)
            proc = subprocess.run(
                [str(driver), str(stub), "keyed", "1k", "2",
                 str(workdir / "ledger.jsonl")],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("keyed entry point", proc.stderr)
            self.assertFalse((workdir / "ledger.jsonl").exists())

    def test_keyed_stub_run_emits_valid_setup_hot_and_teardown_ledgers(self):
        t0 = require_t0(self)
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-klive-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_keyed_stub(workdir)
            ledger = workdir / "ledger.jsonl"
            calls = workdir / "provider-calls"
            env = dict(os.environ, S1TP_STUB_CALLS=str(calls))
            proc = subprocess.run(
                [str(driver), str(stub), "keyed", "1k", "2", str(ledger)],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(proc.returncode, 0,
                             f"rc={proc.returncode}: {proc.stderr[-2000:]}")
            self.assertIn("READY pid=", proc.stdout)
            setup = workdir / "ledger-setup.jsonl"
            teardown = workdir / "ledger-teardown.jsonl"
            for path, want in ((setup, 4), (ledger, 2000), (teardown, 2)):
                with open(path, encoding="utf-8") as stream:
                    rows = t0.read_ledger(stream)
                self.assertEqual(t0.validate_ledger(rows)["issued"], want,
                                 path.name)
            with open(setup, encoding="utf-8") as stream:
                setup_rows = t0.read_ledger(stream)
            fns = [row["fn"] for row in setup_rows
                   if row.get("kind") == "call"]
            self.assertEqual(fns, ["C_Initialize", "C_GetSlotList",
                                   "C_GetSlotList", "C_OpenSession"])
            with open(ledger, encoding="utf-8") as stream:
                hot_rows = t0.read_ledger(stream)
            hot = [row["fn"] for row in hot_rows if row.get("kind") == "call"]
            self.assertEqual(hot[0], "C_GenerateKey")
            self.assertEqual(hot[-1], "C_DestroyObject")
            self.assertEqual(hot.count("C_SignInit"), 999)
            self.assertEqual(hot.count("C_Sign"), 999)
            recorded = calls.read_text().splitlines()
            self.assertEqual(recorded.count("C_GenerateKey"), 1)
            self.assertEqual(recorded.count("C_SignInit"), 999)
            self.assertEqual(recorded.count("C_Sign"), 999)
            self.assertEqual(recorded.count("C_DestroyObject"), 1)
            view = s1.load_ledgers(
                [str(setup), str(ledger), str(teardown)])
            self.assertEqual(view["issued"], 2006)
            windows = s1.check_windows(view, 1000)
            self.assertTrue(all(window["count"] >= 1000
                                for window in windows["windows"]),
                            windows["windows"])

    def test_keyed_churn_run_emits_one_ledger_per_thread(self):
        t0 = require_t0(self)
        with tempfile.TemporaryDirectory(prefix="s1tp-kchurn-") as tmp:
            workdir = Path(tmp)
            driver = self.build_driver(workdir)
            stub = self.build_keyed_stub(workdir)
            prefix = workdir / "churn"
            proc = subprocess.run(
                [str(driver), str(stub), "keyed-churn", "1k", "2",
                 str(prefix)], capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0,
                             f"rc={proc.returncode}: {proc.stderr[-2000:]}")
            ledgers = sorted(workdir.glob("churn.t*.jsonl"))
            self.assertEqual(len(ledgers), 32)
            total = 0
            for path in ledgers:
                with open(path, encoding="utf-8") as stream:
                    rows = t0.read_ledger(stream)
                total += t0.validate_ledger(rows)["issued"]
                hot = [row["fn"] for row in rows
                       if row.get("kind") == "call"]
                self.assertEqual(hot[0], "C_GenerateKey", path.name)
                self.assertEqual(hot[-1], "C_DestroyObject", path.name)
                self.assertEqual(hot.count("C_SignInit"),
                                 hot.count("C_Sign"), path.name)
                self.assertGreater(hot.count("C_SignInit"), 0, path.name)
            self.assertEqual(total, 2000)
            with open(workdir / "churn-setup.jsonl",
                       encoding="utf-8") as stream:
                setup_rows = t0.read_ledger(stream)
            self.assertEqual(t0.validate_ledger(setup_rows)["issued"], 11)
            setup_fns = [row["fn"] for row in setup_rows
                         if row.get("kind") == "call"]
            self.assertEqual(setup_fns,
                             ["C_Initialize", "C_GetSlotList",
                              "C_GetSlotList"] + ["C_OpenSession"] * 8)


class JointHealthy(unittest.TestCase):
    def test_healthy_joint_single_key_passes(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-healthy-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            result = s1.compare([str(path) for path in ledgers],
                                [str(events)], str(inventory),
                                FULL_RATE, joint=True)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["issued"], 20006)
            self.assertEqual(result["min_rate"], FULL_RATE)
            self.assertEqual(len(result["windows"]), 2)
            self.assertTrue(all(window["count"] >= FULL_RATE
                                for window in result["windows"]),
                            result["windows"])
            self.assertEqual(result["conservation"]["entries"], 20006)
            self.assertEqual(result["joint"]["status"], "populated")
            self.assertEqual(result["joint"]["keys"], 1)
            self.assertEqual(result["joint"]["per_key_ops"], [9999])
            self.assertEqual(result["loss"]["events_lost"], 0)
            self.assertEqual(result["latency"]["samples"], 20006)

    def test_healthy_joint_churn_passes_with_uneven_keys(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-churn-") as tmp:
            workdir = Path(tmp)
            ops = (2500, 2000, 1500)
            ledgers, events, inventory = healthy_joint_triple(
                workdir, ops_per_key=ops, per_s=1000, sessions=8)
            result = s1.compare([str(path) for path in ledgers],
                                [str(events)], str(inventory),
                                1000, joint=True)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["joint"]["keys"], 3)
            self.assertEqual(result["joint"]["per_key_ops"],
                             [1500, 2000, 2500])
            self.assertEqual(result["issued"], 11 + 12006 + 9)

    def test_healthy_joint_via_cli_reports_the_joint_block(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-cli-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = s1.main(["--joint", "--min-rate", str(FULL_RATE),
                              "--ledger", str(ledgers[0]),
                              "--ledger", str(ledgers[1]),
                              "--ledger", str(ledgers[2]),
                              "--events", str(events),
                              "--inventory", str(inventory)])
            self.assertEqual(rc, 0)
            verdict = json.loads(out.getvalue())
            self.assertEqual(verdict["verdict"], "pass")
            self.assertIn("joint", verdict)
            self.assertNotIn("s1", verdict)

    def test_joint_windows_ignore_an_early_setup(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-earlysetup-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            shifted = []
            for line in ledgers[0].read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                if row["kind"] == "ready":
                    row["t"] -= 5_000_000_000
                elif row["kind"] == "call":
                    row["t0"] -= 5_000_000_000
                    row["t1"] -= 5_000_000_000
                else:
                    row["t"] -= 5_000_000_000
                shifted.append(row)
            write_jsonl(ledgers[0], shifted)
            result = s1.compare([str(path) for path in ledgers],
                                [str(events)], str(inventory),
                                FULL_RATE, joint=True)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["issued"], 20006)

    def test_joint_windows_exclude_setup_calls(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-nosetuppad-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(
                workdir, ops_per_key=(9998,), per_s=9999)
            with self.assertRaisesRegex(
                    s1.S1Error, r"window 0: 9999 calls/s below minimum"):
                s1.compare([str(path) for path in ledgers], [str(events)],
                           str(inventory), FULL_RATE, joint=True)

    def test_joint_fails_via_cli_with_a_json_fail_verdict(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-clifail-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            doc = json.loads(inventory.read_text(encoding="utf-8"))
            doc["object_observations"]["status"] = "unavailable"
            doc["object_observations"]["reason"] = "journal_unavailable"
            write_json(inventory, doc)
            out = io.StringIO()
            err = io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                rc = s1.main(["--joint",
                              "--ledger", str(ledgers[0]),
                              "--ledger", str(ledgers[1]),
                              "--ledger", str(ledgers[2]),
                              "--events", str(events),
                              "--inventory", str(inventory)])
            self.assertEqual(rc, 1)
            verdict = json.loads(out.getvalue())
            self.assertEqual(verdict["verdict"], "fail")
            self.assertIn("journal_unavailable", verdict["reason"])
            self.assertNotIn("Traceback", err.getvalue())


class JointActiveGate(unittest.TestCase):
    def run_joint(self, workdir, mutate=None, ops_per_key=(9999,),
                  min_rate=FULL_RATE, **kwargs):
        s1 = require_s1(self)
        ledgers, events, inventory = healthy_joint_triple(
            workdir, ops_per_key=ops_per_key, **kwargs)
        if mutate is not None:
            doc = json.loads(inventory.read_text(encoding="utf-8"))
            mutate(doc)
            write_json(inventory, doc)
        return s1.compare([str(path) for path in ledgers], [str(events)],
                          str(inventory), min_rate, joint=True)

    def test_unavailable_object_observations_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-unavail-") as tmp:
            def mutate(doc):
                doc["object_observations"]["status"] = "unavailable"
                doc["object_observations"]["reason"] = "bootstrap_unavailable"
                doc["object_observations"]["key_operations"] = []
                doc["object_observations"]["objects"] = []
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "bootstrap_unavailable"):
                self.run_joint(Path(tmp), mutate)

    def test_journal_unavailable_reason_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-junavail-") as tmp:
            def mutate(doc):
                doc["object_observations"]["status"] = "unavailable"
                doc["object_observations"]["reason"] = "journal_unavailable"
                doc["object_observations"]["key_operations"] = []
                doc["object_observations"]["objects"] = []
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "journal_unavailable"):
                self.run_joint(Path(tmp), mutate)

    def test_unlinked_disclosure_gap_fails(self):
        for subject in ("semantic lane disclosure",
                        "per-key tracking is off; "
                        "this capture keeps S1 mechanisms and API results"):
            with tempfile.TemporaryDirectory(prefix="joint-discl-") as tmp:
                def mutate(doc, subject=subject):
                    doc["gaps"].append(
                        {"caller": None, "module": None, "pid": None,
                         "subject": subject,
                         "reason": "joint_journal_unavailable",
                         "budget": None, "repeats": 1})
                with self.assertRaisesRegex(
                        require_s1(self).S1Error,
                        "joint_journal_unavailable"):
                    self.run_joint(Path(tmp), mutate)

    def test_per_key_count_off_by_one_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-offbyone-") as tmp:
            def mutate(doc):
                row = doc["object_observations"]["key_operations"][0]
                row["started"] += 1
                row["completed"] += 1
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "per-key"):
                self.run_joint(Path(tmp), mutate)

    def test_key_never_created_in_the_window_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-nocreate-") as tmp:
            def mutate(doc):
                doc["object_observations"]["objects"] = []
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "created"):
                self.run_joint(Path(tmp), mutate)

    def test_birth_outside_the_window_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-birth-") as tmp:
            def mutate(doc):
                view = doc["object_observations"]["objects"][0]
                view["birth"] = {"start_ns": R0 - 2_000_000_000,
                                 "end_ns": R0 - 1_000_000_000}
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "birth"):
                self.run_joint(Path(tmp), mutate)

    def test_live_key_never_destroyed_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-live-") as tmp:
            def mutate(doc):
                doc["object_observations"]["objects"][0]["lifetime"] = "live"
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "destroyed"):
                self.run_joint(Path(tmp), mutate)

    def test_unknown_key_operations_fail(self):
        with tempfile.TemporaryDirectory(prefix="joint-unknown-") as tmp:
            def mutate(doc):
                doc["object_observations"]["unknown_key_operations"] = [
                    {"category": "sign", "reason": "unbound",
                     "unit": "operations", "completed": 1, "failed": 0,
                     "cancelled": 0, "unknown": 0, "active": 0}]
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "unknown-key"):
                self.run_joint(Path(tmp), mutate)

    @staticmethod
    def unknown_metadata(doc, unknown_signs):
        """The product's shape when the workload never exposed key
        metadata: no labelled key rows, every sign in the fixed
        `metadata_unknown` summary, identity kept by each key's
        successful key references."""
        observed = doc["object_observations"]
        keys = len(observed["objects"])
        observed["key_operations"] = []
        observed["unknown_key_operations"] = [
            joint_unknown_row("generate_key", "not_applicable", keys),
            joint_unknown_row("sign", "metadata_unknown", unknown_signs)]

    def test_metadata_unknown_signs_with_exact_identity_pass(self):
        with tempfile.TemporaryDirectory(prefix="joint-mdunk-") as tmp:
            result = self.run_joint(
                Path(tmp), lambda doc: self.unknown_metadata(doc, 9999))
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["joint"]["per_key_ops"], [9999])

    def test_metadata_unknown_churn_with_exact_identity_passes(self):
        with tempfile.TemporaryDirectory(prefix="joint-mdunk-churn-") as tmp:
            result = self.run_joint(
                Path(tmp), lambda doc: self.unknown_metadata(doc, 6000),
                ops_per_key=(2500, 2000, 1500), per_s=1000, sessions=8,
                min_rate=1000)
            self.assertEqual(result["verdict"], "pass")

    def test_labelled_and_unknown_signs_sum_exactly(self):
        with tempfile.TemporaryDirectory(prefix="joint-mixed-") as tmp:
            def mutate(doc):
                observed = doc["object_observations"]
                observed["key_operations"][0]["started"] = 9000
                observed["key_operations"][0]["completed"] = 9000
                observed["unknown_key_operations"].append(
                    joint_unknown_row("sign", "metadata_unknown", 999))
            result = self.run_joint(Path(tmp), mutate)
            self.assertEqual(result["verdict"], "pass")

    def test_metadata_unknown_missing_sign_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-mdunk-miss-") as tmp:
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "metadata_unknown != ledgered"):
                self.run_joint(Path(tmp),
                               lambda doc: self.unknown_metadata(doc, 9998))

    def test_metadata_unknown_extra_sign_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-mdunk-extra-") as tmp:
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "metadata_unknown != ledgered"):
                self.run_joint(Path(tmp),
                               lambda doc: self.unknown_metadata(doc, 10000))

    def test_metadata_unknown_missing_key_reference_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-mdunk-ref-") as tmp:
            def mutate(doc):
                self.unknown_metadata(doc, 9999)
                doc["object_observations"]["objects"][0][
                    "successful_key_references"] -= 1
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "per-key operations"):
                self.run_joint(Path(tmp), mutate)

    def test_misattributed_sign_fails(self):
        # One sign moves from one key's identity to another's: totals
        # stay exact, but the per-key identity multiset breaks.
        with tempfile.TemporaryDirectory(prefix="joint-misattr-") as tmp:
            def mutate(doc):
                self.unknown_metadata(doc, 6000)
                views = doc["object_observations"]["objects"]
                views[0]["successful_key_references"] -= 1
                views[1]["successful_key_references"] += 1
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "per-key operations"):
                self.run_joint(Path(tmp), mutate,
                               ops_per_key=(2500, 2000, 1500), per_s=1000,
                               sessions=8, min_rate=1000)

    def test_labelled_row_on_the_wrong_key_fails(self):
        # A labelled row names a key whose identity never saw that many
        # references: the label cannot move signs between keys.
        with tempfile.TemporaryDirectory(prefix="joint-wrongkey-") as tmp:
            def mutate(doc):
                rows = doc["object_observations"]["key_operations"]
                rows[0]["started"] -= 1
                rows[0]["completed"] -= 1
                rows[1]["started"] += 1
                rows[1]["completed"] += 1
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "per-key object"):
                self.run_joint(Path(tmp), mutate,
                               ops_per_key=(2500, 2000, 1500), per_s=1000,
                               sessions=8, min_rate=1000)

    def test_unknown_summary_with_failed_operations_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-mdunk-fail-") as tmp:
            def mutate(doc):
                self.unknown_metadata(doc, 9999)
                doc["object_observations"]["unknown_key_operations"][1][
                    "failed"] = 1
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "failed, cancelled"):
                self.run_joint(Path(tmp), mutate)

    def test_generation_count_must_match_the_ledgered_keys(self):
        with tempfile.TemporaryDirectory(prefix="joint-keygen-") as tmp:
            def mutate(doc):
                doc["object_observations"]["unknown_key_operations"][0][
                    "completed"] = 2
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "generate_key operations"):
                self.run_joint(Path(tmp), mutate)

    def test_foreign_instance_key_row_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-foreignrow-") as tmp:
            def mutate(doc):
                doc["object_observations"]["key_operations"].append(
                    joint_key_row("i9", 99, 5))
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "i9"):
                self.run_joint(Path(tmp), mutate)

    def test_session_count_mismatch_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-sessions-") as tmp:
            def mutate(doc):
                doc["object_observations"]["sessions"] = []
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "session"):
                self.run_joint(Path(tmp), mutate)

    def test_object_budget_refusal_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-budget-") as tmp:
            def mutate(doc):
                budgets = doc["object_observations"]["budgets"]
                budgets["key_rows"]["refused"] = 1
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "refuse"):
                self.run_joint(Path(tmp), mutate)

    def test_object_gap_rows_or_suppression_fail(self):
        def add_row(doc):
            doc["object_observations"]["gaps"]["rows"].append(
                {"subject": "key row shed", "reason": "budget"})
        def suppress(doc):
            doc["object_observations"]["gaps"]["suppressed"] = 1
        for name, mutate in (("rows", add_row),
                             ("suppressed", suppress)):
            with tempfile.TemporaryDirectory(prefix="joint-ogap-") as tmp:
                with self.assertRaisesRegex(
                        require_s1(self).S1Error,
                        "gap rows or suppression"):
                    self.run_joint(Path(tmp), mutate)

    def test_key_row_equation_break_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-equation-") as tmp:
            def mutate(doc):
                row = doc["object_observations"]["key_operations"][0]
                row["completed"] += 1
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "row equation"):
                self.run_joint(Path(tmp), mutate)

    def test_completed_short_of_started_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-completed-") as tmp:
            def mutate(doc):
                row = doc["object_observations"]["key_operations"][0]
                row["failed"] = 1
                row["completed"] -= 1
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "has completed"):
                self.run_joint(Path(tmp), mutate)

    def test_key_row_identity_fields_fail(self):
        for field, bad in (("category", "digest"), ("role", "session"),
                           ("unit", "calls")):
            with tempfile.TemporaryDirectory(prefix="joint-ident-") as tmp:
                def mutate(doc, field=field, bad=bad):
                    doc["object_observations"]["key_operations"][0][field] = bad
                with self.assertRaisesRegex(require_s1(self).S1Error,
                                            field):
                    self.run_joint(Path(tmp), mutate)

    def test_extra_object_view_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-extraobj-") as tmp:
            def mutate(doc):
                doc["object_observations"]["objects"].append(
                    joint_object_view(99, origin="imported",
                                      creation="unwrap"))
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "object views"):
                self.run_joint(Path(tmp), mutate)

    def test_birth_without_an_observed_interval_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-birthshape-") as tmp:
            def mutate(doc):
                view = doc["object_observations"]["objects"][0]
                view["birth"] = {"start_ns": R0, "end_ns": "soon"}
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "observed interval"):
                self.run_joint(Path(tmp), mutate)

    def test_session_shape_failures_fail(self):
        for field, bad, expect in (("origin", "imported", "not opened"),
                                  ("status", "open", "not closed")):
            with tempfile.TemporaryDirectory(prefix="joint-sesshape-") as tmp:
                def mutate(doc, field=field, bad=bad):
                    doc["object_observations"]["sessions"][0][field] = bad
                with self.assertRaisesRegex(require_s1(self).S1Error,
                                            expect):
                    self.run_joint(Path(tmp), mutate)

    def test_expected_per_key_without_a_key_file_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-nokeyfile-") as tmp:
            workdir = Path(tmp)
            s1 = require_s1(self)
            ledger, _events, _inventory = healthy_triple(workdir)
            view = s1.load_ledgers([str(ledger)])
            with self.assertRaisesRegex(s1.S1Error, "no key file"):
                s1._joint_expected_per_key(view)


class JointConservationGate(unittest.TestCase):
    def run_joint(self, workdir, mutate=None, ops_per_key=(9999,),
                  min_rate=FULL_RATE, **kwargs):
        s1 = require_s1(self)
        ledgers, events, inventory = healthy_joint_triple(
            workdir, ops_per_key=ops_per_key, **kwargs)
        if mutate is not None:
            doc = json.loads(inventory.read_text(encoding="utf-8"))
            mutate(doc)
            edge = next(row for row in doc["edges"]
                        if row["caller"] == "c1")
            write_json(inventory, doc)
            rewrite_joint_events_for_edge(
                workdir, edge, joint_hot_last_t1(ledgers))
        return s1.compare([str(path) for path in ledgers], [str(events)],
                          str(inventory), min_rate, joint=True)

    def test_s1_tally_is_not_the_joint_denominator(self):
        with tempfile.TemporaryDirectory(prefix="joint-s1tally-") as tmp:
            def mutate(doc):
                child = doc["semantic_edges"][0]
                child["operations"]["calls"] = 65
                child["api_returns"]["count"] = 65
                for row in child["mechanisms"]:
                    row["calls"] = 0
                    row["errors"] = 0
                child["mechanisms"][0]["calls"] = 65
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "65 != issued 20006"):
                self.run_joint(Path(tmp), mutate)

    def test_missing_keygen_row_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-nokeygen-") as tmp:
            def mutate(doc):
                child = doc["semantic_edges"][0]
                child["mechanisms"] = [child["mechanisms"][0]]
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "C_GenerateKey"):
                self.run_joint(Path(tmp), mutate)

    def test_digest_mechanism_fails_for_the_keyed_workload(self):
        with tempfile.TemporaryDirectory(prefix="joint-digest-") as tmp:
            def mutate(doc):
                row = doc["semantic_edges"][0]["mechanisms"][0]
                row["mechanism"] = 0x250
                row["mechanism_hex"] = "0x250"
                row["name"] = "CKM_SHA256"
                row["operations"] = ["digest"]
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "0x251"):
                self.run_joint(Path(tmp), mutate)

    def test_setup_call_inside_a_mechanism_row_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-setuprow-") as tmp:
            def mutate(doc):
                row = doc["semantic_edges"][0]["mechanisms"][0]
                row["evidence"]["functions"].append("C_OpenSession")
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "C_OpenSession"):
                self.run_joint(Path(tmp), mutate)

    def test_foreign_refused_endpoints_are_recorded_never_gated(self):
        with tempfile.TemporaryDirectory(prefix="joint-refused-") as tmp:
            workdir = Path(tmp)
            s1 = require_s1(self)
            ledgers, events, inventory = healthy_joint_triple(
                workdir, refused_endpoints=3792, continuity_cuts=3)
            result = s1.compare([str(path) for path in ledgers],
                                [str(events)], str(inventory),
                                FULL_RATE, joint=True)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["loss"]["refused_endpoints"], 3792)
            self.assertEqual(result["loss"]["continuity_cuts"], 3)

    def test_foreign_scoped_gap_is_counted_never_gated(self):
        with tempfile.TemporaryDirectory(prefix="joint-fgap-") as tmp:
            workdir = Path(tmp)
            s1 = require_s1(self)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            doc = json.loads(inventory.read_text(encoding="utf-8"))
            doc["gaps"].append(
                {"caller": "c0", "module": "m0", "pid": 999,
                 "subject": "semantic admission refused",
                 "reason": "semantic_unavailable:no_receipt",
                 "budget": None, "repeats": 3792})
            write_json(inventory, doc)
            result = s1.compare([str(path) for path in ledgers],
                                [str(events)], str(inventory),
                                FULL_RATE, joint=True)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["loss"]["foreign_gaps"], 1)

    def test_callerless_shed_gap_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-shed-") as tmp:
            def mutate(doc):
                doc["gaps"].append(
                    {"caller": None, "module": None, "pid": None,
                     "subject": "semantic calls unrouted",
                     "reason": "13 calls shed without a route "
                               "(unobserved=13) with 0 bindings",
                     "budget": None, "repeats": 1})
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "loss gap"):
                self.run_joint(Path(tmp), mutate)

    def test_other_caller_unrouted_gap_is_reported_never_gated(self):
        # A shed whose records prove a caller other than the bound one
        # is the other caller's loss: reported beside the verdict, not
        # a gap in the bound caller's completeness.
        with tempfile.TemporaryDirectory(prefix="joint-oshed-") as tmp:
            def mutate(doc):
                doc["gaps"].append(
                    {"caller": None, "module": None, "pid": None,
                     "subject": OTHER_UNROUTED,
                     "reason": "18 calls shed without a route "
                               "(unobserved=18) from callers other than "
                               "the 1 bound callers",
                     "budget": None, "repeats": 1})
            result = self.run_joint(Path(tmp), mutate)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["loss"]["other_caller_unrouted"], 18)

    def test_other_caller_unrouted_gap_on_the_bound_caller_fails(self):
        # Never trust the subject alone: attributed to the bound caller
        # itself it stays a loss gap.
        with tempfile.TemporaryDirectory(prefix="joint-oshedb-") as tmp:
            def mutate(doc):
                doc["gaps"].append(
                    {"caller": "c1", "module": None, "pid": None,
                     "subject": OTHER_UNROUTED,
                     "reason": "2 calls shed without a route "
                               "(unobserved=2) from callers other than "
                               "the 1 bound callers",
                     "budget": None, "repeats": 1})
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "loss gap"):
                self.run_joint(Path(tmp), mutate)

    def test_slot_refused_setup_conserved(self):
        # The live keyed shape: the two COUNT_ONLY slot probes are
        # refused at conversion and disclosed, so operations and
        # api_returns equal issued minus the named slot term.
        with tempfile.TemporaryDirectory(prefix="joint-slot-") as tmp:
            def mutate(doc):
                child = doc["semantic_edges"][0]
                issued = 20006
                child["operations"]["calls"] = issued - 2
                child["api_returns"]["count"] = issued - 2
                doc["gaps"].append(
                    {"caller": "c1", "module": None, "pid": None,
                     "subject": "semantic input refused", "reason": "slot",
                     "budget": None, "repeats": 2})
            result = self.run_joint(Path(tmp), mutate)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["conservation"]["slot_refused"], 2)

    def test_slot_refused_short_without_gap_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-slot0-") as tmp:
            def mutate(doc):
                child = doc["semantic_edges"][0]
                child["operations"]["calls"] = 20004
                child["api_returns"]["count"] = 20004
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "minus slot-refused 0"):
                self.run_joint(Path(tmp), mutate)

    def test_slot_refused_overcounted_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-slotn-") as tmp:
            def mutate(doc):
                doc["gaps"].append(
                    {"caller": "c1", "module": None, "pid": None,
                     "subject": "semantic input refused", "reason": "slot",
                     "budget": None, "repeats": 2})
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "minus slot-refused 2"):
                self.run_joint(Path(tmp), mutate)

    def test_slot_refused_exceeds_issued_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-slotx-") as tmp:
            def mutate(doc):
                doc["gaps"].append(
                    {"caller": "c1", "module": None, "pid": None,
                     "subject": "semantic input refused", "reason": "slot",
                     "budget": None, "repeats": 20007})
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "exceeds issued"):
                self.run_joint(Path(tmp), mutate)

    def test_slot_refused_foreign_scope_ignored(self):
        with tempfile.TemporaryDirectory(prefix="joint-slotf-") as tmp:
            def mutate(doc):
                child = doc["semantic_edges"][0]
                child["operations"]["calls"] = 20004
                child["api_returns"]["count"] = 20004
                doc["gaps"].append(
                    {"caller": "c0", "module": "m0", "pid": 999,
                     "subject": "semantic input refused", "reason": "slot",
                     "budget": None, "repeats": 2})
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "minus slot-refused 0"):
                self.run_joint(Path(tmp), mutate)

    def test_cross_row_mechanism_swap_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-xrow-") as tmp:
            def mutate(doc):
                child = doc["semantic_edges"][0]
                sign, keygen = child["mechanisms"]
                sign["evidence"]["functions"].append("C_GenerateKey")
                sign["calls"] += keygen["calls"]
                sign["errors"] += keygen["errors"]
                child["mechanisms"] = [sign]
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "pinned"):
                self.run_joint(Path(tmp), mutate)

    def test_native_capture_events_lost_gap_fails(self):
        reason = ("the EVENTS ring was full; the kernel refused records "
                  "before the drain could read them (kernel reserve "
                  "failures; exact count in events_lost)")
        with tempfile.TemporaryDirectory(prefix="joint-evloss-") as tmp:
            def mutate(doc):
                doc["gaps"].append(
                    {"caller": None, "module": None, "pid": None,
                     "subject": "native capture events lost",
                     "reason": reason, "budget": None, "repeats": 1})
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "loss gap"):
                self.run_joint(Path(tmp), mutate)

    def test_native_capture_events_loss_unknown_gap_fails(self):
        reason = ("the EVENTS ring-loss counter could not be read; "
                  "events_lost may undercount until a later good read "
                  "restores the exact cumulative total")
        with tempfile.TemporaryDirectory(prefix="joint-evunk-") as tmp:
            def mutate(doc):
                doc["gaps"].append(
                    {"caller": None, "module": None, "pid": None,
                     "subject": "native capture events loss unknown",
                     "reason": reason, "budget": None, "repeats": 1})
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "loss gap"):
                self.run_joint(Path(tmp), mutate)

    def test_events_lost_nonzero_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-evlost-n-") as tmp:
            def mutate(doc):
                doc["observation"]["semantic_capture"]["events_lost"] = 3
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "events_lost 3"):
                self.run_joint(Path(tmp), mutate)

    def test_events_lost_missing_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-evlost-m-") as tmp:
            def mutate(doc):
                del doc["observation"]["semantic_capture"]["events_lost"]
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "events_lost missing"):
                self.run_joint(Path(tmp), mutate)

    def test_native_capture_events_lost_event_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-evlost-ev-") as tmp:
            workdir = Path(tmp)
            s1 = require_s1(self)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            rows = [json.loads(line) for line in
                    events.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
            ended = rows[-1]
            assert ended["kind"] == "ended"
            gap = event_envelope(ended["seq"], R0 + 1_000, "gap_recorded",
                                 {"index": 0, "caller": None, "module": None,
                                  "pid": None,
                                  "subject": "native capture events lost",
                                  "reason": "ring overwrite before drain",
                                  "budget": None})
            rows.insert(-1, gap)
            ended["seq"] += 1
            write_jsonl(events, rows)
            with self.assertRaisesRegex(s1.S1Error, "loss gap"):
                s1.compare([str(path) for path in ledgers], [str(events)],
                           str(inventory), FULL_RATE, joint=True)

    def test_joint_requires_system_scope(self):
        with tempfile.TemporaryDirectory(prefix="joint-scope-") as tmp:
            workdir = Path(tmp)
            s1 = require_s1(self)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            doc = json.loads(inventory.read_text(encoding="utf-8"))
            doc["scope"] = f"pid:{PID}"
            write_json(inventory, doc)
            with self.assertRaisesRegex(s1.S1Error, "system"):
                s1.compare([str(path) for path in ledgers], [str(events)],
                           str(inventory), FULL_RATE, joint=True)

    def test_joint_events_scope_must_be_system(self):
        with tempfile.TemporaryDirectory(prefix="joint-evscope-") as tmp:
            workdir = Path(tmp)
            s1 = require_s1(self)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            rows = [json.loads(line) for line in
                    events.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
            assert rows[0]["kind"] == "started"
            rows[0]["event"]["scope"] = f"pid:{PID}"
            write_jsonl(events, rows)
            with self.assertRaisesRegex(s1.S1Error, "not --system"):
                s1.compare([str(path) for path in ledgers], [str(events)],
                           str(inventory), FULL_RATE, joint=True)

    def test_missing_driver_caller_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-nodriver-") as tmp:
            def mutate(doc):
                doc["callers"] = [doc["callers"][0]]
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        str(PID)):
                self.run_joint(Path(tmp), mutate)

    def test_retired_driver_fails(self):
        with tempfile.TemporaryDirectory(prefix="joint-retired-") as tmp:
            def mutate(doc):
                doc["callers"][1]["retired"] = True
            with self.assertRaisesRegex(require_s1(self).S1Error,
                                        "retained"):
                self.run_joint(Path(tmp), mutate)


def split_joint_events_at(workdir, events_path, cut):
    """Split a Joint event log into two rotation parts at row `cut`.

    The concatenated stream stays exactly contiguous: the `rotated`
    marker takes the next sequence number and the tail shifts by one
    (production shape; the shared loader sorts by seq, so the marker
    position inside the current part is irrelevant). The ended
    summary records one rotation with nothing evicted. Returns both
    part paths.
    """
    rows = [json.loads(line) for line in
            events_path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    first, rest = rows[:cut], rows[cut:]
    older = workdir / (events_path.name + ".1")
    write_jsonl(older, first)
    marker_seq = first[-1]["seq"] + 1
    marker = {"schema": "p11scope/inventory-events/v1", "seq": marker_seq,
              "at_ns": rest[0]["at_ns"], "kind": "rotated",
              "event": {"prior_file": older.name,
                        "prior_events": len(first),
                        "prior_bytes": older.stat().st_size,
                        "rotation_seq": 1}}
    renumbered = []
    seq = marker_seq + 1
    for row in rest:
        row = dict(row)
        row["seq"] = seq
        seq += 1
        renumbered.append(row)
    for row in renumbered:
        if row["kind"] == "ended":
            row["event"]["stream"] = {"rotations": 1, "evicted_events": 0,
                                      "evicted_bytes": 0}
    write_jsonl(events_path, [marker] + renumbered)
    return older, events_path


class JointRotation(unittest.TestCase):
    def test_joint_rotated_stream_passes(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-rot-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            older, current = split_joint_events_at(workdir, events, 3)
            result = s1.compare([str(path) for path in ledgers],
                                [str(older), str(current)], str(inventory),
                                FULL_RATE, joint=True)
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["loss"]["stream_rotations"], 1)

    def test_joint_evicted_stream_fails(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-evict-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            older, current = split_joint_events_at(workdir, events, 3)
            rows = [json.loads(line) for line in
                    current.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
            for row in rows:
                if row["kind"] == "ended":
                    row["event"]["stream"]["evicted_events"] = 4
                    row["event"]["stream"]["evicted_bytes"] = 400
            write_jsonl(current, rows)
            with self.assertRaisesRegex(s1.S1Error, "retention"):
                s1.compare([str(path) for path in ledgers],
                           [str(older), str(current)], str(inventory),
                           FULL_RATE, joint=True)

    def test_joint_rotation_hole_fails(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-hole-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            older, current = split_joint_events_at(workdir, events, 3)
            rows = [json.loads(line) for line in
                    current.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
            for row in rows[1:]:
                row["seq"] += 1
            write_jsonl(current, rows)
            with self.assertRaisesRegex(s1.S1Error, "sequence"):
                s1.compare([str(path) for path in ledgers],
                           [str(older), str(current)], str(inventory),
                           FULL_RATE, joint=True)

    def test_joint_rotation_count_mismatch_fails(self):
        s1 = require_s1(self)
        with tempfile.TemporaryDirectory(prefix="joint-rotcount-") as tmp:
            workdir = Path(tmp)
            ledgers, events, inventory = healthy_joint_triple(workdir)
            older, current = split_joint_events_at(workdir, events, 3)
            rows = [json.loads(line) for line in
                    current.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
            for row in rows:
                if row["kind"] == "ended":
                    row["event"]["stream"]["rotations"] = 2
            write_jsonl(current, rows)
            with self.assertRaisesRegex(s1.S1Error, "rotation"):
                s1.compare([str(path) for path in ledgers],
                           [str(older), str(current)], str(inventory),
                           FULL_RATE, joint=True)


if __name__ == "__main__":
    unittest.main()

