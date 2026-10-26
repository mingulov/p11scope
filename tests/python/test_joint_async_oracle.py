#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Async-collision fixture/oracle twins.

The oracle (scripts/joint-async-compare.py) compares two per-process
ledgers from tests/fixtures/async-collision/collide.c (driving the new
tests/fixtures/async-collision/collide-provider.c stub) against a
joint-path and an S1Only-path object_observations section plus one
event stream per path: collision identity (distinct processes, one
owner and one challenger, different mechanisms, equal slot/target,
distinct sessions, every challenger id owned), outcomes derived from
observed return values, refused joins with preserved S1 completion,
transfer legitimacy, fenced terminals, paired-path equality, revision
order, cumulative counts, receipts, and interleave order.

Healthy and mutation twins run here; the live-emission tests build the
new provider and driver with gcc (LP64 and -m32) and compare the real
emitted ledgers.
"""

import copy
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
ORACLE_PATH = ROOT / "scripts" / "joint-async-compare.py"
DRIVER_SRC = ROOT / "tests" / "fixtures" / "async-collision" / "collide.c"
PROVIDER_SRC = ROOT / "tests" / "fixtures" / "async-collision" / "collide-provider.c"
STUB_PROVIDER_SRC = ROOT / "tests" / "fixtures" / "live-discovery-provider.c"

try:
    _SPEC = importlib.util.spec_from_file_location(
        "joint_async_oracle", ORACLE_PATH
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


PENDING = 0x204
TOO_SMALL = 0x150
BAD = 7


def scenario(process, role, mechanism, metadata, session, instance, object_id):
    return {"process": process, "role": role, "mechanism": mechanism,
            "slot": 0, "target": "async_begin", "metadata": metadata,
            "session": session, "instance": instance, "object": object_id}


SCEN = {
    "owner_poll": scenario("A", "owner", "poll", "rsa_2048", 1, "i3", 11),
    "owner_persisted": scenario("A", "owner", "persisted", "rsa_2048", 1,
                                "i3", 11),
    "chal_message": scenario("B", "challenger", "message", "rsa_2048", 2,
                             "i4", 12),
    "chal_message_null": scenario("B", "challenger", "message", None, 2,
                                  "i4", 12),
    "chal_cancel": scenario("B", "challenger", "cancel", "rsa_2048", 2,
                            "i4", 12),
}

MODES = {
    "poll_msg": ("owner_poll", "chal_message"),
    "cancel": ("owner_poll", "chal_cancel"),
    "persisted": ("owner_persisted", "chal_message_null"),
}


def call(op, fn, phase, rv, aid):
    return ("call", op, fn, phase, rv, aid)


def plan_poll_owner(ops, ids=None):
    ids = ids or list(range(1, ops + 1))
    steps = []
    for index, op in enumerate(range(1, ops + 1)):
        aid = ids[index]
        steps.append(call(op, "async_begin", "begin", 0, aid))
        steps.append(call(op, "async_poll", "pending", PENDING, aid))
        if op == 1:
            steps.append(call(op, "async_status", "query", PENDING, aid))
        steps.append(call(op, "async_poll", "pending", PENDING, aid))
        steps.append(call(op, "async_poll", "terminal", 0, aid))
    return steps


def plan_message_challenger(ops, ids=None):
    ids = ids or list(range(1, ops + 1))
    steps = []
    for index, op in enumerate(range(1, ops + 1)):
        aid = ids[index]
        steps.append(call(op, "async_begin", "begin", 0, aid))
        steps.append(call(op, "async_wait", "too_small", TOO_SMALL, aid))
        steps.append(call(op, "async_wait", "terminal", 0, aid))
    return steps


def plan_cancel_challenger(ops):
    steps = [call(1, "async_begin_fail", "begin", BAD, 0)]
    for op in range(2, ops + 1):
        aid = op - 1
        steps.append(call(op, "async_begin", "begin", 0, aid))
        steps.append(call(op, "async_poll", "pending", PENDING, aid))
        steps.append(call(op, "async_cancel", "cancel", 0, aid))
    steps.append(call(0, "async_finalize", "teardown", 0, 0))
    steps.append(("fence", "finalize"))
    late = ops + 1
    steps.append(call(late, "async_begin", "begin", 0, ops))
    steps.append(call(late, "async_poll", "pending", PENDING, ops))
    steps.append(call(late, "async_poll", "pending", PENDING, ops))
    steps.append(call(late, "async_poll", "terminal", 0, ops))
    return steps


def plan_persisted_owner(ops, ids=None):
    ids = ids or list(range(1, ops + 1))
    steps = []
    for index, op in enumerate(range(1, ops + 1)):
        aid = ids[index]
        steps.append(call(op, "async_begin", "begin", 0, aid))
        steps.append(call(op, "async_poll", "pending", PENDING, aid))
        steps.append(call(op, "async_status", "query", PENDING, aid))
        steps.append(call(op, "async_poll", "pending", PENDING, aid))
        steps.append(call(op, "async_poll", "terminal", 0, aid))
        steps.append(call(op, "async_status", "query", 0, aid))
    return steps


PLANS = {
    "owner_poll": plan_poll_owner,
    "owner_persisted": plan_persisted_owner,
    "chal_message": plan_message_challenger,
    "chal_message_null": plan_message_challenger,
    "chal_cancel": plan_cancel_challenger,
}


def build_ledger(scen, steps, pid=4242, tid=4242, tick=1_000):
    """Canned collision ledger: ready, scenario, sequenced rows, ack."""
    rows = [{"kind": "ready", "pid": pid, "tid": tid, "t": tick,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    rows.append({"kind": "scenario", **scen})
    seq, calls = 0, 0
    for step in steps:
        seq += 1
        tick += 10
        start, end = tick, tick + 5
        tick = end
        if step[0] == "call":
            _, op, fn, phase, rv, aid = step
            calls += 1
            rows.append({"kind": "call", "seq": seq, "fn": fn, "rv": rv,
                         "pid": pid, "tid": tid, "t0": start, "t1": end,
                         "process": scen["process"], "op": op, "phase": phase,
                         "async_id": aid})
        elif step[0] == "fence":
            rows.append({"kind": "fence", "seq": seq, "fence": step[1],
                         "t": end})
        elif step[0] == "transfer":
            _, op, frm, to, aid = step
            rows.append({"kind": "transfer", "seq": seq, "op": op,
                         "from_pid": frm, "to_pid": to, "async_id": aid,
                         "t": end})
        else:  # pragma: no cover - builder misuse, not oracle input
            raise AssertionError(f"bad step {step}")
    rows.append({"kind": "ack", "issued": calls, "sequenced": seq,
                 "t": tick + 10})
    return rows


def validated_pair(oracle, mode, ops=2, pid_a=4242, pid_b=4343):
    key_a, key_b = MODES[mode]
    rows_a = build_ledger(SCEN[key_a], PLANS[key_a](ops), pid=pid_a)
    rows_b = build_ledger(SCEN[key_b], PLANS[key_b](ops), pid=pid_b)
    first = oracle.validate_ledger(rows_a, "ledger A")
    second = oracle.validate_ledger(rows_b, "ledger B")
    return rows_a, rows_b, first, second


def metadata_block():
    return {"class": {"status": "value", "value": 3},
            "key_type": {"status": "value", "value": 0},
            "token": {"status": "value", "value": 0},
            "value_len": {"status": "unknown", "value": None},
            "modulus_bits": {"status": "value", "value": 2048},
            "ec_params": {"status": "unknown", "value": None}}


def queries_block():
    return {"class": "established", "key_type": "established",
            "token": "established", "value_len": "not_queried",
            "modulus_bits": "established", "ec_params": "not_queried"}


def object_row(object_id, label):
    return {"object": object_id, "session": 1, "origin": "created",
            "creation": "generate_pair",
            "birth": {"start_ns": 1, "end_ns": 2},
            "lifetime": "live", "lifetime_reason": None,
            "attribution": "valid", "attribution_reason": None,
            "requested": metadata_block(), "established": metadata_block(),
            "queries": queries_block(), "label": label,
            "successful_references": 1, "successful_key_references": 1,
            "accessing_sessions": 1}


def section(objects, key_rows, unknown_rows, gaps):
    return {"version": 1, "revision": 7, "status": "populated",
            "reason": "none",
            "sessions": [{"session": 1, "origin": "opened",
                          "status": "live"}],
            "objects": objects, "key_operations": key_rows,
            "unknown_key_operations": unknown_rows,
            "gaps": {"rows": gaps, "suppressed": 0},
            "budgets": {
                "key_rows": {"limit": 65536, "occupied": len(key_rows),
                             "refused": 0},
                "object_rows": {"limit": 65536, "occupied": len(objects),
                                "refused": 0},
                "unknown_rows": {"occupied": len(unknown_rows)},
                "encoded_bytes": 100, "allocation_refused": False,
                "refusal_reason": "none"}}


def healthy_joint(oracle, collision):
    """Build the consistent joint section for a validated collision."""
    owner, challenger = collision["owner"], collision["challenger"]
    owned = oracle._owner_tally(owner, collision)
    chaled = oracle._challenger_tally(challenger, collision)
    objects, key_rows, unknown_rows = [], [], []
    if owner["metadata"] is not None:
        objects.append(object_row(owner["object"], owner["metadata"]))
        key_rows.append({"instance": owner["instance"], "object": owner["object"],
                         "category": "operation", "role": "key",
                         "metadata_at_use": owner["metadata"],
                         "unit": "operations", "started": owned["begun"],
                         "completed": owned["completed"], "failed": owned["failed"],
                         "cancelled": owned["cancelled"], "unknown": 0,
                         "active": owned["pending"], "key_join_lost": 0})
    groups = {}
    if owner["metadata"] is None:
        groups.setdefault(("operation", "metadata_unknown"),
                          {"completed": 0, "failed": 0, "cancelled": 0,
                           "unknown": 0, "active": 0})
        for name in ("completed", "failed", "cancelled"):
            groups[("operation", "metadata_unknown")][name] += owned[name]
        groups[("operation", "metadata_unknown")]["active"] += owned["pending"]
    reason = ("metadata_unknown" if challenger["metadata"] is None
              else "unbound")
    groups.setdefault(("operation", reason),
                      {"completed": 0, "failed": 0, "cancelled": 0,
                       "unknown": 0, "active": 0})
    for name in ("completed", "failed", "cancelled"):
        groups[("operation", reason)][name] += chaled[name]
    groups[("operation", reason)]["active"] += chaled["pending"]
    for (category, gap_reason), counts in sorted(groups.items()):
        unknown_rows.append({"category": category, "reason": gap_reason,
                             "unit": "operations", **counts})
    gaps = []
    if chaled["completed"]:
        gaps.append({"subject": "key_operation",
                     "reason": "duplicate_completion",
                     "repeats": chaled["completed"]})
    fence_repeats = {}
    for feed in (owner, challenger):
        fenced = sum(1 for op in feed["ops"].values()
                     if op["outcome"] == "fenced")
        if fenced:
            fence_repeats[feed["fence"]] = \
                fence_repeats.get(feed["fence"], 0) + fenced
    for fence, repeats in sorted(fence_repeats.items()):
        gaps.append({"subject": "key_operation", "reason": fence,
                     "repeats": repeats})
    gaps.sort(key=lambda row: (row["subject"], row["reason"]))
    return section(objects, key_rows, unknown_rows, gaps)


def healthy_s1only(oracle, collision):
    """Build the consistent S1Only section for a validated collision."""
    owner, challenger = collision["owner"], collision["challenger"]
    owned = oracle._owner_tally(owner, collision)
    chaled = oracle._challenger_tally(challenger, collision)
    unknown = {"category": "operation", "reason": "unbound",
               "unit": "operations",
               "completed": owned["completed"] + chaled["completed"],
               "failed": owned["failed"] + chaled["failed"],
               "cancelled": owned["cancelled"] + chaled["cancelled"],
               "unknown": 0,
               "active": owned["pending"] + chaled["pending"]}
    return section([], [], [unknown], [])


def completion_events(collision, snapshot):
    """Per-row completion stamps in global terminal order."""
    owner, challenger = collision["owner"], collision["challenger"]
    crowns = {}
    owner_key = ("known", (owner["instance"], owner["object"], "operation",
                           "key", owner["metadata"]))
    chal_reason = ("metadata_unknown" if challenger["metadata"] is None
                   else "unbound")
    chal_key = ("unknown", ("operation", chal_reason))
    for op in owner["ops"].values():
        if op["outcome"] == "completed":
            crowns.setdefault(owner_key, []).append(
                (op["terminal_t1"], op["terminal_t0"]))
    for item in collision["transfers"]:
        if item["outcome"] == "completed":
            crowns.setdefault(owner_key, []).append(
                (item["terminal_t1"], item["terminal_t0"]))
    for op in challenger["ops"].values():
        if op["outcome"] == "completed":
            crowns.setdefault(chal_key, []).append(
                (op["terminal_t1"], op["terminal_t0"]))
    if owner["metadata"] is None:
        moved = crowns.pop(owner_key, [])
        target = ("unknown", ("operation", "metadata_unknown"))
        crowns.setdefault(target, []).extend(moved)
    ordered = []
    for key, stamps in crowns.items():
        for end, start in stamps:
            ordered.append((end, start, key))
    ordered.sort()
    return ordered, {key: [row for row in
                           snapshot["key_operations"]
                           + snapshot["unknown_key_operations"]
                           if ((row.get("instance"), row.get("object"),
                                row.get("category"), row.get("role"),
                                row.get("metadata_at_use")) == key[1]
                               if key[0] == "known" else
                               (row.get("category"), row.get("reason"))
                               == key[1])][0]
                     for key in crowns}


def healthy_stream(collision, snapshot):
    """Completion-ordered row events reconciling exactly to the snapshot."""
    lines = []
    seq = 0

    def envelope(kind, event, at_ns):
        nonlocal seq
        line = {"schema": "p11scope/inventory-events/v1", "seq": seq,
                "at_ns": at_ns, "kind": kind, "event": event}
        seq += 1
        return line

    revision = 1
    for row in snapshot["objects"]:
        lines.append(envelope("object_observed",
                              {"revision": revision, "row": copy.deepcopy(row)},
                              500))
    ordered, finals = completion_events(collision, snapshot)
    rank = {}
    for end, _start, key in ordered:
        revision += 1
        rank[key] = rank.get(key, 0) + 1
        row = copy.deepcopy(finals[key])
        row["completed"] = rank[key]
        if key[0] == "known":
            row["active"] = row["started"] - rank[key] - row["failed"]
        else:
            total = finals[key]["completed"] + finals[key]["failed"] \
                + finals[key]["active"]
            row["active"] = total - rank[key] - finals[key]["failed"]
        lines.append(envelope("key_operations_observed",
                              {"revision": revision,
                               "bucket": key[0], "row": row}, end + 100))
    for row in snapshot["key_operations"]:
        key = ("known", (row["instance"], row["object"], row["category"],
                         row["role"], row["metadata_at_use"]))
        if key not in rank:
            revision += 1
            lines.append(envelope("key_operations_observed",
                                  {"revision": revision, "bucket": "known",
                                   "row": copy.deepcopy(row)}, 750))
    for row in snapshot["unknown_key_operations"]:
        key = ("unknown", (row["category"], row["reason"]))
        if key not in rank:
            revision += 1
            lines.append(envelope("key_operations_observed",
                                  {"revision": revision, "bucket": "unknown",
                                   "row": copy.deepcopy(row)}, 750))
    base = ordered[-1][0] if ordered else 800
    lines.append(envelope("pass_committed",
                          {"pass": 1, "object_revision": revision,
                           "object_status": "populated", "gaps_suppressed": 0},
                          base + 200))
    lines.append(envelope("ended", {"gaps_suppressed": 0}, base + 300))
    return lines


def healthy_s1only_stream(collision, snapshot):
    """Completion-ordered events for the single S1Only unknown row."""
    lines = []
    seq = 0

    def envelope(kind, event, at_ns):
        nonlocal seq
        line = {"schema": "p11scope/inventory-events/v1", "seq": seq,
                "at_ns": at_ns, "kind": kind, "event": event}
        seq += 1
        return line

    owner, challenger = collision["owner"], collision["challenger"]
    ends = []
    for op in list(owner["ops"].values()) + list(challenger["ops"].values()):
        if op["outcome"] == "completed":
            ends.append(op["terminal_t1"])
    for item in collision["transfers"]:
        if item["outcome"] == "completed":
            ends.append(item["terminal_t1"])
    ends.sort()
    final = snapshot["unknown_key_operations"][0]
    revision = 1
    if not ends:
        revision += 1
        lines.append(envelope("key_operations_observed",
                              {"revision": revision, "bucket": "unknown",
                               "row": copy.deepcopy(final)}, 750))
    for rank, end in enumerate(ends, start=1):
        revision += 1
        row = copy.deepcopy(final)
        row["completed"] = rank
        total = final["completed"] + final["failed"] + final["active"]
        row["active"] = total - rank - final["failed"]
        lines.append(envelope("key_operations_observed",
                              {"revision": revision, "bucket": "unknown",
                               "row": row}, end + 100))
    base = ends[-1] if ends else 800
    lines.append(envelope("pass_committed",
                          {"pass": 1, "object_revision": revision,
                           "object_status": "populated", "gaps_suppressed": 0},
                          base + 200))
    lines.append(envelope("ended", {"gaps_suppressed": 0}, base + 300))
    return lines


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def write_json(path, document):
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(document, stream)
        stream.write("\n")


def outcomes(summary):
    return {op_id: op["outcome"] for op_id, op in summary["ops"].items()}


class CollisionLedgerTwins(unittest.TestCase):
    def test_healthy_ledgers_validate_with_outcomes(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "poll_msg")
        self.assertEqual(outcomes(first), {1: "completed", 2: "completed"})
        self.assertEqual(outcomes(second), {1: "completed", 2: "completed"})
        _, _, first, second = validated_pair(oracle, "cancel")
        self.assertEqual(outcomes(first), {1: "completed", 2: "completed"})
        self.assertEqual(outcomes(second),
                         {1: "unbegun", 2: "cancelled", 3: "fenced"})
        self.assertEqual(second["fence"], "finalize")
        _, _, first, second = validated_pair(oracle, "persisted")
        self.assertEqual(outcomes(first), {1: "completed", 2: "completed"})
        self.assertEqual(outcomes(second), {1: "completed", 2: "completed"})

    def test_mutation_second_row_must_be_scenario(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        del rows[1]
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "second row must be scenario"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_call_process_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[4]["process"] = "B"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "disagrees with scenario"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_fn_phase_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[3]["phase"] = "query"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "disagrees with phase"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_teardown_with_op_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["chal_cancel"], plan_cancel_challenger(2))
        teardown = next(row for row in rows if row.get("phase") == "teardown")
        teardown["op"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "teardown op must be 0"):
            oracle.validate_ledger(rows, "ledger B")

    def test_mutation_op_id_gap_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(3))
        for row in rows:
            if row.get("op") == 3:
                row["op"] = 4
        with self.assertRaisesRegex(oracle.LedgerError, "op ids are not"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_duplicate_terminal_rejected(self):
        oracle = require_oracle(self)
        steps = plan_poll_owner(1)
        steps.append(call(1, "async_poll", "terminal", 0, 1))
        rows = build_ledger(SCEN["owner_poll"], steps)
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate terminal"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_begun_twice_rejected(self):
        oracle = require_oracle(self)
        steps = plan_poll_owner(1)
        steps.insert(1, call(1, "async_begin", "begin", 0, 9))
        rows = build_ledger(SCEN["owner_poll"], steps)
        with self.assertRaisesRegex(oracle.LedgerError, "begun twice"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_unknown_async_id_rejected(self):
        oracle = require_oracle(self)
        steps = plan_poll_owner(1)
        steps[4] = call(1, "async_poll", "terminal", 0, 99)
        rows = build_ledger(SCEN["owner_poll"], steps)
        with self.assertRaisesRegex(oracle.LedgerError, "unknown async id"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_failed_begin_with_id_rejected(self):
        oracle = require_oracle(self)
        steps = plan_cancel_challenger(2)
        steps[0] = call(1, "async_begin_fail", "begin", BAD, 5)
        rows = build_ledger(SCEN["chal_cancel"], steps)
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "failed begin carries async id"):
            oracle.validate_ledger(rows, "ledger B")

    def test_mutation_pending_bad_rv_rejected(self):
        oracle = require_oracle(self)
        steps = plan_poll_owner(1)
        steps[1] = call(1, "async_poll", "pending", BAD, 1)
        rows = build_ledger(SCEN["owner_poll"], steps)
        with self.assertRaisesRegex(oracle.LedgerError, "pending rv"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_pending_after_terminal_rejected(self):
        oracle = require_oracle(self)
        steps = plan_poll_owner(1)
        steps.append(call(1, "async_poll", "pending", PENDING, 1))
        rows = build_ledger(SCEN["owner_poll"], steps)
        with self.assertRaisesRegex(oracle.LedgerError, "pending after terminal"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_duplicate_fence_rejected(self):
        oracle = require_oracle(self)
        steps = plan_cancel_challenger(2)
        steps.append(("fence", "exec"))
        rows = build_ledger(SCEN["chal_cancel"], steps)
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate fence"):
            oracle.validate_ledger(rows, "ledger B")

    def test_mutation_duplicate_transfer_rejected(self):
        oracle = require_oracle(self)
        steps = plan_poll_owner(1)
        steps.append(("transfer", 1, 4242, 4343, 1))
        steps.append(("transfer", 1, 4242, 4343, 1))
        rows = build_ledger(SCEN["owner_poll"], steps)
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate transfer"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_issued_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[-1]["issued"] -= 1
        with self.assertRaisesRegex(oracle.LedgerError, "issued"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_sequenced_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["chal_cancel"], plan_cancel_challenger(2))
        rows[-1]["sequenced"] -= 1
        with self.assertRaisesRegex(oracle.LedgerError, "sequenced"):
            oracle.validate_ledger(rows, "ledger B")

    def test_mutation_seq_break_across_fence_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["chal_cancel"], plan_cancel_challenger(2))
        fence = next(row for row in rows if row.get("kind") == "fence")
        fence["seq"] += 100
        with self.assertRaisesRegex(oracle.LedgerError, "contiguity"):
            oracle.validate_ledger(rows, "ledger B")

    def test_mutation_t1_after_ack_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[2]["t0"] = rows[-1]["t"]
        rows[2]["t1"] = rows[-1]["t"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "ready/ack window"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_t0_before_ready_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[2]["t0"] = rows[0]["t"] - 1
        rows[2]["t1"] = rows[0]["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "ready/ack window"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_reversed_timestamps_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[3]["t0"], rows[3]["t1"] = rows[3]["t1"], rows[3]["t0"]
        with self.assertRaisesRegex(oracle.LedgerError, "precedes t0"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_foreign_pid_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[5]["pid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "pid"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_tid_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[5]["tid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "tid"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_non_integer_rv_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[2]["rv"] = "CKR_OK"
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_duplicate_seq_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[4]["seq"] = rows[3]["seq"]
        with self.assertRaisesRegex(oracle.LedgerError, "contiguity"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_bad_scenario_field_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[1]["mechanism"] = "smoke"
        with self.assertRaisesRegex(oracle.LedgerError, "mechanism invalid"):
            oracle.validate_ledger(rows, "ledger A")
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[1]["target"] = "async_join"
        with self.assertRaisesRegex(oracle.LedgerError, "target invalid"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_non_call_row_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[3] = {"kind": "gap", "seq": 3}
        with self.assertRaisesRegex(oracle.LedgerError, "unexpected row"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_non_object_frame_row_refused(self):
        oracle = require_oracle(self)
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[0] = ["ready"]
        with self.assertRaisesRegex(oracle.LedgerError, "first row must be ready"):
            oracle.validate_ledger(rows, "ledger A")
        rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        rows[-1] = ["ack"]
        with self.assertRaisesRegex(oracle.LedgerError, "last row must be ack"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_duplicate_json_key_rejected(self):
        oracle = require_oracle(self)
        line = ('{"kind": "ready", "pid": 1, "tid": 1, "t": 2,'
                ' "clock": "CLOCK_MONOTONIC", "unit": "ns", "pid": 2}\n')
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate JSON key"):
            oracle.read_ledger(io.StringIO(line))

    def test_mutation_line_byte_limit_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "byte limit"):
            oracle.read_ledger(io.StringIO("x" * 4097 + "\n"))

    def test_truth_wins_early_and_missed_outcomes(self):
        oracle = require_oracle(self)
        # Op 1 completes on its first pending poll (early OK, no terminal).
        steps = [call(1, "async_begin", "begin", 0, 1),
                 call(1, "async_poll", "pending", 0, 1),
                 call(1, "async_status", "query", 0, 1)]
        rows = build_ledger(SCEN["owner_poll"], steps)
        summary = oracle.validate_ledger(rows, "ledger A")
        self.assertEqual(summary["ops"][1]["outcome"], "completed")
        steps = plan_cancel_challenger(2)
        # Op 2 cancel misses; the op stays pending.
        steps[3] = call(2, "async_cancel", "cancel", 0x91, 1)
        rows = build_ledger(SCEN["chal_cancel"], steps)
        summary = oracle.validate_ledger(rows, "ledger B")
        self.assertEqual(summary["ops"][2]["outcome"], "pending")
        # A too-small wait that answers OK consumes the op (no terminal).
        steps = [call(1, "async_begin", "begin", 0, 1),
                 call(1, "async_wait", "too_small", 0, 1),
                 call(1, "async_status", "query", 0, 1)]
        rows = build_ledger(SCEN["chal_message"], steps)
        summary = oracle.validate_ledger(rows, "ledger B")
        self.assertEqual(summary["ops"][1]["outcome"], "completed")


class CollisionTwins(unittest.TestCase):
    def test_healthy_modes_collide(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "poll_msg")
        collision = oracle.compare_collision(first, second)
        self.assertEqual(collision["collided"], [1, 2])
        self.assertEqual(collision["fenced"], 0)
        _, _, first, second = validated_pair(oracle, "cancel")
        collision = oracle.compare_collision(first, second)
        self.assertEqual(collision["collided"], [1])
        self.assertEqual(collision["fenced"], 1)
        _, _, first, second = validated_pair(oracle, "persisted")
        collision = oracle.compare_collision(first, second)
        self.assertEqual(collision["collided"], [1, 2])

    def test_healthy_swapped_positions_collide(self):
        oracle = require_oracle(self)
        rows_a = build_ledger(SCEN["chal_message"],
                              plan_message_challenger(2), pid=4343)
        rows_b = build_ledger(SCEN["owner_poll"], plan_poll_owner(2),
                              pid=4242)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        collision = oracle.compare_collision(first, second)
        self.assertEqual(collision["owner"]["process"], "A")
        self.assertEqual(collision["challenger"]["process"], "B")
        self.assertEqual(collision["collided"], [1, 2])

    def test_mutation_shared_pid_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "poll_msg", pid_b=4242)
        with self.assertRaisesRegex(oracle.LedgerError, "distinct processes"):
            oracle.compare_collision(first, second)

    def test_mutation_shared_mechanism_rejected(self):
        oracle = require_oracle(self)
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        scen_b = dict(SCEN["chal_message"], mechanism="poll")
        rows_b = build_ledger(scen_b, plan_message_challenger(2), pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "different pending mechanisms"):
            oracle.compare_collision(first, second)

    def test_mutation_slot_diverge_rejected(self):
        oracle = require_oracle(self)
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        scen_b = dict(SCEN["chal_message"], slot=1)
        rows_b = build_ledger(scen_b, plan_message_challenger(2), pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError, "no collision"):
            oracle.compare_collision(first, second)

    def test_mutation_shared_session_rejected(self):
        oracle = require_oracle(self)
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        scen_b = dict(SCEN["chal_message"], session=1)
        rows_b = build_ledger(scen_b, plan_message_challenger(2), pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError, "distinct sessions"):
            oracle.compare_collision(first, second)

    def test_mutation_two_owners_rejected(self):
        oracle = require_oracle(self)
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        scen_b = dict(SCEN["owner_poll"], process="B")
        rows_b = build_ledger(scen_b, plan_poll_owner(2), pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "owner and challenger"):
            oracle.compare_collision(first, second)

    def test_mutation_challenger_id_without_owner_rejected(self):
        oracle = require_oracle(self)
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(1))
        rows_b = build_ledger(SCEN["chal_message"],
                              plan_message_challenger(2), pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError, "has no owner"):
            oracle.compare_collision(first, second)


def paired(oracle, mode, ops=2):
    _, _, first, second = validated_pair(oracle, mode, ops=ops)
    collision = oracle.compare_collision(first, second)
    joint = healthy_joint(oracle, collision)
    single = healthy_s1only(oracle, collision)
    oracle.validate_snapshot(joint, "joint")
    oracle.validate_snapshot(single, "s1only")
    return collision, joint, single


class PairedPathTwins(unittest.TestCase):
    def test_healthy_modes_pass_both_paths(self):
        oracle = require_oracle(self)
        for mode in ("poll_msg", "cancel", "persisted"):
            with self.subTest(mode=mode):
                collision, joint, single = paired(oracle, mode)
                outcome = oracle.compare_joint(collision, joint)
                single_outcome = oracle.compare_s1only(collision, single)
                oracle.cross_totals(joint, single)
                self.assertEqual(outcome["joint_completed"],
                                 single_outcome["s1only_completed"])

    def test_healthy_counts_are_exact_per_mode(self):
        oracle = require_oracle(self)
        collision, joint, single = paired(oracle, "poll_msg")
        key = joint["key_operations"][0]
        self.assertEqual((key["started"], key["completed"]), (2, 2))
        unknown = joint["unknown_key_operations"][0]
        self.assertEqual((unknown["reason"], unknown["completed"]),
                         ("unbound", 2))
        self.assertEqual(joint["gaps"]["rows"],
                         [{"subject": "key_operation",
                           "reason": "duplicate_completion", "repeats": 2}])
        self.assertEqual(single["unknown_key_operations"][0]["completed"], 4)
        collision, joint, single = paired(oracle, "cancel")
        key = joint["key_operations"][0]
        self.assertEqual((key["started"], key["completed"]), (2, 2))
        unknown = joint["unknown_key_operations"][0]
        self.assertEqual((unknown["completed"], unknown["cancelled"]), (0, 1))
        self.assertEqual(joint["gaps"]["rows"],
                         [{"subject": "key_operation", "reason": "finalize",
                           "repeats": 1}])
        only = single["unknown_key_operations"][0]
        self.assertEqual((only["completed"], only["cancelled"]), (2, 1))
        collision, joint, single = paired(oracle, "persisted")
        unknown = joint["unknown_key_operations"][0]
        self.assertEqual((unknown["reason"], unknown["completed"]),
                         ("metadata_unknown", 2))
        self.assertEqual(joint["gaps"]["rows"],
                         [{"subject": "key_operation",
                           "reason": "duplicate_completion", "repeats": 2}])
        self.assertEqual(single["unknown_key_operations"][0]["completed"], 4)

    def test_mutation_challenger_joined_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        joint["key_operations"].append(
            {"instance": "i4", "object": 12, "category": "operation",
             "role": "key", "metadata_at_use": "rsa_2048",
             "unit": "operations", "started": 2, "completed": 2,
             "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
             "key_join_lost": 0})
        with self.assertRaisesRegex(oracle.LedgerError, "challenger joined"):
            oracle.compare_joint(collision, joint)

    def test_mutation_owner_completion_erased_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        joint["key_operations"][0]["completed"] = 1
        joint["key_operations"][0]["active"] = 1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "joint key row completed 1 disagrees"
                                    " with ledger 2"):
            oracle.compare_joint(collision, joint)

    def test_mutation_failed_init_counted_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "cancel")
        joint["key_operations"][0]["started"] = 3
        joint["key_operations"][0]["active"] = 1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "joint key row started 3 disagrees"
                                    " with ledger 2"):
            oracle.compare_joint(collision, joint)

    def test_mutation_refused_join_unpreserved_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        joint["unknown_key_operations"][0]["completed"] = 1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "joint unknown row completed 1 disagrees"
                                    " with ledger 2"):
            oracle.compare_joint(collision, joint)

    def test_mutation_join_gap_missing_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        joint["gaps"]["rows"] = []
        with self.assertRaisesRegex(oracle.LedgerError, "joint gaps"):
            oracle.compare_joint(collision, joint)

    def test_mutation_unexpected_gap_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        joint["gaps"]["rows"].append({"subject": "model", "reason": "loss",
                                      "repeats": 1})
        with self.assertRaisesRegex(oracle.LedgerError, "joint gaps"):
            oracle.compare_joint(collision, joint)

    def test_mutation_fenced_completion_counted_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "cancel")
        joint["unknown_key_operations"][0]["completed"] = 1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "joint unknown row completed 1 disagrees"
                                    " with ledger 0"):
            oracle.compare_joint(collision, joint)

    def test_mutation_fence_gap_missing_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "cancel")
        joint["gaps"]["rows"] = []
        with self.assertRaisesRegex(oracle.LedgerError, "joint gaps"):
            oracle.compare_joint(collision, joint)

    def test_mutation_exec_fence_wrong_reason_rejected(self):
        oracle = require_oracle(self)
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
        steps = plan_cancel_challenger(2)
        fence_at = next(index for index, step in enumerate(steps)
                        if step[0] == "fence")
        steps[fence_at] = ("fence", "exec")
        rows_b = build_ledger(SCEN["chal_cancel"], steps, pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        collision = oracle.compare_collision(first, second)
        joint = healthy_joint(oracle, collision)
        self.assertEqual(joint["gaps"]["rows"],
                         [{"subject": "key_operation", "reason": "exec",
                           "repeats": 1}])
        oracle.compare_joint(collision, joint)
        joint["gaps"]["rows"][0]["reason"] = "finalize"
        with self.assertRaisesRegex(oracle.LedgerError, "joint gaps"):
            oracle.compare_joint(collision, joint)

    def test_mutation_metadata_null_owner_lands_unknown(self):
        oracle = require_oracle(self)
        scen_a = dict(SCEN["owner_poll"], metadata=None)
        rows_a = build_ledger(scen_a, plan_poll_owner(2))
        rows_b = build_ledger(SCEN["chal_message"],
                              plan_message_challenger(2), pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        collision = oracle.compare_collision(first, second)
        joint = healthy_joint(oracle, collision)
        self.assertEqual(joint["key_operations"], [])
        reasons = sorted(row["reason"]
                         for row in joint["unknown_key_operations"])
        self.assertEqual(reasons, ["metadata_unknown", "unbound"])
        oracle.compare_joint(collision, joint)
        joint["key_operations"].append(
            {"instance": "i3", "object": 11, "category": "operation",
             "role": "key", "metadata_at_use": "rsa_2048",
             "unit": "operations", "started": 2, "completed": 2,
             "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
             "key_join_lost": 0})
        with self.assertRaisesRegex(oracle.LedgerError, "unmatched key row"):
            oracle.compare_joint(collision, joint)

    def test_mutation_s1only_key_row_rejected(self):
        oracle = require_oracle(self)
        collision, _joint, single = paired(oracle, "poll_msg")
        single["key_operations"].append(
            {"instance": "i3", "object": 11, "category": "operation",
             "role": "key", "metadata_at_use": "rsa_2048",
             "unit": "operations", "started": 2, "completed": 2,
             "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
             "key_join_lost": 0})
        with self.assertRaisesRegex(oracle.LedgerError, "s1only key row present"):
            oracle.compare_s1only(collision, single)

    def test_mutation_s1only_unknown_shape_rejected(self):
        oracle = require_oracle(self)
        collision, _joint, single = paired(oracle, "poll_msg")
        single["unknown_key_operations"].append(
            {"category": "operation", "reason": "metadata_unknown",
             "unit": "operations", "completed": 0, "failed": 0,
             "cancelled": 0, "unknown": 0, "active": 0})
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "must be exactly operation,unbound"):
            oracle.compare_s1only(collision, single)

    def test_mutation_s1only_completed_short_rejected(self):
        oracle = require_oracle(self)
        collision, _joint, single = paired(oracle, "poll_msg")
        single["unknown_key_operations"][0]["completed"] = 3
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "s1only unknown row completed 3 disagrees"
                                    " with ledger 4"):
            oracle.compare_s1only(collision, single)

    def test_mutation_s1only_gaps_rejected(self):
        oracle = require_oracle(self)
        collision, _joint, single = paired(oracle, "cancel")
        single["gaps"]["rows"].append({"subject": "key_operation",
                                       "reason": "finalize", "repeats": 1})
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "refuses no joins"):
            oracle.compare_s1only(collision, single)

    def test_mutation_cross_run_diverge_rejected(self):
        oracle = require_oracle(self)
        _collision, joint, single = paired(oracle, "poll_msg")
        single["unknown_key_operations"][0]["completed"] = 3
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "cross-run completed diverge"):
            oracle.cross_totals(joint, single)

    def test_mutation_unavailable_snapshot_refused(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        joint["status"] = "unavailable"
        joint["reason"] = "proof_refused_fallback"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "joint evidence absent"):
            oracle.validate_snapshot(joint, "joint")
        _collision, _joint, single = paired(oracle, "poll_msg")
        single["status"] = "stale"
        single["reason"] = "authority_lost"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "joint evidence absent"):
            oracle.validate_snapshot(single, "s1only")

    def test_mutation_suppressed_snapshot_refused(self):
        oracle = require_oracle(self)
        collision, joint, single = paired(oracle, "poll_msg")
        joint["gaps"]["suppressed"] = 1
        with self.assertRaisesRegex(oracle.LedgerError, "hides dispositions"):
            oracle.compare_joint(collision, joint)
        single["gaps"]["suppressed"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "hides dispositions"):
            oracle.compare_s1only(collision, single)

    def test_all_fenced_cell_pins_zero_rows(self):
        oracle = require_oracle(self)
        steps_a = [call(1, "async_begin", "begin", 0, 1),
                   ("fence", "exec"),
                   call(1, "async_poll", "terminal", 0, 1)]
        steps_b = [call(1, "async_begin", "begin", 0, 1),
                   ("fence", "exec"),
                   call(1, "async_wait", "terminal", 0, 1)]
        rows_a = build_ledger(SCEN["owner_poll"], steps_a)
        rows_b = build_ledger(SCEN["chal_message"], steps_b, pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        self.assertEqual(outcomes(first), {1: "fenced"})
        self.assertEqual(outcomes(second), {1: "fenced"})
        collision = oracle.compare_collision(first, second)
        self.assertEqual(collision["collided"], [])
        joint = healthy_joint(oracle, collision)
        self.assertEqual(joint["key_operations"][0]["started"], 0)
        self.assertEqual(joint["unknown_key_operations"][0]["completed"], 0)
        self.assertEqual(joint["gaps"]["rows"],
                         [{"subject": "key_operation", "reason": "exec",
                           "repeats": 2}])
        oracle.compare_joint(collision, joint)
        single = healthy_s1only(oracle, collision)
        self.assertEqual(single["unknown_key_operations"][0]["completed"], 0)
        oracle.compare_s1only(collision, single)
        oracle.cross_totals(joint, single)


    def test_mutation_empty_joint_rows_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        joint["key_operations"] = []
        joint["unknown_key_operations"] = []
        joint["objects"] = []
        joint["gaps"]["rows"] = []
        with self.assertRaisesRegex(oracle.LedgerError, "missing key row"):
            oracle.compare_joint(collision, joint)


class TransferTwins(unittest.TestCase):
    def transfer_pair(self, oracle):
        steps_a = [call(1, "async_begin", "begin", 0, 1),
                   call(1, "async_poll", "pending", PENDING, 1),
                   call(2, "async_begin", "begin", 0, 2),
                   call(2, "async_poll", "pending", PENDING, 2),
                   call(2, "async_poll", "pending", PENDING, 2),
                   call(2, "async_poll", "terminal", 0, 2)]
        steps_b = [("transfer", 1, 4242, 4343, 1),
                   call(1, "async_wait", "terminal", 0, 1),
                   call(2, "async_begin", "begin", 0, 2),
                   call(2, "async_wait", "too_small", TOO_SMALL, 2),
                   call(2, "async_wait", "terminal", 0, 2)]
        rows_a = build_ledger(SCEN["owner_poll"], steps_a, pid=4242)
        rows_b = build_ledger(SCEN["chal_message"], steps_b, pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        return first, second

    def test_healthy_transfer_completes_under_owner_key(self):
        oracle = require_oracle(self)
        first, second = self.transfer_pair(oracle)
        self.assertEqual(outcomes(first), {1: "pending", 2: "completed"})
        self.assertEqual(outcomes(second),
                         {1: "adopted-completed", 2: "completed"})
        collision = oracle.compare_collision(first, second)
        self.assertEqual(len(collision["transfers"]), 1)
        self.assertEqual(collision["transfers"][0]["outcome"], "completed")
        joint = healthy_joint(oracle, collision)
        key = joint["key_operations"][0]
        self.assertEqual((key["started"], key["completed"]), (2, 2))
        unknown = joint["unknown_key_operations"][0]
        self.assertEqual((unknown["reason"], unknown["completed"]),
                         ("unbound", 1))
        self.assertEqual(joint["gaps"]["rows"],
                         [{"subject": "key_operation",
                           "reason": "duplicate_completion", "repeats": 1}])
        oracle.compare_joint(collision, joint)
        single = healthy_s1only(oracle, collision)
        self.assertEqual(single["unknown_key_operations"][0]["completed"], 3)
        oracle.compare_s1only(collision, single)
        oracle.cross_totals(joint, single)

    def test_mutation_transfer_refused_rejected(self):
        oracle = require_oracle(self)
        first, second = self.transfer_pair(oracle)
        collision = oracle.compare_collision(first, second)
        joint = healthy_joint(oracle, collision)
        joint["gaps"]["rows"][0]["repeats"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "joint gaps"):
            oracle.compare_joint(collision, joint)
        joint = healthy_joint(oracle, collision)
        joint["key_operations"][0]["completed"] = 1
        joint["key_operations"][0]["active"] = 1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "joint key row completed 1 disagrees"
                                    " with ledger 2"):
            oracle.compare_joint(collision, joint)

    def test_mutation_transfer_row_dropped_rejected(self):
        oracle = require_oracle(self)
        first, second = self.transfer_pair(oracle)
        rows_b = build_ledger(
            SCEN["chal_message"],
            [call(1, "async_wait", "terminal", 0, 1),
             call(2, "async_begin", "begin", 0, 2),
             call(2, "async_wait", "too_small", TOO_SMALL, 2),
             call(2, "async_wait", "terminal", 0, 2)], pid=4343)
        with self.assertRaisesRegex(oracle.LedgerError, "unknown async id"):
            oracle.validate_ledger(rows_b, "ledger B")

    def test_mutation_transfer_outside_pair_rejected(self):
        oracle = require_oracle(self)
        steps_a = plan_poll_owner(1)
        steps_b = [("transfer", 1, 4242, 9999, 1),
                   call(1, "async_wait", "terminal", 0, 1)]
        rows_a = build_ledger(SCEN["owner_poll"], steps_a, pid=4242)
        rows_b = build_ledger(SCEN["chal_message"], steps_b, pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError, "outside the pair"):
            oracle.compare_collision(first, second)

    def test_mutation_transfer_without_begin_rejected(self):
        oracle = require_oracle(self)
        steps_a = [call(1, "async_begin_fail", "begin", BAD, 0)]
        steps_b = [("transfer", 1, 4242, 4343, 1),
                   call(1, "async_wait", "terminal", 0, 1)]
        rows_a = build_ledger(SCEN["owner_poll"], steps_a, pid=4242)
        rows_b = build_ledger(SCEN["chal_message"], steps_b, pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError, "without begin"):
            oracle.compare_collision(first, second)

    def test_mutation_transfer_already_settled_rejected(self):
        oracle = require_oracle(self)
        steps_a = plan_poll_owner(1)
        steps_b = [("transfer", 1, 4242, 4343, 1),
                   call(1, "async_wait", "terminal", 0, 1)]
        rows_a = build_ledger(SCEN["owner_poll"], steps_a, pid=4242)
        rows_b = build_ledger(SCEN["chal_message"], steps_b, pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError, "already settled"):
            oracle.compare_collision(first, second)

    def test_mutation_transfer_without_adoption_rejected(self):
        oracle = require_oracle(self)
        steps_a = [call(1, "async_begin", "begin", 0, 1),
                   call(1, "async_poll", "pending", PENDING, 1)]
        steps_b = [("transfer", 1, 4242, 4343, 1),
                   call(1, "async_begin", "begin", 0, 1)]
        rows_a = build_ledger(SCEN["owner_poll"], steps_a, pid=4242)
        rows_b = build_ledger(SCEN["chal_message"], steps_b, pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError, "no adopted calls"):
            oracle.compare_collision(first, second)

    def test_mutation_transfer_declared_twice_rejected(self):
        oracle = require_oracle(self)
        first, second = self.transfer_pair(oracle)
        rows_a = build_ledger(
            SCEN["owner_poll"],
            [call(1, "async_begin", "begin", 0, 1),
             call(1, "async_poll", "pending", PENDING, 1),
             ("transfer", 1, 4242, 4343, 1),
             call(2, "async_begin", "begin", 0, 2),
             call(2, "async_poll", "terminal", 0, 2)], pid=4242)
        dupe = oracle.validate_ledger(rows_a, "ledger A")
        with self.assertRaisesRegex(oracle.LedgerError, "declared twice"):
            oracle.compare_collision(dupe, second)

    def test_mutation_transfer_fenced_rejected(self):
        oracle = require_oracle(self)
        steps_a = [call(1, "async_begin", "begin", 0, 1),
                   call(1, "async_poll", "pending", PENDING, 1)]
        steps_b = [("transfer", 1, 4242, 4343, 1),
                   ("fence", "finalize"),
                   call(1, "async_wait", "terminal", 0, 1)]
        rows_a = build_ledger(SCEN["owner_poll"], steps_a, pid=4242)
        rows_b = build_ledger(SCEN["chal_message"], steps_b, pid=4343)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaisesRegex(oracle.LedgerError, "fenced"):
            oracle.compare_collision(first, second)


class AsyncStreamTwins(unittest.TestCase):
    def test_healthy_streams_pass_both_views(self):
        oracle = require_oracle(self)
        for mode in ("poll_msg", "cancel", "persisted"):
            with self.subTest(mode=mode):
                collision, joint, single = paired(oracle, mode)
                stream = healthy_stream(collision, joint)
                oracle.compare_stream(stream, collision, joint, "joint")
                stream = healthy_s1only_stream(collision, single)
                oracle.compare_stream(stream, collision, single, "s1only")

    def test_healthy_transfer_stream_passes(self):
        oracle = require_oracle(self)
        twins = TransferTwins("test_healthy_transfer_completes_under_owner_key")
        first, second = twins.transfer_pair(oracle)
        collision = oracle.compare_collision(first, second)
        joint = healthy_joint(oracle, collision)
        single = healthy_s1only(oracle, collision)
        oracle.compare_stream(healthy_stream(collision, joint), collision,
                              joint, "joint")
        oracle.compare_stream(healthy_s1only_stream(collision, single),
                              collision, single, "s1only")

    def test_mutation_reordered_replay_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        completions = [line for line in stream
                       if line["kind"] == "key_operations_observed"]
        owner_row = [line for line in completions
                     if line["event"]["bucket"] == "known"]
        owner_row[0]["event"]["revision"], owner_row[1]["event"]["revision"] = \
            owner_row[1]["event"]["revision"], owner_row[0]["event"]["revision"]
        with self.assertRaisesRegex(oracle.LedgerError, "revision order"):
            oracle.compare_stream(stream, collision, joint, "joint")

    def test_mutation_chain_break_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        objects = [line for line in stream if line["kind"] == "object_observed"]
        completions = [line for line in stream
                       if line["kind"] == "key_operations_observed"]
        objects[0]["event"]["revision"], completions[0]["event"]["revision"] = \
            completions[0]["event"]["revision"], objects[0]["event"]["revision"]
        with self.assertRaisesRegex(oracle.LedgerError, "leave one chain"):
            oracle.compare_stream(stream, collision, joint, "joint")

    def test_mutation_completed_decreases_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        completions = [line for line in stream
                       if line["kind"] == "key_operations_observed"]
        owner_row = [line for line in completions
                     if line["event"]["bucket"] == "known"]
        owner_row[1]["event"]["row"]["completed"] = 0
        owner_row[1]["event"]["row"]["active"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "completed decreases"):
            oracle.compare_stream(stream, collision, joint, "joint")

    def test_mutation_receipt_before_t0_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        first_cover = next(line for line in stream
                           if line["kind"] == "key_operations_observed")
        if first_cover["event"]["bucket"] == "known":
            feed = collision["owner"]
        else:
            feed = collision["challenger"]
        earliest = min(op["terminal_t0"] for op in feed["ops"].values()
                       if op["outcome"] == "completed")
        first_cover["at_ns"] = earliest - 1
        with self.assertRaisesRegex(oracle.LedgerError, "precedes call t0"):
            oracle.compare_stream(stream, collision, joint, "joint")

    def test_preemption_window_at_t0_passes(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        covers = [line for line in stream
                  if line["kind"] == "key_operations_observed"]
        owner = collision["owner"]
        first_op = min(owner["ops"], key=lambda op_id: owner["ops"][op_id]
                       ["terminal_t1"])
        owner_cover = next(line for line in covers
                           if line["event"]["bucket"] == "known")
        owner_cover["at_ns"] = owner["ops"][first_op]["terminal_t0"]
        oracle.compare_stream(stream, collision, joint, "joint")

    def test_mutation_interleave_violated_rejected(self):
        oracle = require_oracle(self)
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(1),
                              pid=4242, tick=1_000)
        rows_b = build_ledger(SCEN["chal_message"],
                              plan_message_challenger(1), pid=4343,
                              tick=100_000)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        collision = oracle.compare_collision(first, second)
        term_a = first["ops"][1]
        term_b = second["ops"][1]
        self.assertLess(term_a["terminal_t1"], term_b["terminal_t0"])
        joint = healthy_joint(oracle, collision)
        key_row = joint["key_operations"][0]
        unknown_row = joint["unknown_key_operations"][0]
        stream = [
            {"schema": "p11scope/inventory-events/v1", "seq": 0,
             "at_ns": 500, "kind": "object_observed",
             "event": {"revision": 1,
                       "row": copy.deepcopy(joint["objects"][0])}},
            {"schema": "p11scope/inventory-events/v1", "seq": 1,
             "at_ns": term_b["terminal_t1"] + 100,
             "kind": "key_operations_observed",
             "event": {"revision": 2, "bucket": "unknown",
                       "row": copy.deepcopy(unknown_row)}},
            {"schema": "p11scope/inventory-events/v1", "seq": 2,
             "at_ns": term_a["terminal_t1"] + 100,
             "kind": "key_operations_observed",
             "event": {"revision": 3, "bucket": "known",
                       "row": copy.deepcopy(key_row)}},
        ]
        with self.assertRaisesRegex(oracle.LedgerError, "interleave order"):
            oracle.compare_stream(stream, collision, joint, "joint")
        stream[1]["event"]["revision"], stream[2]["event"]["revision"] = 3, 2
        stream[1], stream[2] = stream[2], stream[1]
        stream[1]["seq"], stream[2]["seq"] = 1, 2
        oracle.compare_stream(stream, collision, joint, "joint")

    def test_mutation_stream_snapshot_diverge_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        completions = [line for line in stream
                       if line["kind"] == "key_operations_observed"]
        completions[-1]["event"]["row"]["completed"] -= 1
        completions[-1]["event"]["row"]["active"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees with snapshot"):
            oracle.compare_stream(stream, collision, joint, "joint")

    def test_mutation_stream_missing_row_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        kept = [line for line in stream
                if line["event"].get("bucket") != "unknown"]
        with self.assertRaisesRegex(oracle.LedgerError, "never carries"):
            oracle.compare_stream(kept, collision, joint, "joint")

    def test_mutation_gaps_suppressed_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        marker = next(line for line in stream if line["kind"] == "pass_committed")
        marker["event"]["gaps_suppressed"] = 1
        with self.assertRaisesRegex(oracle.LedgerError, "hides dispositions"):
            oracle.compare_stream(stream, collision, joint, "joint")

    def test_mutation_object_status_disagree_rejected(self):
        oracle = require_oracle(self)
        collision, joint, _single = paired(oracle, "poll_msg")
        stream = healthy_stream(collision, joint)
        marker = next(line for line in stream if line["kind"] == "pass_committed")
        marker["event"]["object_status"] = "stale"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "object_status .* disagrees"):
            oracle.compare_stream(stream, collision, joint, "joint")

    def test_cli_healthy_and_mutation_reason(self):
        require_oracle(self)
        oracle = ORACLE
        collision, joint, single = paired(oracle, "poll_msg")
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(2),
                              pid=4242)
        rows_b = build_ledger(SCEN["chal_message"],
                              plan_message_challenger(2), pid=4343)
        with tempfile.TemporaryDirectory() as tmp:
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            snap_joint = Path(tmp) / "joint.json"
            snap_single = Path(tmp) / "s1only.json"
            events_joint = Path(tmp) / "joint.jsonl"
            events_single = Path(tmp) / "s1only.jsonl"
            write_jsonl(ledger_a, rows_a)
            write_jsonl(ledger_b, rows_b)
            write_json(snap_joint, joint)
            write_json(snap_single, single)
            write_jsonl(events_joint, healthy_stream(collision, joint))
            write_jsonl(events_single,
                        healthy_s1only_stream(collision, single))
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger_a),
                 str(ledger_b), str(snap_joint), str(snap_single),
                 str(events_joint), str(events_single)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads(completed.stdout)
            self.assertEqual(summary["joint_completed"], 4)
            self.assertEqual(summary["s1only_completed"], 4)
            broken = copy.deepcopy(joint)
            broken["key_operations"][0]["completed"] = 1
            broken["key_operations"][0]["active"] = 1
            write_json(snap_joint, broken)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger_a),
                 str(ledger_b), str(snap_joint), str(snap_single)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertRegex(completed.stderr,
                             r"async refused: joint key row completed 1"
                             r" disagrees with ledger 2")

    def test_cli_string_payload_not_echoed(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            snap_joint = Path(tmp) / "joint.json"
            snap_single = Path(tmp) / "s1only.json"
            rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
            rows[5]["pid"] = "PIN=1234-secret"
            write_jsonl(ledger_a, rows)
            write_jsonl(ledger_b, build_ledger(
                SCEN["chal_message"], plan_message_challenger(2)))
            write_json(snap_joint, {"version": 1})
            write_json(snap_single, {"version": 1})
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger_a),
                 str(ledger_b), str(snap_joint), str(snap_single)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("async refused: ledger A: pid string disagrees",
                          completed.stderr)
            self.assertNotIn("PIN=1234-secret", completed.stderr)

    def test_cli_non_object_first_row_refused_without_traceback(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            snap_joint = Path(tmp) / "joint.json"
            snap_single = Path(tmp) / "s1only.json"
            rows = build_ledger(SCEN["owner_poll"], plan_poll_owner(2))
            rows[0] = ["ready"]
            write_jsonl(ledger_a, rows)
            write_jsonl(ledger_b, build_ledger(
                SCEN["chal_message"], plan_message_challenger(2)))
            write_json(snap_joint, {"version": 1})
            write_json(snap_single, {"version": 1})
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger_a),
                 str(ledger_b), str(snap_joint), str(snap_single)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("async refused: ledger A: first row must be ready",
                          completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)


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


class CollisionEmissionTests(unittest.TestCase):
    def build_provider(self, tmp, m32=False):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not PROVIDER_SRC.is_file():
            self.fail(f"provider missing: {PROVIDER_SRC}"
                      " (implementation not present)")
        provider = Path(tmp) / ("collide-provider32.so" if m32
                                else "collide-provider.so")
        command = ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        if m32:
            command.append("-m32")
        command += ["-fPIC", "-shared", "-Wl,-z,defs",
                    "-o", str(provider), str(PROVIDER_SRC)]
        build = subprocess.run(command, capture_output=True, text=True,
                               timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return provider

    def build_driver(self, tmp, m32=False):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not DRIVER_SRC.is_file():
            self.fail(f"driver missing: {DRIVER_SRC} (implementation not present)")
        driver = Path(tmp) / ("collide32" if m32 else "collide")
        command = ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        if m32:
            command.append("-m32")
        command += [str(DRIVER_SRC), "-ldl", "-o", str(driver)]
        build = subprocess.run(command, capture_output=True, text=True,
                               timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return driver

    def build_pair(self, tmp):
        return self.build_provider(tmp), self.build_driver(tmp)

    def test_live_modes_collide_and_compare(self):
        oracle = require_oracle(self)
        for mode in ("poll_msg", "cancel", "persisted"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                provider, driver = self.build_pair(tmp)
                ledger_a = Path(tmp) / "a.jsonl"
                ledger_b = Path(tmp) / "b.jsonl"
                completed = subprocess.run(
                    [str(driver), str(provider), mode, "2",
                     str(ledger_a), str(ledger_b)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("READY pid=", completed.stdout)
                targets = [json.loads(line[len("TARGET "):])
                           for line in completed.stdout.splitlines()
                           if line.startswith("TARGET ")]
                self.assertEqual(len(targets), 2)
                self.assertEqual((targets[0]["dev"], targets[0]["ino"]),
                                 (targets[1]["dev"], targets[1]["ino"]))
                with open(ledger_a, encoding="utf-8") as stream:
                    first = oracle.validate_ledger(
                        oracle.read_ledger(stream), "ledger A")
                with open(ledger_b, encoding="utf-8") as stream:
                    second = oracle.validate_ledger(
                        oracle.read_ledger(stream), "ledger B")
                self.assertNotEqual(first["pid"], second["pid"])
                self.assertNotEqual(first["mechanism"], second["mechanism"])
                collision = oracle.compare_collision(first, second)
                owner_ids = sorted(op["async_id"]
                                   for op in collision["owner"]["ops"].values()
                                   if op["async_id"] is not None
                                   and op["outcome"] in (
                                       "completed", "cancelled", "failed",
                                       "pending"))
                chal_ids = sorted(op["async_id"]
                                  for op in collision["challenger"]["ops"].values()
                                  if op["async_id"] is not None
                                  and op["outcome"] in (
                                      "completed", "cancelled", "failed",
                                      "pending"))
                for aid in chal_ids:
                    self.assertIn(aid, owner_ids)
                joint = healthy_joint(oracle, collision)
                single = healthy_s1only(oracle, collision)
                oracle.validate_snapshot(joint, "joint")
                oracle.validate_snapshot(single, "s1only")
                outcome = oracle.compare_joint(collision, joint)
                single_outcome = oracle.compare_s1only(collision, single)
                oracle.cross_totals(joint, single)
                self.assertEqual(outcome["joint_completed"],
                                 single_outcome["s1only_completed"])
                oracle.compare_stream(healthy_stream(collision, joint),
                                      collision, joint, "joint")
                oracle.compare_stream(
                    healthy_s1only_stream(collision, single), collision,
                    single, "s1only")

    def test_live_counts_are_exact(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            completed = subprocess.run(
                [str(driver), str(provider), "cancel", "3",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger_a, encoding="utf-8") as stream:
                first = oracle.validate_ledger(
                    oracle.read_ledger(stream), "ledger A")
            with open(ledger_b, encoding="utf-8") as stream:
                second = oracle.validate_ledger(
                    oracle.read_ledger(stream), "ledger B")
            self.assertEqual(outcomes(first), {1: "completed", 2: "completed",
                                               3: "completed"})
            self.assertEqual(outcomes(second), {1: "unbegun", 2: "cancelled",
                                                3: "cancelled", 4: "fenced"})
            collision = oracle.compare_collision(first, second)
            joint = healthy_joint(oracle, collision)
            key = joint["key_operations"][0]
            self.assertEqual((key["started"], key["completed"]), (3, 3))
            unknown = joint["unknown_key_operations"][0]
            self.assertEqual((unknown["completed"], unknown["cancelled"]),
                             (0, 2))
            self.assertEqual(joint["gaps"]["rows"],
                             [{"subject": "key_operation", "reason": "finalize",
                               "repeats": 1}])
            single = healthy_s1only(oracle, collision)
            only = single["unknown_key_operations"][0]
            self.assertEqual((only["completed"], only["cancelled"]), (3, 2))
            oracle.compare_joint(collision, joint)
            oracle.compare_s1only(collision, single)

    def test_live_mutation_fails(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            completed = subprocess.run(
                [str(driver), str(provider), "persisted", "2",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger_a, encoding="utf-8") as stream:
                first = oracle.validate_ledger(
                    oracle.read_ledger(stream), "ledger A")
            with open(ledger_b, encoding="utf-8") as stream:
                second = oracle.validate_ledger(
                    oracle.read_ledger(stream), "ledger B")
            collision = oracle.compare_collision(first, second)
            joint = healthy_joint(oracle, collision)
            joint["unknown_key_operations"][0]["completed"] -= 1
            with self.assertRaisesRegex(oracle.LedgerError, "disagrees"):
                oracle.compare_joint(collision, joint)

    def test_driver_waits_for_go(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            gate = Path(tmp) / "GO"
            child = subprocess.Popen(
                [str(driver), str(provider), "poll_msg", "1",
                 str(ledger_a), str(ledger_b), str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stderr = ""
            try:
                line = child.stdout.readline()
                self.assertIn(f"READY pid={child.pid}", line)
                time.sleep(0.5)
                self.assertFalse(ledger_a.exists())
                self.assertFalse(ledger_b.exists())
                gate.touch()
                _, stderr = child.communicate(timeout=60)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr)
            with open(ledger_a, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(
                    oracle.read_ledger(stream), "ledger A")
            self.assertEqual(
                [op["outcome"] for op in summary["ops"].values()],
                ["completed"])

    def test_driver_stop_flag_interrupts_wait(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            gate = Path(tmp) / "GO"
            child = subprocess.Popen(
                [str(driver), str(provider), "poll_msg", "1",
                 str(ledger_a), str(ledger_b), str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stderr = ""
            try:
                line = child.stdout.readline()
                self.assertIn(f"READY pid={child.pid}", line)
                self.assertFalse(ledger_a.exists())
                child.terminate()
                _, stderr = child.communicate(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)
            self.assertEqual(child.returncode, 2)
            self.assertIn("gate", stderr)
            self.assertFalse(ledger_a.exists())
            self.assertFalse(ledger_b.exists())

    def test_driver_refuses_nonstub_provider(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            if not shutil.which("gcc"):
                self.skipTest("requires gcc; installs nothing")
            driver = self.build_driver(tmp)
            provider_c = Path(tmp) / "plain.c"
            provider = Path(tmp) / "plain.so"
            provider_c.write_text(REFUSAL_PROVIDER, encoding="utf-8")
            build = subprocess.run(
                ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-fPIC", "-shared", "-Wl,-z,defs",
                 "-o", str(provider), str(provider_c)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stderr)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            completed = subprocess.run(
                [str(driver), str(provider), "poll_msg", "1",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("stub", completed.stderr)
            self.assertFalse(ledger_a.exists())
            self.assertFalse(ledger_b.exists())

    def test_driver_refuses_stub_without_async_capability(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            if not shutil.which("gcc"):
                self.skipTest("requires gcc; installs nothing")
            driver = self.build_driver(tmp)
            provider = Path(tmp) / "stub.so"
            build = subprocess.run(
                ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-fPIC", "-DP11SCOPE_EXPORT_TABLES=1", "-shared",
                 "-Wl,-z,defs", "-o", str(provider), str(STUB_PROVIDER_SRC)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stderr)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            completed = subprocess.run(
                [str(driver), str(provider), "poll_msg", "1",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60,
                env=dict(os.environ, P11SCOPE_FIXTURE_QUIET="1"))
            self.assertEqual(completed.returncode, 2)
            self.assertIn("async capability", completed.stderr)
            self.assertFalse(ledger_a.exists())
            self.assertFalse(ledger_b.exists())

    def test_driver_refuses_bad_argv(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            completed = subprocess.run(
                [str(driver)], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            completed = subprocess.run(
                [str(driver), str(provider), "nope", "1",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(ledger_a.exists())
            completed = subprocess.run(
                [str(driver), str(provider), "cancel", "0",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(ledger_a.exists())

    def test_driver_m32_build_runs(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            if not shutil.which("gcc"):
                self.skipTest("requires gcc; installs nothing")
            probe = subprocess.run(
                ["gcc", "-m32", "-x", "c", "-", "-o", str(Path(tmp) / "probe")],
                input="int main(void){return 0;}\n",
                capture_output=True, text=True, timeout=60)
            if probe.returncode != 0:
                self.skipTest("32-bit multilib is not installed")
            try:
                provider = self.build_provider(tmp, m32=True)
                driver = self.build_driver(tmp, m32=True)
            except AssertionError:
                self.skipTest("32-bit collision build is not supported here")
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            try:
                completed = subprocess.run(
                    [str(driver), str(provider), "persisted", "1",
                     str(ledger_a), str(ledger_b)],
                    capture_output=True, text=True, timeout=60)
            except OSError:
                self.skipTest("32-bit execution is not supported here")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("READY pid=", completed.stdout)


def require_s1(test):
    """Fail naming the missing S1 mode (RED) or return the oracle."""
    oracle = require_oracle(test)
    if not hasattr(oracle, "compare_s1"):
        test.fail("S1 mode not implemented: oracle.compare_s1 missing")
    return oracle


def s1_section():
    """The v0.5.0 S1 marker: unavailable/journal_unavailable, no rows."""
    return {"version": 1, "revision": 7, "status": "unavailable",
            "reason": "journal_unavailable", "sessions": [], "objects": [],
            "key_operations": [], "unknown_key_operations": [],
            "gaps": {"rows": [], "suppressed": 0},
            "budgets": {
                "key_rows": {"limit": 65536, "occupied": 0, "refused": 0},
                "object_rows": {"limit": 65536, "occupied": 0,
                                "refused": 0},
                "unknown_rows": {"occupied": 0},
                "encoded_bytes": 0, "allocation_refused": False,
                "refusal_reason": "none"}}


def s1_stream(status="unavailable"):
    """Markers-only S1 stream: no H9 rows ride an unavailable section."""
    return [
        {"schema": "p11scope/inventory-events/v1", "seq": 0, "at_ns": 1000,
         "kind": "pass_committed",
         "event": {"pass": 1, "object_revision": 7,
                   "object_status": status, "gaps_suppressed": 0}},
        {"schema": "p11scope/inventory-events/v1", "seq": 1, "at_ns": 1100,
         "kind": "ended", "event": {"gaps_suppressed": 0}},
    ]


def expected_s1(rows_a, rows_b):
    """Independent S1 tallies: every call row counts, per (fn, rv).

    Mechanisms come from each ledger's own scenario row (never the
    oracle's summary); errors are non-OK returns at S1 granularity.
    """
    returns, mechanisms, calls = {}, {}, 0
    for rows in (rows_a, rows_b):
        mechanism = rows[1]["mechanism"]
        group = mechanisms.setdefault(mechanism, {"calls": 0, "errors": 0})
        for row in rows:
            if row.get("kind") != "call":
                continue
            calls += 1
            tally = returns.setdefault(row["fn"], {})
            tally[row["rv"]] = tally.get(row["rv"], 0) + 1
            group["calls"] += 1
            if row["rv"] != 0:
                group["errors"] += 1
    return {"calls": calls, "returns": returns, "mechanisms": mechanisms}


class S1Twins(unittest.TestCase):
    def test_s1_healthy_pair_passes(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        result = oracle.compare_s1(rows_a, rows_b, s1_section(),
                                   s1_section(), s1_stream(), s1_stream())
        want = expected_s1(rows_a, rows_b)
        self.assertEqual(result["mode"], "s1")
        self.assertEqual(result["processes"], 2)
        self.assertEqual(result["calls"], want["calls"])
        self.assertEqual(result["returns"], want["returns"])
        self.assertEqual(result["mechanisms"], want["mechanisms"])

    def test_s1_works_without_streams(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        result = oracle.compare_s1(rows_a, rows_b, s1_section(),
                                   s1_section())
        self.assertEqual(result["mode"], "s1")
        self.assertEqual(result["calls"], expected_s1(rows_a, rows_b)["calls"])

    def test_s1_counts_every_call_row(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "cancel")
        kinds = {(row["fn"], row["phase"]) for row in rows_b
                 if row.get("kind") == "call"}
        self.assertIn(("async_finalize", "teardown"), kinds)
        result = oracle.compare_s1(rows_a, rows_b, s1_section(),
                                   s1_section(), s1_stream(), s1_stream())
        want = expected_s1(rows_a, rows_b)
        self.assertEqual(result["calls"], want["calls"])
        self.assertEqual(result["returns"], want["returns"])
        self.assertEqual(result["mechanisms"], want["mechanisms"])

    def test_s1_populated_sections_refused(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        collision = oracle.compare_collision(
            oracle.validate_ledger(rows_a, "ledger A"),
            oracle.validate_ledger(rows_b, "ledger B"))
        joint = healthy_joint(oracle, collision)
        single = healthy_s1only(oracle, collision)
        for label, first, second in (("joint", joint, s1_section()),
                                    ("s1only", s1_section(), single)):
            with self.subTest(label), self.assertRaises(oracle.LedgerError) as caught:
                oracle.compare_s1(rows_a, rows_b, first, second)
            self.assertIn("want unavailable/journal_unavailable",
                          str(caught.exception))

    def test_s1_reason_must_be_journal(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        for label in ("joint", "s1only"):
            with self.subTest(label):
                first, second = s1_section(), s1_section()
                target = first if label == "joint" else second
                target["reason"] = "bootstrap_unavailable"
                with self.assertRaises(oracle.LedgerError) as caught:
                    oracle.compare_s1(rows_a, rows_b, first, second)
                self.assertIn("want unavailable/journal_unavailable",
                              str(caught.exception))

    def test_s1_rows_refused_everywhere(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        key_row = {"instance": "i3", "object": 11, "category": "operation",
                   "role": "key", "metadata_at_use": "rsa_2048",
                   "unit": "operations", "started": 1, "completed": 1,
                   "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
                   "key_join_lost": 0}
        unknown_row = {"category": "operation", "reason": "unbound",
                       "unit": "operations", "completed": 1, "failed": 0,
                       "cancelled": 0, "unknown": 0, "active": 0}
        session_row = {"session": 1, "origin": "opened", "status": "live"}
        cases = (("key_operations", [key_row], "needs no key-operation rows"),
                 ("unknown_key_operations", [unknown_row],
                  "needs no unknown key-operation rows"),
                 ("sessions", [session_row], "needs no session rows"),
                 ("objects", [object_row(11, "rsa_2048")],
                  "needs no session rows"))
        for label in ("joint", "s1only"):
            for field, planted, token in cases:
                with self.subTest(label, field=field):
                    first, second = s1_section(), s1_section()
                    target = first if label == "joint" else second
                    target[field] = planted
                    with self.assertRaises(oracle.LedgerError) as caught:
                        oracle.compare_s1(rows_a, rows_b, first, second)
                    self.assertIn(token, str(caught.exception))

    def test_s1_section_denied_gap_everywhere(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        denied = "joint machine unavailable"
        for label in ("joint", "s1only"):
            for field in ("subject", "reason"):
                with self.subTest(label, field=field):
                    first, second = s1_section(), s1_section()
                    target = first if label == "joint" else second
                    gap = {"subject": "model", "reason": "loss",
                           "repeats": 1}
                    gap[field] = denied
                    target["gaps"]["rows"] = [gap]
                    with self.assertRaises(oracle.LedgerError) as caught:
                        oracle.compare_s1(rows_a, rows_b, first, second)
                    self.assertIn("denied joint-machine text",
                                  str(caught.exception))

    def test_s1_section_benign_gap_still_refused(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        first, second = s1_section(), s1_section()
        first["gaps"]["rows"] = [{"subject": "model", "reason": "loss",
                                  "repeats": 2}]
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, first, second)
        self.assertNotIn("denied joint-machine text", str(caught.exception))

    def test_s1_section_shape_still_enforced(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        first, second = s1_section(), s1_section()
        first["gaps"]["rows"] = [{"subject": "bogus", "reason": "loss",
                                  "repeats": 1}]
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, first, second)
        self.assertIn("subject invalid", str(caught.exception))

    def test_s1_section_suppressed_refused(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        for label in ("joint", "s1only"):
            with self.subTest(label):
                first, second = s1_section(), s1_section()
                target = first if label == "joint" else second
                target["gaps"]["suppressed"] = 1
                with self.assertRaises(oracle.LedgerError) as caught:
                    oracle.compare_s1(rows_a, rows_b, first, second)
                self.assertIn("hides dispositions", str(caught.exception))

    def test_s1_stream_denied_gap_everywhere(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        denied = "joint machine unavailable"
        for label in ("joint", "s1only"):
            for field in ("subject", "reason"):
                with self.subTest(label, field=field):
                    gap = {"schema": "p11scope/inventory-events/v1",
                           "seq": 1, "at_ns": 1050, "kind": "gap_recorded",
                           "event": {"subject": "model", "reason": "loss"}}
                    gap["event"][field] = denied
                    joint_events = s1_stream()
                    single_events = s1_stream()
                    joint_events.insert(1, copy.deepcopy(gap))
                    single_events.insert(1, copy.deepcopy(gap))
                    for position, line in enumerate(joint_events):
                        line["seq"] = position
                    for position, line in enumerate(single_events):
                        line["seq"] = position
                    with self.assertRaises(oracle.LedgerError) as caught:
                        oracle.compare_s1(rows_a, rows_b, s1_section(),
                                          s1_section(), joint_events,
                                          single_events)
                    self.assertIn("denied joint-machine text",
                                  str(caught.exception))

    def test_s1_stream_markers_enforced(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        with self.subTest("suppressed"):
            events = s1_stream()
            events[1]["event"]["gaps_suppressed"] = 1
            with self.assertRaises(oracle.LedgerError) as caught:
                oracle.compare_s1(rows_a, rows_b, s1_section(),
                                  s1_section(), events, s1_stream())
            self.assertIn("hides dispositions", str(caught.exception))
        with self.subTest("status"):
            events = s1_stream()
            events[0]["event"]["object_status"] = "populated"
            with self.assertRaises(oracle.LedgerError) as caught:
                oracle.compare_s1(rows_a, rows_b, s1_section(),
                                  s1_section(), events, s1_stream())
            self.assertIn("disagrees with snapshot status",
                          str(caught.exception))
        with self.subTest("row-event"):
            events = s1_stream()
            row = {"category": "operation", "reason": "unbound",
                   "unit": "operations", "completed": 1, "failed": 0,
                   "cancelled": 0, "unknown": 0, "active": 0}
            events.insert(1, {"schema": "p11scope/inventory-events/v1",
                              "seq": 1, "at_ns": 1050,
                              "kind": "key_operations_observed",
                              "event": {"revision": 2, "bucket": "unknown",
                                        "row": row}})
            for position, line in enumerate(events):
                line["seq"] = position
            with self.assertRaises(oracle.LedgerError) as caught:
                oracle.compare_s1(rows_a, rows_b, s1_section(),
                                  s1_section(), events, s1_stream())
            self.assertIn("unclaimed row", str(caught.exception))

    def test_s1_empty_ledgers_refused(self):
        oracle = require_s1(self)
        rows_a = build_ledger(SCEN["owner_poll"], [], pid=4242)
        rows_b = build_ledger(SCEN["chal_message"], [], pid=4343)
        oracle.validate_ledger(rows_a, "ledger A")
        oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, s1_section(), s1_section())
        self.assertIn("at least one ledger call", str(caught.exception))

    def test_s1_returns_follow_ledger_mutation(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "poll_msg")
        before = expected_s1(rows_a, rows_b)
        terminal = next(row for row in rows_a
                        if row.get("kind") == "call"
                        and row["phase"] == "terminal")
        terminal["rv"] = BAD
        result = oracle.compare_s1(rows_a, rows_b, s1_section(),
                                   s1_section())
        want = expected_s1(rows_a, rows_b)
        self.assertEqual(result["returns"], want["returns"])
        self.assertEqual(result["mechanisms"], want["mechanisms"])
        self.assertEqual(result["returns"]["async_poll"][BAD], 1)
        self.assertEqual(result["mechanisms"]["poll"]["errors"],
                         before["mechanisms"]["poll"]["errors"] + 1)
        terminal["fn"] = "async_wait"
        result = oracle.compare_s1(rows_a, rows_b, s1_section(),
                                   s1_section())
        want = expected_s1(rows_a, rows_b)
        self.assertEqual(result["returns"], want["returns"])
        self.assertIn("async_wait", result["returns"])

    def test_s1_collision_still_required(self):
        oracle = require_s1(self)
        rows_a = build_ledger(SCEN["owner_poll"], plan_poll_owner(2),
                              pid=4242)
        rows_b = build_ledger(SCEN["owner_poll"], plan_poll_owner(2),
                              pid=4343)
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, s1_section(), s1_section())
        self.assertIn("processes share one label", str(caught.exception))

    def test_s1_cli_healthy_and_mutation(self):
        require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(ORACLE, "poll_msg")
        want = expected_s1(rows_a, rows_b)
        with tempfile.TemporaryDirectory() as tmp:
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            snap_joint = Path(tmp) / "joint.json"
            snap_single = Path(tmp) / "s1only.json"
            events_joint = Path(tmp) / "joint.jsonl"
            events_single = Path(tmp) / "s1only.jsonl"
            write_jsonl(ledger_a, rows_a)
            write_jsonl(ledger_b, rows_b)
            write_json(snap_joint, s1_section())
            write_json(snap_single, s1_section())
            write_jsonl(events_joint, s1_stream())
            write_jsonl(events_single, s1_stream())
            healthy = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), "--s1", str(ledger_a),
                 str(ledger_b), str(snap_joint), str(snap_single),
                 str(events_joint), str(events_single)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(healthy.returncode, 0, healthy.stderr)
            summary = json.loads(healthy.stdout)
            self.assertEqual(summary["mode"], "s1")
            self.assertEqual(summary["calls"], want["calls"])
            self.assertEqual(
                {name: {int(rv): count for rv, count in tally.items()}
                 for name, tally in summary["returns"].items()},
                want["returns"])
            self.assertEqual(summary["mechanisms"], want["mechanisms"])
            broken = s1_section()
            broken["status"] = "populated"
            broken["reason"] = "none"
            write_json(snap_joint, broken)
            refused = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), "--s1", str(ledger_a),
                 str(ledger_b), str(snap_joint), str(snap_single)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(refused.stdout, "")
            self.assertIn("want unavailable/journal_unavailable",
                          refused.stderr)
            self.assertNotIn("Traceback", refused.stderr)


if __name__ == "__main__":
    unittest.main()
