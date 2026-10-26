#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Two-feed H9 population fixture/oracle twins.

The oracle (scripts/joint-h9-compare.py) compares two interleaved feed
ledgers from tests/fixtures/joint-populations/two-feed.c against an
object_observations section and its event stream: operation order and
phase scripts, key_row started/completed with the row equation,
metadata_at_use equality with ledger-declared established labels, role
separation, unit agreement, unknown-row partition, S1Only permanence,
equal-handle separation across scopes, revision order, cumulative
counts, per-operation receipts, and cross-feed interleave order.

Healthy and mutation twins run here; the live-emission tests build the
tracked stub provider and the two-feed emitter with gcc and compare the
real emitted ledgers.
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
ORACLE_PATH = ROOT / "scripts" / "joint-h9-compare.py"
FIXTURE_SRC = ROOT / "tests" / "fixtures" / "joint-populations" / "two-feed.c"
PROVIDER_SRC = ROOT / "tests" / "fixtures" / "live-discovery-provider.c"

try:
    _SPEC = importlib.util.spec_from_file_location(
        "joint_h9_oracle", ORACLE_PATH
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


SIGN4 = [("init", 40), ("update", 41), ("update", 41), ("terminal", 42)]
MSG3 = [("init", 40), ("update", 41), ("terminal", 42)]
WRAP_A = [("init", 43), ("terminal", 43)]
WRAP_B = [("init", 44), ("terminal", 44)]
SIGN2 = [("init", 40), ("terminal", 42)]

MODES = {
    "interleave": [
        {"feed": "A", "path": "joint", "instance": "i3", "object": 11,
         "category": "sign", "role": "key", "metadata": "rsa_2048",
         "scope": "session:1", "steps": SIGN4},
        {"feed": "B", "path": "joint", "instance": "i4", "object": 12,
         "category": "message_sign", "role": "key", "metadata": "rsa_2048",
         "scope": "session:2", "steps": MSG3},
    ],
    "wrap": [
        {"feed": "A", "path": "joint", "instance": "i3", "object": 11,
         "category": "wrap", "role": "wrapping_key", "metadata": "rsa_2048",
         "scope": "provider:PA", "steps": WRAP_A},
        {"feed": "B", "path": "joint", "instance": "i3", "object": 12,
         "category": "wrap", "role": "wrapped_object", "metadata": "rsa_2048",
         "scope": "provider:PB", "steps": WRAP_B},
    ],
    "loss": [
        {"feed": "A", "path": "joint", "instance": "i3", "object": 11,
         "category": "sign", "role": "key", "metadata": "rsa_2048",
         "scope": "image:IA", "steps": SIGN2},
        {"feed": "B", "path": "s1only", "instance": "i4", "object": 12,
         "category": "sign", "role": "key", "metadata": "rsa_2048",
         "scope": "image:IB", "steps": SIGN2},
    ],
}


def unit_for(category):
    return "message_contexts" if category.startswith("message_") else "operations"


def healthy_ledger(cfg, ops=3, pid=4242, tid=4242, tick=1_000, rv=None):
    """Canned feed ledger: ready, feed row, scripted calls, ack."""
    rv = rv or {}
    rows = [{"kind": "ready", "pid": pid, "tid": tid, "t": tick,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    rows.append({"kind": "feed", "feed": cfg["feed"], "path": cfg["path"],
                 "instance": cfg["instance"], "object": cfg["object"],
                 "category": cfg["category"], "role": cfg["role"],
                 "metadata": cfg["metadata"], "scope": cfg["scope"],
                 "handle": 101})
    seq = 0
    for op in range(1, ops + 1):
        for index, (phase, slot) in enumerate(cfg["steps"]):
            seq += 1
            start = tick + 10
            end = start + 5
            rows.append({"kind": "call", "seq": seq, "fn": f"table[{slot}]",
                         "rv": rv.get((op, index), 0), "pid": pid, "tid": tid,
                         "t0": start, "t1": end, "feed": cfg["feed"],
                         "op": op, "phase": phase})
            tick = end
    rows.append({"kind": "ack", "issued": seq, "t": tick + 10})
    return rows


def metadata_block():
    cell = {"status": "value", "value": 3}
    return {"class": dict(cell),
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


def healthy_snapshot(summaries):
    """Build the consistent section for validated feed summaries."""
    keyed, unkeyed = {}, {}
    for feed in summaries:
        if feed["path"] == "joint" and feed["metadata"] is not None:
            key = (feed["instance"], feed["object"], feed["category"],
                   feed["role"], feed["metadata"])
            keyed.setdefault(key, []).append(feed)
        else:
            reason = "metadata_unknown" if feed["path"] == "joint" else "unbound"
            keyed_unknown = (feed["category"], reason)
            unkeyed.setdefault(keyed_unknown, []).append(feed)
    objects = sorted({feed["object"] for group in keyed.values() for feed in group})
    key_rows = []
    for key in sorted(keyed):
        group = keyed[key]
        begun = sum(feed["begun"] for feed in group)
        completed = sum(feed["completed"] for feed in group)
        failed = sum(feed["failed"] for feed in group)
        pending = sum(feed["pending"] for feed in group)
        key_rows.append({"instance": key[0], "object": key[1], "category": key[2],
                         "role": key[3], "metadata_at_use": key[4],
                         "unit": unit_for(key[2]), "started": begun,
                         "completed": completed, "failed": failed,
                         "cancelled": 0, "unknown": 0, "active": pending,
                         "key_join_lost": 0})
    unknown_rows = []
    for key in sorted(unkeyed):
        group = unkeyed[key]
        unknown_rows.append({"category": key[0], "reason": key[1],
                             "unit": unit_for(key[0]),
                             "completed": sum(feed["completed"] for feed in group),
                             "failed": sum(feed["failed"] for feed in group),
                             "cancelled": 0, "unknown": 0,
                             "active": sum(feed["pending"] for feed in group)})
    labels = {feed["object"]: feed["metadata"] for group in keyed.values()
              for feed in group}
    return {"version": 1, "revision": 7, "status": "populated", "reason": "none",
            "sessions": [{"session": 1, "origin": "opened", "status": "live"}],
            "objects": [object_row(object_id, labels[object_id])
                        for object_id in objects],
            "key_operations": key_rows,
            "unknown_key_operations": unknown_rows,
            "gaps": {"rows": [], "suppressed": 0},
            "budgets": {
                "key_rows": {"limit": 65536, "occupied": len(key_rows),
                             "refused": 0},
                "object_rows": {"limit": 65536, "occupied": len(objects),
                                "refused": 0},
                "unknown_rows": {"occupied": len(unknown_rows)},
                "encoded_bytes": 100, "allocation_refused": False,
                "refusal_reason": "none"}}


def healthy_stream(summaries, snapshot):
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
    # One cumulative event per completed operation, in global terminal
    # order, so receipts follow completion order across feeds.
    completions = []
    for feed in summaries:
        for op_id, op in feed["ops"].items():
            if op["outcome"] == "completed":
                completions.append((op["terminal_t1"], feed["feed"], op_id))
    completions.sort()
    rank = {}
    for terminal_t1, feed_name, op_id in completions:
        feed = next(item for item in summaries if item["feed"] == feed_name)
        revision += 1
        if feed["path"] == "joint" and feed["metadata"] is not None:
            key = (feed["instance"], feed["object"], feed["category"],
                   feed["role"], feed["metadata"])
            final = next(row for row in snapshot["key_operations"]
                         if (row["instance"], row["object"], row["category"],
                             row["role"], row["metadata_at_use"]) == key)
            bucket = "known"
        else:
            reason = "metadata_unknown" if feed["path"] == "joint" else "unbound"
            key = (feed["category"], reason)
            final = next(row for row in snapshot["unknown_key_operations"]
                         if (row["category"], row["reason"]) == key)
            bucket = "unknown"
        rank[key] = rank.get(key, 0) + 1
        row = copy.deepcopy(final)
        row["completed"] = rank[key]
        if bucket == "known":
            row["active"] = row["started"] - rank[key] - row["failed"]
        else:
            total = (final["completed"] + final["failed"] + final["active"])
            row["active"] = total - rank[key] - final["failed"]
        lines.append(envelope("key_operations_observed",
                              {"revision": revision, "bucket": bucket,
                               "row": row},
                              terminal_t1 + 100))
    base = completions[-1][0] if completions else 800
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


def validated_pair(oracle, mode, ops=3, rv_a=None, rv_b=None):
    rows_a = healthy_ledger(MODES[mode][0], ops=ops, rv=rv_a)
    rows_b = healthy_ledger(MODES[mode][1], ops=ops, rv=rv_b)
    first = oracle.validate_ledger(rows_a, "ledger A")
    second = oracle.validate_ledger(rows_b, "ledger B")
    return rows_a, rows_b, first, second


class FeedLedgerTwins(unittest.TestCase):
    def test_healthy_ledgers_validate(self):
        oracle = require_oracle(self)
        for mode in ("interleave", "wrap", "loss"):
            with self.subTest(mode=mode):
                _, _, first, second = validated_pair(oracle, mode)
                self.assertEqual(first["completed"], 3)
                self.assertEqual(second["completed"], 3)
                self.assertEqual(first["begun"], 3)
                self.assertEqual(second["begun"], 3)

    def test_mutation_second_row_must_be_feed(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        del rows[1]
        with self.assertRaisesRegex(oracle.LedgerError, "second row must be feed"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_call_feed_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[4]["feed"] = "B"
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees with feed row"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_op_phase_disorder_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[2]["phase"], rows[5]["phase"] = rows[5]["phase"], rows[2]["phase"]
        with self.assertRaisesRegex(oracle.LedgerError, "op 1 phase order"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_non_tail_open_op_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["loss"][0], ops=3)
        kept = [row for row in rows
                if not (row.get("kind") == "call" and row.get("op") == 1
                        and row.get("phase") == "terminal")]
        for position, row in enumerate(
                [row for row in kept if row.get("kind") == "call"], start=1):
            row["seq"] = position
        kept[-1] = {"kind": "ack", "issued": sum(1 for row in kept
                                                if row.get("kind") == "call"),
                    "t": kept[-1]["t"]}
        with self.assertRaisesRegex(oracle.LedgerError, "op 1 phase order"):
            oracle.validate_ledger(kept, "ledger A")

    def test_tail_open_op_counts_pending(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["loss"][0], ops=3)
        kept = [row for row in rows
                if not (row.get("kind") == "call" and row.get("op") == 3
                        and row.get("phase") == "terminal")]
        for position, row in enumerate(
                [row for row in kept if row.get("kind") == "call"], start=1):
            row["seq"] = position
        kept[-1] = {"kind": "ack", "issued": sum(1 for row in kept
                                                if row.get("kind") == "call"),
                    "t": kept[-1]["t"]}
        summary = oracle.validate_ledger(kept, "ledger A")
        self.assertEqual(summary["pending"], 1)
        self.assertEqual(summary["completed"], 2)
        rows_b = healthy_ledger(MODES["loss"][1], ops=3)
        other = oracle.validate_ledger(rows_b, "ledger B")
        snapshot = healthy_snapshot([summary, other])
        oracle.validate_snapshot(snapshot)
        self.assertEqual(snapshot["key_operations"][0]["active"], 1)
        oracle.compare_pair(summary, other, snapshot)
        stream = healthy_stream([summary, other], snapshot)
        oracle.compare_stream(stream, [summary, other], snapshot)

    def test_mutation_op_id_gap_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["loss"][0], ops=3)
        for row in rows:
            if row.get("op") == 3:
                row["op"] = 4
        with self.assertRaisesRegex(oracle.LedgerError, "op ids are not"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_t1_after_ack_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[2]["t0"] = rows[-1]["t"]
        rows[2]["t1"] = rows[-1]["t"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "ready/ack window"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_t0_before_ready_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[2]["t0"] = rows[0]["t"] - 1
        rows[2]["t1"] = rows[0]["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "ready/ack window"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_reversed_timestamps_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[3]["t0"], rows[3]["t1"] = rows[3]["t1"], rows[3]["t0"]
        with self.assertRaisesRegex(oracle.LedgerError, "precedes t0"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_foreign_pid_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[5]["pid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "pid"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_tid_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[5]["tid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "tid"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_non_integer_rv_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[2]["rv"] = "CKR_OK"
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_duplicate_seq_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[4]["seq"] = rows[3]["seq"]
        with self.assertRaisesRegex(oracle.LedgerError, "contiguity"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_issued_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[-1] = {"kind": "ack", "issued": 11, "t": rows[-1]["t"]}
        with self.assertRaisesRegex(oracle.LedgerError, "issued"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_fn_label_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[2]["fn"] = "C_Sign"
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows, "ledger A")
        rows = healthy_ledger(MODES["interleave"][0])
        rows[2]["fn"] = "table[104]"
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_clock_basis_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[0]["clock"] = "CLOCK_REALTIME"
        with self.assertRaisesRegex(oracle.LedgerError, "clock basis"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_non_call_row_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[3] = {"kind": "gap", "index": 0}
        with self.assertRaisesRegex(oracle.LedgerError, "non-call"):
            oracle.validate_ledger(rows, "ledger A")

    def test_mutation_non_object_frame_row_refused(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(MODES["interleave"][0])
        rows[0] = ["ready"]
        with self.assertRaisesRegex(oracle.LedgerError, "first row must be ready"):
            oracle.validate_ledger(rows, "ledger A")
        rows = healthy_ledger(MODES["interleave"][0])
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


class SnapshotTwins(unittest.TestCase):
    def test_healthy_snapshot_validates(self):
        oracle = require_oracle(self)
        for mode in ("interleave", "wrap", "loss"):
            with self.subTest(mode=mode):
                _, _, first, second = validated_pair(oracle, mode)
                snapshot = healthy_snapshot([first, second])
                oracle.validate_snapshot(snapshot)

    def test_mutation_unavailable_snapshot_refused(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        snapshot["status"] = "unavailable"
        snapshot["reason"] = "proof_refused_fallback"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "status unavailable"
                                    " reason proof_refused_fallback"
                                    ": joint evidence absent"):
            oracle.validate_snapshot(snapshot)

    def test_mutation_status_reason_disagree_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        snapshot["reason"] = "authority_lost"
        with self.assertRaisesRegex(oracle.LedgerError, "status/reason disagree"):
            oracle.validate_snapshot(snapshot)

    def test_mutation_row_equation_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        snapshot["key_operations"][0]["started"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "row equation"):
            oracle.validate_snapshot(snapshot)

    def test_mutation_unit_mismatch_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        message = next(row for row in snapshot["key_operations"]
                       if row["category"] == "message_sign")
        message["unit"] = "operations"
        with self.assertRaisesRegex(oracle.LedgerError, "unit .* disagrees"):
            oracle.validate_snapshot(snapshot)
        snapshot = healthy_snapshot([first, second])
        sign = next(row for row in snapshot["key_operations"]
                    if row["category"] == "sign")
        sign["unit"] = "message_contexts"
        with self.assertRaisesRegex(oracle.LedgerError, "unit .* disagrees"):
            oracle.validate_snapshot(snapshot)

    def test_mutation_unknown_row_with_started_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "loss")
        snapshot = healthy_snapshot([first, second])
        snapshot["unknown_key_operations"][0]["started"] = 3
        with self.assertRaisesRegex(oracle.LedgerError, "unexpected fields"):
            oracle.validate_snapshot(snapshot)

    def test_mutation_key_rows_out_of_order_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        snapshot["key_operations"].reverse()
        with self.assertRaisesRegex(oracle.LedgerError, "rows out of order"):
            oracle.validate_snapshot(snapshot)


class CompareTwins(unittest.TestCase):
    def test_healthy_modes_pass_with_stream(self):
        oracle = require_oracle(self)
        for mode in ("interleave", "wrap", "loss"):
            with self.subTest(mode=mode):
                _, _, first, second = validated_pair(oracle, mode)
                snapshot = healthy_snapshot([first, second])
                oracle.validate_snapshot(snapshot)
                result = oracle.compare_pair(first, second, snapshot)
                self.assertEqual(result["completed"], 6)
                stream = healthy_stream([first, second], snapshot)
                oracle.compare_stream(stream, [first, second], snapshot)

    def test_healthy_same_scope_handle_joins_one_row(self):
        oracle = require_oracle(self)
        cfg_b = dict(MODES["loss"][0], feed="B")
        rows_a = healthy_ledger(MODES["loss"][0], ops=2)
        rows_b = healthy_ledger(cfg_b, ops=2)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        snapshot = healthy_snapshot([first, second])
        self.assertEqual(len(snapshot["key_operations"]), 1)
        result = oracle.compare_pair(first, second, snapshot)
        self.assertEqual(result["completed"], 4)
        stream = healthy_stream([first, second], snapshot)
        oracle.compare_stream(stream, [first, second], snapshot)

    def test_healthy_null_metadata_feed_lands_unknown(self):
        oracle = require_oracle(self)
        cfg_b = dict(MODES["interleave"][1], metadata=None)
        rows_a = healthy_ledger(MODES["interleave"][0], ops=2)
        rows_b = healthy_ledger(cfg_b, ops=2)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        snapshot = healthy_snapshot([first, second])
        self.assertEqual(len(snapshot["key_operations"]), 1)
        self.assertEqual(snapshot["unknown_key_operations"][0]["reason"],
                         "metadata_unknown")
        oracle.compare_pair(first, second, snapshot)

    def test_mutation_joined_equal_handles_rejected(self):
        oracle = require_oracle(self)
        rows_a = healthy_ledger(MODES["loss"][0], ops=2)
        rows_b = healthy_ledger(MODES["loss"][1], ops=2)
        rows_b[1]["object"] = 11
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        snapshot = healthy_snapshot([first, second])
        with self.assertRaisesRegex(oracle.LedgerError, "joined equal handles"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_split_same_scope_handle_rejected(self):
        oracle = require_oracle(self)
        rows_a = healthy_ledger(MODES["loss"][0], ops=2)
        rows_b = healthy_ledger(MODES["loss"][1], ops=2)
        rows_b[1]["scope"] = "image:IA"
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        snapshot = healthy_snapshot([first, second])
        with self.assertRaisesRegex(oracle.LedgerError, "split same-scope handle"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_backfilled_metadata_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        sign = next(row for row in snapshot["key_operations"]
                    if row["category"] == "sign")
        sign["metadata_at_use"] = "rsa_4096"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "missing key row for feed A"
                                    " i3,11,sign,key,rsa_2048"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_null_metadata_feed_upgraded_rejected(self):
        oracle = require_oracle(self)
        cfg_b = dict(MODES["interleave"][1], metadata=None)
        rows_a = healthy_ledger(MODES["interleave"][0], ops=2)
        rows_b = healthy_ledger(cfg_b, ops=2)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        snapshot = healthy_snapshot([first, second])
        snapshot["key_operations"].append(
            {"instance": "i4", "object": 12, "category": "message_sign",
             "role": "key", "metadata_at_use": "rsa_2048",
             "unit": "message_contexts", "started": 2, "completed": 2,
             "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
             "key_join_lost": 0})
        snapshot["key_operations"].sort(
            key=lambda row: (row["instance"], row["object"], row["category"],
                             row["role"], row["metadata_at_use"]))
        with self.assertRaisesRegex(oracle.LedgerError, "upgrade refused"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_s1only_feed_upgraded_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "loss")
        snapshot = healthy_snapshot([first, second])
        snapshot["key_operations"].append(
            {"instance": "i4", "object": 12, "category": "sign",
             "role": "key", "metadata_at_use": "rsa_2048",
             "unit": "operations", "started": 3, "completed": 3,
             "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
             "key_join_lost": 0})
        snapshot["objects"].append(object_row(12, "rsa_2048"))
        snapshot["objects"].sort(key=lambda row: row["object"])
        with self.assertRaisesRegex(oracle.LedgerError, "upgrade refused"):
            oracle.compare_pair(first, second, snapshot)
        snapshot = healthy_snapshot([first, second])
        snapshot["objects"].append(object_row(12, "rsa_2048"))
        with self.assertRaisesRegex(oracle.LedgerError, "staged for"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_summed_role_rows_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "wrap")
        snapshot = healthy_snapshot([first, second])
        wrapping = next(row for row in snapshot["key_operations"]
                        if row["role"] == "wrapping_key")
        wrapping["started"] = 6
        wrapping["completed"] = 6
        snapshot["key_operations"] = [wrapping]
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "key row started 6 disagrees with ledger 3"
                                    " for feed A"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_doubled_unknown_completed_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "loss")
        snapshot = healthy_snapshot([first, second])
        snapshot["unknown_key_operations"][0]["completed"] = 4
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "unknown row completed 4 disagrees"
                                    " with ledger 3 for feed B"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_erased_completion_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        sign = next(row for row in snapshot["key_operations"]
                    if row["category"] == "sign")
        sign["completed"] = 2
        sign["active"] = 1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "key row completed 2 disagrees"
                                    " with ledger 3"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_hidden_failure_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(
            oracle, "interleave", rv_a={(2, 3): 7})
        self.assertEqual(first["failed"], 1)
        snapshot = healthy_snapshot([first, second])
        sign = next(row for row in snapshot["key_operations"]
                    if row["category"] == "sign")
        sign["failed"] = 0
        sign["active"] = 1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "key row failed 0 disagrees with ledger 1"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_snapshot_gaps_suppressed_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "loss")
        snapshot = healthy_snapshot([first, second])
        snapshot["gaps"]["suppressed"] = 1
        with self.assertRaisesRegex(oracle.LedgerError, "hides dispositions"):
            oracle.compare_pair(first, second, snapshot)

    def test_mutation_unmatched_key_row_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "loss")
        snapshot = healthy_snapshot([first, second])
        snapshot["key_operations"].append(
            {"instance": "i9", "object": 99, "category": "sign",
             "role": "key", "metadata_at_use": "rsa_2048",
             "unit": "operations", "started": 1, "completed": 1,
             "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
             "key_join_lost": 0})
        snapshot["key_operations"].sort(
            key=lambda row: (row["instance"], row["object"], row["category"],
                             row["role"], row["metadata_at_use"]))
        with self.assertRaisesRegex(oracle.LedgerError, "unmatched key row"):
            oracle.compare_pair(first, second, snapshot)


    def test_mutation_empty_snapshot_rows_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        snapshot["key_operations"] = []
        snapshot["unknown_key_operations"] = []
        snapshot["objects"] = []
        with self.assertRaisesRegex(oracle.LedgerError, "missing key row"):
            oracle.compare_pair(first, second, snapshot)


class StreamTwins(unittest.TestCase):
    def test_mutation_reordered_replay_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        completions = [line for line in stream
                       if line["kind"] == "key_operations_observed"]
        same_row = [line for line in completions
                    if line["event"]["row"]["category"] == "sign"]
        same_row[0]["event"]["revision"], same_row[1]["event"]["revision"] = \
            same_row[1]["event"]["revision"], same_row[0]["event"]["revision"]
        with self.assertRaisesRegex(oracle.LedgerError, "revision order"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_chain_break_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        completions = [line for line in stream
                       if line["kind"] == "key_operations_observed"]
        # Swap one revision across rows; each row series stays ordered.
        completions[2]["event"]["revision"], completions[3]["event"]["revision"] = \
            completions[3]["event"]["revision"], completions[2]["event"]["revision"]
        with self.assertRaisesRegex(oracle.LedgerError, "leave one chain"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_completed_decreases_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        completions = [line for line in stream
                       if line["kind"] == "key_operations_observed"]
        same_row = [line for line in completions
                    if line["event"]["row"]["category"] == "sign"]
        same_row[1]["event"]["row"]["completed"] = 0
        same_row[1]["event"]["row"]["active"] = 3
        with self.assertRaisesRegex(oracle.LedgerError, "completed decreases"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_receipt_before_t0_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        first_cover = next(line for line in stream
                           if line["kind"] == "key_operations_observed")
        row = first_cover["event"]["row"]
        feed = first if (row.get("instance"), row.get("object")) == (
            first["instance"], first["object"]) else second
        op_id = next(op_id for op_id, op in feed["ops"].items()
                     if op["outcome"] == "completed")
        first_cover["at_ns"] = feed["ops"][op_id]["terminal_t0"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "precedes call t0"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_preemption_window_at_t0_passes(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        first_cover = next(line for line in stream
                           if line["kind"] == "key_operations_observed")
        row = first_cover["event"]["row"]
        feed = first if (row.get("instance"), row.get("object")) == (
            first["instance"], first["object"]) else second
        op_id = next(op_id for op_id, op in feed["ops"].items()
                     if op["outcome"] == "completed")
        first_cover["at_ns"] = feed["ops"][op_id]["terminal_t0"]
        oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_interleave_violated_rejected(self):
        oracle = require_oracle(self)
        rows_a = healthy_ledger(MODES["interleave"][0], ops=1, tick=1_000)
        rows_b = healthy_ledger(MODES["interleave"][1], ops=1, tick=100_000)
        first = oracle.validate_ledger(rows_a, "ledger A")
        second = oracle.validate_ledger(rows_b, "ledger B")
        term_a = first["ops"][1]
        term_b = second["ops"][1]
        self.assertLess(term_a["terminal_t1"], term_b["terminal_t0"])
        snapshot = healthy_snapshot([first, second])
        key_a = next(row for row in snapshot["key_operations"]
                     if row["instance"] == "i3")
        key_b = next(row for row in snapshot["key_operations"]
                     if row["instance"] == "i4")
        stream = [
            {"schema": "p11scope/inventory-events/v1", "seq": 0,
             "at_ns": 500, "kind": "object_observed",
             "event": {"revision": 1,
                       "row": copy.deepcopy(snapshot["objects"][0])}},
            {"schema": "p11scope/inventory-events/v1", "seq": 1,
             "at_ns": 500, "kind": "object_observed",
             "event": {"revision": 1,
                       "row": copy.deepcopy(snapshot["objects"][1])}},
            {"schema": "p11scope/inventory-events/v1", "seq": 2,
             "at_ns": term_b["terminal_t1"] + 100,
             "kind": "key_operations_observed",
             "event": {"revision": 2, "bucket": "known",
                       "row": copy.deepcopy(key_b)}},
            {"schema": "p11scope/inventory-events/v1", "seq": 3,
             "at_ns": term_a["terminal_t1"] + 100,
             "kind": "key_operations_observed",
             "event": {"revision": 3, "bucket": "known",
                       "row": copy.deepcopy(key_a)}},
        ]
        with self.assertRaisesRegex(oracle.LedgerError, "interleave order"):
            oracle.compare_stream(stream, [first, second], snapshot)
        stream[2]["event"]["revision"], stream[3]["event"]["revision"] = 3, 2
        stream[2], stream[3] = stream[3], stream[2]
        stream[2]["seq"], stream[3]["seq"] = 2, 3
        oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_stream_snapshot_diverge_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        completions = [line for line in stream
                       if line["kind"] == "key_operations_observed"]
        completions[-1]["event"]["row"]["completed"] -= 1
        completions[-1]["event"]["row"]["active"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees with snapshot"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_uncovered_completion_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        _, _, short_first, short_second = validated_pair(
            oracle, "interleave", ops=2)
        snapshot = healthy_snapshot([short_first, short_second])
        stream = healthy_stream([short_first, short_second], snapshot)
        with self.assertRaisesRegex(oracle.LedgerError, "never covers"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_stream_missing_row_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        kept = [line for line in stream
                if not (line["kind"] == "key_operations_observed"
                        and line["event"]["row"].get("instance") == "i4")]
        with self.assertRaisesRegex(oracle.LedgerError, "never carries"):
            oracle.compare_stream(kept, [first, second], snapshot)

    def test_mutation_stream_upgrade_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "loss")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        smuggled = {"instance": "i4", "object": 12, "category": "sign",
                    "role": "key", "metadata_at_use": "rsa_2048",
                    "unit": "operations", "started": 3, "completed": 3,
                    "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
                    "key_join_lost": 0}
        last_revision = max(line["event"]["revision"] for line in stream
                            if line["kind"] in ("object_observed",
                                                "key_operations_observed"))
        extra = {"schema": "p11scope/inventory-events/v1", "seq": len(stream),
                 "at_ns": 999_999, "kind": "key_operations_observed",
                 "event": {"revision": last_revision, "bucket": "known",
                           "row": smuggled}}
        stream.insert(-2, extra)
        for position, line in enumerate(stream):
            line["seq"] = position
        with self.assertRaisesRegex(oracle.LedgerError, "unclaimed row"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_gaps_suppressed_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        marker = next(line for line in stream if line["kind"] == "pass_committed")
        marker["event"]["gaps_suppressed"] = 1
        with self.assertRaisesRegex(oracle.LedgerError, "hides dispositions"):
            oracle.compare_stream(stream, [first, second], snapshot)
        stream = healthy_stream([first, second], snapshot)
        terminal = next(line for line in stream if line["kind"] == "ended")
        terminal["event"]["gaps_suppressed"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "hides dispositions"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_mutation_object_status_disagree_rejected(self):
        oracle = require_oracle(self)
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        marker = next(line for line in stream if line["kind"] == "pass_committed")
        marker["event"]["object_status"] = "stale"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "object_status .* disagrees"):
            oracle.compare_stream(stream, [first, second], snapshot)

    def test_cli_healthy_and_mutation_reason(self):
        require_oracle(self)
        oracle = ORACLE
        _, _, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        stream = healthy_stream([first, second], snapshot)
        with tempfile.TemporaryDirectory() as tmp:
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            snap = Path(tmp) / "snap.json"
            events = Path(tmp) / "events.jsonl"
            write_jsonl(ledger_a, healthy_ledger(MODES["interleave"][0]))
            write_jsonl(ledger_b, healthy_ledger(MODES["interleave"][1]))
            write_json(snap, snapshot)
            write_jsonl(events, stream)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger_a),
                 str(ledger_b), str(snap), str(events)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["completed"], 6)
            broken = copy.deepcopy(snapshot)
            sign = next(row for row in broken["key_operations"]
                        if row["category"] == "sign")
            sign["completed"] = 2
            sign["active"] = 1
            write_json(snap, broken)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger_a),
                 str(ledger_b), str(snap)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertRegex(completed.stderr,
                             r"h9 refused: key row completed 2 disagrees"
                             r" with ledger 3")

    def test_cli_string_payload_not_echoed(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            snap = Path(tmp) / "snap.json"
            rows = healthy_ledger(MODES["interleave"][0])
            rows[5]["pid"] = "PIN=1234-secret"
            write_jsonl(ledger_a, rows)
            write_jsonl(ledger_b, healthy_ledger(MODES["interleave"][1]))
            write_json(snap, {"version": 1})
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger_a),
                 str(ledger_b), str(snap)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("h9 refused: ledger A: pid string disagrees",
                          completed.stderr)
            self.assertNotIn("PIN=1234-secret", completed.stderr)

    def test_cli_non_object_first_row_refused_without_traceback(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            snap = Path(tmp) / "snap.json"
            rows = healthy_ledger(MODES["interleave"][0])
            rows[0] = ["ready"]
            write_jsonl(ledger_a, rows)
            write_jsonl(ledger_b, healthy_ledger(MODES["interleave"][1]))
            write_json(snap, {"version": 1})
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger_a),
                 str(ledger_b), str(snap)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("h9 refused: ledger A: first row must be ready",
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


class FeedEmissionTests(unittest.TestCase):
    def build_provider(self, tmp, export_tables=1, m32=False):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        provider = Path(tmp) / ("provider32.so" if m32 else "provider.so")
        command = ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        if m32:
            command.append("-m32")
        command += ["-fPIC", f"-DP11SCOPE_EXPORT_TABLES={export_tables}",
                    "-shared", "-Wl,-z,defs",
                    "-o", str(provider), str(PROVIDER_SRC)]
        build = subprocess.run(command, capture_output=True, text=True,
                               timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return provider

    def build_fixture(self, tmp, m32=False):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
        fixture = Path(tmp) / ("two-feed32" if m32 else "two-feed")
        command = ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        if m32:
            command.append("-m32")
        command += [str(FIXTURE_SRC), "-ldl", "-o", str(fixture)]
        build = subprocess.run(command, capture_output=True, text=True,
                               timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return fixture

    def build_pair(self, tmp):
        return self.build_provider(tmp), self.build_fixture(tmp)

    def test_live_modes_validate_and_compare(self):
        oracle = require_oracle(self)
        env = dict(os.environ, P11SCOPE_FIXTURE_QUIET="1")
        for mode in ("interleave", "wrap", "loss"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                provider, fixture = self.build_pair(tmp)
                ledger_a = Path(tmp) / "a.jsonl"
                ledger_b = Path(tmp) / "b.jsonl"
                completed = subprocess.run(
                    [str(fixture), str(provider), str(provider), mode, "4",
                     str(ledger_a), str(ledger_b)],
                    capture_output=True, text=True, timeout=60, env=env)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("READY pid=", completed.stdout)
                with open(ledger_a, encoding="utf-8") as stream:
                    first = oracle.validate_ledger(
                        oracle.read_ledger(stream), "ledger A")
                with open(ledger_b, encoding="utf-8") as stream:
                    second = oracle.validate_ledger(
                        oracle.read_ledger(stream), "ledger B")
                self.assertEqual(first["completed"], 4)
                self.assertEqual(second["completed"], 4)
                with open(ledger_a, encoding="utf-8") as stream:
                    calls_a = [row for row in oracle.read_ledger(stream)
                               if row.get("kind") == "call"]
                with open(ledger_b, encoding="utf-8") as stream:
                    calls_b = [row for row in oracle.read_ledger(stream)
                               if row.get("kind") == "call"]
                self.assertLess(calls_a[0]["t0"], calls_b[0]["t0"])
                self.assertLess(calls_b[0]["t0"], calls_a[1]["t0"])
                snapshot = healthy_snapshot([first, second])
                oracle.validate_snapshot(snapshot)
                result = oracle.compare_pair(first, second, snapshot)
                self.assertEqual(result["completed"], 8)
                stream = healthy_stream([first, second], snapshot)
                oracle.compare_stream(stream, [first, second], snapshot)

    def test_live_mutation_fails(self):
        oracle = require_oracle(self)
        env = dict(os.environ, P11SCOPE_FIXTURE_QUIET="1")
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(provider), "wrap", "2",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger_a, encoding="utf-8") as stream:
                first = oracle.validate_ledger(
                    oracle.read_ledger(stream), "ledger A")
            with open(ledger_b, encoding="utf-8") as stream:
                second = oracle.validate_ledger(
                    oracle.read_ledger(stream), "ledger B")
            snapshot = healthy_snapshot([first, second])
            snapshot["key_operations"][0]["completed"] -= 1
            snapshot["key_operations"][0]["active"] += 1
            with self.assertRaisesRegex(oracle.LedgerError, "disagrees"):
                oracle.compare_pair(first, second, snapshot)

    def test_fixture_waits_for_go(self):
        oracle = require_oracle(self)
        env = dict(os.environ, P11SCOPE_FIXTURE_QUIET="1")
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            gate = Path(tmp) / "GO"
            child = subprocess.Popen(
                [str(fixture), str(provider), str(provider), "loss", "2",
                 str(ledger_a), str(ledger_b), str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=env)
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
            self.assertEqual(summary["completed"], 2)

    def test_fixture_stop_flag_interrupts_wait(self):
        require_oracle(self)
        env = dict(os.environ, P11SCOPE_FIXTURE_QUIET="1")
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            gate = Path(tmp) / "GO"
            child = subprocess.Popen(
                [str(fixture), str(provider), str(provider), "loss", "2",
                 str(ledger_a), str(ledger_b), str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=env)
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

    def test_fixture_refuses_nonstub_provider(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            if not shutil.which("gcc"):
                self.skipTest("requires gcc; installs nothing")
            fixture = self.build_fixture(tmp)
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
                [str(fixture), str(provider), str(provider), "wrap", "2",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("stub", completed.stderr)
            self.assertFalse(ledger_a.exists())
            self.assertFalse(ledger_b.exists())

    def test_fixture_refuses_hidden_tables_provider(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_provider(tmp, export_tables=0)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(provider), "wrap", "2",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("stub", completed.stderr)
            self.assertFalse(ledger_a.exists())

    def test_fixture_refuses_bad_argv(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            completed = subprocess.run(
                [str(fixture)], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            completed = subprocess.run(
                [str(fixture), str(provider), str(provider), "nope", "2",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(ledger_a.exists())
            completed = subprocess.run(
                [str(fixture), str(provider), str(provider), "wrap", "0",
                 str(ledger_a), str(ledger_b)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(ledger_a.exists())

    def test_fixture_m32_build_runs(self):
        require_oracle(self)
        env = dict(os.environ, P11SCOPE_FIXTURE_QUIET="1")
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
                fixture = self.build_fixture(tmp, m32=True)
            except AssertionError:
                self.skipTest("32-bit provider build is not supported here")
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            try:
                completed = subprocess.run(
                    [str(fixture), str(provider), str(provider), "loss", "1",
                     str(ledger_a), str(ledger_b)],
                    capture_output=True, text=True, timeout=60, env=env)
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

    Categories come from each ledger's own feed row (never the
    oracle's summary); the two-feed fixture declares no mechanism, so
    its category is the attribution dimension. Errors are non-OK
    returns at S1 granularity.
    """
    returns, categories, calls = {}, {}, 0
    for rows in (rows_a, rows_b):
        category = rows[1]["category"]
        group = categories.setdefault(category, {"calls": 0, "errors": 0})
        for row in rows:
            if row.get("kind") != "call":
                continue
            calls += 1
            tally = returns.setdefault(row["fn"], {})
            tally[row["rv"]] = tally.get(row["rv"], 0) + 1
            group["calls"] += 1
            if row["rv"] != 0:
                group["errors"] += 1
    return {"calls": calls, "returns": returns, "categories": categories}


class S1Twins(unittest.TestCase):
    def test_s1_healthy_pair_passes(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        result = oracle.compare_s1(rows_a, rows_b, s1_section(),
                                   s1_stream())
        want = expected_s1(rows_a, rows_b)
        self.assertEqual(result["mode"], "s1")
        self.assertEqual(result["feeds"], 2)
        self.assertEqual(result["calls"], want["calls"])
        self.assertEqual(result["returns"], want["returns"])
        self.assertEqual(result["categories"], want["categories"])

    def test_s1_works_without_stream(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        result = oracle.compare_s1(rows_a, rows_b, s1_section())
        self.assertEqual(result["mode"], "s1")
        self.assertEqual(result["calls"], expected_s1(rows_a, rows_b)["calls"])

    def test_s1_populated_section_refused(self):
        oracle = require_s1(self)
        rows_a, rows_b, first, second = validated_pair(oracle, "interleave")
        snapshot = healthy_snapshot([first, second])
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, snapshot)
        self.assertIn("want unavailable/journal_unavailable",
                      str(caught.exception))

    def test_s1_reason_must_be_journal(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        section = s1_section()
        section["reason"] = "bootstrap_unavailable"
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, section)
        self.assertIn("want unavailable/journal_unavailable",
                      str(caught.exception))

    def test_s1_rows_refused(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        key_row = {"instance": "i3", "object": 11, "category": "sign",
                   "role": "key", "metadata_at_use": "rsa_2048",
                   "unit": "operations", "started": 1, "completed": 1,
                   "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
                   "key_join_lost": 0}
        unknown_row = {"category": "sign", "reason": "unbound",
                       "unit": "operations", "completed": 1, "failed": 0,
                       "cancelled": 0, "unknown": 0, "active": 0}
        session_row = {"session": 1, "origin": "opened", "status": "live"}
        cases = (("key_operations", [key_row], "needs no key-operation rows"),
                 ("unknown_key_operations", [unknown_row],
                  "needs no unknown key-operation rows"),
                 ("sessions", [session_row], "needs no session rows"),
                 ("objects", [object_row(11, "rsa_2048")],
                  "needs no session rows"))
        for field, planted, token in cases:
            with self.subTest(field=field):
                section = s1_section()
                section[field] = planted
                with self.assertRaises(oracle.LedgerError) as caught:
                    oracle.compare_s1(rows_a, rows_b, section)
                self.assertIn(token, str(caught.exception))

    def test_s1_section_denied_gap_in_either_position(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        denied = "joint machine unavailable"
        for field in ("subject", "reason"):
            with self.subTest(field=field):
                section = s1_section()
                gap = {"subject": "model", "reason": "loss", "repeats": 1}
                gap[field] = denied
                section["gaps"]["rows"] = [gap]
                with self.assertRaises(oracle.LedgerError) as caught:
                    oracle.compare_s1(rows_a, rows_b, section)
                self.assertIn("denied joint-machine text",
                              str(caught.exception))

    def test_s1_section_benign_gap_still_refused(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        section = s1_section()
        section["gaps"]["rows"] = [{"subject": "model", "reason": "loss",
                                    "repeats": 2}]
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, section)
        self.assertNotIn("denied joint-machine text", str(caught.exception))

    def test_s1_section_shape_still_enforced(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        section = s1_section()
        section["gaps"]["rows"] = [{"subject": "bogus", "reason": "loss",
                                    "repeats": 1}]
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, section)
        self.assertIn("subject invalid", str(caught.exception))

    def test_s1_section_suppressed_refused(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        section = s1_section()
        section["gaps"]["suppressed"] = 1
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, section)
        self.assertIn("hides dispositions", str(caught.exception))

    def test_s1_stream_denied_gap_in_either_position(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        denied = "joint machine unavailable"
        for field in ("subject", "reason"):
            with self.subTest(field=field):
                events = s1_stream()
                gap = {"schema": "p11scope/inventory-events/v1",
                       "seq": 1, "at_ns": 1050, "kind": "gap_recorded",
                       "event": {"subject": "model", "reason": "loss"}}
                gap["event"][field] = denied
                events.insert(1, gap)
                for position, line in enumerate(events):
                    line["seq"] = position
                with self.assertRaises(oracle.LedgerError) as caught:
                    oracle.compare_s1(rows_a, rows_b, s1_section(), events)
                self.assertIn("denied joint-machine text",
                              str(caught.exception))

    def test_s1_stream_markers_enforced(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        with self.subTest("suppressed"):
            events = s1_stream()
            events[1]["event"]["gaps_suppressed"] = 1
            with self.assertRaises(oracle.LedgerError) as caught:
                oracle.compare_s1(rows_a, rows_b, s1_section(), events)
            self.assertIn("hides dispositions", str(caught.exception))
        with self.subTest("status"):
            events = s1_stream()
            events[0]["event"]["object_status"] = "populated"
            with self.assertRaises(oracle.LedgerError) as caught:
                oracle.compare_s1(rows_a, rows_b, s1_section(), events)
            self.assertIn("disagrees with snapshot status",
                          str(caught.exception))
        with self.subTest("row-event"):
            events = s1_stream()
            row = {"category": "sign", "reason": "unbound",
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
                oracle.compare_s1(rows_a, rows_b, s1_section(), events)
            self.assertIn("unclaimed row", str(caught.exception))

    def test_s1_empty_ledgers_refused(self):
        oracle = require_s1(self)
        rows_a = healthy_ledger(MODES["interleave"][0], ops=0)
        rows_b = healthy_ledger(MODES["interleave"][1], ops=0)
        oracle.validate_ledger(rows_a, "ledger A")
        oracle.validate_ledger(rows_b, "ledger B")
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, s1_section())
        self.assertIn("at least one ledger call", str(caught.exception))

    def test_s1_returns_follow_ledger_mutation(self):
        oracle = require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(oracle, "interleave")
        terminal = next(row for row in rows_a
                        if row.get("kind") == "call"
                        and row["phase"] == "terminal")
        terminal["rv"] = 7
        result = oracle.compare_s1(rows_a, rows_b, s1_section())
        want = expected_s1(rows_a, rows_b)
        self.assertEqual(result["returns"], want["returns"])
        self.assertEqual(result["categories"], want["categories"])
        self.assertEqual(result["returns"]["table[42]"][7], 1)
        self.assertEqual(result["categories"]["sign"]["errors"], 1)
        terminal["fn"] = "table[9]"
        result = oracle.compare_s1(rows_a, rows_b, s1_section())
        want = expected_s1(rows_a, rows_b)
        self.assertEqual(result["returns"], want["returns"])
        self.assertIn("table[9]", result["returns"])

    def test_s1_pair_shape_still_required(self):
        oracle = require_s1(self)
        rows_a = healthy_ledger(MODES["interleave"][0])
        rows_b = healthy_ledger(MODES["interleave"][0])
        with self.assertRaises(oracle.LedgerError) as caught:
            oracle.compare_s1(rows_a, rows_b, s1_section())
        self.assertIn("feeds share one label", str(caught.exception))

    def test_s1_pair_scope_handle_rules_still_required(self):
        oracle = require_s1(self)
        with self.subTest("joined-handles"):
            cfg_b = dict(MODES["interleave"][1])
            rows_a = healthy_ledger(MODES["interleave"][0])
            rows_b = healthy_ledger(cfg_b)
            rows_b[1]["object"] = rows_a[1]["object"]
            with self.assertRaises(oracle.LedgerError) as caught:
                oracle.compare_s1(rows_a, rows_b, s1_section())
            self.assertIn("joined equal handles", str(caught.exception))
        with self.subTest("split-handle"):
            cfg_a = dict(MODES["interleave"][0], scope="session:9")
            cfg_b = dict(MODES["interleave"][1], scope="session:9")
            rows_a = healthy_ledger(cfg_a)
            rows_b = healthy_ledger(cfg_b)
            rows_b[1]["object"] = rows_a[1]["object"] + 100
            with self.assertRaises(oracle.LedgerError) as caught:
                oracle.compare_s1(rows_a, rows_b, s1_section())
            self.assertIn("split same-scope handle", str(caught.exception))

    def test_s1_cli_healthy_and_mutation(self):
        require_s1(self)
        rows_a, rows_b, _, _ = validated_pair(ORACLE, "interleave")
        want = expected_s1(rows_a, rows_b)
        with tempfile.TemporaryDirectory() as tmp:
            ledger_a = Path(tmp) / "a.jsonl"
            ledger_b = Path(tmp) / "b.jsonl"
            snap = Path(tmp) / "snapshot.json"
            events_path = Path(tmp) / "events.jsonl"
            write_jsonl(ledger_a, rows_a)
            write_jsonl(ledger_b, rows_b)
            write_json(snap, s1_section())
            write_jsonl(events_path, s1_stream())
            healthy = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), "--s1", str(ledger_a),
                 str(ledger_b), str(snap), str(events_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(healthy.returncode, 0, healthy.stderr)
            summary = json.loads(healthy.stdout)
            self.assertEqual(summary["mode"], "s1")
            self.assertEqual(summary["calls"], want["calls"])
            self.assertEqual(
                {name: {int(rv): count for rv, count in tally.items()}
                 for name, tally in summary["returns"].items()},
                want["returns"])
            self.assertEqual(summary["categories"], want["categories"])
            broken = s1_section()
            broken["status"] = "populated"
            broken["reason"] = "none"
            write_json(snap, broken)
            refused = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), "--s1", str(ledger_a),
                 str(ledger_b), str(snap)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(refused.stdout, "")
            self.assertIn("want unavailable/journal_unavailable",
                          refused.stderr)
            self.assertNotIn("Traceback", refused.stderr)


if __name__ == "__main__":
    unittest.main()
