#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Two-provider ledger/oracle twins.

The oracle (scripts/joint-two-provider-compare.py) compares the
feed-labeled ledger emitted by tests/fixtures/two-providers/dlmopen-sibs.c
(same-file dlmopen siblings with colliding handles) and late-b.c (late B
arrival, physical cut, post-cut burst; providers and tokens prepared by
mk-providers.sh) against snapshot rows: per-feed positives on one caller
with distinct modules, handle-collision evidence, cut arithmetic with
mapping-interruption and identity-gap evidence, uncertainty that preserves
the sibling feed, file-local negatives, module identity resolution, and
the association bound.

Healthy and mutation twins run unignored; the live-emission tests build
the fixtures with gcc and validate the real emitted ledgers.
"""

import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "scripts" / "joint-two-provider-compare.py"
SIBS_SRC = ROOT / "tests" / "fixtures" / "two-providers" / "dlmopen-sibs.c"
LATE_SRC = ROOT / "tests" / "fixtures" / "two-providers" / "late-b.c"
MK_PROVIDERS = ROOT / "tests" / "fixtures" / "two-providers" / "mk-providers.sh"

SOFT_LIBS = (
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
)

try:
    _SPEC = importlib.util.spec_from_file_location(
        "joint_two_provider_compare", ORACLE_PATH
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


SHA_A = "aa" * 32
SHA_B = "bb" * 32


def ledger_rows(calls_a=10, calls_b=10, order="ab", rv_a=0, rv_b=0,
                handles=True, cut_at=None, pid=4242, tid=4242):
    """Canned two-feed ledger: readys, handles, interleaved calls, cut, ack."""
    rows = [
        {"kind": "ready", "feed": "A", "pid": pid, "tid": tid, "t": 1_000,
         "clock": "CLOCK_MONOTONIC", "unit": "ns"},
        {"kind": "ready", "feed": "B", "pid": pid, "tid": tid, "t": 1_010,
         "clock": "CLOCK_MONOTONIC", "unit": "ns"},
    ]
    if handles:
        rows += [
            {"kind": "handle", "feed": "A", "slot": 12, "value": 0xA11CE,
             "t": 1_020},
            {"kind": "handle", "feed": "B", "slot": 12, "value": 0xA11CE,
             "t": 1_030},
        ]
    first = "A" if order == "ab" else "B"
    rounds = max(calls_a, calls_b)
    counts = {"A": 0, "B": 0}
    tick = 1_100
    seq = 0
    for _ in range(rounds):
        for feed in (first, "B" if first == "A" else "A"):
            want = calls_a if feed == "A" else calls_b
            if counts[feed] >= want:
                continue
            counts[feed] += 1
            rv = rv_a if feed == "A" else rv_b
            if callable(rv):
                rv = rv(counts[feed])
            seq += 1
            start = tick + 10
            end = start + 5
            rows.append({"kind": "call", "seq": seq, "feed": feed,
                         "fn": "table[4]", "rv": rv, "pid": pid, "tid": tid,
                         "t0": start, "t1": end})
            tick = end
    if cut_at is not None:
        rows.append({"kind": "cut", "feed": "B", "at_seq": cut_at,
                     "t": tick + 5})
        tick += 5
    rows.append({"kind": "ack", "issued": seq, "t": tick + 10})
    return rows


def module_row(mid, dev, ino, sha, lifecycle="mapped"):
    return {"id": mid, "key": {"device": list(dev), "inode": ino,
                               "sha256": sha},
            "lifecycle": lifecycle}


def instance_row(iid, caller, module, feed, state="observed", reason=None,
                 first=1_000, last=2_000):
    return {"id": iid, "caller": caller, "module": module, "feed": feed,
            "state": state, "reason": reason, "first_seen_ns": first,
            "last_seen_ns": last}


def key_row(iid, feed, started, completed, failed=0, unknown=0,
            cut_published=0, cut_published_failed=0):
    return {"instance": iid, "feed": feed, "started": started,
            "completed": completed, "failed": failed, "unknown": unknown,
            "cut_published": cut_published,
            "cut_published_failed": cut_published_failed}


def split_snapshot(calls_a=10, calls_b=10, failed_a=0, failed_b=0,
                   b_state="observed", cut_published=0,
                   cut_published_failed=0):
    """Canned split-path snapshot: two modules, two instances, one caller."""
    return {
        "instances": [
            instance_row("i0", "c0", "m0", "A"),
            instance_row("i1", "c0", "m1", "B", state=b_state),
        ],
        "modules": [
            module_row("m0", (8, 1), 101, SHA_A),
            module_row("m1", (8, 1), 102, SHA_B),
        ],
        "key_rows": [
            key_row("i0", "A", calls_a, calls_a - failed_a,
                    failed=failed_a),
            key_row("i1", "B", calls_b, calls_b - failed_b,
                    failed=failed_b,
                    cut_published=cut_published,
                    cut_published_failed=cut_published_failed),
        ],
        "gaps": [],
    }


def merge_snapshot():
    """Canned merge-path snapshot: one module, latched edge, naming gap."""
    return {
        "instances": [instance_row("i0", "c0", "m0", "A")],
        "modules": [module_row("m0", (8, 1), 101, SHA_A)],
        "key_rows": [],
        "gaps": [{"subject": "same-file double-load detected",
                  "reason": "duplicate executable file-offset coverage"}],
    }


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def write_snapshot(path, snapshot):
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(snapshot, stream)


def compare_pair(oracle, rows, snapshot):
    return oracle.compare(oracle.validate_ledger(rows), snapshot)


WITNESS_PROVIDER = """/* Test-only counting sibling provider: marker plus per-entry witness. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} WitnessTable;
int TwoProvidersMarker;
static WitnessTable witness_table;
static unsigned long witness_entry(void **out) {
    if (out != NULL) {
        *out = &witness_table;
    }
    const char *path = getenv("P11SCOPE_SIBLING_WITNESS_PATH");
    if (path != NULL) {
        FILE *sink = fopen(path, "a");
        if (sink != NULL) {
            fprintf(sink, "table=%p\\n", (void *)&witness_table);
            fclose(sink);
        }
    }
    return 0;
}
static unsigned long witness_handle(void **out) {
    if (out == NULL) {
        return 7;
    }
    *(unsigned long *)out = 0x0A11CEUL;
    return 0;
}
__attribute__((constructor)) static void witness_init(void) {
    witness_table.major = 3;
    witness_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        witness_table.functions[i] = (void *)witness_entry;
    }
    witness_table.functions[12] = (void *)witness_handle;
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &witness_table;
    return 0;
}
"""

REFUSAL_PROVIDER = """/* Test-only non-sibling provider: no marker, so the driver refuses it. */
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
    plain_table.major = 3;
    plain_table.minor = 2;
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


class LedgerShapeTwins(unittest.TestCase):
    def test_healthy_two_feed_ledger_passes(self):
        oracle = require_oracle(self)
        summary = oracle.validate_ledger(ledger_rows())
        self.assertEqual(summary["issued"], 20)
        self.assertEqual(summary["feeds"]["A"]["calls"], 10)
        self.assertEqual(summary["feeds"]["B"]["calls"], 10)
        self.assertEqual(summary["feeds"]["A"]["ok"], 10)

    def test_healthy_single_unlabeled_feed_passes(self):
        oracle = require_oracle(self)
        rows = [
            {"kind": "ready", "pid": 7, "tid": 7, "t": 100,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"},
            {"kind": "call", "seq": 1, "fn": "table[4]", "rv": 0,
             "pid": 7, "tid": 7, "t0": 110, "t1": 115},
            {"kind": "ack", "issued": 1, "t": 120},
        ]
        summary = oracle.validate_ledger(rows)
        self.assertEqual(list(summary["feeds"]), ["main"])

    def test_mutation_call_names_undeclared_feed_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[4]["feed"] = "C"
        with self.assertRaisesRegex(oracle.LedgerError, "undeclared feed"):
            oracle.validate_ledger(rows)

    def test_mutation_unlabeled_call_ambiguous_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        del rows[4]["feed"]
        with self.assertRaisesRegex(oracle.LedgerError, "ambiguous"):
            oracle.validate_ledger(rows)

    def test_mutation_duplicate_ready_feed_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[1]["feed"] = "A"
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate ready"):
            oracle.validate_ledger(rows)

    def test_mutation_mixed_labeled_ready_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        del rows[1]["feed"]
        with self.assertRaisesRegex(oracle.LedgerError, "mixed labeled"):
            oracle.validate_ledger(rows)

    def test_healthy_late_ready_passes(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False)
        ready_b = rows.pop(1)
        first_b = next(index for index, row in enumerate(rows)
                       if row.get("feed") == "B")
        rows.insert(first_b, ready_b)
        summary = oracle.validate_ledger(rows)
        self.assertEqual(summary["issued"], 20)
        self.assertEqual(summary["feeds"]["B"]["ready_t"], 1_010)

    def test_mutation_call_before_own_ready_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False)
        first_b = next(row for row in rows
                       if row.get("kind") == "call" and row.get("feed") == "B")
        rows[1]["t"] = first_b["t0"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "precedes the B ready"):
            oracle.validate_ledger(rows)

    def test_mutation_ready_after_ack_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[1]["t"] = rows[-1]["t"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "ready follows the ack"):
            oracle.validate_ledger(rows)

    def test_mutation_marker_before_own_ready_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[3]["t"] = 1_005
        with self.assertRaisesRegex(oracle.LedgerError, "precedes the B ready"):
            oracle.validate_ledger(rows)

    def test_mutation_cut_names_undeclared_feed_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(cut_at=12)
        rows[-2]["feed"] = "C"
        with self.assertRaisesRegex(oracle.LedgerError, "undeclared feed"):
            oracle.validate_ledger(rows)

    def test_mutation_cut_names_missing_seq_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(cut_at=12)
        rows[-2]["at_seq"] = 999
        with self.assertRaisesRegex(oracle.LedgerError, "names no call"):
            oracle.validate_ledger(rows)

    def test_mutation_cut_names_other_feed_call_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(cut_at=11)
        with self.assertRaisesRegex(oracle.LedgerError, "another feed"):
            oracle.validate_ledger(rows)

    def test_mutation_duplicate_cut_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(cut_at=12)
        rows.insert(-1, dict(rows[-2]))
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate cut"):
            oracle.validate_ledger(rows)

    def test_mutation_cut_before_its_call_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(cut_at=12)
        cut = rows.pop(-2)
        rows.insert(6, cut)
        with self.assertRaisesRegex(oracle.LedgerError, "emitted before"):
            oracle.validate_ledger(rows)

    def test_mutation_cut_stamp_before_call_end_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(cut_at=12)
        rows[-2]["t"] = 1_015
        with self.assertRaisesRegex(oracle.LedgerError, "precedes its last"):
            oracle.validate_ledger(rows)

    def test_mutation_seq_gap_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[6]["seq"] = 999
        with self.assertRaisesRegex(oracle.LedgerError, "contiguity"):
            oracle.validate_ledger(rows)

    def test_mutation_call_outside_window_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[4]["t0"] = 1
        rows[4]["t1"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "window"):
            oracle.validate_ledger(rows)

    def test_mutation_foreign_pid_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[5]["pid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "pid/tid 4243/4242 match no ready row"):
            oracle.validate_ledger(rows)

    def test_mutation_fn_label_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[4]["fn"] = "table[4];id"
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows)

    def test_mutation_rv_out_of_range_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[4]["rv"] = 2 ** 64
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_handle_slot_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[2]["slot"] = 104
        with self.assertRaisesRegex(oracle.LedgerError, "slot out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_non_object_middle_row_refused(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[5] = ["call"]
        with self.assertRaisesRegex(oracle.LedgerError, "must be an object"):
            oracle.validate_ledger(rows)

    def test_mutation_non_object_frame_row_refused(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[0] = ["ready"]
        with self.assertRaisesRegex(oracle.LedgerError, "first row must be ready"):
            oracle.validate_ledger(rows)
        rows = ledger_rows()
        rows[-1] = ["ack"]
        with self.assertRaisesRegex(oracle.LedgerError, "last row must be ack"):
            oracle.validate_ledger(rows)

    def test_mutation_duplicate_json_key_rejected(self):
        oracle = require_oracle(self)
        line = ('{"kind": "ready", "feed": "A", "pid": 1, "tid": 1, "t": 2,'
                ' "clock": "CLOCK_MONOTONIC", "unit": "ns", "pid": 2}\n')
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate JSON key"):
            oracle.read_ledger(io.StringIO(line))

    def test_mutation_line_byte_limit_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "byte limit"):
            oracle.read_ledger(io.StringIO("x" * 4097 + "\n"))

    def test_mutation_row_limit_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "row limit"):
            oracle.read_ledger(io.StringIO("{}\n" * 200065))

    def test_boundary_count_200000_passes(self):
        oracle = require_oracle(self)
        rows = ledger_rows(calls_a=100000, calls_b=100000)
        text = "\n".join(json.dumps(row) for row in rows) + "\n"
        with io.StringIO(text) as stream:
            read = oracle.read_ledger(stream)
        summary = oracle.validate_ledger(read)
        self.assertEqual(summary["issued"], 200000)


class CompareTwins(unittest.TestCase):
    def test_healthy_split_both_orders_pass(self):
        oracle = require_oracle(self)
        for order in ("ab", "ba"):
            rows = ledger_rows(order=order)
            result = compare_pair(oracle, rows, split_snapshot())
            self.assertEqual(result["path"], "split")
            self.assertEqual(result["issued"], 20)
            self.assertEqual(result["associations"], 2)

    def test_healthy_merge_passes(self):
        oracle = require_oracle(self)
        result = compare_pair(oracle, ledger_rows(), merge_snapshot())
        self.assertEqual(result["path"], "merge")
        self.assertEqual(result["associations"], 1)

    def test_healthy_cut_cell_passes(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False, cut_at=12)
        snapshot = split_snapshot()
        key_b = snapshot["key_rows"][1]
        key_b["completed"] = 4
        key_b["unknown"] = 6
        snapshot["gaps"] = [
            {"subject": "inventory attach target changed identity",
             "reason": "object changed identity since its endpoints were taken"}
        ]
        snapshot["edges"] = [
            {"module": "m0",
             "mapping": {"state": "mapped", "interruptions": 0}},
            {"module": "m1",
             "mapping": {"state": "mapped", "interruptions": 1}},
        ]
        result = compare_pair(oracle, rows, snapshot)
        self.assertEqual(result["path"], "split")

    def test_healthy_cut_with_published_prefix_passes(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False, cut_at=12)
        snapshot = split_snapshot(cut_published=2)
        key_b = snapshot["key_rows"][1]
        key_b["completed"] = 6
        key_b["unknown"] = 4
        snapshot["gaps"] = [
            {"subject": "inventory attach target changed identity",
             "reason": "object changed identity since its endpoints were taken"}
        ]
        snapshot["edges"] = [
            {"module": "m1",
             "mapping": {"state": "mapped", "interruptions": 2}},
        ]
        result = compare_pair(oracle, rows, snapshot)
        self.assertEqual(result["path"], "split")

    def test_healthy_uncertain_b_preserves_a(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot(b_state="uncertain")
        snapshot["instances"][1]["reason"] = "caller_unbound"
        result = compare_pair(oracle, ledger_rows(), snapshot)
        self.assertEqual(result["path"], "split")

    def test_healthy_file_local_negatives_pass(self):
        oracle = require_oracle(self)
        rows = ledger_rows(rv_a=lambda i: 7 if i == 3 else 0,
                           rv_b=lambda i: 5 if i in (1, 9) else 0)
        snapshot = split_snapshot(failed_a=1, failed_b=2)
        result = compare_pair(oracle, rows, snapshot)
        self.assertEqual(result["path"], "split")
        summary = oracle.validate_ledger(rows)
        self.assertEqual(summary["feeds"]["A"]["failed"], 1)
        self.assertEqual(summary["feeds"]["B"]["failed"], 2)

    def test_healthy_512x8_associations_accepted(self):
        oracle = require_oracle(self)
        instances = []
        for caller in range(512):
            for slot in range(8):
                number = caller * 8 + slot
                instances.append(instance_row(
                    f"i{number}", f"c{caller}", f"m{number}", "A",
                    first=1_000 + number, last=2_000 + number))
        snapshot = {
            "instances": instances,
            "modules": [module_row(f"m{n}", (8, 1), 1000 + n, f"{n:064x}")
                        for n in range(4096)],
            "key_rows": [],
            "gaps": [],
            "budgets": {"instances": {"limit": 4096, "occupied": 4096,
                                      "refused": 0}},
        }
        associations = oracle.check_associations(snapshot)
        self.assertEqual(associations["associations"], 4096)

    def test_mutation_mixed_feeds_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(calls_a=10, calls_b=6)
        snapshot = split_snapshot(calls_a=10, calls_b=6)
        snapshot["key_rows"][0]["completed"] = 6
        snapshot["key_rows"][1]["completed"] = 10
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees"):
            compare_pair(oracle, rows, snapshot)

    def test_mutation_handles_differ_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows()
        rows[3]["value"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "no collision"):
            compare_pair(oracle, rows, split_snapshot())

    def test_mutation_handle_feed_missing_rejected(self):
        oracle = require_oracle(self)
        rows = [row for row in ledger_rows()
                if not (row.get("kind") == "handle" and
                        row.get("feed") == "B")]
        with self.assertRaisesRegex(oracle.LedgerError, "without a handle"):
            compare_pair(oracle, rows, split_snapshot())

    def test_mutation_positive_from_unread_post_cut_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False, cut_at=12)
        snapshot = split_snapshot()
        snapshot["gaps"] = [
            {"subject": "inventory attach target changed identity",
             "reason": "object changed identity since its endpoints were taken"}
        ]
        snapshot["edges"] = [
            {"module": "m1",
             "mapping": {"state": "mapped", "interruptions": 1}},
        ]
        with self.assertRaisesRegex(oracle.LedgerError, "mixes pre-cut"):
            compare_pair(oracle, rows, snapshot)

    def test_mutation_lost_post_cut_burst_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False, cut_at=12)
        snapshot = split_snapshot()
        key_b = snapshot["key_rows"][1]
        key_b["completed"] = 3
        key_b["unknown"] = 6
        snapshot["gaps"] = [
            {"subject": "inventory attach target changed identity",
             "reason": "object changed identity since its endpoints were taken"}
        ]
        snapshot["edges"] = [
            {"module": "m1",
             "mapping": {"state": "mapped", "interruptions": 1}},
        ]
        with self.assertRaisesRegex(oracle.LedgerError, "mixes pre-cut"):
            compare_pair(oracle, rows, snapshot)

    def test_mutation_lost_a_during_b_uncertainty_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot(b_state="uncertain")
        snapshot["key_rows"][0]["completed"] = 9
        snapshot["key_rows"][0]["unknown"] = 1
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_b_overclaims_while_uncertain_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot(b_state="uncertain")
        snapshot["key_rows"][1]["completed"] = 11
        with self.assertRaisesRegex(oracle.LedgerError, "over-claims"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_cut_without_gap_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False, cut_at=12)
        snapshot = split_snapshot()
        snapshot["edges"] = [
            {"module": "m1",
             "mapping": {"state": "mapped", "interruptions": 1}},
        ]
        with self.assertRaisesRegex(oracle.LedgerError, "changed-identity gap"):
            compare_pair(oracle, rows, snapshot)

    def test_mutation_cut_without_interruption_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False, cut_at=12)
        snapshot = split_snapshot()
        snapshot["key_rows"][1]["completed"] = 4
        snapshot["key_rows"][1]["unknown"] = 6
        snapshot["gaps"] = [
            {"subject": "inventory attach target changed identity",
             "reason": "object changed identity since its endpoints were taken"}
        ]
        snapshot["edges"] = [
            {"module": "m1",
             "mapping": {"state": "mapped", "interruptions": 0}},
        ]
        with self.assertRaisesRegex(oracle.LedgerError, "interruption"):
            compare_pair(oracle, rows, snapshot)

    def test_mutation_cut_published_exceeds_pre_cut_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False, cut_at=12)
        snapshot = split_snapshot(cut_published=7)
        snapshot["gaps"] = [
            {"subject": "inventory attach target changed identity",
             "reason": "object changed identity since its endpoints were taken"}
        ]
        snapshot["edges"] = [
            {"module": "m1",
             "mapping": {"state": "mapped", "interruptions": 1}},
        ]
        with self.assertRaisesRegex(oracle.LedgerError, "exceeds"):
            compare_pair(oracle, rows, snapshot)

    def test_mutation_cross_feed_failure_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(rv_a=0, rv_b=lambda i: 5 if i == 2 else 0)
        snapshot = split_snapshot(failed_a=1, failed_b=0)
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees"):
            compare_pair(oracle, rows, snapshot)

    def test_mutation_dangling_module_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["instances"][1]["module"] = "m9"
        with self.assertRaisesRegex(oracle.LedgerError, "missing module"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_bad_sha_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["modules"][1]["key"]["sha256"] = "zz"
        with self.assertRaisesRegex(oracle.LedgerError, "sha256"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_duplicate_module_key_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["modules"][1]["key"] = dict(snapshot["modules"][0]["key"])
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate module key"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_two_callers_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["instances"][1]["caller"] = "c1"
        with self.assertRaisesRegex(oracle.LedgerError, "one caller"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_orphan_module_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["modules"].append(module_row("m2", (8, 1), 103, "cc" * 32))
        with self.assertRaisesRegex(oracle.LedgerError, "without an instance"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_fully_retired_feed_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["instances"][1]["state"] = "retired"
        snapshot["instances"][1]["reason"] = "instance_retired"
        with self.assertRaisesRegex(oracle.LedgerError, "current modules"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_healthy_retired_history_passes(self):
        oracle = require_oracle(self)
        rows = ledger_rows(handles=False, cut_at=12)
        snapshot = split_snapshot()
        key_b = snapshot["key_rows"][1]
        key_b["completed"] = 4
        key_b["unknown"] = 6
        snapshot["gaps"] = [
            {"subject": "inventory attach target changed identity",
             "reason": "object changed identity since its endpoints were taken"}
        ]
        snapshot["edges"] = [
            {"module": "m1",
             "mapping": {"state": "mapped", "interruptions": 1}},
        ]
        snapshot["modules"].append(module_row("m2", (8, 1), 102, "cc" * 32))
        snapshot["instances"].append(
            instance_row("i2", "c0", "m2", "B", state="retired",
                         reason="instance_retired"))
        result = compare_pair(oracle, rows, snapshot)
        self.assertEqual(result["path"], "split")

    def test_mutation_feed_without_positive_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(calls_a=10, calls_b=0)
        with self.assertRaisesRegex(oracle.LedgerError, "no positive"):
            compare_pair(oracle, rows, split_snapshot(calls_b=0))

    def test_mutation_merge_claims_positive_rejected(self):
        oracle = require_oracle(self)
        snapshot = merge_snapshot()
        snapshot["key_rows"] = [key_row("i0", "A", 20, 20)]
        with self.assertRaisesRegex(oracle.LedgerError, "claim a positive"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_merge_without_gap_rejected(self):
        oracle = require_oracle(self)
        snapshot = merge_snapshot()
        snapshot["gaps"] = []
        with self.assertRaisesRegex(oracle.LedgerError, "double-load gap"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_key_row_feed_mismatch_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["key_rows"][1]["feed"] = "A"
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees with instance"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_4097th_observed_rejected(self):
        oracle = require_oracle(self)
        instances = [instance_row(f"i{n}", "c0", f"m{n}", "A",
                                  first=1_000 + n, last=2_000 + n)
                     for n in range(4097)]
        snapshot = {
            "instances": instances,
            "modules": [module_row(f"m{n}", (8, 1), 1000 + n, f"{n:064x}")
                        for n in range(4097)],
            "key_rows": [],
            "gaps": [],
        }
        with self.assertRaisesRegex(oracle.LedgerError, "association bound"):
            oracle.check_associations(snapshot)

    def test_mutation_budget_refused_without_overflow_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["budgets"] = {"instances": {"limit": 4096, "occupied": 2,
                                             "refused": 1}}
        with self.assertRaisesRegex(oracle.LedgerError, "without overflow"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_cut_precedes_own_ready_rejected(self):
        oracle = require_oracle(self)
        rows = ledger_rows(cut_at=12)
        rows[-2]["t"] = 1_005
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "cut precedes the B ready row"):
            oracle.validate_ledger(rows)

    def test_mutation_instance_undeclared_feed_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["instances"][1]["feed"] = "C"
        with self.assertRaisesRegex(oracle.LedgerError, "undeclared feed"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_key_row_missing_instance_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["key_rows"].append(key_row("i9", "A", 0, 0))
        with self.assertRaisesRegex(oracle.LedgerError, "missing instance"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_merge_two_instances_rejected(self):
        oracle = require_oracle(self)
        snapshot = merge_snapshot()
        snapshot["instances"].append(
            instance_row("i1", "c0", "m0", "B", state="uncertain",
                         reason="caller_unbound"))
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "without exactly one instance"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_fully_retired_split_feed_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["instances"] = [
            instance_row("i1", "c0", "m1", "B", state="retired",
                         reason="instance_retired"),
            instance_row("i0", "c0", "m0", "A"),
            instance_row("i2", "c0", "m2", "A", state="uncertain",
                         reason="caller_unbound"),
        ]
        snapshot["modules"].append(module_row("m2", (8, 1), 103, "cc" * 32))
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "without a current instance"):
            compare_pair(oracle, ledger_rows(), snapshot)

    def test_mutation_snapshot_instance_id_invalid_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["instances"][0]["id"] = "x0"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "instance id invalid"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_snapshot_module_lifecycle_invalid_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["modules"][0]["lifecycle"] = "pending"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "module lifecycle invalid"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_snapshot_key_count_negative_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["key_rows"][0]["unknown"] = -1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "key row unknown out of range"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_snapshot_gap_subject_empty_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["gaps"] = [{"subject": "", "reason": "x"}]
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "gap subject invalid"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_snapshot_budget_limit_zero_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["budgets"] = {"instances": {"limit": 0, "occupied": 2,
                                             "refused": 0}}
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "budget limit invalid"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_snapshot_edge_interruptions_negative_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["edges"] = [{"module": "m0", "mapping": {"state": "mapped",
                                                          "interruptions": -1}}]
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "interruptions out of range"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_snapshot_duplicate_instance_id_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["instances"][1]["id"] = "i0"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "duplicate instance id"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_snapshot_duplicate_key_instance_rejected(self):
        oracle = require_oracle(self)
        snapshot = split_snapshot()
        snapshot["key_rows"].append(key_row("i0", "A", 1, 1))
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "duplicate key row instance"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))


class ComparisonCliTwins(unittest.TestCase):
    def test_cli_healthy_pair_passes(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            snap = Path(tmp) / "snapshot.json"
            write_jsonl(ledger, ledger_rows())
            write_snapshot(snap, split_snapshot())
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger), str(snap)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["path"], "split")

    def test_cli_mixed_feeds_refused(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            snap = Path(tmp) / "snapshot.json"
            rows = ledger_rows(calls_a=10, calls_b=6)
            snapshot = split_snapshot(calls_a=10, calls_b=6)
            snapshot["key_rows"][0]["completed"] = 6
            write_jsonl(ledger, rows)
            write_snapshot(snap, snapshot)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger), str(snap)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertRegex(completed.stderr,
                             r"comparison refused: feed A completed 6 disagrees")

    def test_cli_string_payload_not_echoed(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            snap = Path(tmp) / "snapshot.json"
            rows = ledger_rows()
            rows[5]["pid"] = "PIN=1234-secret"
            write_jsonl(ledger, rows)
            write_snapshot(snap, split_snapshot())
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger), str(snap)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("comparison refused: pid/tid string/4242 match "
                          "no ready row",
                          completed.stderr)
            self.assertNotIn("PIN=1234-secret", completed.stderr)

    def test_cli_non_object_first_row_refused_without_traceback(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            snap = Path(tmp) / "snapshot.json"
            rows = ledger_rows()
            rows[0] = ["ready"]
            write_jsonl(ledger, rows)
            write_snapshot(snap, split_snapshot())
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger), str(snap)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("comparison refused: first row must be ready",
                          completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)


def softhsm_available():
    return (shutil.which("softhsm2-util") is not None and
            any(os.path.exists(path) for path in SOFT_LIBS))


class EmissionTests(unittest.TestCase):
    def build_sibs_pair(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not SIBS_SRC.is_file():
            self.fail(f"fixture missing: {SIBS_SRC} (implementation not present)")
        provider = Path(tmp) / "sibs-provider.so"
        driver = Path(tmp) / "dlmopen-sibs"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-fPIC", "-DTWO_PROVIDERS_SIBLING_BUILD", "-shared",
             "-Wl,-z,defs", "-o", str(provider), str(SIBS_SRC)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(SIBS_SRC), "-ldl", "-o", str(driver)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return provider, driver

    def build_sibs_driver(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not SIBS_SRC.is_file():
            self.fail(f"fixture missing: {SIBS_SRC} (implementation not present)")
        driver = Path(tmp) / "dlmopen-sibs"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(SIBS_SRC), "-ldl", "-o", str(driver)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return driver

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

    def test_fixture_emits_valid_ledger_both_orders(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_sibs_pair(tmp)
            for order in ("ab", "ba"):
                ledger = Path(tmp) / f"ledger-{order}.jsonl"
                child = subprocess.Popen(
                    [str(driver), str(provider), order, "25", str(ledger)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    stdout, stderr = child.communicate(timeout=60)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, stderr)
                self.assertIn(f"READY pid={child.pid}", stdout)
                tables = re.findall(r"^NS feed=(A|B) table=(0x[0-9a-f]+)",
                                    stdout, re.M)
                self.assertEqual(len(tables), 2)
                self.assertNotEqual(tables[0][1], tables[1][1])
                with open(ledger, encoding="utf-8") as stream:
                    summary = oracle.validate_ledger(
                        oracle.read_ledger(stream))
                self.assertEqual(summary["issued"], 50)
                self.assertEqual(summary["feeds"]["A"]["calls"], 25)
                self.assertEqual(summary["feeds"]["B"]["calls"], 25)
                values = {row["value"] for row in summary["handles"]}
                self.assertEqual(values, {0xA11CE})
                first = summary["feeds"]["A"]["seqs"][0]
                other = summary["feeds"]["B"]["seqs"][0]
                if order == "ab":
                    self.assertLess(first, other)
                else:
                    self.assertGreater(first, other)

    def test_fixture_calls_both_namespaces(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            driver = self.build_sibs_driver(tmp)
            provider = self.build_inline_provider(
                tmp, "witness", WITNESS_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            witness = Path(tmp) / "witness"
            env = dict(os.environ,
                       P11SCOPE_SIBLING_WITNESS_PATH=str(witness))
            completed = subprocess.run(
                [str(driver), str(provider), "ab", "5", str(ledger)],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            lines = witness.read_text(encoding="utf-8").split()
            self.assertEqual(len(lines), 10)
            addresses = {line.split("=", 1)[1] for line in lines}
            self.assertEqual(len(addresses), 2)
            for address in addresses:
                self.assertEqual(lines.count(f"table={address}"), 5)

    def test_fixture_waits_for_go(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_sibs_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            gate = Path(tmp) / "GO"
            child = subprocess.Popen(
                [str(driver), str(provider), "ab", "5", str(ledger),
                 str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stderr = ""
            try:
                line = child.stdout.readline()
                self.assertIn(f"READY pid={child.pid}", line)
                time.sleep(0.5)
                self.assertFalse(ledger.exists())
                gate.touch()
                deadline = time.monotonic() + 30
                while not ledger.exists() and time.monotonic() < deadline:
                    time.sleep(0.1)
                self.assertTrue(ledger.exists())
                child.terminate()
                _, stderr = child.communicate(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 10)

    def test_fixture_stop_flag_interrupts_wait(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_sibs_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            gate = Path(tmp) / "GO"
            child = subprocess.Popen(
                [str(driver), str(provider), "ab", "5", str(ledger),
                 str(gate)],
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

    def test_fixture_holds_mapping_until_stop(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_sibs_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            gate = Path(tmp) / "GO"
            gate.touch()
            child = subprocess.Popen(
                [str(driver), str(provider), "ab", "5", str(ledger),
                 str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                line = child.stdout.readline()
                self.assertIn(f"READY pid={child.pid}", line)
                time.sleep(1.0)
                self.assertIsNone(child.poll())
                self.assertTrue(ledger.exists())
                child.terminate()
                _, stderr = child.communicate(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr)

    def test_fixture_refuses_foreign_provider(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            driver = self.build_sibs_driver(tmp)
            provider = self.build_inline_provider(
                tmp, "plain", REFUSAL_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(driver), str(provider), "ab", "5", str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("stub", completed.stderr)
            self.assertFalse(ledger.exists())

    def test_fixture_refuses_bad_argv(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, driver = self.build_sibs_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(driver)], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            completed = subprocess.run(
                [str(driver), str(provider), "xx", "5", str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(ledger.exists())

    def build_late_driver(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not LATE_SRC.is_file():
            self.fail(f"fixture missing: {LATE_SRC} (implementation not present)")
        driver = Path(tmp) / "late-b"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(LATE_SRC), "-ldl", "-o", str(driver)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return driver

    def make_providers(self, tmp):
        if not softhsm_available():
            self.skipTest("requires softhsm2-util and libsofthsm2.so")
        if not MK_PROVIDERS.is_file():
            self.fail(f"helper missing: {MK_PROVIDERS} (implementation not present)")
        dest = Path(tmp) / "prov"
        completed = subprocess.run(
            ["sh", str(MK_PROVIDERS), str(dest)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return dest, completed.stdout

    def test_mk_providers_builds_two_files_and_tokens(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            dest, stdout = self.make_providers(tmp)
            first = dest / "provider-a.so"
            second = dest / "provider-b.so"
            self.assertTrue(first.is_file())
            self.assertTrue(second.is_file())
            self.assertNotEqual(first.stat().st_ino, second.stat().st_ino)
            self.assertIn("PROVIDER_A", stdout)
            self.assertIn("PROVIDER_B", stdout)
            env = dict(os.environ,
                       SOFTHSM2_CONF=str(dest / "softhsm2.conf"))
            completed = subprocess.run(
                ["softhsm2-util", "--show-slots"],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("P11SCOPE-A", completed.stdout)
            self.assertIn("P11SCOPE-B", completed.stdout)

    def test_late_b_emits_cut_ledger(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            driver = self.build_late_driver(tmp)
            dest, _ = self.make_providers(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            env = dict(os.environ,
                       SOFTHSM2_CONF=str(dest / "softhsm2.conf"))
            size_before = (dest / "provider-b.so").stat().st_size
            completed = subprocess.run(
                [str(driver), str(dest / "provider-a.so"),
                 str(dest / "provider-b.so"), "2", str(ledger)],
                capture_output=True, text=True, timeout=120, env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("READY pid=", completed.stdout)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(
                    oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 36)
            self.assertEqual(summary["feeds"]["A"]["calls"], 12)
            self.assertEqual(summary["feeds"]["B"]["calls"], 24)
            self.assertEqual(len(summary["cuts"]), 1)
            self.assertEqual(summary["cuts"][0]["feed"], "B")
            self.assertEqual(summary["cuts"][0]["at_seq"], 24)
            self.assertEqual(summary["handles"], [])
            self.assertGreater(summary["feeds"]["B"]["ready_t"],
                               summary["feeds"]["A"]["ready_t"])
            size_after = (dest / "provider-b.so").stat().st_size
            self.assertEqual(size_after, size_before + 4096)

    def test_late_b_gated_run_completes(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            driver = self.build_late_driver(tmp)
            dest, _ = self.make_providers(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            gate = Path(tmp) / "GO"
            env = dict(os.environ,
                       SOFTHSM2_CONF=str(dest / "softhsm2.conf"))
            child = subprocess.Popen(
                [str(driver), str(dest / "provider-a.so"),
                 str(dest / "provider-b.so"), "1", str(ledger), str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=env)
            stderr = ""
            try:
                line = child.stdout.readline()
                self.assertIn(f"READY pid={child.pid}", line)
                time.sleep(0.5)
                self.assertFalse(ledger.exists())
                gate.touch()
                time.sleep(2.0)
                self.assertIsNone(child.poll())
                child.terminate()
                _, stderr = child.communicate(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 18)


if __name__ == "__main__":
    unittest.main()
