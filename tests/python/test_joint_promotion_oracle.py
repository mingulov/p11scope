#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""A/B promotion ledger fixture/oracle twins.

The oracle (scripts/joint-promotion-compare.py) validates the A/B ledger
emitted by tests/fixtures/promotion/ab-pair.c (ready, hold_begin, side-B
calls, alive, cancel, hold_end, retire, ack on a declared
CLOCK_MONOTONIC/ns basis) and joins it to the observer's promotion
evidence: drawn/revalidated/detailed/completed rows, seal-settlement rows,
owner-transfer and retirement rows, cancel rows, exact-label refusal rows
and broad-Inventory pulse rows.

Healthy and mutation twins run unignored; the live-emission tests build the
tracked live-discovery-provider.c fixture and the pair emitter with gcc
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
ORACLE_PATH = ROOT / "scripts" / "joint-promotion-compare.py"
FIXTURE_SRC = ROOT / "tests" / "fixtures" / "promotion" / "ab-pair.c"
PROVIDER_SRC = ROOT / "tests" / "fixtures" / "live-discovery-provider.c"

try:
    _SPEC = importlib.util.spec_from_file_location(
        "joint_promotion_compare", ORACLE_PATH
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


def healthy_ledger(mode="pair", b_calls=8, pid=4242, tid=4242):
    """Canned A/B ledger mirroring ab-pair emission order; strictly rising stamps."""
    if mode not in ("pair", "cancel", "retire"):
        raise AssertionError(f"unknown mode {mode}")
    rows = [{"kind": "ready", "pid": pid, "tid": tid, "t": 1000,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    tick = 1000
    seq = 0

    def stamp(step=10):
        nonlocal tick
        tick += step
        return tick

    def append(row):
        nonlocal seq
        seq += 1
        row["seq"] = seq
        rows.append(row)
        return row

    def add_call():
        t0 = stamp()
        t1 = stamp(5)
        append({"kind": "call", "side": "B", "fn": "table[12]", "rv": 0,
                "pid": pid, "tid": tid, "t0": t0, "t1": t1})

    def add_alive():
        append({"kind": "alive", "pid": pid, "tid": tid, "t": stamp()})

    append({"kind": "hold_begin", "side": "A", "fn": "table[4]",
            "pid": pid, "tid": tid, "t0": stamp()})
    before = b_calls // 2 if mode == "cancel" else b_calls
    for _ in range(before):
        add_call()
    if mode == "cancel":
        append({"kind": "cancel", "t": stamp()})
        add_alive()
    else:
        add_alive()
    end = append({"kind": "hold_end", "side": "A", "ref": 1, "rv": 0,
                  "t1": stamp()})
    if mode == "retire":
        append({"kind": "retire", "side": "A", "after": end["seq"],
                "t": stamp()})
    for _ in range(b_calls - before):
        add_call()
    add_alive()
    rows.append({"kind": "ack", "issued": b_calls, "held": 1, "t": stamp()})
    return rows


def renumber(rows):
    """Reassign contiguous seqs after moving body rows; repair ref/after links."""
    old = {id(row): row["seq"] for row in rows[1:-1]}
    seq = 0
    for row in rows[1:-1]:
        seq += 1
        row["seq"] = seq
    new_by_old = {}
    for row in rows[1:-1]:
        new_by_old.setdefault(old[id(row)], row["seq"])
    for row in rows[1:-1]:
        if row["kind"] == "hold_end":
            row["ref"] = new_by_old[row["ref"]]
        if row["kind"] == "retire":
            row["after"] = new_by_old[row["after"]]
    return rows


def spans(rows):
    """Ledger landmarks the evidence builders derive their stamps from."""
    calls = [row for row in rows if row.get("kind") == "call"]
    retires = [row for row in rows if row.get("kind") == "retire"]
    cancels = [row for row in rows if row.get("kind") == "cancel"]
    begin = next(row for row in rows if row.get("kind") == "hold_begin")
    end = next(row for row in rows if row.get("kind") == "hold_end")
    return {
        "ready_t": rows[0]["t"],
        "ack_t": rows[-1]["t"],
        "begin_t0": begin["t0"],
        "end_t1": end["t1"],
        "calls": calls,
        "retire_t": retires[0]["t"] if retires else None,
        "cancel_t": cancels[0]["t"] if cancels else None,
    }


def healthy_events(rows, chain="full", req=1, seal=1, caller=3, provider=7):
    """Evidence derived from ledger stamps: one request chain plus pulses.

    Pulse stamps use fixed offsets from the Detailed stamp, never raw
    ledger stamps, so the strict before/after holds on any clock
    granularity, including live ledgers with tied consecutive reads.
    """
    if chain not in ("full", "retire", "cancel"):
        raise AssertionError(f"unknown chain {chain}")
    found = spans(rows)
    if found["begin_t0"] < 1:
        raise AssertionError("detailed stamp leaves no room for a before-pulse")
    events = [
        {"kind": "drawn", "req": req, "caller": caller,
         "provider": provider, "view": 11, "t": found["ready_t"]},
        {"kind": "revalidated", "req": req, "t": found["begin_t0"]},
        {"kind": "seal_settled", "seal": seal, "t": found["begin_t0"]},
        {"kind": "detailed", "req": req, "seal": seal, "t": found["begin_t0"]},
        {"kind": "inventory_pulse", "t": found["begin_t0"] - 1, "calls": 3},
    ]
    if chain in ("full", "retire"):
        completed_t = found["end_t1"] + 5
        events.append({"kind": "completed", "req": req, "seal": seal,
                       "t": completed_t})
        events.append({"kind": "owner_transferred", "req": req, "from": "A",
                       "to": "B", "seal": seal, "t": found["end_t1"] + 10})
        if chain == "retire":
            events.append({"kind": "retired", "req": req, "side": "A",
                           "t": completed_t + 5})
    else:
        last = max((call["t1"] for call in found["calls"]),
                   default=found["end_t1"])
        events.append({"kind": "cancelled", "req": req, "t": last + 5})
    events.append({"kind": "inventory_pulse", "t": found["ack_t"] + 5, "calls": 5})
    return events


def refused_events(rows, cell):
    """Req1 full chain plus a req2 refusal carrying its cell precondition."""
    if cell not in ("busy", "stale", "scan", "unsupported"):
        raise AssertionError(f"unknown cell {cell}")
    found = spans(rows)
    events = healthy_events(rows, chain="full")
    completed_t = found["end_t1"] + 5
    transfer_t = found["end_t1"] + 10

    def drawn(t):
        return {"kind": "drawn", "req": 2, "caller": 4,
                "provider": 8, "view": 12, "t": t}

    def refused(reason, t):
        return {"kind": "refused", "req": 2, "reason": reason, "t": t}

    if cell == "busy":
        events.append(drawn(completed_t - 2))
        events.append(refused("another promotion is outstanding",
                              completed_t - 1))
    elif cell == "stale":
        events.append(drawn(transfer_t + 1))
        events.append({"kind": "view_expired", "req": 2, "view": 12,
                       "t": transfer_t + 2})
        events.append(refused("view expired", transfer_t + 3))
    elif cell == "scan":
        events.append({"kind": "inventory_ended", "t": transfer_t + 1})
        events.append(drawn(transfer_t + 2))
        events.append(refused("parent scope ended", transfer_t + 3))
    else:
        events.append(drawn(transfer_t + 1))
        events.append({"kind": "scope", "req": 2, "parent": "cgroup"})
        events.append(refused("parent scope unsupported", transfer_t + 2))
    return events


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


PAIR_COUNTING_PROVIDER = """/* Test-only counting stub: entry 4 writes A, entry 12 writes B. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} PairTable;
int P11ScopeSlot68;
static void mark(char letter) {
    const char *path = getenv("P11SCOPE_PAIR_COUNT_PATH");
    if (path != NULL) {
        FILE *sink = fopen(path, "a");
        if (sink != NULL) {
            fputc(letter, sink);
            fclose(sink);
        }
    }
}
static unsigned long count_a(void **out) {
    (void)out;
    mark('A');
    return 0;
}
static unsigned long count_b(void **out) {
    (void)out;
    mark('B');
    return 0;
}
static unsigned long count_noop(void **out) {
    (void)out;
    return 0;
}
static PairTable pair_table;
__attribute__((constructor)) static void pair_init(void) {
    pair_table.major = 3;
    pair_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        pair_table.functions[i] = (void *)count_noop;
    }
    pair_table.functions[4] = (void *)count_a;
    pair_table.functions[12] = (void *)count_b;
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &pair_table;
    return 0;
}
"""

PAIR_SLOW_PROVIDER = """/* Test-only slow stub: the B entry sleeps, so t1-t0 proves post-call stamping. */
#define _GNU_SOURCE
#include <stddef.h>
#include <time.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} PairSlowTable;
int P11ScopeSlot68;
static unsigned long slow_b(void **out) {
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
static PairSlowTable pair_slow_table;
__attribute__((constructor)) static void pair_slow_init(void) {
    pair_slow_table.major = 3;
    pair_slow_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        pair_slow_table.functions[i] = (void *)slow_noop;
    }
    pair_slow_table.functions[12] = (void *)slow_b;
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &pair_slow_table;
    return 0;
}
"""

PAIR_REFUSAL_PROVIDER = """/* Test-only non-stub provider: no marker export, so the stub-only emitter refuses it. */
#define _GNU_SOURCE
#include <stddef.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} PairPlainTable;
static unsigned long plain_noop(void **out) {
    (void)out;
    return 0;
}
static PairPlainTable pair_plain_table;
__attribute__((constructor)) static void pair_plain_init(void) {
    pair_plain_table.major = 2;
    pair_plain_table.minor = 40;
    for (int i = 0; i < 104; i++) {
        pair_plain_table.functions[i] = (void *)plain_noop;
    }
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &pair_plain_table;
    return 0;
}
"""


class PromotionLedgerTwins(unittest.TestCase):
    def test_healthy_pair_ledger_passes(self):
        oracle = require_oracle(self)
        summary = oracle.validate_ledger(healthy_ledger(mode="pair"))
        self.assertEqual(summary["issued"], 8)
        self.assertEqual(summary["held"], 1)

    def test_healthy_cancel_ledger_passes(self):
        oracle = require_oracle(self)
        summary = oracle.validate_ledger(healthy_ledger(mode="cancel"))
        self.assertEqual(summary["issued"], 8)
        self.assertEqual(summary["held"], 1)

    def test_healthy_retire_ledger_passes(self):
        oracle = require_oracle(self)
        summary = oracle.validate_ledger(healthy_ledger(mode="retire"))
        self.assertEqual(summary["issued"], 8)
        self.assertEqual(summary["held"], 1)

    def test_healthy_pair_passes_through_cli(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            events_path = Path(tmp) / "events.jsonl"
            rows = healthy_ledger(mode="pair")
            write_jsonl(ledger, rows)
            write_jsonl(events_path, healthy_events(rows, chain="full"))
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger),
                 str(events_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(
                (result["issued"], result["held"], result["reqs"],
                 result["detailed"], result["transfers"]),
                (8, 1, 1, 1, 1))

    def test_mutation_dropped_b_call_rejected(self):
        oracle = require_oracle(self)
        rows = [row for row in healthy_ledger() if row.get("seq") != 3]
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "issued"):
            oracle.validate_ledger(rows)

    def test_mutation_hold_end_unknown_ref_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        end = next(row for row in rows if row.get("kind") == "hold_end")
        end["ref"] = 99
        with self.assertRaisesRegex(oracle.LedgerError, "unknown hold_begin ref"):
            oracle.validate_ledger(rows)

    def test_mutation_hold_end_before_begin_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        begin = next(row for row in rows if row.get("kind") == "hold_begin")
        end = next(row for row in rows if row.get("kind") == "hold_end")
        end["t1"] = begin["t0"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "precedes its hold_begin"):
            oracle.validate_ledger(rows)

    def test_mutation_wrong_side_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["side"] = "A"
        with self.assertRaisesRegex(oracle.LedgerError, "is not B"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        begin = next(row for row in rows if row.get("kind") == "hold_begin")
        begin["side"] = "B"
        with self.assertRaisesRegex(oracle.LedgerError, "is not A"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        end = next(row for row in rows if row.get("kind") == "hold_end")
        end["side"] = "B"
        with self.assertRaisesRegex(oracle.LedgerError, "is not A"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger(mode="retire")
        retire = next(row for row in rows if row.get("kind") == "retire")
        retire["side"] = "B"
        with self.assertRaisesRegex(oracle.LedgerError, "is not A"):
            oracle.validate_ledger(rows)

    def test_mutation_second_cancel_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="cancel")
        cancel = next(row for row in rows if row.get("kind") == "cancel")
        rows.insert(rows.index(cancel) + 1, dict(cancel))
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "two cancel markers"):
            oracle.validate_ledger(rows)

    def test_mutation_retire_unknown_after_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        retire = next(row for row in rows if row.get("kind") == "retire")
        retire["after"] = 99
        with self.assertRaisesRegex(oracle.LedgerError, "unknown hold_end after"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger(mode="retire")
        retire = next(row for row in rows if row.get("kind") == "retire")
        retire["after"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "after out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_retire_before_end_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        retire = next(row for row in rows if row.get("kind") == "retire")
        end = next(row for row in rows if row.get("kind") == "hold_end")
        rows.remove(retire)
        rows.insert(rows.index(end), retire)
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "precedes its hold_end"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger(mode="retire")
        retire = next(row for row in rows if row.get("kind") == "retire")
        end = next(row for row in rows if row.get("kind") == "hold_end")
        retire["t"] = end["t1"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "precedes its hold_end"):
            oracle.validate_ledger(rows)

    def test_mutation_cancel_outside_hold_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="cancel")
        cancel = next(row for row in rows if row.get("kind") == "cancel")
        cancel["t"] = rows[-1]["t"]
        with self.assertRaisesRegex(oracle.LedgerError, "outside the A hold window"):
            oracle.validate_ledger(rows)

    def test_mutation_b_call_t1_after_ack_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["t0"] = rows[-1]["t"]
        call["t1"] = rows[-1]["t"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "outside the ready/ack window"):
            oracle.validate_ledger(rows)

    def test_mutation_unexpected_kind_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        rows[3] = {"kind": "gap", "seq": 3}
        with self.assertRaisesRegex(oracle.LedgerError, "unexpected ledger kind"):
            oracle.validate_ledger(rows)

    def test_mutation_ack_before_ready_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        rows[-1]["t"] = rows[0]["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "ack precedes"):
            oracle.validate_ledger(rows)

    def test_mutation_empty_ledger_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "empty ledger"):
            oracle.validate_ledger([])

    def test_mutation_ready_fields_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        rows[0]["pid"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "ready pid out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[0]["tid"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "ready tid out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[0]["t"] = "now"
        with self.assertRaisesRegex(oracle.LedgerError, "ready t out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[0]["clock"] = "CLOCK_REALTIME"
        with self.assertRaisesRegex(oracle.LedgerError, "clock basis"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[0]["unit"] = "ms"
        with self.assertRaisesRegex(oracle.LedgerError, "clock unit"):
            oracle.validate_ledger(rows)

    def test_mutation_ack_fields_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        rows[-1]["issued"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "ack issued out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[-1]["held"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "ack held out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[-1]["held"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "held 2 disagrees"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[-1]["t"] = "done"
        with self.assertRaisesRegex(oracle.LedgerError, "ack t out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_seq_break_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        rows[2]["seq"] = 99
        with self.assertRaisesRegex(oracle.LedgerError, "breaks contiguity"):
            oracle.validate_ledger(rows)

    def test_mutation_tid_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["tid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "tid"):
            oracle.validate_ledger(rows)

    def test_mutation_alive_stamp_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        alive = next(row for row in rows if row.get("kind") == "alive")
        alive["t"] = "soon"
        with self.assertRaisesRegex(oracle.LedgerError, "t out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        alive = next(row for row in rows if row.get("kind") == "alive")
        alive["t"] = rows[-1]["t"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "outside the ready/ack window"):
            oracle.validate_ledger(rows)

    def test_mutation_call_stamps_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["t0"] = "early"
        with self.assertRaisesRegex(oracle.LedgerError, "t0/t1 out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["t0"], call["t1"] = call["t1"], call["t0"]
        with self.assertRaisesRegex(oracle.LedgerError, "precedes t0"):
            oracle.validate_ledger(rows)

    def test_mutation_unclosed_hold_rejected(self):
        oracle = require_oracle(self)
        rows = [row for row in healthy_ledger()
                if row.get("kind") != "hold_end"]
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "hold ends close"):
            oracle.validate_ledger(rows)

    def test_mutation_double_close_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        begin = next(row for row in rows if row.get("kind") == "hold_begin")
        end = next(row for row in rows if row.get("kind") == "hold_end")
        rows.insert(rows.index(begin) + 1, dict(begin))
        rows.insert(rows.index(end) + 1, dict(end))
        renumber(rows)
        rows[-1]["held"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "closes twice"):
            oracle.validate_ledger(rows)

    def test_mutation_double_retire_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        retire = next(row for row in rows if row.get("kind") == "retire")
        rows.insert(rows.index(retire) + 1, dict(retire))
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "retires twice"):
            oracle.validate_ledger(rows)

    def test_mutation_extra_field_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["note"] = "extra"
        with self.assertRaisesRegex(oracle.LedgerError, "unexpected fields"):
            oracle.validate_ledger(rows)

    def test_mutation_row_limit_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "row limit"):
            oracle.read_ledger(io.StringIO("{}\n" * 200003))

    def test_mutation_line_byte_limit_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "byte limit"):
            oracle.read_ledger(io.StringIO("x" * 4097 + "\n"))

    def test_mutation_invalid_ledger_text_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "invalid ledger row"):
            oracle.read_ledger(io.StringIO("not json\n"))
        with self.assertRaisesRegex(oracle.LedgerError, "invalid ledger encoding"):
            oracle.read_ledger(io.StringIO(chr(0xD800) + "\n"))
        with self.assertRaisesRegex(oracle.LedgerError, "nonfinite JSON number"):
            oracle.read_ledger(io.StringIO('{"kind": NaN}\n'))

    def test_mutation_fn_label_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["fn"] = "table[12];id"
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        begin = next(row for row in rows if row.get("kind") == "hold_begin")
        begin["fn"] = ""
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows)

    def test_mutation_rv_out_of_range_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["rv"] = 2 ** 64
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        end = next(row for row in rows if row.get("kind") == "hold_end")
        end["rv"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_duplicate_json_key_rejected(self):
        oracle = require_oracle(self)
        line = ('{"kind": "ready", "pid": 1, "tid": 1, "t": 2,'
                ' "clock": "CLOCK_MONOTONIC", "unit": "ns", "pid": 2}\n')
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate JSON key"):
            oracle.read_ledger(io.StringIO(line))

    def test_mutation_non_object_frame_row_refused(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        rows[0] = ["ready"]
        with self.assertRaisesRegex(oracle.LedgerError, "first row must be ready"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[-1] = ["ack"]
        with self.assertRaisesRegex(oracle.LedgerError, "last row must be ack"):
            oracle.validate_ledger(rows)
        rows = healthy_ledger()
        rows[2] = ["call"]
        with self.assertRaisesRegex(oracle.LedgerError, "must be an object"):
            oracle.validate_ledger(rows)

    def test_cli_string_payload_not_echoed(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            rows = healthy_ledger()
            call = next(row for row in rows if row.get("kind") == "call")
            call["pid"] = "PIN=1234-secret"
            write_jsonl(ledger, rows)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("promotion refused: pid string disagrees with ready pid",
                          completed.stderr)
            self.assertNotIn("PIN=1234-secret", completed.stderr)

    def test_cli_missing_file_refused(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH),
                 str(Path(tmp) / "absent.jsonl")],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("promotion refused: unreadable input", completed.stderr)

    def test_cli_non_object_first_row_refused_without_traceback(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            rows = healthy_ledger()
            rows[0] = ["ready"]
            write_jsonl(ledger, rows)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("promotion refused: first row must be ready",
                          completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)


class PromotionEvidenceTwins(unittest.TestCase):
    def test_mutation_refusal_label_outside_cells_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = refused_events(rows, "stale")
        refused = next(row for row in events if row.get("kind") == "refused")
        refused["reason"] = "view stale"
        with self.assertRaisesRegex(oracle.LedgerError, "outside the four cells"):
            oracle.validate_events(events)
        events = refused_events(rows, "stale")
        refused = next(row for row in events if row.get("kind") == "refused")
        refused["reason"] = "caller retired"
        with self.assertRaisesRegex(oracle.LedgerError, "outside the four cells"):
            oracle.validate_events(events)

    def test_mutation_drawn_twice_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        drawn = next(row for row in events if row.get("kind") == "drawn")
        events.append(dict(drawn))
        with self.assertRaisesRegex(oracle.LedgerError, "drawn twice"):
            oracle.validate_events(events)

    def test_mutation_detailed_twice_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        detailed = next(row for row in events if row.get("kind") == "detailed")
        events.append(dict(detailed))
        with self.assertRaisesRegex(oracle.LedgerError, "detailed twice"):
            oracle.validate_events(events)

    def test_mutation_event_field_ranges_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        drawn = next(row for row in events if row.get("kind") == "drawn")
        drawn["req"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "drawn req out of range"):
            oracle.validate_events(events)
        events = healthy_events(rows)
        drawn = next(row for row in events if row.get("kind") == "drawn")
        drawn["caller"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "drawn caller out of range"):
            oracle.validate_events(events)
        events = healthy_events(rows)
        drawn = next(row for row in events if row.get("kind") == "drawn")
        drawn["provider"] = "seven"
        with self.assertRaisesRegex(oracle.LedgerError, "drawn provider out of range"):
            oracle.validate_events(events)
        events = healthy_events(rows)
        drawn = next(row for row in events if row.get("kind") == "drawn")
        drawn["view"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "drawn view out of range"):
            oracle.validate_events(events)
        events = healthy_events(rows)
        drawn = next(row for row in events if row.get("kind") == "drawn")
        drawn["t"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "drawn t out of range"):
            oracle.validate_events(events)
        events = refused_events(rows, "stale")
        expired = next(row for row in events if row.get("kind") == "view_expired")
        expired["view"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "view_expired view out of range"):
            oracle.validate_events(events)
        events = healthy_events(rows)
        pulse = next(row for row in events if row.get("kind") == "inventory_pulse")
        pulse["calls"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "inventory_pulse calls out of range"):
            oracle.validate_events(events)

    def test_mutation_event_helpers_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        revalidated = next(row for row in events
                           if row.get("kind") == "revalidated")
        revalidated["req"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "revalidated req out of range"):
            oracle.validate_events(events)
        cancel_rows = healthy_ledger(mode="cancel")
        events = healthy_events(cancel_rows, chain="cancel")
        cancelled = next(row for row in events if row.get("kind") == "cancelled")
        cancelled["t"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "cancelled t out of range"):
            oracle.validate_events(events)
        events = healthy_events(rows)
        completed = next(row for row in events if row.get("kind") == "completed")
        completed["seal"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "completed seal out of range"):
            oracle.validate_events(events)

    def test_mutation_revalidated_twice_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        revalidated = next(row for row in events
                           if row.get("kind") == "revalidated")
        events.append(dict(revalidated))
        with self.assertRaisesRegex(oracle.LedgerError, "revalidated twice"):
            oracle.validate_events(events)

    def test_mutation_seal_settled_twice_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        seal = next(row for row in events if row.get("kind") == "seal_settled")
        events.append(dict(seal))
        with self.assertRaisesRegex(oracle.LedgerError, "settled twice"):
            oracle.validate_events(events)

    def test_mutation_transfer_direction_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        transfer = next(row for row in events
                        if row.get("kind") == "owner_transferred")
        transfer["from"] = "B"
        with self.assertRaisesRegex(oracle.LedgerError, "transfer from"):
            oracle.validate_events(events)
        events = healthy_events(rows)
        transfer = next(row for row in events
                        if row.get("kind") == "owner_transferred")
        transfer["to"] = "A"
        with self.assertRaisesRegex(oracle.LedgerError, "transfer to"):
            oracle.validate_events(events)

    def test_mutation_retired_side_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        events = healthy_events(rows, chain="retire")
        retired = next(row for row in events if row.get("kind") == "retired")
        retired["side"] = "C"
        with self.assertRaisesRegex(oracle.LedgerError, "is not a lane"):
            oracle.validate_events(events)

    def test_mutation_scope_parent_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = refused_events(rows, "unsupported")
        scope = next(row for row in events if row.get("kind") == "scope")
        scope["parent"] = "moon"
        with self.assertRaisesRegex(oracle.LedgerError, "is not a scope"):
            oracle.validate_events(events)

    def test_mutation_unexpected_event_kind_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        events.append({"kind": "gap"})
        with self.assertRaisesRegex(oracle.LedgerError, "unexpected event kind"):
            oracle.validate_events(events)

    def test_mutation_duplicate_terminal_rows_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        events = healthy_events(rows, chain="retire")
        completed = next(row for row in events if row.get("kind") == "completed")
        events.append(dict(completed))
        with self.assertRaisesRegex(oracle.LedgerError, "completed twice"):
            oracle.compare_promotion(rows, events)
        events = healthy_events(rows, chain="retire")
        transfer = next(row for row in events
                        if row.get("kind") == "owner_transferred")
        events.append(dict(transfer))
        with self.assertRaisesRegex(oracle.LedgerError, "transferred twice"):
            oracle.compare_promotion(rows, events)
        events = healthy_events(rows, chain="retire")
        retired = next(row for row in events if row.get("kind") == "retired")
        events.append(dict(retired))
        with self.assertRaisesRegex(oracle.LedgerError, "retired twice"):
            oracle.compare_promotion(rows, events)
        cancel_rows = healthy_ledger(mode="cancel")
        cancel_events = healthy_events(cancel_rows, chain="cancel")
        cancelled = next(row for row in cancel_events
                         if row.get("kind") == "cancelled")
        cancel_events.append(dict(cancelled))
        with self.assertRaisesRegex(oracle.LedgerError, "cancelled twice"):
            oracle.compare_promotion(cancel_rows, cancel_events)
        refused = refused_events(rows, "scan")
        denied = next(row for row in refused if row.get("kind") == "refused")
        refused.append(dict(denied))
        with self.assertRaisesRegex(oracle.LedgerError, "refused twice"):
            oracle.compare_promotion(rows, refused)


class PromotionCompareTwins(unittest.TestCase):
    def test_healthy_full_chain_passes(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="pair")
        result = oracle.compare_promotion(rows, healthy_events(rows, chain="full"))
        self.assertEqual((result["reqs"], result["detailed"], result["transfers"]),
                         (1, 1, 1))

    def test_healthy_cancel_chain_passes(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="cancel")
        result = oracle.compare_promotion(rows, healthy_events(rows, chain="cancel"))
        self.assertEqual((result["reqs"], result["detailed"], result["transfers"]),
                         (1, 1, 0))

    def test_healthy_retire_chain_passes(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        result = oracle.compare_promotion(rows, healthy_events(rows, chain="retire"))
        self.assertEqual((result["reqs"], result["detailed"], result["transfers"]),
                         (1, 1, 1))

    def test_healthy_refusal_cells_pass(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="pair")
        for cell in ("busy", "stale", "scan", "unsupported"):
            with self.subTest(cell=cell):
                result = oracle.compare_promotion(rows, refused_events(rows, cell))
                self.assertEqual(result["reqs"], 2)

    def test_mutation_detailed_without_revalidated_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = [row for row in healthy_events(rows)
                  if row.get("kind") != "revalidated"]
        with self.assertRaisesRegex(oracle.LedgerError, "without revalidated"):
            oracle.compare_promotion(rows, events)
        events = healthy_events(rows)
        revalidated = next(row for row in events
                           if row.get("kind") == "revalidated")
        detailed = next(row for row in events if row.get("kind") == "detailed")
        detailed["t"] = revalidated["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "detailed precedes revalidation"):
            oracle.compare_promotion(rows, events)

    def test_mutation_revalidated_without_drawn_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = [row for row in healthy_events(rows)
                  if row.get("kind") != "drawn"]
        with self.assertRaisesRegex(oracle.LedgerError, "revalidated without drawn"):
            oracle.compare_promotion(rows, events)
        events = healthy_events(rows)
        drawn = next(row for row in events if row.get("kind") == "drawn")
        revalidated = next(row for row in events
                           if row.get("kind") == "revalidated")
        revalidated["t"] = drawn["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "revalidation precedes drawn"):
            oracle.compare_promotion(rows, events)

    def test_mutation_detailed_without_drawn_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = [row for row in healthy_events(rows)
                  if row.get("kind") not in ("drawn", "revalidated")]
        with self.assertRaisesRegex(oracle.LedgerError, "detailed without drawn"):
            oracle.compare_promotion(rows, events)

    def test_mutation_completed_without_detailed_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = [row for row in healthy_events(rows)
                  if row.get("kind") != "detailed"]
        with self.assertRaisesRegex(oracle.LedgerError, "completed without detailed"):
            oracle.compare_promotion(rows, events)

    def test_mutation_completed_unsettled_seal_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        completed = next(row for row in events if row.get("kind") == "completed")
        completed["seal"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "unsettled seal"):
            oracle.compare_promotion(rows, events)

    def test_mutation_completed_before_seal_settlement_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        completed = next(row for row in events if row.get("kind") == "completed")
        events.append({"kind": "seal_settled", "seal": 2,
                       "t": completed["t"] + 100})
        completed["seal"] = 2
        with self.assertRaisesRegex(oracle.LedgerError, "precedes seal"):
            oracle.compare_promotion(rows, events)

    def test_mutation_transfer_without_completed_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = [row for row in healthy_events(rows)
                  if row.get("kind") != "completed"]
        with self.assertRaisesRegex(oracle.LedgerError, "transfer without completed"):
            oracle.compare_promotion(rows, events)
        events = healthy_events(rows)
        completed = next(row for row in events if row.get("kind") == "completed")
        transfer = next(row for row in events
                        if row.get("kind") == "owner_transferred")
        transfer["t"] = completed["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "transfer precedes completed"):
            oracle.compare_promotion(rows, events)

    def test_mutation_completed_precedes_detailed_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        detailed = next(row for row in events if row.get("kind") == "detailed")
        completed = next(row for row in events if row.get("kind") == "completed")
        events.append({"kind": "seal_settled", "seal": 2, "t": rows[0]["t"]})
        completed["seal"] = 2
        completed["t"] = detailed["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "completed precedes detailed"):
            oracle.compare_promotion(rows, events)

    def test_mutation_retired_before_or_without_completed_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        events = healthy_events(rows, chain="retire")
        completed = next(row for row in events if row.get("kind") == "completed")
        retired = next(row for row in events if row.get("kind") == "retired")
        retired["t"] = completed["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "retired before completion"):
            oracle.compare_promotion(rows, events)
        events = [row for row in healthy_events(rows, chain="retire")
                  if row.get("kind") not in ("completed", "owner_transferred")]
        with self.assertRaisesRegex(oracle.LedgerError, "retired without completed"):
            oracle.compare_promotion(rows, events)

    def test_mutation_retired_side_b_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        events = healthy_events(rows, chain="retire")
        retired = next(row for row in events if row.get("kind") == "retired")
        retired["side"] = "B"
        with self.assertRaisesRegex(oracle.LedgerError, "is not the A lane"):
            oracle.compare_promotion(rows, events)

    def test_mutation_busy_without_outstanding_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = refused_events(rows, "busy")
        completed = next(row for row in events if row.get("kind") == "completed")
        refused = next(row for row in events if row.get("kind") == "refused")
        refused["t"] = completed["t"] + 50
        with self.assertRaisesRegex(oracle.LedgerError, "without an outstanding"):
            oracle.compare_promotion(rows, events)

    def test_mutation_stale_without_expiry_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = [row for row in refused_events(rows, "stale")
                  if row.get("kind") != "view_expired"]
        with self.assertRaisesRegex(oracle.LedgerError, "without a view_expired row"):
            oracle.compare_promotion(rows, events)

    def test_mutation_scan_without_ended_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = [row for row in refused_events(rows, "scan")
                  if row.get("kind") != "inventory_ended"]
        with self.assertRaisesRegex(oracle.LedgerError, "without an inventory_ended row"):
            oracle.compare_promotion(rows, events)

    def test_mutation_unsupported_without_cgroup_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = refused_events(rows, "unsupported")
        scope = next(row for row in events if row.get("kind") == "scope")
        scope["parent"] = "pid"
        with self.assertRaisesRegex(oracle.LedgerError, "without a cgroup parent scope"):
            oracle.compare_promotion(rows, events)

    def test_mutation_refused_without_drawn_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = refused_events(rows, "scan")
        events.remove(next(row for row in events
                           if row.get("kind") == "drawn" and row["req"] == 2))
        with self.assertRaisesRegex(oracle.LedgerError, "refused without drawn"):
            oracle.compare_promotion(rows, events)
        events = refused_events(rows, "scan")
        drawn = next(row for row in events
                     if row.get("kind") == "drawn" and row["req"] == 2)
        refused = next(row for row in events if row.get("kind") == "refused")
        refused["t"] = drawn["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "refused precedes drawn"):
            oracle.compare_promotion(rows, events)

    def test_mutation_detailed_without_b_calls_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(b_calls=0)
        oracle.validate_ledger(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "no B useful call"):
            oracle.compare_promotion(rows, healthy_events(rows, chain="full"))

    def test_mutation_stray_b_call_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        completed = next(row for row in events if row.get("kind") == "completed")
        last = max((row for row in rows if row.get("kind") == "call"),
                   key=lambda row: row["seq"])
        last["t1"] = rows[-1]["t"]
        self.assertGreater(last["t1"], completed["t"])
        with self.assertRaisesRegex(oracle.LedgerError, "outside every Detailed window"):
            oracle.compare_promotion(rows, events)

    def test_mutation_inventory_gap_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        detailed = next(row for row in healthy_events(rows)
                        if row.get("kind") == "detailed")
        events = [row for row in healthy_events(rows)
                  if not (row.get("kind") == "inventory_pulse"
                           and row["t"] > detailed["t"])]
        with self.assertRaisesRegex(oracle.LedgerError, "stalls after Detailed"):
            oracle.compare_promotion(rows, events)
        events = [row for row in healthy_events(rows)
                  if not (row.get("kind") == "inventory_pulse"
                           and row["t"] < detailed["t"])]
        with self.assertRaisesRegex(oracle.LedgerError, "stalls before Detailed"):
            oracle.compare_promotion(rows, events)

    def test_mutation_zero_call_pulse_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger()
        events = healthy_events(rows)
        detailed = next(row for row in events if row.get("kind") == "detailed")
        after = next(row for row in events
                     if row.get("kind") == "inventory_pulse" and row["t"] > detailed["t"])
        after["calls"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "stalls after Detailed"):
            oracle.compare_promotion(rows, events)

    def test_mutation_cancel_drops_caller_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="cancel")
        cancel = next(row for row in rows if row.get("kind") == "cancel")
        rows = [row for row in rows
                if row.get("kind") != "alive" or row["t"] <= cancel["t"]]
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "no liveness after"):
            oracle.compare_promotion(rows, healthy_events(rows, chain="cancel"))

    def test_mutation_b_admitted_during_cancel_gap_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="cancel")
        cancel = next(row for row in rows if row.get("kind") == "cancel")
        late = max((row for row in rows if row.get("kind") == "call"),
                   key=lambda row: row["seq"])
        late["t0"] = cancel["t"] + 1
        late["t1"] = cancel["t"] + 2
        with self.assertRaisesRegex(oracle.LedgerError, "during the cancel gap"):
            oracle.compare_promotion(rows, healthy_events(rows, chain="cancel"))

    def test_mutation_ledger_cancel_without_observed_row_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="cancel")
        events = [row for row in healthy_events(rows, chain="cancel")
                  if row.get("kind") != "cancelled"]
        with self.assertRaisesRegex(oracle.LedgerError, "without an observed cancelled"):
            oracle.compare_promotion(rows, events)

    def test_mutation_observed_cancel_without_ledger_marker_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="pair")
        with self.assertRaisesRegex(oracle.LedgerError, "without a ledger cancel marker"):
            oracle.compare_promotion(rows, healthy_events(rows, chain="cancel"))

    def test_mutation_ledger_retire_without_observed_row_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        with self.assertRaisesRegex(oracle.LedgerError, "without an observed retired"):
            oracle.compare_promotion(rows, healthy_events(rows, chain="full"))

    def test_mutation_observed_retired_without_ledger_row_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="pair")
        with self.assertRaisesRegex(oracle.LedgerError, "without a ledger retirement"):
            oracle.compare_promotion(rows, healthy_events(rows, chain="retire"))

    def test_mutation_b_admitted_before_a_retires_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="retire")
        found = spans(rows)
        events = healthy_events(rows, chain="retire")
        transfer = next(row for row in events
                        if row.get("kind") == "owner_transferred")
        completed = next(row for row in events if row.get("kind") == "completed")
        transfer["t"] = found["retire_t"] - 1
        self.assertGreaterEqual(transfer["t"], completed["t"])
        with self.assertRaisesRegex(oracle.LedgerError, "B admitted before A retires"):
            oracle.compare_promotion(rows, events)

    def test_mutation_transfer_before_a_completion_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="pair")
        found = spans(rows)
        last_b = max(call["t1"] for call in found["calls"])
        events = healthy_events(rows, chain="full")
        completed = next(row for row in events if row.get("kind") == "completed")
        transfer = next(row for row in events
                        if row.get("kind") == "owner_transferred")
        completed["t"] = last_b + 1
        transfer["t"] = last_b + 2
        self.assertLess(transfer["t"], found["end_t1"])
        with self.assertRaisesRegex(oracle.LedgerError, "before the A completion"):
            oracle.compare_promotion(rows, events)

    def test_mutation_cancelled_without_drawn_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(b_calls=0)
        events = [{"kind": "cancelled", "req": 1, "t": rows[-1]["t"]}]
        with self.assertRaisesRegex(oracle.LedgerError, "cancelled without drawn"):
            oracle.compare_promotion(rows, events)

    def test_mutation_cancelled_precedes_drawn_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="cancel")
        events = healthy_events(rows, chain="cancel")
        drawn = next(row for row in events if row.get("kind") == "drawn")
        cancelled = next(row for row in events if row.get("kind") == "cancelled")
        cancelled["t"] = drawn["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "cancelled precedes drawn"):
            oracle.compare_promotion(rows, events)

    def test_mutation_b_calls_without_any_detailed_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="pair")
        events = [
            {"kind": "drawn", "req": 1, "caller": 3, "provider": 7,
             "view": 11, "t": rows[0]["t"]},
            {"kind": "inventory_ended", "t": rows[0]["t"] + 1},
            {"kind": "refused", "req": 1, "reason": "parent scope ended",
             "t": rows[0]["t"] + 2},
        ]
        with self.assertRaisesRegex(oracle.LedgerError, "outside every Detailed window"):
            oracle.compare_promotion(rows, events)

    def test_mutation_cancel_outside_hold_compare_rejected(self):
        oracle = require_oracle(self)
        rows = healthy_ledger(mode="cancel")
        end = next(row for row in rows if row.get("kind") == "hold_end")
        cancel = next(row for row in rows if row.get("kind") == "cancel")
        cancel["t"] = end["t1"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "outside the A hold window"):
            oracle.compare_promotion(rows, healthy_events(rows, chain="cancel"))


class PromotionRunTwins(unittest.TestCase):
    def test_identical_runs_converge(self):
        oracle = require_oracle(self)
        first = healthy_ledger(mode="cancel")
        second = healthy_ledger(mode="cancel", pid=9999, tid=9999)
        result = oracle.compare_runs(first, second)
        self.assertEqual(result["matched_rows"], len(first))

    def test_mutation_divergent_fn_rejected(self):
        oracle = require_oracle(self)
        first = healthy_ledger()
        second = healthy_ledger()
        call = next(row for row in second if row.get("kind") == "call")
        call["fn"] = "table[13]"
        with self.assertRaisesRegex(oracle.LedgerError, "diverge at row"):
            oracle.compare_runs(first, second)

    def test_mutation_divergent_rv_rejected(self):
        oracle = require_oracle(self)
        first = healthy_ledger()
        second = healthy_ledger()
        call = next(row for row in second if row.get("kind") == "call")
        call["rv"] = 7
        with self.assertRaisesRegex(oracle.LedgerError, "diverge at row"):
            oracle.compare_runs(first, second)

    def test_mutation_divergent_length_rejected(self):
        oracle = require_oracle(self)
        first = healthy_ledger()
        second = healthy_ledger(b_calls=4)
        with self.assertRaisesRegex(oracle.LedgerError, "differ in length"):
            oracle.compare_runs(first, second)

    def test_mutation_run_kind_divergence_rejected(self):
        oracle = require_oracle(self)
        first = healthy_ledger(mode="cancel", b_calls=8)
        second = healthy_ledger(mode="cancel", b_calls=8)
        position = next(index for index, row in enumerate(second)
                        if row.get("kind") == "cancel")
        cancel = second[position]
        second[position] = {"kind": "alive", "seq": cancel["seq"],
                            "pid": 4242, "tid": 4242, "t": cancel["t"]}
        oracle.validate_ledger(second)
        with self.assertRaisesRegex(oracle.LedgerError, "diverge at row"):
            oracle.compare_runs(first, second)

    def test_cli_second_run_converges(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            first_path = Path(tmp) / "first.jsonl"
            second_path = Path(tmp) / "second.jsonl"
            write_jsonl(first_path, healthy_ledger(mode="retire"))
            write_jsonl(second_path, healthy_ledger(mode="retire"))
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(first_path),
                 "--second", str(second_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["matched_rows"], len(healthy_ledger(mode="retire")))


class PromotionEmissionTests(unittest.TestCase):
    def build_pair(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
        provider = Path(tmp) / "provider.so"
        fixture = Path(tmp) / "ab-pair"
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

    def build_fixture(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
        fixture = Path(tmp) / "ab-pair"
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

    def test_fixture_pair_emits_valid_ledger(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            child = subprocess.Popen(
                [str(fixture), str(provider), str(ledger)],
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
            self.assertEqual((summary["issued"], summary["held"]), (8, 1))
            calls = [row for row in rows if row["kind"] == "call"]
            self.assertEqual(len(calls), 8)
            for row in calls:
                self.assertEqual(row["rv"], 0)
                self.assertEqual((row["pid"], row["tid"]), (child.pid, child.pid))

    def test_fixture_cancel_emits_valid_ledger(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "cancel", "8"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual((summary["issued"], summary["held"]), (8, 1))
            cancel = next(row for row in rows if row["kind"] == "cancel")
            end = next(row for row in rows if row["kind"] == "hold_end")
            for row in rows:
                if row.get("kind") != "call":
                    continue
                self.assertFalse(cancel["t"] < row["t0"] < end["t1"],
                                 f"B call seq {row['seq']} lands in the cancel gap")

    def test_fixture_retire_emits_valid_ledger(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "retire", "4"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual((summary["issued"], summary["held"]), (4, 1))
            retire = next(row for row in rows if row["kind"] == "retire")
            end = next(row for row in rows if row["kind"] == "hold_end")
            self.assertEqual(retire["after"], end["seq"])

    def test_live_ledger_joins_derived_events(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "pair", "8"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            oracle.validate_ledger(rows)
            result = oracle.compare_promotion(rows, healthy_events(rows, chain="full"))
            self.assertEqual(result["transfers"], 1)

    def test_repeated_live_runs_converge(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            first = Path(tmp) / "first.jsonl"
            second = Path(tmp) / "second.jsonl"
            for ledger in (first, second):
                completed = subprocess.run(
                    [str(fixture), str(provider), str(ledger), "", "retire", "4"],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(first, encoding="utf-8") as stream:
                first_rows = oracle.read_ledger(stream)
            with open(second, encoding="utf-8") as stream:
                second_rows = oracle.read_ledger(stream)
            result = oracle.compare_runs(first_rows, second_rows)
            self.assertEqual(result["matched_rows"], len(first_rows))

    def test_fixture_calls_provider_for_every_row(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "count", PAIR_COUNTING_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            witness = Path(tmp) / "count"
            env = dict(os.environ, P11SCOPE_PAIR_COUNT_PATH=str(witness))
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "pair", "8"],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 8)
            self.assertEqual(witness.read_bytes(), b"B" * 8 + b"A")

    def test_fixture_slow_provider_call_duration(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "slow", PAIR_SLOW_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "pair", "3"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual(summary["issued"], 3)
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
                [str(fixture), str(provider), str(ledger), str(gate)],
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
            self.assertEqual(summary["issued"], 8)

    def test_fixture_refuses_bad_argv(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture)], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "bogus"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(ledger.exists())
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "pair", "0"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(ledger.exists())
            completed = subprocess.run(
                [str(fixture), str(Path(tmp) / "absent.so"), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(ledger.exists())

    def test_fixture_refuses_nonstub_provider(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "plain", PAIR_REFUSAL_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger)],
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
                [str(fixture), str(provider), str(ledger), str(gate)],
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

