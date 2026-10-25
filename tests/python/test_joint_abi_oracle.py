#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""104-entry ABI execution fixture/oracle twins.

The oracle (scripts/joint-abi-compare.py) validates the ABI ledger emitted
by tests/fixtures/abi-execution/abi-104.c (ready, thread declarations,
call rows with entry/fn/rv stamps, entry rows for unreturned calls, cpu
rows, ack on a declared CLOCK_MONOTONIC/ns basis) and joins it to the
observer's per-(cell, entry) counts: calls, returns, fn labels and the
full-width return-value multiset.

Healthy and mutation twins run unignored; the live-emission tests build the
tracked live-discovery-provider.c fixture and the ABI emitter with gcc
(LP64 and -m32) and validate the real emitted ledger.
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
ORACLE_PATH = ROOT / "scripts" / "joint-abi-compare.py"
FIXTURE_SRC = ROOT / "tests" / "fixtures" / "abi-execution" / "abi-104.c"
PROVIDER_SRC = ROOT / "tests" / "fixtures" / "live-discovery-provider.c"

try:
    _SPEC = importlib.util.spec_from_file_location(
        "joint_abi_compare", ORACLE_PATH
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


def build_ledger(calls=(), threads=(), blocked=(), cpus=(), pid=4242, tid=4242):
    """Assemble a canned ABI ledger; call dicts may override t0/t1."""
    rows = [{"kind": "ready", "pid": pid, "tid": tid, "t": 1000,
             "clock": "CLOCK_MONOTONIC", "unit": "ns"}]
    tick = 1000
    seq = 0
    latest = 1000

    def stamp(step=10):
        nonlocal tick
        tick += step
        return tick

    def append(row):
        nonlocal seq, latest
        seq += 1
        row["seq"] = seq
        rows.append(row)
        for key in ("t", "t0", "t1"):
            if key in row and type(row[key]) is int:
                latest = max(latest, row[key])
        return row

    for worker in threads:
        append({"kind": "thread", "pid": pid, "tid": worker})
    for call in calls:
        t0 = call.get("t0", stamp())
        t1 = call.get("t1", stamp(5))
        append({"kind": "call", "entry": call["entry"], "fn": call["fn"],
                "rv": call.get("rv", 0), "pid": pid,
                "tid": call.get("tid", tid), "t0": t0, "t1": t1,
                "cond": call["cond"], "cell": call["cell"]})
    for entry in blocked:
        append({"kind": "entry", "entry": entry["entry"], "fn": entry["fn"],
                "pid": pid, "tid": entry.get("tid", tid),
                "t0": entry.get("t0", stamp()), "cond": entry["cond"],
                "cell": entry["cell"]})
    for cpu in cpus:
        append({"kind": "cpu", "pid": pid, "tid": cpu.get("tid", tid),
                "cpu": cpu["cpu"], "t": cpu.get("t", stamp())})
    rows.append({"kind": "ack", "issued": len(calls),
                 "blocked": len(blocked), "t": max(tick, latest) + 10})
    return rows


def full_ledger(pid=4242, tid=4242):
    """Canned 104/104 ledger with resolved (non-table) fn labels."""
    calls = [{"entry": index, "fn": "C_FullEntry", "rv": 0,
              "cond": "full", "cell": "full"} for index in range(104)]
    return build_ledger(calls=calls, pid=pid, tid=tid)


def threads_ledger(workers=2, per=3, entry=5, cond="threads", cell="threads"):
    """Canned threaded ledger: worker tids with declared thread rows."""
    tids = [5001 + index for index in range(workers)]
    calls = []
    for number in range(workers * per):
        calls.append({"entry": entry, "fn": "C_GetSlotInfo", "rv": 0,
                      "tid": tids[number % workers], "cond": cond, "cell": cell})
    return build_ledger(calls=calls, threads=tids)


def hot_ledger():
    """Canned hot-key ledger: one hot entry shared by two threads."""
    return threads_ledger(workers=2, per=5, entry=5, cond="hot", cell="hot-keys")


def blocked_ledger():
    """Canned blocked ledger: one completed call plus one unreturned entry."""
    calls = [{"entry": 9, "fn": "C_InitToken", "rv": 0,
              "cond": "blocked", "cell": "blocked-unreturned"}]
    entries = [{"entry": 10, "fn": "C_InitPIN", "tid": 6001,
                "cond": "blocked", "cell": "blocked-unreturned"}]
    return build_ledger(calls=calls, threads=[6001], blocked=entries)


def nesting_ledger(depth=3, cond="nesting"):
    """Canned nested ledger: strictly nested call intervals."""
    calls = []
    for level in range(depth):
        calls.append({"entry": 6, "fn": "C_GetTokenInfo", "rv": 0,
                      "cond": cond, "cell": f"cond-{cond}",
                      "t0": 1010 + 10 * level,
                      "t1": 1010 + 10 * (2 * depth - level)})
    return build_ledger(calls=calls)


def cell_ledger(tag="g31-575"):
    """Canned opaque-cell ledger: entries 0..2 under one population tag."""
    names = ["C_Initialize", "C_Finalize", "C_GetInfo"]
    calls = [{"entry": index, "fn": names[index], "rv": 0,
              "cond": "cellrun", "cell": tag} for index in range(3)]
    return build_ledger(calls=calls)


def rv64_ledger():
    """Canned high-bit ledger: full-width return values incl. high bits."""
    names = ["C_Initialize", "C_Finalize", "C_GetInfo", "P11ScopeSlot3"]
    rvs = [0x8000000000000001, 0xFFFFFFFFFFFFFFFF, 0x80000000, 0]
    calls = [{"entry": index, "fn": names[index], "rv": rvs[index],
              "cond": "rv64", "cell": "rv64"} for index in range(4)]
    return build_ledger(calls=calls)


def migration_ledger():
    """Canned migration ledger: two calls with surrounding cpu rows."""
    calls = [{"entry": 5, "fn": "C_GetSlotInfo", "rv": 0,
              "cond": "migration", "cell": "cond-migration"} for _ in range(2)]
    cpus = [{"cpu": 0}, {"cpu": 1}]
    return build_ledger(calls=calls, cpus=cpus)


def healthy_counts(rows):
    """Per-(cell, entry) counts derived from ledger rows."""
    groups = {}
    for row in rows:
        if row.get("kind") not in ("call", "entry"):
            continue
        key = (row["cell"], row["entry"])
        slot = groups.setdefault(key, {"fn": row["fn"], "calls": 0,
                                       "returns": 0, "rv": []})
        slot["calls"] += 1
        if row["kind"] == "call":
            slot["returns"] += 1
            slot["rv"].append(row["rv"])
    return [{"kind": "counts", "cell": cell, "entry": entry, "fn": slot["fn"],
             "calls": slot["calls"], "returns": slot["returns"], "rv": slot["rv"]}
            for (cell, entry), slot in sorted(groups.items())]


def renumber(rows):
    """Reassign contiguous seqs after moving body rows."""
    seq = 0
    for row in rows[1:-1]:
        seq += 1
        row["seq"] = seq
    return rows


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


ABI_COUNTING_PROVIDER = """/* Test-only counting stub: every entry writes one byte to the witness. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} AbiTable;
int P11ScopeSlot68;
static unsigned long count_hit(void **out) {
    (void)out;
    const char *path = getenv("P11SCOPE_ABI_COUNT_PATH");
    if (path != NULL) {
        FILE *sink = fopen(path, "a");
        if (sink != NULL) {
            fputc('.', sink);
            fclose(sink);
        }
    }
    return 0;
}
static AbiTable abi_table;
__attribute__((constructor)) static void abi_init(void) {
    abi_table.major = 3;
    abi_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        abi_table.functions[i] = (void *)count_hit;
    }
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &abi_table;
    return 0;
}
"""

ABI_SLOW_PROVIDER = """/* Test-only slow stub: entry 0 sleeps, so t1-t0 proves post-call stamping. */
#define _GNU_SOURCE
#include <stddef.h>
#include <time.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} AbiSlowTable;
int P11ScopeSlot68;
static unsigned long slow_zero(void **out) {
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
static AbiSlowTable abi_slow_table;
__attribute__((constructor)) static void abi_slow_init(void) {
    abi_slow_table.major = 3;
    abi_slow_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        abi_slow_table.functions[i] = (void *)slow_noop;
    }
    abi_slow_table.functions[0] = (void *)slow_zero;
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &abi_slow_table;
    return 0;
}
"""

ABI_HIBIT_PROVIDER = """/* Test-only high-bit stub (LP64 only): entries 0..3 return full-width RVs. */
#define _GNU_SOURCE
#include <stddef.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} AbiHiTable;
int P11ScopeSlot68;
static unsigned long hi_bit63(void **out) {
    (void)out;
    return 0x8000000000000001UL;
}
static unsigned long hi_allbits(void **out) {
    (void)out;
    return 0xFFFFFFFFFFFFFFFFUL;
}
static unsigned long hi_bit31(void **out) {
    (void)out;
    return 0x80000000UL;
}
static unsigned long hi_noop(void **out) {
    (void)out;
    return 0;
}
static AbiHiTable abi_hi_table;
__attribute__((constructor)) static void abi_hi_init(void) {
    abi_hi_table.major = 3;
    abi_hi_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        abi_hi_table.functions[i] = (void *)hi_noop;
    }
    abi_hi_table.functions[0] = (void *)hi_bit63;
    abi_hi_table.functions[1] = (void *)hi_allbits;
    abi_hi_table.functions[2] = (void *)hi_bit31;
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &abi_hi_table;
    return 0;
}
"""

ABI_HIBIT32_PROVIDER = """/* Test-only 32-bit high-bit stub: entries 0..1 return high-bit RVs. */
#define _GNU_SOURCE
#include <stddef.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} AbiHi32Table;
int P11ScopeSlot68;
static unsigned long hi32_bit31(void **out) {
    (void)out;
    return 0x80000000UL;
}
static unsigned long hi32_allbits(void **out) {
    (void)out;
    return 0xFFFFFFFFUL;
}
static unsigned long hi32_noop(void **out) {
    (void)out;
    return 0;
}
static AbiHi32Table abi_hi32_table;
__attribute__((constructor)) static void abi_hi32_init(void) {
    abi_hi32_table.major = 3;
    abi_hi32_table.minor = 2;
    for (int i = 0; i < 104; i++) {
        abi_hi32_table.functions[i] = (void *)hi32_noop;
    }
    abi_hi32_table.functions[0] = (void *)hi32_bit31;
    abi_hi32_table.functions[1] = (void *)hi32_allbits;
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &abi_hi32_table;
    return 0;
}
"""

# Slot 0..67 dlsym names, copied from standard_names in
# tests/fixtures/abi-execution/abi-104.c; the mixed-identity twin below
# exports these plus P11ScopeSlot69..103 as functions with the
# P11ScopeSlot68 marker variable at slot 68.
STANDARD68 = (
    "C_Initialize", "C_Finalize", "C_GetInfo", "P11ScopeSlot3",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList",
    "C_GetMechanismInfo", "C_InitToken", "C_InitPIN", "C_SetPIN",
    "C_OpenSession", "C_CloseSession", "C_CloseAllSessions",
    "C_GetSessionInfo", "C_GetOperationState", "C_SetOperationState",
    "C_Login", "C_Logout", "C_CreateObject", "C_CopyObject",
    "C_DestroyObject", "C_GetObjectSize", "C_GetAttributeValue",
    "C_SetAttributeValue", "C_FindObjectsInit", "C_FindObjects",
    "C_FindObjectsFinal", "C_EncryptInit", "C_Encrypt", "C_EncryptUpdate",
    "C_EncryptFinal", "C_DecryptInit", "C_Decrypt", "C_DecryptUpdate",
    "C_DecryptFinal", "C_DigestInit", "C_Digest", "C_DigestUpdate",
    "C_DigestKey", "C_DigestFinal", "C_SignInit", "C_Sign", "C_SignUpdate",
    "C_SignFinal", "C_SignRecoverInit", "C_SignRecover", "C_VerifyInit",
    "C_Verify", "C_VerifyUpdate", "C_VerifyFinal", "C_VerifyRecoverInit",
    "C_VerifyRecover", "C_DigestEncryptUpdate", "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate", "C_DecryptVerifyUpdate", "C_GenerateKey",
    "C_GenerateKeyPair", "C_WrapKey", "C_UnwrapKey", "C_DeriveKey",
    "C_SeedRandom", "C_GenerateRandom", "C_GetFunctionStatus",
    "C_CancelFunction", "C_WaitForSlotEvent",
)

ABI_REFUSAL_PROVIDER = """/* Test-only non-stub provider: no marker export, so the stub-only emitter refuses it. */
#define _GNU_SOURCE
#include <stddef.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} AbiPlainTable;
static unsigned long plain_noop(void **out) {
    (void)out;
    return 0;
}
static AbiPlainTable abi_plain_table;
__attribute__((constructor)) static void abi_plain_init(void) {
    abi_plain_table.major = 2;
    abi_plain_table.minor = 40;
    for (int i = 0; i < 104; i++) {
        abi_plain_table.functions[i] = (void *)plain_noop;
    }
}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &abi_plain_table;
    return 0;
}
"""


class AbiLedgerTwins(unittest.TestCase):
    def test_healthy_full_ledger_passes(self):
        oracle = require_oracle(self)
        summary = oracle.validate_ledger(full_ledger())
        self.assertEqual((summary["issued"], summary["blocked"], summary["cells"]),
                         (104, 0, 1))

    def test_healthy_threads_ledger_passes(self):
        oracle = require_oracle(self)
        summary = oracle.validate_ledger(threads_ledger())
        self.assertEqual((summary["issued"], summary["blocked"], summary["cells"]),
                         (6, 0, 1))

    def test_healthy_blocked_ledger_passes(self):
        oracle = require_oracle(self)
        summary = oracle.validate_ledger(blocked_ledger())
        self.assertEqual((summary["issued"], summary["blocked"], summary["cells"]),
                         (1, 1, 1))

    def test_healthy_nested_ledgers_pass(self):
        oracle = require_oracle(self)
        for cond in ("nesting", "recursion"):
            with self.subTest(cond=cond):
                summary = oracle.validate_ledger(nesting_ledger(cond=cond))
                self.assertEqual(summary["issued"], 3)

    def test_healthy_full_passes_through_cli(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            counts_path = Path(tmp) / "counts.jsonl"
            rows = full_ledger()
            write_jsonl(ledger, rows)
            write_jsonl(counts_path, healthy_counts(rows))
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger),
                 str(counts_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(
                (result["issued"], result["blocked"], result["cells"],
                 result["count_rows"], result["keys"], result["calls"],
                 result["returns"]),
                (104, 0, 1, 104, 104, 104, 104))

    def test_mutation_empty_ledger_rejected(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.LedgerError, "empty ledger"):
            oracle.validate_ledger([])

    def test_mutation_ready_fields_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        rows[0]["pid"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "ready pid out of range"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[0]["tid"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "ready tid out of range"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[0]["t"] = "now"
        with self.assertRaisesRegex(oracle.LedgerError, "ready t out of range"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[0]["clock"] = "CLOCK_REALTIME"
        with self.assertRaisesRegex(oracle.LedgerError, "clock basis"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[0]["unit"] = "ms"
        with self.assertRaisesRegex(oracle.LedgerError, "clock unit"):
            oracle.validate_ledger(rows)

    def test_mutation_ack_fields_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        rows[-1]["issued"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "ack issued out of range"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[-1]["blocked"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "ack blocked out of range"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[-1]["t"] = "done"
        with self.assertRaisesRegex(oracle.LedgerError, "ack t out of range"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[-1]["t"] = rows[0]["t"] - 1
        with self.assertRaisesRegex(oracle.LedgerError, "ack precedes"):
            oracle.validate_ledger(rows)

    def test_mutation_seq_break_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        rows[2]["seq"] = 99
        with self.assertRaisesRegex(oracle.LedgerError, "breaks contiguity"):
            oracle.validate_ledger(rows)

    def test_mutation_unexpected_kind_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        rows[3] = {"kind": "gap", "seq": 3}
        with self.assertRaisesRegex(oracle.LedgerError, "unexpected ledger kind"):
            oracle.validate_ledger(rows)

    def test_mutation_non_object_rows_refused(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        rows[0] = ["ready"]
        with self.assertRaisesRegex(oracle.LedgerError, "first row must be ready"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[-1] = ["ack"]
        with self.assertRaisesRegex(oracle.LedgerError, "last row must be ack"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        rows[2] = ["call"]
        with self.assertRaisesRegex(oracle.LedgerError, "must be an object"):
            oracle.validate_ledger(rows)

    def test_mutation_entry_out_of_range_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["entry"] = 104
        with self.assertRaisesRegex(oracle.LedgerError, "entry .* out of range"):
            oracle.validate_ledger(rows)
        rows = blocked_ledger()
        entry = next(row for row in rows if row.get("kind") == "entry")
        entry["entry"] = 104
        with self.assertRaisesRegex(oracle.LedgerError, "entry .* out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_fn_label_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["fn"] = "C_GetSlotInfo;id"
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows)
        rows = blocked_ledger()
        entry = next(row for row in rows if row.get("kind") == "entry")
        entry["fn"] = ""
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_ledger(rows)

    def test_mutation_rv_out_of_range_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["rv"] = 2 ** 64
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_pid_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["pid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees with ready pid"):
            oracle.validate_ledger(rows)

    def test_mutation_undeclared_tid_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["tid"] = 9999
        with self.assertRaisesRegex(oracle.LedgerError, "undeclared"):
            oracle.validate_ledger(rows)
        rows = blocked_ledger()
        entry = next(row for row in rows if row.get("kind") == "entry")
        entry["tid"] = 9999
        with self.assertRaisesRegex(oracle.LedgerError, "undeclared"):
            oracle.validate_ledger(rows)
        rows = migration_ledger()
        cpu = next(row for row in rows if row.get("kind") == "cpu")
        cpu["tid"] = 9999
        with self.assertRaisesRegex(oracle.LedgerError, "undeclared"):
            oracle.validate_ledger(rows)

    def test_mutation_cond_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["cond"] = "bogus"
        with self.assertRaisesRegex(oracle.LedgerError, "is not a cond"):
            oracle.validate_ledger(rows)

    def test_mutation_cell_label_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["cell"] = "has space"
        with self.assertRaisesRegex(oracle.LedgerError, "cell label invalid"):
            oracle.validate_ledger(rows)

    def test_mutation_call_stamps_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["t0"] = "early"
        with self.assertRaisesRegex(oracle.LedgerError, "t0/t1 out of range"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["t0"], call["t1"] = call["t1"], call["t0"]
        with self.assertRaisesRegex(oracle.LedgerError, "precedes t0"):
            oracle.validate_ledger(rows)

    def test_mutation_call_t1_after_ack_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["t0"] = rows[-1]["t"]
        call["t1"] = rows[-1]["t"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "outside the ready/ack window"):
            oracle.validate_ledger(rows)

    def test_mutation_thread_declared_twice_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        thread = next(row for row in rows if row.get("kind") == "thread")
        rows.insert(rows.index(thread) + 1, dict(thread))
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "declared twice"):
            oracle.validate_ledger(rows)

    def test_mutation_thread_fields_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        thread = next(row for row in rows if row.get("kind") == "thread")
        thread["pid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "thread pid"):
            oracle.validate_ledger(rows)
        rows = threads_ledger()
        thread = next(row for row in rows if row.get("kind") == "thread")
        thread["tid"] = 0
        with self.assertRaisesRegex(oracle.LedgerError, "thread tid out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_cpu_fields_rejected(self):
        oracle = require_oracle(self)
        rows = migration_ledger()
        cpu = next(row for row in rows if row.get("kind") == "cpu")
        cpu["cpu"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "cpu out of range"):
            oracle.validate_ledger(rows)
        rows = migration_ledger()
        cpu = next(row for row in rows if row.get("kind") == "cpu")
        cpu["t"] = "soon"
        with self.assertRaisesRegex(oracle.LedgerError, "t out of range"):
            oracle.validate_ledger(rows)
        rows = migration_ledger()
        cpu = next(row for row in rows if row.get("kind") == "cpu")
        cpu["pid"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "disagrees with ready pid"):
            oracle.validate_ledger(rows)
        rows = migration_ledger()
        cpu = next(row for row in rows if row.get("kind") == "cpu")
        cpu["t"] = rows[-1]["t"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "outside the ready/ack window"):
            oracle.validate_ledger(rows)

    def test_mutation_entry_stamp_rejected(self):
        oracle = require_oracle(self)
        rows = blocked_ledger()
        entry = next(row for row in rows if row.get("kind") == "entry")
        entry["t0"] = "early"
        with self.assertRaisesRegex(oracle.LedgerError, "t0 out of range"):
            oracle.validate_ledger(rows)

    def test_mutation_nesting_flat_rejected(self):
        oracle = require_oracle(self)
        for cond in ("nesting", "recursion"):
            with self.subTest(cond=cond):
                calls = []
                tick = 1000
                for _ in range(3):
                    tick += 10
                    t0 = tick
                    tick += 5
                    calls.append({"entry": 6, "fn": "C_GetTokenInfo", "rv": 0,
                                  "cond": cond, "cell": f"cond-{cond}",
                                  "t0": t0, "t1": tick})
                with self.assertRaisesRegex(oracle.LedgerError, "do not nest"):
                    oracle.validate_ledger(build_ledger(calls=calls))

    def test_mutation_nesting_single_rejected(self):
        oracle = require_oracle(self)
        rows = nesting_ledger(depth=3)
        calls = [row for row in rows if row.get("kind") == "call"][:1]
        single = build_ledger(calls=[{key: call[key] for key in
                                      ("entry", "fn", "rv", "cond", "cell",
                                       "t0", "t1")} for call in calls])
        with self.assertRaisesRegex(oracle.LedgerError, "at least two"):
            oracle.validate_ledger(single)

    def test_mutation_dropped_call_rejected(self):
        oracle = require_oracle(self)
        rows = [row for row in threads_ledger() if row.get("seq") != 4]
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "issued"):
            oracle.validate_ledger(rows)

    def test_mutation_dropped_entry_rejected(self):
        oracle = require_oracle(self)
        rows = [row for row in blocked_ledger() if row.get("kind") != "entry"]
        renumber(rows)
        with self.assertRaisesRegex(oracle.LedgerError, "blocked"):
            oracle.validate_ledger(rows)

    def test_mutation_extra_field_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
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

    def test_mutation_duplicate_json_key_rejected(self):
        oracle = require_oracle(self)
        line = ('{"kind": "ready", "pid": 1, "tid": 1, "t": 2,'
                ' "clock": "CLOCK_MONOTONIC", "unit": "ns", "pid": 2}\n')
        with self.assertRaisesRegex(oracle.LedgerError, "duplicate JSON key"):
            oracle.read_ledger(io.StringIO(line))

    def test_cli_string_payload_not_echoed(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            rows = threads_ledger()
            call = next(row for row in rows if row.get("kind") == "call")
            call["pid"] = "PIN=1234-secret"
            write_jsonl(ledger, rows)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("abi refused: pid string disagrees with ready pid",
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
            self.assertIn("abi refused: unreadable input", completed.stderr)

    def test_cli_non_object_first_row_refused_without_traceback(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            rows = threads_ledger()
            rows[0] = ["ready"]
            write_jsonl(ledger, rows)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("abi refused: first row must be ready", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)


class AbiCountsTwins(unittest.TestCase):
    def test_mutation_counts_kind_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0] = {"kind": "gap"}
        with self.assertRaisesRegex(oracle.LedgerError, "unexpected counts kind"):
            oracle.validate_counts(counts)

    def test_mutation_counts_non_object_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0] = ["counts"]
        with self.assertRaisesRegex(oracle.LedgerError, "must be an object"):
            oracle.validate_counts(counts)

    def test_mutation_counts_cell_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0]["cell"] = "bad cell"
        with self.assertRaisesRegex(oracle.LedgerError, "cell label invalid"):
            oracle.validate_counts(counts)

    def test_mutation_counts_entry_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0]["entry"] = 104
        with self.assertRaisesRegex(oracle.LedgerError, "entry .* out of range"):
            oracle.validate_counts(counts)

    def test_mutation_counts_fn_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0]["fn"] = ""
        with self.assertRaisesRegex(oracle.LedgerError, "fn label invalid"):
            oracle.validate_counts(counts)

    def test_mutation_counts_calls_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0]["calls"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "calls out of range"):
            oracle.validate_counts(counts)

    def test_mutation_counts_returns_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0]["returns"] = -1
        with self.assertRaisesRegex(oracle.LedgerError, "returns out of range"):
            oracle.validate_counts(counts)
        counts = healthy_counts(threads_ledger())
        counts[0]["returns"] = counts[0]["calls"] + 1
        with self.assertRaisesRegex(oracle.LedgerError, "returns exceed calls"):
            oracle.validate_counts(counts)

    def test_mutation_counts_rv_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0]["rv"] = [2 ** 64]
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_counts(counts)
        counts = healthy_counts(threads_ledger())
        counts[0]["rv"] = 5
        with self.assertRaisesRegex(oracle.LedgerError, "rv out of range"):
            oracle.validate_counts(counts)

    def test_mutation_counts_rv_length_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts[0]["rv"] = []
        with self.assertRaisesRegex(oracle.LedgerError, "rv list length"):
            oracle.validate_counts(counts)

    def test_mutation_counts_twice_rejected(self):
        oracle = require_oracle(self)
        counts = healthy_counts(threads_ledger())
        counts.append(dict(counts[0]))
        with self.assertRaisesRegex(oracle.LedgerError, "counted twice"):
            oracle.validate_counts(counts)


class AbiCompareTwins(unittest.TestCase):
    def test_healthy_full_join_passes(self):
        oracle = require_oracle(self)
        rows = full_ledger()
        result = oracle.compare_abi(rows, healthy_counts(rows))
        self.assertEqual((result["cells"], result["keys"], result["calls"],
                          result["returns"]),
                         (1, 104, 104, 104))

    def test_healthy_threads_join_passes(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        result = oracle.compare_abi(rows, healthy_counts(rows))
        self.assertEqual((result["cells"], result["keys"], result["calls"],
                          result["returns"]),
                         (1, 1, 6, 6))

    def test_healthy_hot_join_passes(self):
        oracle = require_oracle(self)
        rows = hot_ledger()
        result = oracle.compare_abi(rows, healthy_counts(rows))
        self.assertEqual((result["cells"], result["keys"], result["calls"],
                          result["returns"]),
                         (1, 1, 10, 10))

    def test_healthy_blocked_join_passes(self):
        oracle = require_oracle(self)
        rows = blocked_ledger()
        result = oracle.compare_abi(rows, healthy_counts(rows))
        self.assertEqual((result["cells"], result["keys"], result["calls"],
                          result["returns"]),
                         (1, 2, 2, 1))

    def test_healthy_cell_join_passes(self):
        oracle = require_oracle(self)
        for tag in ("g31-575", "g31-576", "g31-577", "n", "n-plus-1"):
            with self.subTest(tag=tag):
                rows = cell_ledger(tag=tag)
                result = oracle.compare_abi(rows, healthy_counts(rows))
                self.assertEqual(result["keys"], 3)

    def test_healthy_rv64_join_passes(self):
        oracle = require_oracle(self)
        rows = rv64_ledger()
        result = oracle.compare_abi(rows, healthy_counts(rows))
        self.assertEqual((result["keys"], result["returns"]), (4, 4))

    def test_mutation_counts_missing_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        counts = healthy_counts(rows)[:-1]
        with self.assertRaisesRegex(oracle.LedgerError, "counts missing"):
            oracle.compare_abi(rows, counts)

    def test_mutation_counts_without_ledger_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        counts = healthy_counts(rows)
        counts.append({"kind": "counts", "cell": "extra", "entry": 0,
                       "fn": "C_Initialize", "calls": 1, "returns": 1,
                       "rv": [0]})
        with self.assertRaisesRegex(oracle.LedgerError, "counts without ledger rows"):
            oracle.compare_abi(rows, counts)

    def test_mutation_call_less_against_empty_counts_rejected(self):
        oracle = require_oracle(self)
        rows = build_ledger()
        summary = oracle.validate_ledger(rows)
        self.assertEqual((summary["issued"], summary["blocked"]), (0, 0))
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "comparison without ledger populations"):
            oracle.compare_abi(rows, [])

    def test_mutation_calls_against_empty_counts_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        oracle.validate_ledger(rows)
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "comparison without observed populations"):
            oracle.compare_abi(rows, [])

    def test_mutation_calls_disagree_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        counts = healthy_counts(rows)
        counts[0]["calls"] += 1
        with self.assertRaisesRegex(oracle.LedgerError, "calls disagree"):
            oracle.compare_abi(rows, counts)

    def test_mutation_returns_disagree_rejected(self):
        oracle = require_oracle(self)
        rows = blocked_ledger()
        counts = healthy_counts(rows)
        held = next(row for row in counts if row["returns"] == 0)
        held["returns"] = 1
        held["rv"] = [0]
        with self.assertRaisesRegex(oracle.LedgerError, "returns disagree"):
            oracle.compare_abi(rows, counts)

    def test_mutation_fn_within_key_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        call = next(row for row in rows if row.get("kind") == "call")
        call["fn"] = "C_Other"
        with self.assertRaisesRegex(oracle.LedgerError, "fn disagrees within"):
            oracle.compare_abi(rows, healthy_counts(rows))

    def test_mutation_fn_disagree_rejected(self):
        oracle = require_oracle(self)
        rows = threads_ledger()
        counts = healthy_counts(rows)
        counts[0]["fn"] = "C_Other"
        with self.assertRaisesRegex(oracle.LedgerError, "fn disagrees for"):
            oracle.compare_abi(rows, counts)

    def test_mutation_rv_multiset_rejected(self):
        oracle = require_oracle(self)
        rows = rv64_ledger()
        counts = healthy_counts(rows)
        wide = next(row for row in counts
                    if row["rv"] == [0x8000000000000001])
        wide["rv"] = [1]
        with self.assertRaisesRegex(oracle.LedgerError, "rv multiset disagrees"):
            oracle.compare_abi(rows, counts)

    def test_mutation_full_missing_entry_rejected(self):
        oracle = require_oracle(self)
        rows = [row for row in full_ledger() if row.get("entry") != 57]
        renumber(rows)
        rows[-1]["issued"] = 103
        with self.assertRaisesRegex(oracle.LedgerError, "never executed"):
            oracle.compare_abi(rows, healthy_counts(rows))

    def test_mutation_full_duplicate_entry_rejected(self):
        oracle = require_oracle(self)
        rows = full_ledger()
        fifth = next(row for row in rows if row.get("entry") == 5)
        rows.insert(rows.index(fifth) + 1, dict(fifth))
        renumber(rows)
        rows[-1]["issued"] = 105
        with self.assertRaisesRegex(oracle.LedgerError, "executed twice"):
            oracle.compare_abi(rows, healthy_counts(rows))

    def test_mutation_full_unverified_name_rejected(self):
        oracle = require_oracle(self)
        rows = full_ledger()
        fifth = next(row for row in rows if row.get("entry") == 5)
        fifth["fn"] = "table[5]"
        with self.assertRaisesRegex(oracle.LedgerError, "lacks a verified name"):
            oracle.compare_abi(rows, healthy_counts(rows))

    def test_mutation_full_blocked_row_rejected(self):
        oracle = require_oracle(self)
        rows = full_ledger()
        rows.insert(-1, {"kind": "entry", "entry": 10, "fn": "C_FullEntry",
                         "pid": 4242, "tid": 4242, "t0": 1500,
                         "cond": "full", "cell": "full"})
        renumber(rows)
        rows[-1]["blocked"] = 1
        with self.assertRaisesRegex(oracle.LedgerError, "unreturned entry row"):
            oracle.compare_abi(rows, healthy_counts(rows))

    def test_mutation_g31_tag_mismatch_rejected(self):
        oracle = require_oracle(self)
        rows = cell_ledger(tag="g31-575")
        counts = healthy_counts(cell_ledger(tag="g31-576"))
        with self.assertRaisesRegex(oracle.LedgerError, "counts missing"):
            oracle.compare_abi(rows, counts)

    def test_cli_counts_refusal_reports_reason(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            counts_path = Path(tmp) / "counts.jsonl"
            rows = threads_ledger()
            counts = healthy_counts(rows)
            counts[0]["calls"] += 1
            write_jsonl(ledger, rows)
            write_jsonl(counts_path, counts)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), str(ledger),
                 str(counts_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertRegex(completed.stderr, r"abi refused: calls disagree")


class AbiEmissionTests(unittest.TestCase):
    def build_pair(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
        provider = Path(tmp) / "provider.so"
        fixture = Path(tmp) / "abi-104"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-fPIC", "-DP11SCOPE_EXPORT_TABLES=1", "-shared", "-Wl,-z,defs",
             "-o", str(provider), str(PROVIDER_SRC)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-pthread", str(FIXTURE_SRC), "-ldl", "-o", str(fixture)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return provider, fixture

    def build_pair_m32(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
        provider = Path(tmp) / "provider32.so"
        fixture = Path(tmp) / "abi-104-32"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-m32", "-fPIC", "-DP11SCOPE_EXPORT_TABLES=1", "-shared",
             "-Wl,-z,defs", "-o", str(provider), str(PROVIDER_SRC)],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(build.returncode, 0, build.stderr)
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-m32", "-pthread", str(FIXTURE_SRC), "-ldl", "-o", str(fixture)],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(build.returncode, 0, build.stderr)
        return provider, fixture

    def build_fixture(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
        fixture = Path(tmp) / "abi-104"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-pthread", str(FIXTURE_SRC), "-ldl", "-o", str(fixture)],
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

    def build_fixture_m32(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not FIXTURE_SRC.is_file():
            self.fail(f"fixture missing: {FIXTURE_SRC} (implementation not present)")
        fixture = Path(tmp) / "abi-104-32"
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-m32", "-pthread", str(FIXTURE_SRC), "-ldl", "-o", str(fixture)],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(build.returncode, 0, build.stderr)
        return fixture

    def build_inline_provider_m32(self, tmp, name, source):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        provider_c = Path(tmp) / (name + ".c")
        provider = Path(tmp) / (name + ".so")
        provider_c.write_text(source, encoding="utf-8")
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-m32", "-fPIC", "-shared", "-Wl,-z,defs",
             "-o", str(provider), str(provider_c)],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(build.returncode, 0, build.stderr)
        return provider

    def build_mixed_provider(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        self.assertEqual(len(STANDARD68), 68)
        names = list(STANDARD68) + [f"P11ScopeSlot{i}" for i in range(69, 104)]
        parts = ["""/* Test-only mixed-identity stub: 103 named functions plus
 * the P11ScopeSlot68 marker variable at slot 68. Generated. */
#define _GNU_SOURCE
#include <stddef.h>
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[104];
} AbiMixedTable;
int P11ScopeSlot68;
static unsigned long mixed_slot68(void **out) {
    (void)out;
    return 0;
}
"""]
        for name in names:
            parts.append(f"unsigned long {name}(void **out) {{\n"
                         "    (void)out;\n"
                         "    return 0;\n"
                         "}\n")
        parts.append("static AbiMixedTable abi_mixed_table;\n"
                     "__attribute__((constructor)) static void abi_mixed_init(void) {\n"
                     "    abi_mixed_table.major = 3;\n"
                     "    abi_mixed_table.minor = 2;\n")
        for index, name in enumerate(names[:68]):
            parts.append(f"    abi_mixed_table.functions[{index}] = (void *){name};\n")
        parts.append("    abi_mixed_table.functions[68] = (void *)mixed_slot68;\n")
        for index, name in enumerate(names[68:], start=69):
            parts.append(f"    abi_mixed_table.functions[{index}] = (void *){name};\n")
        parts.append("""}
unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &abi_mixed_table;
    return 0;
}
""")
        return self.build_inline_provider(tmp, "mixed", "".join(parts))

    def assert_full_shape(self, rows, child_pid):
        calls = [row for row in rows if row["kind"] == "call"]
        self.assertEqual([call["entry"] for call in calls], list(range(104)))
        names = {call["entry"]: call["fn"] for call in calls}
        self.assertEqual(names[0], "C_Initialize")
        self.assertEqual(names[67], "C_WaitForSlotEvent")
        self.assertEqual(names[68], "P11ScopeSlot68")
        self.assertEqual(names[103], "P11ScopeSlot103")
        for call in calls:
            self.assertNotIn("table[", call["fn"])
            self.assertEqual(call["rv"], 0)
            self.assertEqual((call["pid"], call["tid"]), (child_pid, child_pid))

    def test_fixture_full_lp64_emits_104(self):
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
            self.assertEqual((summary["issued"], summary["blocked"]), (104, 0))
            self.assert_full_shape(rows, child.pid)
            result = oracle.compare_abi(rows, healthy_counts(rows))
            self.assertEqual(result["keys"], 104)

    def test_fixture_full_ia32_emits_104(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair_m32(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual((summary["issued"], summary["blocked"]), (104, 0))
            calls = [row for row in rows if row["kind"] == "call"]
            self.assertEqual([call["entry"] for call in calls], list(range(104)))
            names = {call["entry"]: call["fn"] for call in calls}
            self.assertEqual(names[0], "C_Initialize")
            self.assertEqual(names[67], "C_WaitForSlotEvent")
            self.assertEqual(names[68], "P11ScopeSlot68")
            self.assertEqual(names[103], "P11ScopeSlot103")
            for call in calls:
                self.assertNotIn("table[", call["fn"])
                self.assertEqual(call["rv"], 0)

    def test_fixture_threads_exact_counts(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "threads", "4,25,5"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual(summary["issued"], 100)
            threads = [row for row in rows if row["kind"] == "thread"]
            self.assertEqual(len(threads), 4)
            calls = [row for row in rows if row["kind"] == "call"]
            self.assertEqual(len(calls), 100)
            self.assertTrue(all(call["entry"] == 5 for call in calls))
            self.assertEqual({call["tid"] for call in calls},
                             {thread["tid"] for thread in threads})
            result = oracle.compare_abi(rows, healthy_counts(rows))
            self.assertEqual((result["keys"], result["calls"]), (1, 100))

    def test_fixture_hot_exact_counts(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "hot", "8,50,5"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual(summary["issued"], 400)
            calls = [row for row in rows if row["kind"] == "call"]
            self.assertTrue(all(call["cell"] == "hot-keys" for call in calls))
            result = oracle.compare_abi(rows, healthy_counts(rows))
            self.assertEqual((result["keys"], result["calls"]), (1, 400))

    def test_fixture_cond_modes_validate(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            for cond in ("migration", "nesting", "recursion", "longjmp",
                         "thread-exit", "held-detach"):
                with self.subTest(cond=cond):
                    ledger = Path(tmp) / f"{cond}.jsonl"
                    completed = subprocess.run(
                        [str(fixture), str(provider), str(ledger), "",
                         f"cond:{cond}"],
                        capture_output=True, text=True, timeout=60)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    with open(ledger, encoding="utf-8") as stream:
                        rows = oracle.read_ledger(stream)
                    summary = oracle.validate_ledger(rows)
                    self.assertGreater(summary["issued"], 0)
                    if cond in ("nesting", "recursion"):
                        ordered = sorted(
                            (row for row in rows if row.get("kind") == "call"),
                            key=lambda row: row["t0"])
                        self.assertGreaterEqual(len(ordered), 2)
                        for outer, inner in zip(ordered, ordered[1:]):
                            self.assertLessEqual(outer["t0"], inner["t0"])
                            self.assertLessEqual(inner["t1"], outer["t1"])

    def test_fixture_migration_cpu_rows(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "cond:migration"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            oracle.validate_ledger(rows)
            cpus = [row["cpu"] for row in rows if row.get("kind") == "cpu"]
            self.assertEqual(len(cpus), 2)
            self.assertTrue(all(type(cpu) is int and cpu >= 0 for cpu in cpus))

    def test_fixture_blocked_emits_entry_without_return(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "blocked"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual((summary["issued"], summary["blocked"]), (1, 1))
            entries = [row for row in rows if row.get("kind") == "entry"]
            self.assertEqual(len(entries), 1)
            self.assertNotIn("t1", entries[0])
            self.assertNotIn("rv", entries[0])
            result = oracle.compare_abi(rows, healthy_counts(rows))
            self.assertEqual((result["calls"], result["returns"]), (2, 1))

    def test_fixture_cell_tag_round_trip(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "cell:g31-575"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual((summary["issued"], summary["cells"]), (3, 1))
            calls = [row for row in rows if row.get("kind") == "call"]
            self.assertTrue(all(call["cell"] == "g31-575" for call in calls))
            result = oracle.compare_abi(rows, healthy_counts(rows))
            self.assertEqual(result["keys"], 3)

    def test_fixture_rv64_records_full_width(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "hibit", ABI_HIBIT_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "rv64"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            oracle.validate_ledger(rows)
            calls = [row for row in rows if row.get("kind") == "call"]
            self.assertEqual([call["rv"] for call in calls],
                             [0x8000000000000001, 0xFFFFFFFFFFFFFFFF,
                              0x80000000, 0])
            result = oracle.compare_abi(rows, healthy_counts(rows))
            self.assertEqual(result["returns"], 4)

    def test_fixture_rv64_ia32_records_high_bit(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture_m32(tmp)
            provider = self.build_inline_provider_m32(
                tmp, "hibit32", ABI_HIBIT32_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "rv64"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            summary = oracle.validate_ledger(rows)
            self.assertEqual(summary["issued"], 4)
            calls = [row for row in rows if row.get("kind") == "call"]
            self.assertEqual([call["rv"] for call in calls],
                             [0x80000000, 0xFFFFFFFF, 0, 0])
            result = oracle.compare_abi(rows, healthy_counts(rows))
            self.assertEqual(result["returns"], 4)

    def test_fixture_mixed_identity_refused(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_mixed_provider(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("entry identity mismatch (103 of 104 names "
                          "resolve)", completed.stderr)
            self.assertNotIn("READY", completed.stdout)
            self.assertFalse(ledger.exists())



    def test_fixture_entry_bounds(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger), "", "entry", "103"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 1)
            refused = Path(tmp) / "refused.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(refused), "", "entry", "104"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(refused.exists())

    def test_fixture_calls_provider_for_every_row(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "count", ABI_COUNTING_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            witness = Path(tmp) / "count"
            env = dict(os.environ, P11SCOPE_ABI_COUNT_PATH=str(witness))
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger)],
                capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                summary = oracle.validate_ledger(oracle.read_ledger(stream))
            self.assertEqual(summary["issued"], 104)
            self.assertEqual(witness.stat().st_size, 104)

    def test_fixture_slow_provider_call_duration(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "slow", ABI_SLOW_PROVIDER)
            ledger = Path(tmp) / "ledger.jsonl"
            completed = subprocess.run(
                [str(fixture), str(provider), str(ledger)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with open(ledger, encoding="utf-8") as stream:
                rows = oracle.read_ledger(stream)
            oracle.validate_ledger(rows)
            zero = next(row for row in rows if row.get("entry") == 0)
            self.assertGreaterEqual(zero["t1"] - zero["t0"], 1_000_000)

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
            self.assertEqual(summary["issued"], 104)

    def test_fixture_refuses_bad_argv(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            provider, fixture = self.build_pair(tmp)
            completed = subprocess.run(
                [str(fixture)], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(completed.returncode, 0)
            for argv in (["", "bogus"], ["", "cond:bogus"],
                        ["", "cell:bad tag"], ["", "threads", "0,5,5"],
                        ["", "threads", "4,5"], ["", "entry"]):
                target = Path(tmp) / "refused.jsonl"
                try:
                    target.unlink()
                except FileNotFoundError:
                    pass
                completed = subprocess.run(
                    [str(fixture), str(provider), str(target), *argv],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(completed.returncode, 2, argv)
                self.assertFalse(target.exists(), argv)

    def test_fixture_refuses_nonstub_provider(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.build_fixture(tmp)
            provider = self.build_inline_provider(tmp, "plain", ABI_REFUSAL_PROVIDER)
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
