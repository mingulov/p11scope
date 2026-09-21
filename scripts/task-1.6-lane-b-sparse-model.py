#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 1.6 Lane B: bounded non-evicting sparse-map storage model.

Lane A decided the coverage question (broad attaches every validated
target; selected misses beyond K=4) and the A2 probe showed broad needs
~6530 slots for one real p11-kit — far past the dense 512 ceiling. This
script evaluates the storage half WITHOUT any BPF ABI change:

1. Memory math anchored in MEASURED memlock (Lane A bpftool snapshots):
   dense per-cpu array vs bounded non-evicting per-cpu hash keyed by
   physical target, at 512 and 6530 scale, 12 and 64 CPUs.
2. First-touch allocation protocol: lookup -> alloc+init with NOEXIST ->
   EEXIST relookup -> update; a full map refuses with counted failure
   evidence (never evicts, never merges identities). The model runs the
   exact protocol, including a threaded race check for exactly-once
   alloc and lossless updates.
3. Residency replay: the real Lane A call stream (broad-single-metrics
   stage.log) plus synthetic p11-kit-shape activation patterns, showing
   peak residency, alloc count, and failure counts at several
   capacities.

This is a userspace MODEL of kernel behavior, not a kernel
measurement: it validates the protocol logic and the capacity
arithmetic. Per-entry hash overhead (~72B) is derived from measured
START/RV memlock, not assumed.

Usage:
  scripts/task-1.6-lane-b-sparse-model.py [--stage-log PATH]
      [--self-test]

Stdlib only. --self-test pins the model invariants, the memory math
against the measured anchors, and replay determinism.
"""

import argparse
import json
import sys
import threading
from pathlib import Path

# Measured anchors (Lane A bpftool snapshots, 12 CPUs):
#   STATS percpu_array 512 x 296B: memlock 1,823,024
#     (512*296*12 = 1,818,624 payload + ~4KB overhead)
#   START hash 16384 x (16+288)B: memlock 6,034,528
#     (16384*304 = 4,980,736 payload -> ~64B/entry overhead)
#   RV_COUNTS percpu_hash 4096 x (16+8*12)B: memlock 754,560
#     (4096*112 = 458,752 payload -> ~72B/entry overhead)
SLOT_STATS_BYTES = 296
START_KEY_BYTES = 16
START_VALUE_BYTES = 288
RV_KEY_BYTES = 16
RV_VALUE_BYTES = 8
TARGET_KEY_BYTES = 16  # (dev, ino, file_offset) packed
HTAB_OVERHEAD_BYTES = 72  # conservative measured per-entry overhead
NCPUS_MEASURED = 12


def dense_stats_bytes(slots, ncpu):
    """Dense per-cpu STATS array: slots x 296B x ncpu (+ page slack)."""
    return slots * SLOT_STATS_BYTES * ncpu


def sparse_stats_bytes(resident, ncpu, capacity):
    """Bounded NO_PREALLOC per-cpu hash: resident x (key + 296B x ncpu + ~72B).

    NO_PREALLOC allocates bucket/element memory on insert; at zero
    residency the map holds only its bucket array (~8B x capacity).
    """
    buckets = 8 * capacity
    return buckets + resident * (
        TARGET_KEY_BYTES + SLOT_STATS_BYTES * ncpu + HTAB_OVERHEAD_BYTES)


def start_bytes(entries):
    return entries * (START_KEY_BYTES + START_VALUE_BYTES
                      + HTAB_OVERHEAD_BYTES)


def rv_bytes(entries, ncpu):
    return entries * (RV_KEY_BYTES + RV_VALUE_BYTES * ncpu
                      + HTAB_OVERHEAD_BYTES)


class BoundedSparseMap:
    """Bounded non-evicting map with first-touch allocation.

    Models the kernel protocol exactly: lookup; on miss, alloc+init
    with NOEXIST (the loser of a race relooks-up the winner's entry);
    when full, count a failure (caller's stats are lost AND counted —
    never evicted, never merged into another identity).
    """

    def __init__(self, capacity):
        self.capacity = capacity
        self.entries = {}
        self.allocs = 0
        self.race_relookups = 0
        self.failed_allocs = 0
        self.failed_keys = set()
        self.lock = threading.Lock()

    def touch(self, key, update, contend=None):
        """First-touch `key`, apply `update(entry)`; returns True if kept.

        Faithful to the kernel protocol: an unlocked lookup fast path;
        on miss, alloc outside the lock and insert with NOEXIST — the
        loser of an alloc race relooks-up the winner's entry (counted)
        instead of double-allocating; when full, count a failure.
        `contend` (test-only) runs between the unlocked miss and the
        locked insert to inject a deterministic race.
        """
        if self.entries.get(key) is not None:
            with self.lock:
                update(self.entries[key])
            return True
        entry = {"calls": 0}
        if contend is not None:
            contend()
        with self.lock:
            if key in self.entries:
                self.race_relookups += 1
                update(self.entries[key])
                return True
            if len(self.entries) >= self.capacity:
                self.failed_allocs += 1
                self.failed_keys.add(key)
                return False
            self.entries[key] = entry
            self.allocs += 1
            update(entry)
            return True

    def residency(self):
        with self.lock:
            return len(self.entries)


def replay_calls(calls, capacity):
    """Replay a target-id call stream; return (map, kept, lost)."""
    table = BoundedSparseMap(capacity)
    kept = lost = 0
    for target in calls:
        if table.touch(target, lambda entry: entry.__setitem__(
                "calls", entry["calls"] + 1)):
            kept += 1
        else:
            lost += 1
    return table, kept, lost


def fixture_targets(stage_log):
    """Map a Lane A stage.log to an ordered wrapper-target stream.

    Target identity is the (wrapper index, ordinal) pair — the exact
    closure the call executes. Backend records are not targets (the
    observer never probes backend.so).
    """
    func_to_ord = {"C_Initialize": 0, "C_GetSlotList": 5,
                   "C_OpenSession": 13, "C_Login": 18,
                   "C_Sign": 43, "C_SignUpdate": 44}
    targets = []
    with open(stage_log, encoding="utf-8") as handle:
        for line in handle:
            parts = line.split(" ")
            if len(parts) != 7 or parts[2] != "wrapper":
                continue
            targets.append((int(parts[4]), func_to_ord[parts[3]]))
    return targets


def p11kit_shape():
    """Synthetic 6530-target shape: 64 templates x 104 entries, the last
    table sharing 3 implementations (A2 measured 6530 = 64*104 - 126:
    entries alias within/across tables; model as 6530 distinct)."""
    return [(table, ordinal) for table in range(64)
            for ordinal in range(104)][:6530]


def report_memory():
    print("== STATS memory: dense array (fixed by slots) vs bounded "
          "sparse hash (by residency), bytes ==")
    print(f"  dense-512 : @12cpu {dense_stats_bytes(512, 12):>12,}  "
          f"@64cpu {dense_stats_bytes(512, 64):>12,}")
    print(f"  dense-6530: @12cpu {dense_stats_bytes(6530, 12):>12,}  "
          f"@64cpu {dense_stats_bytes(6530, 64):>12,}")
    # 34 = the lane's 36 (idx, ord) pairs minus the 2 forwarded ones
    # (backend-direct, never wrapper targets — see the replay below).
    for resident in (0, 34, 512, 6530):
        sparse12 = sparse_stats_bytes(resident, 12, 8192)
        sparse64 = sparse_stats_bytes(resident, 64, 8192)
        print(f"  sparse C=8192 resident {resident:>4}: @12cpu "
              f"{sparse12:>12,}  @64cpu {sparse64:>12,}")
    print("measured anchors (@12cpu): STATS dense-512 memlock 1,823,024; "
          "START 6,034,528; RV 754,560")
    print(f"  START 16384-entry hash model: {start_bytes(16384):,} "
          f"(measured 6,034,528)")
    print(f"  RV 4096-entry percpu-hash model @12: {rv_bytes(4096, 12):,} "
          f"(measured 754,560)")


def report_replay(stage_log):
    print("\n== residency replay ==")
    if stage_log is not None and Path(stage_log).is_file():
        calls = fixture_targets(stage_log)
        distinct = len(set(calls))
        print(f"fixture trace {stage_log}: {len(calls)} calls, "
              f"{distinct} distinct targets")
        for capacity in (34, 512, 8192):
            table, kept, lost = replay_calls(calls, capacity)
            print(f"  capacity {capacity}: peak residency "
                  f"{table.residency()}, allocs {table.allocs}, "
                  f"kept {kept}, lost {lost}")
    else:
        print("fixture trace: no --stage-log given (pass a Lane A "
              "stage.log); synthetic shapes only")
    full = p11kit_shape()
    print(f"p11-kit shape: {len(full)} targets (A2: 6530 demanded)")
    for name, calls in (
            ("full sweep (every target called once)", list(full)),
            ("hot prefix (4 templates x 104, 10x each)",
             [(t, o) for t in range(4) for o in range(104)
              for _ in range(10)]),
            ("sparse random (5% of targets, 20x each)",
             [full[i] for i in range(0, len(full), 20)
              for _ in range(20)])):
        distinct = len(set(calls))
        row = f"  {name}: {len(calls)} calls, {distinct} distinct:"
        for capacity in (512, 2048, 8192):
            table, kept, lost = replay_calls(calls, capacity)
            row += (f" | C={capacity}: resident {table.residency()} "
                    f"allocs {table.allocs} lost {lost}")
        print(row)


def self_test():
    # Model invariants: bounded, non-evicting, failures counted.
    table = BoundedSparseMap(2)
    assert table.touch("a", lambda e: e.update(calls=1))
    assert table.touch("b", lambda e: e.update(calls=1))
    assert not table.touch("c", lambda e: None)
    assert table.touch("a", lambda e: e.update(calls=e["calls"] + 1))
    assert table.entries["a"]["calls"] == 2
    assert table.residency() == 2 and table.allocs == 2
    assert table.failed_allocs == 1 and table.failed_keys == {"c"}

    # Deterministic race injection: the loser relooks-up (never
    # double-allocates) and its update lands on the winner's entry.
    racy = BoundedSparseMap(4)
    assert racy.touch(
        "z", lambda e: e.__setitem__("calls", e["calls"] + 1),
        contend=lambda: racy.entries.setdefault("z", {"calls": 100}))
    assert racy.allocs == 0 and racy.race_relookups == 1
    assert racy.entries["z"]["calls"] == 101

    # Race: 8 threads first-touching 4 shared keys -> exactly-once
    # alloc per key, lossless updates.
    shared = BoundedSparseMap(4)
    total = [0]

    def hammer(key):
        for _ in range(250):
            assert shared.touch(
                key, lambda e: e.__setitem__(
                    "calls", e["calls"] + 1))

    threads = [threading.Thread(target=hammer, args=(f"k{i % 4}",))
               for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert shared.allocs == 4, shared.allocs
    assert shared.failed_allocs == 0
    assert sum(e["calls"] for e in shared.entries.values()) == 2000

    # Race under pressure: capacity 2, 4 keys -> exactly 2 resident,
    # every other touch a counted failure (winner depends on schedule;
    # the INVARIANT is allocs + failures accounting, not which keys).
    pressured = BoundedSparseMap(2)
    kept = [0]

    def hammer_pressure(key):
        for _ in range(100):
            if pressured.touch(
                    key, lambda e: e.__setitem__(
                        "calls", e["calls"] + 1)):
                kept[0] += 1

    threads = [threading.Thread(target=hammer_pressure, args=(f"k{i}",))
               for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert pressured.allocs == 2
    assert pressured.failed_allocs + kept[0] == 400, (
        pressured.failed_allocs, kept[0])

    # Memory math vs MEASURED memlock anchors (within 5%; memlock
    # includes kernel-side page/bucket slack the model omits).
    assert abs(dense_stats_bytes(512, 12) - 1_823_024) / 1_823_024 < 0.05
    assert abs(start_bytes(16384) - 6_034_528) / 6_034_528 < 0.05
    assert abs(rv_bytes(4096, 12) - 754_560) / 754_560 < 0.05

    # Replay determinism on a fixed stream.
    calls = [("w", o) for o in range(6) for _ in range(10)]
    first = replay_calls(calls, 6)
    second = replay_calls(calls, 6)
    assert (first[0].residency(), first[1], first[2]) == \
        (second[0].residency(), second[1], second[2]) == (6, 60, 0)
    tight = replay_calls(calls, 5)
    assert (tight[0].residency(), tight[1], tight[2]) == (5, 50, 10)

    # Fixture-target mapping on an embedded log sample.
    sample = Path("/tmp/task-1.6-lane-b-selftest.log")
    sample.write_text("1 1 wrapper C_Sign 4 direct 0\n"
                      "1 1 backend C_Sign 4 nested 0\n"
                      "1 1 wrapper C_Initialize 0 direct 0\n",
                      encoding="utf-8")
    try:
        mapped = fixture_targets(sample)
    finally:
        sample.unlink()
    assert mapped == [(4, 43), (0, 0)], mapped

    print("task-1.6-lane-b self-test: 7 groups green")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-log", default=None)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    report_memory()
    report_replay(args.stage_log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
