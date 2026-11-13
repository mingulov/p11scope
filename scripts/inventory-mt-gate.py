#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Wait until every workload edge is native-matched in the event stream.

Inventory usage counting only observes calls made after a caller's edge is
native-matched, so the inventory-mt cells release their workload gate only
once the event log carries, for every workload pid, an `edge_observed`
record on the owned provider whose entries coverage is `counted` or
`watched_no_use` (attached with zero calls so far).

The wait is driven by the product's own progress, not by a wall budget on
the match: matching is a load-sensitive multi-pass phase (scan, attach,
verify), so the gate releases whenever the qualifying edges arrive while
`pass_committed` records keep flowing. It fails loudly on a stall (no new
pass within --timeout of the previous one; the first pass does one-time
setup, so only --overall-timeout bounds the wait before it), past
--overall-timeout with no match, or as soon as the stream ends (`ended`)
unmatched, so the gate never opens on an unobservable workload and never
idles past a decided outcome.

`--settle-passes N` waits instead for N further passes past the gate start
(the post-LEDGER count settle: the second pass after the ledger surely
collected after it, since pass collections run sequentially). It needs no
workload transcript and takes the same stall/overall/ended rules.

Exit 0 when the condition holds, 1 on stall/overall/ended, 2 on bad
arguments.
"""

import argparse
import json
import math
import sys
import time


class EventTail:
    """Incremental append-only tail of the event log.

    Tracks how many `pass_committed` records arrived and whether the
    stream ended. Missing file reads as no new records (the observer
    may not have created it yet); malformed lines are skipped.
    """

    def __init__(self, path):
        self._path = path
        self._offset = 0
        self.passes = 0
        self.ended = False

    def poll(self):
        try:
            with open(self._path, encoding="utf-8") as handle:
                handle.seek(self._offset)
                chunk = handle.read()
                self._offset = handle.tell()
        except FileNotFoundError:
            return []
        records = []
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            records.append(record)
            kind = record.get("kind")
            if kind == "pass_committed":
                self.passes += 1
            elif kind == "ended":
                self.ended = True
        return records


def unmatched_line(missing):
    return "unmatched workload edges for pids %r" % (missing,)


def release(tail, want, dev, ino, stall, overall):
    matched = set()
    start = time.monotonic()
    last_pass = None
    seen_passes = 0
    while True:
        for record in tail.poll():
            if record.get("kind") != "edge_observed":
                continue
            event = record.get("event", {})
            context = event.get("identity_context", {})
            caller = context.get("caller", {})
            module = context.get("module", {})
            if (caller.get("pid") not in want or
                    module.get("device_major") != dev[0] or
                    module.get("device_minor") != dev[1] or
                    module.get("inode") != ino):
                continue
            entries = event.get("entries", {})
            coverage = entries.get("coverage", {})
            state = coverage.get("state")
            if state in ("counted", "watched_no_use"):
                matched.add(caller["pid"])
            if matched >= want:
                print("inventory-mt-gate: released: all %d workload edges "
                      "matched after %.1fs (%d passes)"
                      % (len(want), time.monotonic() - start, tail.passes),
                      file=sys.stderr)
                return 0
        if tail.ended:
            print("inventory-mt-gate: event stream ended without match; %s"
                  % unmatched_line(sorted(set(want) - matched)),
                  file=sys.stderr)
            return 1
        now = time.monotonic()
        if tail.passes > seen_passes:
            seen_passes = tail.passes
            last_pass = now
        if last_pass is not None and now - last_pass > stall:
            print("inventory-mt-gate: stalled: no pass_committed for %.1fs "
                      "(last pass #%d); %s"
                  % (stall, tail.passes,
                     unmatched_line(sorted(set(want) - matched))),
                  file=sys.stderr)
            return 1
        if now - start > overall:
            print("inventory-mt-gate: overall budget exhausted after %.1fs "
                      "(%d passes); %s"
                  % (overall, tail.passes,
                     unmatched_line(sorted(set(want) - matched))),
                  file=sys.stderr)
            return 1
        time.sleep(0.1)


def settle(tail, need, stall, overall):
    start = time.monotonic()
    last_pass = None
    tail.poll()
    baseline = tail.passes
    seen = baseline
    while True:
        tail.poll()
        if tail.passes >= baseline + need:
            print("inventory-mt-gate: settled: observed %d further passes "
                      "after %.1fs (%d total)"
                  % (need, time.monotonic() - start, tail.passes),
                  file=sys.stderr)
            return 0
        if tail.ended:
            print("inventory-mt-gate: event stream ended after %d of %d "
                      "further passes" % (tail.passes - baseline, need),
                  file=sys.stderr)
            return 1
        now = time.monotonic()
        if tail.passes > seen:
            seen = tail.passes
            last_pass = now
        if last_pass is not None and now - last_pass > stall:
            print("inventory-mt-gate: stalled: no pass_committed for %.1fs "
                      "(%d/%d further passes)"
                  % (stall, tail.passes - baseline, need),
                  file=sys.stderr)
            return 1
        if now - start > overall:
            print("inventory-mt-gate: overall budget exhausted after %.1fs "
                      "(%d/%d further passes)"
                  % (overall, tail.passes - baseline, need),
                  file=sys.stderr)
            return 1
        time.sleep(0.1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-log", required=True)
    parser.add_argument("--wl", required=False, default=None,
                        help="workload TARGET/READY/CHILD transcript "
                             "(release mode only)")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="stall budget in seconds between passes (the "
                             "first pass is bounded only by "
                             "--overall-timeout)")
    parser.add_argument("--overall-timeout", type=float, default=60.0,
                        help="overall backstop in seconds from gate start")
    parser.add_argument("--settle-passes", type=int, default=0,
                        help="settle mode: wait for this many further "
                             "passes instead of matching edges")
    args = parser.parse_args(argv)
    if any(math.isnan(value) for value in (args.timeout, args.overall_timeout)):
        print("inventory-mt-gate: timeouts must be numbers, not NaN",
              file=sys.stderr)
        return 2
    if args.settle_passes < 0:
        print("inventory-mt-gate: --settle-passes must not be negative",
              file=sys.stderr)
        return 2
    tail = EventTail(args.event_log)
    if args.settle_passes > 0:
        return settle(tail, args.settle_passes, args.timeout,
                      args.overall_timeout)
    if args.wl is None:
        print("inventory-mt-gate: --wl is required to release the workload "
              "gate", file=sys.stderr)
        return 2
    want, dev_ino = set(), set()
    try:
        with open(args.wl, encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("READY pid="):
                    want.add(int(line[len("READY pid="):].strip()))
                elif line.startswith("CHILD pid="):
                    want.add(int(line[len("CHILD pid="):].strip()))
                elif line.startswith("TARGET "):
                    target = json.loads(line[len("TARGET "):])
                    dev_ino.add((tuple(target["dev"]), target["ino"]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("inventory-mt-gate: unreadable workload transcript: %s" % (error,), file=sys.stderr)
        return 2
    if not want or len(dev_ino) != 1:
        print("inventory-mt-gate: need READY pids and one provider identity", file=sys.stderr)
        return 2
    (dev, ino) = dev_ino.pop()
    return release(tail, want, dev, ino, args.timeout, args.overall_timeout)


if __name__ == "__main__":
    sys.exit(main())
