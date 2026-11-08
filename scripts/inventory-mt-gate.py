#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Wait until every workload edge is native-matched in the event stream.

Inventory usage counting only observes calls made after a caller's edge is
native-matched, so the inventory-mt cells release their workload gate only
once the event log carries, for every workload pid, an `edge_observed`
record on the owned provider whose entries coverage is `counted` or
`watched_no_use` (attached with zero calls so far). Any other terminal
state, or the deadline, fails loudly so the gate never opens on an
unobservable workload.

Exit 0 when all edges are matched, 1 on timeout, 2 on bad arguments.
"""

import argparse
import json
import sys
import time


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-log", required=True)
    parser.add_argument("--wl", required=True, help="workload TARGET/READY/CHILD transcript")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)
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
    matched = set()
    deadline = time.monotonic() + args.timeout
    offset = 0
    while time.monotonic() < deadline:
        try:
            with open(args.event_log, encoding="utf-8") as handle:
                handle.seek(offset)
                chunk = handle.read()
                offset = handle.tell()
        except FileNotFoundError:
            chunk = ""
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
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
                return 0
        time.sleep(0.1)
    missing = sorted(want - matched)
    print("inventory-mt-gate: unmatched workload edges for pids %r" % (missing,),
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
