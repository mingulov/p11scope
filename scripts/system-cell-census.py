#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Fork-free /proc census for the system-scope public CLI cells.

A busy host always has ambient process churn (logins, timers), and every
short-lived exit the scope walks never list counts a `pid_descendant_gap`.
The product reports honest gap counts with no per-gap ancestry, so the
oracle cannot tell ambient bursts from workload gaps on its own. The
qualify harness runs this census alongside the `system` and `mt-system`
cells; the oracle joins census exits outside the workload and observer
trees as proven ambient and keeps the unproven remainder at the strict
lone-gap ceiling.

The poll loop uses only /proc reads and existence checks: no fork, no
exec, no sleep binary. It is spawned before the observer starts and
stopped after it settles, so its own long-lived process is walk-listed,
never a gap. Records carry ancestry, flags and timing only (pid, ppid,
pgrp, session, flags, starttime, monotonic seen times); no comm, no
command lines.

Output is JSON lines: one `header`, any number of `baseline` (alive at
census start), `birth`, `ephemeral` (seen but unreadable before exit),
`exit` and `marker` records, then one `trailer`. The harness appends the
`observer` line (observer pid, known only after launch) once the census
stops. Marker files are touched with shell builtins when the harness
observes capture readiness (`capturing`) and observer settlement
(`settled`); the capture window is the monotonic interval between them.
The census creates the `--ready` file once its baseline sweep completes;
the harness waits for it before launching the observer, so every process
born inside the capture window gets a birth record (a birth racing the
baseline sweep would be baselined, and baselined exits never join).
"""

import argparse
import json
import os
import sys
import time

SCHEMA = "p11scope/system-cell-census/v1"


def read_stat(pid):
    """(ppid, pgrp, session, flags, starttime) from /proc/PID/stat, or None.

    Pure reads, never a fork. Field indices run past the comm tail:
    state ppid pgrp session ... flags is the 7th past comm, starttime
    the 20th. Flags carry PF_KTHREAD, which the oracle needs to keep
    kernel-thread exits out of the ambient join.
    """
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8") as stream:
            tail = stream.read().rsplit(")", 1)[1].split()
        ppid, pgrp, session, flags, starttime = (
            int(tail[1]), int(tail[2]), int(tail[3]), int(tail[6]), int(tail[19]))
    except (OSError, ValueError, IndexError):
        return None
    # Kernel threads carry pgrp/session 0; they are valid census members
    # (the oracle keeps their exits out of the ambient join by flags).
    if ppid < 0 or pgrp < 0 or session < 0 or flags < 0 or starttime < 0:
        return None
    return ppid, pgrp, session, flags, starttime


def live_pids():
    try:
        entries = os.listdir("/proc")
    except OSError:
        return None
    pids = set()
    for entry in entries:
        if entry.isdigit():
            pid = int(entry)
            if 0 < pid <= 1 << 30:
                pids.add(pid)
    return pids


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--stop", required=True)
    parser.add_argument("--workload", required=True)
    parser.add_argument("--capturing", required=True)
    parser.add_argument("--settled", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--poll-ms", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        workload = int(args.workload)
    except ValueError:
        workload = 0
    if workload <= 0:
        print("system-cell-census: --workload needs a live pid", file=sys.stderr)
        return 2
    if args.poll_ms <= 0 or args.poll_ms > 1000:
        print("system-cell-census: --poll-ms needs 1..1000", file=sys.stderr)
        return 2
    try:
        out = open(args.out, "w", encoding="utf-8", buffering=1)
    except OSError as error:
        print("system-cell-census: cannot write %s: %s" % (args.out, error), file=sys.stderr)
        return 2
    start = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    out.write(json.dumps({"type": "header", "schema": SCHEMA,
                          "workload_pid": workload, "poll_ms": args.poll_ms,
                          "census_start_mono_ns": start}) + "\n")
    # pid -> [ppid, pgrp, session, flags, starttime, first_seen_mono_ns or None]
    known = {}
    for pid in sorted(live_pids() or ()):
        facts = read_stat(pid)
        if facts is None:
            continue
        ppid, pgrp, session, flags, starttime = facts
        known[pid] = [ppid, pgrp, session, flags, starttime, None]
        out.write(json.dumps({"type": "baseline", "pid": pid, "ppid": ppid,
                              "pgrp": pgrp, "session": session, "flags": flags,
                              "starttime": starttime}) + "\n")
    try:
        with open(args.ready, "w", encoding="utf-8") as ready:
            ready.write("ready\n")
    except OSError as error:
        print("system-cell-census: cannot write %s: %s" % (args.ready, error),
              file=sys.stderr)
        return 2
    seen_markers = set()

    def check_markers(now):
        for name, path in (("capturing", args.capturing), ("settled", args.settled)):
            if name not in seen_markers and os.path.exists(path):
                seen_markers.add(name)
                out.write(json.dumps({"type": "marker", "name": name,
                                      "seen_mono_ns": now}) + "\n")

    def sweep(now):
        live = live_pids()
        if live is None:
            return
        for pid in sorted(live - set(known)):
            facts = read_stat(pid)
            if facts is None:
                out.write(json.dumps({"type": "ephemeral", "pid": pid,
                                      "seen_mono_ns": now}) + "\n")
                known[pid] = None
                continue
            ppid, pgrp, session, flags, starttime = facts
            known[pid] = [ppid, pgrp, session, flags, starttime, now]
            out.write(json.dumps({"type": "birth", "pid": pid, "ppid": ppid,
                                  "pgrp": pgrp, "session": session, "flags": flags,
                                  "starttime": starttime,
                                  "seen_mono_ns": now}) + "\n")
        for pid in sorted(set(known) - live):
            facts = known.pop(pid)
            if facts is None:
                continue
            ppid, pgrp, session, flags, starttime, born = facts
            out.write(json.dumps({"type": "exit", "pid": pid,
                                  "starttime": starttime,
                                  "birth_seen_mono_ns": born,
                                  "exit_seen_mono_ns": now}) + "\n")

    while not os.path.exists(args.stop):
        sweep(time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        check_markers(time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        time.sleep(args.poll_ms / 1000)
    # Final sweep: deaths landing between the last poll and the stop
    # marker must still be recorded, or the oracle under-joins.
    sweep(time.clock_gettime_ns(time.CLOCK_MONOTONIC))
    check_markers(time.clock_gettime_ns(time.CLOCK_MONOTONIC))
    out.write(json.dumps({"type": "trailer", "census_stop_mono_ns":
                          time.clock_gettime_ns(time.CLOCK_MONOTONIC)}) + "\n")
    out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
