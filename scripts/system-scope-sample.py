#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sample a privileged observer's CPU/RSS/fds from /proc at a fixed cadence.

The observer runs under sudo, so this sampler runs under sudo too (reading
another root process's /proc/PID/fd needs it). Exact mode takes a retained PID
and starttime identity. Legacy parent mode resolves a child via the children
file. Each mode writes one JSON object per line: monotonic + wall timestamps,
utime/stime ticks, RSS bytes, fd count, thread count. Exits when the exact
target, or the legacy target and its parent, are gone.

Stdlib only. No arguments are echoed; the output path is the only write.
"""

import argparse
import json
import os
import sys
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE_BYTES = os.sysconf("SC_PAGE_SIZE")
# include/linux/sched.h: set by exit_signals() at the start of do_exit(),
# before exit_mm()/exit_files() tear down what the metrics reads need.
PF_EXITING = 0x00000004


class TargetInspectionError(RuntimeError):
    """The exact target identity could not be inspected safely."""


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def resolve_children(ppid):
    """Return live child PIDs of the sudo parent (oldest first)."""
    try:
        tasks = sorted(os.listdir(f"/proc/{ppid}/task"))
    except OSError:
        return []
    kids = []
    for task in tasks:
        try:
            found = read_text(f"/proc/{ppid}/task/{task}/children").split()
        except OSError:
            continue
        kids.extend(int(kid) for kid in found if kid.isdigit())
    return kids


def pick_child(ppid):
    """Pick the observed child: sudo may interpose a short-lived monitor
    also named sudo, so prefer a non-sudo child and fall back to any."""
    kids = resolve_children(ppid)
    if not kids:
        return None
    for kid in sorted(kids):
        try:
            comm = read_text(f"/proc/{kid}/comm").strip()
        except OSError:
            continue
        if comm != "sudo":
            return kid
    return sorted(kids)[0]


def sample(pid):
    """Return a sample dict, or None if the process is gone."""
    try:
        stat = read_text(f"/proc/{pid}/stat")
        statm = read_text(f"/proc/{pid}/statm").split()
        fds = len(os.listdir(f"/proc/{pid}/fd"))
    except (OSError, ValueError):
        return None
    # comm may contain spaces/parens; fields 14/15/20 follow the last ')'.
    tail = stat.rsplit(")", 1)[1].split()
    try:
        utime = int(tail[11])
        stime = int(tail[12])
        threads = int(tail[17])
        rss_bytes = int(statm[1]) * PAGE_BYTES
    except (IndexError, ValueError):
        return None
    return {
        "t_mono_ns": time.monotonic_ns(),
        "t_wall_ns": time.time_ns(),
        "pid": pid,
        "utime_ticks": utime,
        "stime_ticks": stime,
        "rss_bytes": rss_bytes,
        "fds": fds,
        "threads": threads,
        "clk_tck": CLK_TCK,
    }


def read_exact_stat(pid):
    """Return parsed stat fields, None when terminal, or fail on unknown."""
    try:
        stat = read_text(f"/proc/{pid}/stat")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as error:
        raise TargetInspectionError(
            f"cannot inspect exact target stat: {type(error).__name__}"
        ) from error
    try:
        tail = stat.rsplit(")", 1)[1].split()
        state = tail[0]
        starttime = int(tail[19])
    except (IndexError, ValueError) as error:
        raise TargetInspectionError("exact target stat is malformed") from error
    return tail, state, starttime


def exact_target_exited(pid, expected_starttime):
    """Re-read the identity after a failed metrics read.

    True when the retained generation is gone, dead, a zombie, or has entered
    do_exit (PF_EXITING in the stat flags field). False when it is still the
    same live, non-exiting process. A changed birth identity or an unknown
    stat read stays fatal through read_exact_stat / TargetInspectionError.
    """
    probe = read_exact_stat(pid)
    if probe is None:
        return True
    tail, state, starttime = probe
    if starttime != expected_starttime:
        raise TargetInspectionError("exact target birth identity changed")
    if state in ("X", "x", "Z"):
        return True
    try:
        flags = int(tail[6])
    except (IndexError, ValueError) as error:
        raise TargetInspectionError("exact target stat is malformed") from error
    return bool(flags & PF_EXITING)


def sample_exact(pid, expected_starttime):
    """Sample only one retained process generation, bracketed by stat reads."""
    before = read_exact_stat(pid)
    if before is None:
        return None
    before_tail, before_state, before_starttime = before
    if before_starttime != expected_starttime:
        raise TargetInspectionError("exact target birth identity changed")
    if before_state in ("X", "x", "Z"):
        return None
    try:
        statm = read_text(f"/proc/{pid}/statm").split()
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        rss_bytes = int(statm[1]) * PAGE_BYTES
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as error:
        # The target may have begun exiting after the first stat read: exit
        # teardown releases mm and files, and a zombie's /proc/PID/fd refuses
        # even its owner with EACCES. Re-read the identity and treat that
        # refusal as the exit it is. A live, non-exiting target keeps the
        # refusal fatal.
        if exact_target_exited(pid, expected_starttime):
            return None
        raise TargetInspectionError(
            f"cannot inspect exact target metrics: {type(error).__name__}"
        ) from error
    except (IndexError, ValueError) as error:
        raise TargetInspectionError(
            f"cannot inspect exact target metrics: {type(error).__name__}"
        ) from error

    after = read_exact_stat(pid)
    if after is None:
        return None
    after_tail, after_state, after_starttime = after
    if after_starttime != expected_starttime:
        raise TargetInspectionError("exact target birth identity changed")
    if after_state in ("X", "x", "Z"):
        return None
    try:
        utime = int(after_tail[11])
        stime = int(after_tail[12])
        threads = int(after_tail[17])
    except (IndexError, ValueError) as error:
        raise TargetInspectionError("exact target stat is malformed") from error
    return {
        "t_mono_ns": time.monotonic_ns(),
        "t_wall_ns": time.time_ns(),
        "pid": pid,
        "utime_ticks": utime,
        "stime_ticks": stime,
        "rss_bytes": rss_bytes,
        "fds": fds,
        "threads": threads,
        "clk_tck": CLK_TCK,
    }


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--ppid", type=int)
    target.add_argument("--pid", type=int)
    parser.add_argument("--starttime", type=int)
    parser.add_argument("--out", required=True)
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--settle-s", type=float, default=30.0)
    args = parser.parse_args(argv)
    if not 0.005 <= args.interval <= 5.0:
        raise SystemExit("interval must be within [0.005, 5.0] seconds")
    if args.pid is not None and args.starttime is None:
        parser.error("--pid requires --starttime")
    if args.ppid is not None and args.starttime is not None:
        parser.error("--starttime is valid only with --pid")
    if args.pid is not None and (args.pid <= 0 or args.starttime <= 0):
        parser.error("--pid and --starttime must be positive")

    if args.pid is not None:
        seen = False
        # Create the bounded artifact even when the initial identity is absent
        # or unknown; it remains empty and the nonzero outcome invalidates the
        # measurement without a later missing-file ambiguity.
        with open(args.out, "w", encoding="utf-8", buffering=1) as handle:
            while True:
                try:
                    row = sample_exact(args.pid, args.starttime)
                except TargetInspectionError as error:
                    raise SystemExit(str(error)) from error
                if row is None:
                    if not seen:
                        raise SystemExit("exact target was not live")
                    return 0
                seen = True
                handle.write(json.dumps(row) + "\n")
                time.sleep(args.interval)

    deadline = time.monotonic() + args.settle_s
    target = None
    while time.monotonic() < deadline:
        target = pick_child(args.ppid)
        if target is not None and sample(target) is not None:
            break
        target = None
        # Parent gone before any child appeared: nothing to sample.
        if not os.path.isdir(f"/proc/{args.ppid}"):
            break
        time.sleep(min(args.interval, 0.05))
    if target is None:
        raise SystemExit(f"no live child of {args.ppid} appeared within settle window")

    misses = 0
    # Line-buffered: the harness tails this file live while waiting for the
    # attach ramp to plateau.
    with open(args.out, "w", encoding="utf-8", buffering=1) as handle:
        while True:
            row = sample(target)
            if row is None:
                # The latched child may have been a transient sudo helper:
                # re-resolve and follow a live replacement before giving up.
                replacement = pick_child(args.ppid)
                if replacement is not None and replacement != target:
                    probe = sample(replacement)
                    if probe is not None:
                        target = replacement
                        misses = 0
                        handle.write(json.dumps(probe) + "\n")
                        time.sleep(args.interval)
                        continue
                misses += 1
                # Two consecutive misses with a dead parent: target is gone.
                if misses >= 2 and not os.path.isdir(f"/proc/{args.ppid}"):
                    return 0
                if misses >= 40:  # ~2 s of misses: stop anyway, never hang.
                    return 0
            else:
                misses = 0
                handle.write(json.dumps(row) + "\n")
            # Sleep in small slices so exit latency stays low on short runs.
            time.sleep(args.interval)


if __name__ == "__main__":
    main(sys.argv[1:])
