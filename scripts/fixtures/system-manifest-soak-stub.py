#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Dry-run stand-in for the installed observer in manifest-soak trials.

Speaks the observer's inventory argv shape (`inventory --system
--manifest PATH --duration S --json -o OUT`), prints the pass-0 line
the attach gate waits for, sleeps the full duration, then writes an
inventory-shaped report. It observes nothing: with --loopback-log (one
per workload) it echoes each workload's own post-gate LEDGER totals
back as that caller's edge entries (labeled dry-run-loopback) so the
ledger join, verdict plumbing and sampler wiring run end to end on
real timestamps. The semantic stop line conserves with zero shed.

Live mode never invokes this stub. Stdlib only. Unprivileged.
"""
import argparse
import json
import sys
import time
from pathlib import Path


def read_ledgers(paths, deadline_s=60.0):
    """Wait for DONE in every log, then sum post-gate LEDGER rows per pid."""
    end = time.monotonic() + deadline_s
    texts = {}
    while time.monotonic() < end:
        ready = True
        for path in paths:
            try:
                text = Path(path).read_text(encoding="utf-8")
            except OSError:
                ready = False
                break
            texts[path] = text
            if "\nDONE " not in text and not text.startswith("DONE "):
                ready = False
                break
        if ready:
            break
        time.sleep(0.2)
    totals = {}
    modules = {}
    for path in paths:
        for line in texts.get(path, "").splitlines():
            if not line.startswith("LEDGER "):
                continue
            fields = dict(part.split("=", 1) for part in line.split()[1:])
            if fields.get("phase") not in ("main", "teardown"):
                continue
            pid = int(fields["pid"])
            totals[pid] = totals.get(pid, 0) + int(fields["n"])
            modules[pid] = fields["module"]
    return totals, modules


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["inventory"])
    parser.add_argument("--system", action="store_true", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--json", action="store_true", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--loopback-log", action="append", default=[])
    parser.add_argument("--attach-delay", type=float, default=0.5)
    args = parser.parse_args(argv)
    if args.duration <= 0 or args.attach_delay < 0:
        print("stub: nonpositive duration or negative attach delay", file=sys.stderr)
        return 2
    if not Path(args.manifest).is_file():
        print(f"stub: manifest {args.manifest} is missing", file=sys.stderr)
        return 2
    print("p11scope: pass 0: 2 scanned (2 maps-matched; 2 native, 0 scan-pinned)",
          file=sys.stderr, flush=True)
    time.sleep(args.attach_delay)
    deadline = time.monotonic() + args.duration
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(remaining, 0.5))
    totals, modules = read_ledgers(args.loopback_log)
    started_ns = time.monotonic_ns() - args.duration * 1_000_000_000
    callers = [{"id": f"c{index}", "pid": pid}
               for index, pid in enumerate(sorted(totals))]
    caller_of = {pid: f"c{index}" for index, pid in enumerate(sorted(totals))}
    module_ids = {}
    for pid in sorted(totals):
        module_ids.setdefault(modules[pid], f"m{len(module_ids)}")
    report = {
        "scope": "system",
        "observation": {
            "started_ns": started_ns, "ended_ns": time.monotonic_ns(),
            "passes": 2,
            "semantic_capture": {
                "status": "active", "admitted_endpoints": 30,
                "refused_endpoints": 0, "continuity_cuts": 0,
                "unrouted_returns": 0, "stop_quiescence": "quiesced",
                "final_drain": True,
            },
        },
        "budgets": {
            "callers": {"limit": 4096, "occupied": len(totals), "refused": 0},
            "modules": {"limit": 4096, "occupied": len(module_ids), "refused": 0},
            "edges": {"limit": 32768, "occupied": len(totals), "refused": 0},
            "endpoints": {"limit": 4096, "occupied": 30, "refused": 0},
            "counters": {"cap": 1 << 62, "observed_edges": len(totals),
                         "saturated_edges": 0},
        },
        "callers": callers,
        "modules": [{"id": module_id, "paths": [path]}
                    for path, module_id in sorted(module_ids.items(), key=lambda kv: kv[1])],
        "edges": [{"caller": caller_of[pid], "module": module_ids[modules[pid]],
                   "entries": {"count": totals[pid]},
                   "coverage": {"state": "counted", "lossy": False}}
                  for pid in sorted(totals)],
        "semantic_edges": [],
        "object_observations": {"status": "unavailable", "reason": "journal_unavailable"},
        "gaps": [],
        "gaps_suppressed": 0,
        "soak_stub": {"mode": "dry-run-loopback", "loopback": True},
    }
    Path(args.output).write_text(json.dumps(report), encoding="utf-8")
    joined = sum(totals.values())
    print(f"p11scope: semantic calls: collected {joined}, joined {joined}, "
          f"shed 0, bindings {len(totals)}, refused 0", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
