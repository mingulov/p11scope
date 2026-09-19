#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bench-overhead report oracle: render the per-condition median overhead table from work times files. Oracle extracted from scripts/bench-overhead.sh (lines 245-276)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Bench-overhead report oracle: render the per-condition median overhead table from work times files").print_help()
    raise SystemExit(0)

import statistics, sys

work, n_calls, kernel, cpu = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

conditions = [
    ("unobserved", "unobserved.times"),
    ("profile --mode metrics", "metrics.times"),
    ("profile --mode profile", "profile.times"),
    ("trace", "trace.times"),
]

print(f"kernel: {kernel}")
print(f"cpu: {cpu}")
print(f"calls per run: {n_calls}")
print()

rows = []
baseline_percall_median = None
for label, fname in conditions:
    ns = [int(x) for x in open(f"{work}/{fname}") if x.strip()]
    ms = [x / 1e6 for x in ns]
    percall = [x / n_calls for x in ns]
    med_ms = statistics.median(ms)
    med_percall = statistics.median(percall)
    if label == "unobserved":
        baseline_percall_median = med_percall
    rows.append((label, ms, med_ms, percall, med_percall))

print(f"{'condition':<26} {'median ms':>10} {'min..max ms':>18} {'median ns/call':>15} {'overhead ns/call':>18}")
for label, ms, med_ms, percall, med_percall in rows:
    overhead = med_percall - baseline_percall_median
    print(f"{label:<26} {med_ms:>10.1f} {min(ms):>7.1f}..{max(ms):<8.1f} {med_percall:>15.1f} {overhead:>18.1f}")
