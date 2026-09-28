#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bench-overhead bounded-trace oracle: assert the --max-events truncation evidence shape of trace_bound.txt. Oracle extracted from scripts/bench-overhead.sh (lines 197-206)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Bench-overhead bounded-trace oracle: assert the --max-events truncation evidence shape of trace_bound.txt").print_help()
    raise SystemExit(0)

import json, sys

# Terminal records a trace writes besides call events (src/trace.rs): the
# COUNT_EVIDENCE count record immediately precedes EVIDENCE, as the canary
# checker (scripts/check-canary-evidence.py) also requires.
NON_EVENT_PREFIXES = ("CAPTURE ", "TRUNCATED ", "COUNT_EVIDENCE ", "EVIDENCE ", "LOST ")


def check(lines):
    events = [line for line in lines if line and not line.startswith(NON_EVENT_PREFIXES)]
    assert any(line.startswith("CAPTURE ") for line in lines), lines
    assert len(events) <= 1, events
    # src/trace.rs truncation_line cites the explicit cap.
    assert sum(line == "TRUNCATED at 1 events (--max-events 1)" for line in lines) == 1, lines
    evidence = [index for index, line in enumerate(lines) if line.startswith("EVIDENCE ")]
    assert len(evidence) == 1, evidence
    counts = [index for index, line in enumerate(lines) if line.startswith("COUNT_EVIDENCE ")]
    assert len(counts) == 1, f"expected one COUNT_EVIDENCE record, got {len(counts)}"
    assert counts[0] + 1 == evidence[0], "COUNT_EVIDENCE must immediately precede EVIDENCE"
    json.loads(lines[counts[0]].removeprefix("COUNT_EVIDENCE "))
    assert json.loads(lines[evidence[0]].removeprefix("EVIDENCE "))["trace_truncated"] is True, lines[evidence[0]]


def self_test():
    good = [
        "CAPTURE privacy=allowlisted",
        "01:44:49.558662 pid 7 tid 7 C_GetFunctionList → CKR_OK 18.1µs",
        "TRUNCATED at 1 events (--max-events 1)",
        'COUNT_EVIDENCE {"stats_entered":2,"stats_returned":1,"raw_calls":1}',
        'EVIDENCE {"trace_truncated":true}',
    ]
    check(good)
    bad = {
        "missing count record": good[:3] + good[4:],
        "count record after evidence": good[:3] + [good[4], good[3]],
        "two count records": good[:4] + good[3:],
        "second event": good[:2] + [good[1]] + good[2:],
        "not truncated": good[:4] + ['EVIDENCE {"trace_truncated":false}'],
        "default-cap truncation": good[:2]
        + ["TRUNCATED at 1 events (default cap; pass --max-events <n> to change it)"]
        + good[3:],
    }
    for name, lines in bad.items():
        try:
            check(lines)
        except (AssertionError, ValueError):
            continue
        raise SystemExit(f"self-test: {name} accepted")
    print("lane-bench-overhead-oracle-1 self-test: OK")


if sys.argv[1:] == ["--self-test"]:
    self_test()
    raise SystemExit(0)

check([line.rstrip("\n") for line in open(sys.argv[1])])
