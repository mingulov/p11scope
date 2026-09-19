#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Gate G2 induced-gaps lane oracle assert_gap2: validate the stranded in-flight call gap with no completed count and no latency. Oracle extracted from scripts/verify-induced-gaps.sh (lines 222-286)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Gate G2 induced-gaps lane oracle assert_gap2: validate the stranded in-flight call gap with no completed count and no latency").print_help()
    raise SystemExit(0)

import copy
import json
import sys


def oracle(observed):
    in_flight = observed["evidence"]["in_flight_at_end"]
    reports = [f for f in observed["functions"] if "C_WaitForSlotEvent" in f["names"]]
    assert len(reports) == 1, (
        f"expected exactly one function report naming C_WaitForSlotEvent, got {reports}"
    )
    report = reports[0]
    assert report["in_flight"] >= 1, f"slot in_flight: want >= 1, got {report['in_flight']}"
    assert report["calls"] == 0, f"stranded call must not count as completed: {report['calls']}"
    assert report["latency_ns"]["p50"] is None, (
        "stranded call must be excluded from latency percentiles"
    )
    assert report["latency_ns"]["p95"] is None
    assert report["latency_ns"]["p99"] is None
    return in_flight


GOOD = {
    "evidence": {"in_flight_at_end": 1},
    "functions": [
        {
            "names": ["C_WaitForSlotEvent"],
            "in_flight": 1,
            "calls": 0,
            "latency_ns": {"p50": None, "p95": None, "p99": None},
        }
    ],
}


def mutate(path, value):
    document = copy.deepcopy(GOOD)
    cursor = document
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return document


if sys.argv[1] == "--self-test":
    oracle(GOOD)
    for label, document in [
        ("one stranded report", mutate(["functions"], GOOD["functions"] * 2)),
        ("named report", mutate(["functions", 0, "names"], ["C_GetInfo"])),
        ("in-flight count", mutate(["functions", 0, "in_flight"], 0)),
        ("completed calls", mutate(["functions", 0, "calls"], 1)),
        ("p50 exclusion", mutate(["functions", 0, "latency_ns"], {"p50": 1, "p95": None, "p99": None})),
        ("p95 exclusion", mutate(["functions", 0, "latency_ns"], {"p50": None, "p95": 1, "p99": None})),
        ("p99 exclusion", mutate(["functions", 0, "latency_ns"], {"p50": None, "p95": None, "p99": 1})),
    ]:
        try:
            oracle(document)
        except (AssertionError, KeyError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: gap 2 {label}")
    print("gap 2 in-flight oracle mutations rejected: OK")
    raise SystemExit(0)

in_flight = oracle(json.load(open(sys.argv[1])))
print(f"gap 2 OK: in_flight_at_end={in_flight}, stranded call excluded from percentiles")
