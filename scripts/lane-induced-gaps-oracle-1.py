#!/usr/bin/env python3
"""Gate G2 induced-gaps lane oracle assert_gap1: validate the aliasing gap where two names share one address and counts belong to the group. Oracle extracted from scripts/verify-induced-gaps.sh (lines 156-216)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Gate G2 induced-gaps lane oracle assert_gap1: validate the aliasing gap where two names share one address and counts belong to the group").print_help()
    raise SystemExit(0)

import copy
import json
import sys

WANT = sorted(["C_CancelFunction", "C_WaitForSlotEvent"])
WANT_CALLS = 25 + 17


def oracle(observed):
    alias_groups = observed["evidence"]["aliased"]
    matches = [group for group in alias_groups if sorted(group) == WANT]
    assert matches, f"no alias group == {WANT} in evidence.aliased: {alias_groups}"
    assert len(matches) == 1, f"expected exactly one matching alias group, got {matches}"

    reports = [f for f in observed["functions"] if sorted(f["names"]) == WANT]
    assert len(reports) == 1, f"expected exactly one function report for {WANT}, got {reports}"
    report = reports[0]
    assert report["aliased"] is True, "aliased slot must be flagged aliased=true"
    assert report["calls"] == WANT_CALLS, (
        f"aliased group calls: want {WANT_CALLS}, got {report['calls']}"
    )
    return report["calls"]


GOOD = {
    "evidence": {"aliased": [list(WANT)]},
    "functions": [
        {"names": list(WANT), "aliased": True, "calls": WANT_CALLS},
        {"names": ["C_GetInfo"], "aliased": False, "calls": 1},
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
        ("alias group present", mutate(["evidence", "aliased"], [["C_GetInfo"]])),
        ("one alias group", mutate(["evidence", "aliased"], [list(WANT), list(WANT)])),
        ("one function report", mutate(["functions"], GOOD["functions"] + [GOOD["functions"][0]])),
        ("aliased flag", mutate(["functions", 0, "aliased"], False)),
        ("aliased group calls", mutate(["functions", 0, "calls"], WANT_CALLS - 1)),
    ]:
        try:
            oracle(document)
        except (AssertionError, KeyError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: gap 1 {label}")
    print("gap 1 alias oracle mutations rejected: OK")
    raise SystemExit(0)

calls = oracle(json.load(open(sys.argv[1])))
print(f"gap 1 OK: alias group {WANT} calls={calls} (want {WANT_CALLS})")
