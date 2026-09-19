#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Gate G1 attach-e2e lane oracle assert_lane_evidence: validate scan/manifest capture evidence and refuse mutations. Oracle extracted from scripts/verify-attach-e2e.sh (lines 17-98)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Gate G1 attach-e2e lane oracle assert_lane_evidence: validate scan/manifest capture evidence and refuse mutations").print_help()
    raise SystemExit(0)

import copy
import json
import sys


def oracle(document, lane):
    evidence = document["evidence"]
    discovery = evidence["discovery"]
    assert evidence["authority"] == "hash-pinned", evidence["authority"]
    assert document["capture"]["modules"][0]["path"].endswith("libsofthsm2.so"), document["capture"]
    if lane == "scan":
        assert [m["sources"] for m in discovery] == [["scan"]], discovery
        assert [m["corroborated"] for m in discovery] == [False], discovery
        assert [m["corroboration"] for m in discovery] == [["single_source"]], discovery
    else:
        assert [m["sources"] for m in discovery] == [["scan", "manifest"]], discovery
        assert [m["corroborated"] for m in discovery] == [True], discovery
        assert [m["corroboration"] for m in discovery] == [["agreed"]], discovery
        assert evidence["discovery_conflicts"] == 0, evidence["discovery_conflicts"]
        assert evidence["discovery_uncorroborated"] == 0, evidence["discovery_uncorroborated"]


def good(lane):
    corroborated = lane != "scan"
    return {
        "evidence": {
            "authority": "hash-pinned",
            "discovery": [
                {
                    "sources": ["scan", "manifest"] if corroborated else ["scan"],
                    "corroborated": corroborated,
                    "corroboration": ["agreed"] if corroborated else ["single_source"],
                }
            ],
            "discovery_conflicts": 0,
            "discovery_uncorroborated": 0,
        },
        "capture": {"modules": [{"path": "/usr/lib/softhsm/libsofthsm2.so"}]},
    }


def mutate(document, path, value):
    mutated = copy.deepcopy(document)
    cursor = mutated
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return mutated


if sys.argv[1] == "--self-test":
    lanes = {
        "scan": [
            ("authority", ["evidence", "authority"], "unpinned"),
            ("scan-only sources", ["evidence", "discovery", 0, "sources"], ["scan", "manifest"]),
            ("uncorroborated flag", ["evidence", "discovery", 0, "corroborated"], True),
            ("single-source label", ["evidence", "discovery", 0, "corroboration"], ["agreed"]),
            ("captured module", ["capture", "modules", 0, "path"], "/tmp/other.so"),
        ],
        "manifest": [
            ("authority", ["evidence", "authority"], "unpinned"),
            ("corroborated sources", ["evidence", "discovery", 0, "sources"], ["scan"]),
            ("corroborated flag", ["evidence", "discovery", 0, "corroborated"], False),
            ("agreement label", ["evidence", "discovery", 0, "corroboration"], ["single_source"]),
            ("discovery conflicts", ["evidence", "discovery_conflicts"], 1),
            ("uncorroborated count", ["evidence", "discovery_uncorroborated"], 1),
        ],
    }
    for lane, mutations in lanes.items():
        oracle(good(lane), lane)
        for label, path, value in mutations:
            try:
                oracle(mutate(good(lane), path, value), lane)
            except (AssertionError, KeyError, IndexError):
                continue
            raise SystemExit(f"mutation accepted: {lane} {label}")
    print("attach-e2e lane oracle mutations rejected: OK")
    raise SystemExit(0)

lane, path = sys.argv[1], sys.argv[2]
oracle(json.load(open(path)), lane)
print(f"{lane} lane: OK")
