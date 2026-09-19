#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Gate K1 k8s-attach lane oracle assert_k8s_evidence: validate DaemonSet capture evidence and refuse mutations. Oracle extracted from scripts/verify-k8s-attach.sh (lines 20-71)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Gate K1 k8s-attach lane oracle assert_k8s_evidence: validate DaemonSet capture evidence and refuse mutations").print_help()
    raise SystemExit(0)

import copy
import json
import sys


def oracle(document):
    evidence = document["evidence"]
    assert evidence["authority"] == "hash-pinned", evidence["authority"]
    assert evidence["attached_probes"] > 0, evidence["attached_probes"]
    assert evidence["slots"] > 0, evidence["slots"]
    paths = [m["path"] for m in document["capture"]["modules"]]
    assert any(p.endswith("libsofthsm2.so") for p in paths), paths


def good():
    return {
        "evidence": {
            "authority": "hash-pinned",
            "attached_probes": 136,
            "slots": 68,
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
    oracle(good())
    for label, path, value in [
        ("authority", ["evidence", "authority"], "unpinned"),
        ("attached", ["evidence", "attached_probes"], 0),
        ("slots", ["evidence", "slots"], 0),
        ("captured module", ["capture", "modules"], []),
    ]:
        try:
            oracle(mutate(good(), path, value))
        except (AssertionError, KeyError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: {label}")
    print("k8s-e2e oracle mutations rejected: OK")
    raise SystemExit(0)

oracle(json.load(open(sys.argv[1])))
print("k8s capture: OK")
