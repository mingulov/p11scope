#!/usr/bin/env python3
"""Gate G2 induced-gaps lane oracle policy_map_ids: publish the expected policy-map id set to a 0600 file. Oracle extracted from scripts/verify-induced-gaps.sh (lines 297-329)."""
import argparse
import sys
import tempfile

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Gate G2 induced-gaps lane oracle policy_map_ids: publish the expected policy-map id set to a 0600 file").print_help()
    raise SystemExit(0)
if sys.argv[1:] == ["--self-test"]:
    # The lane always passes a work directory; standalone runs pass none.
    # A fresh temporary directory is what the synthetic self-test needs.
    _SELF_TEST_WORKDIR = tempfile.TemporaryDirectory(prefix="lane-oracle-selftest-")
    sys.argv.append(_SELF_TEST_WORKDIR.name)

import json, os, sys
expected = {"CONFIG", "PID_FILTER", "CGROUP_FILTER", "DESCRIPTORS",
            "ASYNC_FUNCTIONS", "MECH_SHAPE", "ATTR_BOOL_BITS", "TAIL_CALLS"}


def oracle(items, output_path):
    assert set(items) >= expected, (set(items), expected)
    with open(output_path, "w", encoding="utf-8") as output:
        os.chmod(output_path, 0o600)
        for name in sorted(expected):
            print(f"{name}={items[name]}", file=output)


if sys.argv[1] == "--self-test":
    work = sys.argv[2]
    good = {name: index for index, name in enumerate(sorted(expected), start=1)}
    oracle(good, f"{work}/ids")
    written = dict(line.split("=") for line in open(f"{work}/ids").read().splitlines())
    assert sorted(written) == sorted(expected), written
    assert oct(os.stat(f"{work}/ids").st_mode)[-3:] == "600", "policy-map id file must be 0600"
    for label, items in [
        ("missing published policy map", {k: v for k, v in good.items() if k != "DESCRIPTORS"}),
        ("empty inventory", {}),
    ]:
        try:
            oracle(items, f"{work}/ids")
        except AssertionError:
            continue
        raise SystemExit(f"mutation accepted: {label}")
    print("policy-map id oracle mutations rejected: OK")
    raise SystemExit(0)

oracle({item["name"]: item["id"] for item in json.load(open(sys.argv[1]))}, sys.argv[2])
