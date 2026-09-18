#!/usr/bin/env python3
"""Gate G2 induced-gaps lane oracle assert_dynamic_maps_advanced: require stable observer-owned map ids and advanced counters across the freeze lane. Oracle extracted from scripts/verify-induced-gaps.sh (lines 340-431)."""
import argparse
import sys
import tempfile

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Gate G2 induced-gaps lane oracle assert_dynamic_maps_advanced: require stable observer-owned map ids and advanced counters across the freeze lane").print_help()
    raise SystemExit(0)
if sys.argv[1:] == ["--self-test"]:
    # The lane always passes a work directory; standalone runs pass none.
    # A fresh temporary directory is what the synthetic self-test needs.
    _SELF_TEST_WORKDIR = tempfile.TemporaryDirectory(prefix="lane-oracle-selftest-")
    sys.argv.append(_SELF_TEST_WORKDIR.name)

import json, os, struct, sys


def identity(before, after):
    assert before["EVENTS"]["oracle"] == after["EVENTS"]["oracle"] == "mmap"
    assert "file" not in before["EVENTS"] and "file" not in after["EVENTS"]
    assert {name: item["id"] for name, item in before.items()} == {
        name: item["id"] for name, item in after.items()
    }, "observer-owned map ids changed during freeze lane"


def total(path):
    doc = json.load(open(path))
    cells = []

    def walk(value):
        if isinstance(value, dict):
            encoded = value.get("value")
            if isinstance(encoded, list) and all(isinstance(item, str) for item in encoded):
                raw = bytes(int(item, 16) for item in encoded)
                assert len(raw) % 8 == 0, (path, len(raw))
                cells.extend(struct.unpack(f"<{len(raw) // 8}Q", raw))
            else:
                for child in value.values(): walk(child)
        elif isinstance(value, list):
            for child in value: walk(child)

    walk(doc)
    return sum(cells)


DYNAMIC = ("STATS", "RV_COUNTS", "EVIDENCE")


def advanced(before, after):
    identity(before, after)
    for name in DYNAMIC:
        previous, current = total(before[name]["file"]), total(after[name]["file"])
        assert current > previous, f"dynamic {name} did not advance: {previous} -> {current}"
        print(f"dynamic {name} exact id={before[name]['id']} advanced: {previous} -> {current}")


if sys.argv[1] == "--self-test":
    work = sys.argv[2]

    def dump(name, cells):
        path = os.path.join(work, f"{name}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                [{"value": [f"0x{byte:02x}" for byte in struct.pack("<Q", cell)]} for cell in cells],
                handle,
            )
        return path

    def side(suffix, counts):
        maps = {"EVENTS": {"id": 1, "oracle": "mmap"}}
        for index, name in enumerate(DYNAMIC, start=2):
            maps[name] = {"id": index, "file": dump(f"{name}-{suffix}", [counts])}
        return maps

    good_before, good_after = side("before", 1), side("after", 2)
    advanced(good_before, good_after)
    mutations = [
        ("EVENTS ring oracle", good_before, {**good_after, "EVENTS": {"id": 1, "oracle": "file"}}),
        (
            "EVENTS dumped to a file",
            good_before,
            {**good_after, "EVENTS": {"id": 1, "oracle": "mmap", "file": "/dev/null"}},
        ),
        (
            "observer-owned map ids",
            good_before,
            {**good_after, "STATS": {**good_after["STATS"], "id": 99}},
        ),
        ("STATS advanced", good_before, {**good_after, "STATS": good_before["STATS"]}),
        ("RV_COUNTS advanced", good_before, {**good_after, "RV_COUNTS": good_before["RV_COUNTS"]}),
        ("EVIDENCE advanced", good_before, {**good_after, "EVIDENCE": good_before["EVIDENCE"]}),
    ]
    for label, before_side, after_side in mutations:
        try:
            advanced(before_side, after_side)
        except (AssertionError, KeyError):
            continue
        raise SystemExit(f"mutation accepted: {label}")
    print(f"dynamic policy-map oracle mutations rejected: OK ({len(mutations)} lanes)")
    raise SystemExit(0)

before_path, after_path = sys.argv[1:3]
advanced(
    {item["name"]: item for item in json.load(open(before_path))},
    {item["name"]: item for item in json.load(open(after_path))},
)
