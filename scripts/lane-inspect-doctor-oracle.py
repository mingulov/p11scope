#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged inspect-doctor lane oracle assert_inspect_doctor: validate inspect documents against doctor verdicts and refuse mutations. Oracle extracted from scripts/verify-inspect-doctor.sh (lines 23-204)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Unprivileged inspect-doctor lane oracle assert_inspect_doctor: validate inspect documents against doctor verdicts and refuse mutations").print_help()
    raise SystemExit(0)

import copy
import json
import sys


def oracle(document, doctor):
    assert document["schema"] == "p11scope/inspect/v1", document["schema"]
    paths = [module["path"] for module in document["modules"]]
    # Listing the provider needs only /proc/<pid>/maps and .dynsym, so it must
    # hold on both targets whether or not the memory scan could run.
    assert any(path.endswith("libsofthsm2.so") for path in paths), paths
    verdict = [line for line in doctor.splitlines() if line.startswith("verdict:")][-1]
    scanned = document["scan"]["status"] == "scanned"
    assert scanned == ("memory scan available" in verdict), (document["scan"], verdict)
    if scanned:
        details = []
        for provider in [
            module
            for module in document["modules"]
            if module["path"].endswith("libsofthsm2.so")
        ]:
            tableless = {
                "subject": provider["path"],
                "reason": "no function table was found in its file-backed data; a table built at run time in .bss or on the heap is outside the memory scan's reach",
            }
            tableless_skips = [skip for skip in document.get("skipped", []) if skip == tableless]
            if provider["tables"]:
                assert not tableless_skips, document.get("skipped", [])
                assert all(table["entries"] > 0 for table in provider["tables"]), provider["tables"]
                details.extend(
                    (table["version"], table["walk"], table["entries"])
                    for table in provider["tables"]
                )
            else:
                assert tableless_skips == [tableless], document.get("skipped", [])
                details.append(tableless["reason"])
        return "inspect: OK", paths, details
    assert document["scan"]["reason"], document["scan"]
    return "inspect: OK (scan refused, maps-only)", paths, document["scan"]["reason"]


def host_oracle(doctor):
    lines = doctor.splitlines()
    assert [line for line in lines if line.startswith("verdict:")], doctor
    # No --pid and no --cgroup: those two lanes must be reported n/a, never failed.
    for name in ("/proc/<pid>/maps", "cgroup path"):
        assert any(
            line.startswith(name) and " n/a" in line for line in lines
        ), (name, doctor)


def mutate(document, path, value):
    mutated = copy.deepcopy(document)
    cursor = mutated
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return mutated


SCANNED = {
    "schema": "p11scope/inspect/v1",
    "scan": {"status": "scanned", "reason": None},
    "modules": [
        {
            "path": "/usr/lib/softhsm/libsofthsm2.so",
            "tables": [{"version": "2.40", "walk": "full", "entries": 68}],
        }
    ],
}
SCANNED_TABLELESS = {
    "schema": "p11scope/inspect/v1",
    "scan": {"status": "scanned", "reason": None},
    "modules": [
        {
            "path": "/usr/lib64/pkcs11/libsofthsm2.so",
            "tables": [],
        }
    ],
    "skipped": [
        {
            "subject": "/usr/lib64/pkcs11/libsofthsm2.so",
            "reason": "no function table was found in its file-backed data; a table built at run time in .bss or on the heap is outside the memory scan's reach",
        }
    ],
}
REFUSED = {
    "schema": "p11scope/inspect/v1",
    "scan": {"status": "refused", "reason": "ptrace_scope"},
    "modules": [{"path": "/usr/lib/softhsm/libsofthsm2.so", "tables": []}],
}
SCANNED_DOCTOR = "verdict: memory scan available\n"
REFUSED_DOCTOR = "verdict: maps only\n"
HOST_DOCTOR = (
    "/proc/<pid>/maps .................. n/a    no --pid\n"
    "cgroup path ....................... n/a    no --cgroup\n"
    "verdict: capture available\n"
)

if sys.argv[1] == "--self-test":
    oracle(SCANNED, SCANNED_DOCTOR)
    oracle(SCANNED_TABLELESS, SCANNED_DOCTOR)
    oracle(REFUSED, REFUSED_DOCTOR)
    host_oracle(HOST_DOCTOR)
    mutations = [
        ("inspect schema", SCANNED, mutate(SCANNED, ["schema"], "other/v1"), SCANNED_DOCTOR),
        (
            "provider listed",
            SCANNED,
            mutate(SCANNED, ["modules", 0, "path"], "/usr/lib/other.so"),
            SCANNED_DOCTOR,
        ),
        ("scan/doctor agreement", SCANNED, SCANNED, REFUSED_DOCTOR),
        ("refused/doctor agreement", REFUSED, REFUSED, SCANNED_DOCTOR),
        (
            "decoded tables",
            SCANNED,
            mutate(SCANNED, ["modules", 0, "tables"], []),
            SCANNED_DOCTOR,
        ),
        (
            "decoded entries",
            SCANNED,
            mutate(SCANNED, ["modules", 0, "tables"], [{"version": "2.40", "walk": "full", "entries": 0}]),
            SCANNED_DOCTOR,
        ),
        (
            "tableless reason",
            SCANNED_TABLELESS,
            mutate(SCANNED_TABLELESS, ["skipped", 0, "reason"], "other"),
            SCANNED_DOCTOR,
        ),
        (
            "tableless subject",
            SCANNED_TABLELESS,
            mutate(SCANNED_TABLELESS, ["skipped", 0, "subject"], "/usr/lib64/other.so"),
            SCANNED_DOCTOR,
        ),
        (
            "tableless missing",
            SCANNED_TABLELESS,
            mutate(SCANNED_TABLELESS, ["skipped"], []),
            SCANNED_DOCTOR,
        ),
        (
            "tableless duplicated",
            SCANNED_TABLELESS,
            mutate(SCANNED_TABLELESS, ["skipped"], SCANNED_TABLELESS["skipped"] * 2),
            SCANNED_DOCTOR,
        ),
        ("refusal reason", REFUSED, mutate(REFUSED, ["scan", "reason"], ""), REFUSED_DOCTOR),
    ]
    for label, _, document, doctor in mutations:
        try:
            oracle(document, doctor)
        except (AssertionError, KeyError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: {label}")
    maps_line, cgroup_line, verdict_line = HOST_DOCTOR.splitlines(keepends=True)
    for label, doctor in [
        ("host verdict", maps_line + cgroup_line),
        ("maps n/a", cgroup_line + verdict_line),
        ("cgroup n/a", maps_line + verdict_line),
        (
            "maps failed not n/a",
            maps_line.replace(" n/a ", " FAIL ") + cgroup_line + verdict_line,
        ),
    ]:
        try:
            host_oracle(doctor)
        except (AssertionError, IndexError):
            continue
        raise SystemExit(f"mutation accepted: {label}")
    print("inspect/doctor oracle mutations rejected: OK")
    raise SystemExit(0)

if sys.argv[1] == "--host":
    host_oracle(open(sys.argv[2]).read())
    print("doctor host lane: OK")
    raise SystemExit(0)

print(*oracle(json.load(open(sys.argv[1])), open(sys.argv[2]).read()))
