#!/usr/bin/env python3
"""Require pkcs11-check's independent CK_RV trace to be a capture subset."""

import json
from pathlib import Path
import runpy
import sys


KNOWN_ORACLE_MISATTRIBUTION_NODEIDS = {
    "src/pkcs11_check/testcases/test_interface.py::TestInterfaceV32::test_v32_interface_negotiated",
}


def evidence_oracle():
    """Load the canonical evidence oracle relative to this script."""
    return runpy.run_path(str(Path(__file__).with_name("check-capture-evidence.py")))


def check_subset_oracle(report_path, observed_path):
    # Only teardown records count. Failed traces also appear on call reports,
    # so reading both phases would double-count. The fixed exclusion is an
    # upstream attribution error: that node cannot issue the copied calls.
    oracle = {}
    oracle_tests = 0
    excluded = 0
    with open(report_path) as report:
        for line in report:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("when") != "teardown":
                continue
            trace = dict(record.get("user_properties") or []).get("pkcs11_rv_trace")
            if trace is None:
                continue
            if record.get("nodeid") in KNOWN_ORACLE_MISATTRIBUTION_NODEIDS:
                excluded += 1
                continue
            oracle_tests += 1
            for entry in trace:
                key = (entry["fn"], f"0x{entry['rv'] & 0xffffffffffffffff:016x}")
                oracle[key] = oracle.get(key, 0) + 1

    oracle_calls = sum(oracle.values())
    print(
        f"oracle: {oracle_tests} tests carried a CK_RV trace, "
        f"{len(oracle)} distinct (function, CK_RV) pairs, "
        f"{oracle_calls} total calls logged"
    )
    if excluded:
        print(
            "oracle: excluded "
            f"{excluded} teardown record(s) matching a known oracle-side "
            "misattribution nodeid (docs/notes/phase4-oracle.md)"
        )

    with open(observed_path) as capture_file:
        observed = json.load(capture_file)
    capture = {}
    capture_by_name = {}
    for function in observed["functions"]:
        for name in function["names"]:
            capture_by_name[name] = capture_by_name.get(name, 0) + function["calls"]
            for rv_hex, count in function["rv_counts"].items():
                key = (name, rv_hex)
                capture[key] = capture.get(key, 0) + count

    fail = 0
    if oracle_calls == 0:
        print("FAIL oracle: no independent PKCS#11 calls were logged")
        fail = 1
    for key, want in sorted(oracle.items()):
        got = capture.get(key, 0)
        if got < want:
            function, rv = key
            print(
                f"FAIL oracle-only: {function} {rv}: "
                f"oracle logged {want}, capture has {got}"
            )
            fail = 1

    if not fail:
        print(
            "oracle subset-of capture: every (function, CK_RV) pair "
            "pkcs11-check logged is present in the capture at least as many times"
        )

    # Capture-only surplus is expected: fixture bootstrap and plugin
    # housekeeping happen outside pkcs11-check's per-test trace window.
    oracle_names = {function for function, _rv in oracle}
    surplus_names = sorted(name for name in capture_by_name if name not in oracle_names)
    print(
        f"informational: {len(surplus_names)} function names appear in the "
        "capture with zero oracle-logged calls (expected: bootstrap-only functions)"
    )
    for name in surplus_names[:20]:
        print(f"  capture-only: {name} calls={capture_by_name[name]}")
    if len(surplus_names) > 20:
        print(f"  ... and {len(surplus_names) - 20} more")

    evidence = observed["evidence"]
    print("evidence:", evidence["attached_probes"], "probes,", evidence["completeness"])
    if evidence["attached_probes"] == 0:
        print("no probes attached")
        fail = 1
    try:
        evidence_oracle()["terminal_capture_is_clean"](evidence, uncorroborated=1)
    except AssertionError as error:
        print(f"terminal evidence: {error}")
        fail = 1
    return fail


def main(argv):
    if len(argv) != 2:
        raise AssertionError("usage: check-subset-oracle.py REPORT OBSERVED")
    return check_subset_oracle(*argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
