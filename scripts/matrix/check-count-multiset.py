#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-slot call counts of a clean SoftHSM2 capture, as a multiset.

A scan-only table whose slots are named `unknown` can only be counted exactly
in total by the shared checker. Each attach slot is still one PKCS#11 function,
so the multiset of nonzero per-slot counts must equal the multiset of the
oracle's per-function counts (plus the bootstrap C_GetFunctionList once),
each times the lane's multiplier. This holds unchanged once slots carry real
names, where the shared checker compares them per name.

usage: check-count-multiset.py OUTPUT EXPECTED [MULTIPLIER]
"""

import json
import sys


def main(argv):
    if len(argv) not in (2, 3):
        raise SystemExit(__doc__.strip().splitlines()[-1])
    multiplier = int(argv[2]) if len(argv) == 3 else 1
    if multiplier < 1:
        raise SystemExit(f"invalid multiplier: {multiplier}")
    with open(argv[0], encoding="utf-8") as handle:
        document = json.load(handle)
    expected = {}
    with open(argv[1], encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                name, calls = line.split()
                expected[name] = int(calls)
    if "C_GetFunctionList" in expected:
        raise SystemExit("expected-count file must omit bootstrap")
    expected["C_GetFunctionList"] = 1
    wanted = sorted((calls * multiplier for calls in expected.values()), reverse=True)
    actual = sorted(
        (item["calls"] for item in document["functions"] if item["calls"]),
        reverse=True,
    )
    print(f"per-slot counts: want {wanted}")
    print(f"per-slot counts: got  {actual}")
    if actual != wanted:
        raise SystemExit("per-slot call-count multiset differs from the oracle")
    print(f"per-slot call-count multiset matches the oracle x{multiplier}")


if __name__ == "__main__":
    main(sys.argv[1:])
