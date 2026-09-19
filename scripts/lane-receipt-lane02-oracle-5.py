#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 4 lane 02 workload-mapping oracle: classify the harness provider mapping state as invalid, ready, or pending. Oracle extracted from scripts/verify-receipt-lane02.sh (lines 162-181)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 workload-mapping oracle: classify the harness provider mapping state as invalid, ready, or pending").print_help()
    raise SystemExit(0)

import sys
path, expected, rejected = sys.argv[1:]
marker = b"HARNESS_PROVIDER_MAPPED"
expected = expected.encode()
rejected = rejected.encode()
with open(sys.argv[1], "rb") as stream:
    snapshot = stream.read()
marker_count = snapshot.count(marker)
expected_count = snapshot.count(expected)
rejected_count = snapshot.count(rejected)
if marker_count > 1 or expected_count > 1 or rejected_count:
    print("invalid 0")
elif marker_count == 1 and expected_count == 1:
    offset = snapshot.index(marker) + len(marker)
    lines = snapshot[offset:].splitlines(keepends=True)
    frames = sum(line.endswith(b"\n") and b"p11scope" in line
                 and b"privacy=aggregate-only" in line for line in lines)
    print(("ready" if frames >= 2 else "pending"), frames)
else:
    print("pending 0")
