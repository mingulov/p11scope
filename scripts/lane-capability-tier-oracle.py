#!/usr/bin/env python3
"""Capability-tier lane oracle check_row: validate one finite doctor capability tier row against its expected exit and label. Oracle extracted from scripts/verify-capability-tier.sh (lines 9-44)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Capability-tier lane oracle check_row: validate one finite doctor capability tier row against its expected exit and label").print_help()
    raise SystemExit(0)

import os
import re
import sys

if len(sys.argv) != 6:
    raise SystemExit("usage: checker TIER ASSESSMENT EXPECTED_STATUS ACTUAL_STATUS OUTPUT")
expected_tier, assessment, raw_expected_status, raw_status, path = sys.argv[1:]
try:
    expected_status = int(raw_expected_status)
    status = int(raw_status)
except ValueError:
    raise SystemExit(f"{assessment}: invalid exit status")
if expected_status not in (0, 1) or status != expected_status:
    raise SystemExit(f"{assessment}: expected doctor exit {expected_status}, got {status}")
if not os.path.isfile(path):
    raise SystemExit(f"{assessment}: produced no output")
with open(path, encoding="utf-8") as source:
    lines = source.read().splitlines()
tiers = [line for line in lines if line.startswith("capability tier:")]
if len(tiers) != 1:
    raise SystemExit(f"{assessment}: expected one capability tier line, got {tiers!r}")
match = re.fullmatch(
    r"capability tier: (T[0-4]) (offline|host attach|target readable|lifecycle|current full) "
    r"\(target (assessed|unassessed)\)",
    tiers[0],
)
if not match:
    raise SystemExit(f"{assessment}: malformed finite tier line {tiers[0]!r}")
labels = {"T0": "offline", "T1": "host attach", "T2": "target readable", "T3": "lifecycle", "T4": "current full"}
if labels[match.group(1)] != match.group(2):
    raise SystemExit(f"{assessment}: tier number and label disagree")
if match.group(1) != expected_tier:
    raise SystemExit(f"{assessment}: expected {expected_tier}, got {match.group(1)}")
if match.group(3) != assessment:
    raise SystemExit(f"{assessment}: target state is {match.group(3)!r}")
print(f"{assessment}: {match.group(1)} {match.group(2)}")
