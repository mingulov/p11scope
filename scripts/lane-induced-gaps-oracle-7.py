#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Gate G2 induced-gaps gap-3b oracle: disclose ring_bytes 4096 and drain_interval_ms 1000. Oracle extracted from scripts/verify-induced-gaps.sh (lines 1166-1171)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Gate G2 induced-gaps gap-3b oracle: disclose ring_bytes 4096 and drain_interval_ms 1000").print_help()
    raise SystemExit(0)

import json
import sys
capture = json.load(open(sys.argv[1]))["capture"]
assert capture["ring_bytes"] == 4096, capture
assert capture["drain_interval_ms"] == 1000, capture
print("gap 3b disclosed ring_bytes=4096 drain_interval_ms=1000: OK")
