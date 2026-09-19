#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 4 lane 02 count_byte_token oracle: count token occurrences in a file. Oracle extracted from scripts/verify-receipt-lane02.sh (lines 137-141)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 count_byte_token oracle: count token occurrences in a file").print_help()
    raise SystemExit(0)

import sys
if len(sys.argv) != 3 or not sys.argv[2]:
    raise SystemExit("count_byte_token: expected path and non-empty token")
with open(sys.argv[1], "rb") as stream:
    print(stream.read().count(sys.argv[2].encode()))
