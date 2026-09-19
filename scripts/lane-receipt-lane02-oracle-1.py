#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 4 lane 02 evidence-root oracle: require the parent to be caller-owned and private. Oracle extracted from scripts/verify-receipt-lane02.sh (lines 39-42)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 evidence-root oracle: require the parent to be caller-owned and private").print_help()
    raise SystemExit(0)

import os, stat, sys
s = os.stat(sys.argv[1])
if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) & 0o077:
    raise SystemExit("evidence parent must be caller-owned and private")
