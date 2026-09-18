#!/usr/bin/env python3
"""Task 4 lane 02 validate_root oracle: refuse when the evidence-root identity changed. Oracle extracted from scripts/verify-receipt-lane02.sh (lines 60-65)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 validate_root oracle: refuse when the evidence-root identity changed").print_help()
    raise SystemExit(0)

import os, stat, sys
s = os.lstat(sys.argv[1])
if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid()
        or stat.S_IMODE(s.st_mode) != 0o700
        or f"{s.st_dev}:{s.st_ino}" != sys.argv[2]):
    raise SystemExit("evidence root identity changed")
