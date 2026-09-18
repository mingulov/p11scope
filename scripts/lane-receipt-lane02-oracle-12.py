#!/usr/bin/env python3
"""Task 4 lane 02 no_atomic_temps oracle: refuse a row that retained an atomic temporary file. Oracle extracted from scripts/verify-receipt-lane02.sh (lines 634-641)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 no_atomic_temps oracle: refuse a row that retained an atomic temporary file").print_help()
    raise SystemExit(0)

import os, sys
directory, identity = sys.argv[1:]
fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
s = os.fstat(fd)
if f"{s.st_dev}:{s.st_ino}" != identity:
    raise SystemExit("row directory identity changed")
if any(name.startswith('.p11scope.') and name.endswith('.tmp') for name in os.listdir(fd)):
    raise SystemExit("row retained an atomic temporary file")
