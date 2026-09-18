#!/usr/bin/env python3
"""Task 4 lane 02 remove_verified_pidfile oracle: unlink a pidfile after verifying directory identity. Oracle extracted from scripts/verify-task4-lane02.sh (lines 619-628)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 remove_verified_pidfile oracle: unlink a pidfile after verifying directory identity").print_help()
    raise SystemExit(0)

import os, sys
directory, identity, name = sys.argv[1:]
fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
s = os.fstat(fd)
if f"{s.st_dev}:{s.st_ino}" != identity:
    raise SystemExit("row directory identity changed")
try:
    os.unlink(name, dir_fd=fd)
except FileNotFoundError:
    pass
