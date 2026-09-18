#!/usr/bin/env python3
"""Task 4 lane 02 row_identity oracle: require a caller-owned mode-0700 row directory and print its device and inode. Oracle extracted from scripts/verify-task4-lane02.sh (lines 589-593)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 row_identity oracle: require a caller-owned mode-0700 row directory and print its device and inode").print_help()
    raise SystemExit(0)

import os, stat, sys
s = os.lstat(sys.argv[1])
if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
    raise SystemExit("row directory is not caller-owned mode 0700")
print(f"{s.st_dev}:{s.st_ino}")
