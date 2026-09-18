#!/usr/bin/env python3
"""Task 4 lane 16 receipt finalizer oracle: enforce the exact receipt tree shape with 0700 dirs and 0600 files. Oracle extracted from scripts/verify-receipt-lane16.sh (lines 283-297)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 16 receipt finalizer oracle: enforce the exact receipt tree shape with 0700 dirs and 0600 files").print_help()
    raise SystemExit(0)

import os, stat, sys
root = sys.argv[1]
if set(os.listdir(root)) != {"facts.log", "stdout.log", "stderr.log", "artifacts", "work"}:
    raise SystemExit("unexpected receipt tree")
for directory, dirs, files in os.walk(root, followlinks=False):
    mode = os.lstat(directory).st_mode
    if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o700:
        raise SystemExit("unsafe receipt directory")
    for name in dirs + files:
        path = os.path.join(directory, name); mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode): raise SystemExit("receipt symlink")
    for name in files:
        mode = os.lstat(os.path.join(directory, name)).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
            raise SystemExit("unsafe retained file")
