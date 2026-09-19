#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Release Task 4 receipt finalizer oracle: enforce the exact evidence-root tree shape with 0700 dirs and 0600 files. Oracle extracted from scripts/build-release.sh (lines 811-820)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Release Task 4 receipt finalizer oracle: enforce the exact evidence-root tree shape with 0700 dirs and 0600 files").print_help()
    raise SystemExit(0)

import os, stat, sys
root=sys.argv[1]
if set(os.listdir(root)) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: raise SystemExit("foreign root entry")
for directory, dirs, files in os.walk(root,followlinks=False):
    if stat.S_IMODE(os.lstat(directory).st_mode)!=0o700: raise SystemExit("directory mode")
    for name in dirs+files:
        if stat.S_ISLNK(os.lstat(os.path.join(directory,name)).st_mode): raise SystemExit("symlink")
    for name in files:
        mode=os.lstat(os.path.join(directory,name)).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode)!=0o600: raise SystemExit("file mode")
