#!/usr/bin/env python3
"""Task 4 lane 02 owned-harness absence oracle: refuse when an owned harness is still running. Oracle extracted from scripts/verify-task4-lane02.sh (lines 501-512)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 owned-harness absence oracle: refuse when an owned harness is still running").print_help()
    raise SystemExit(0)

import os, sys
wanted = {os.fsencode(path) for path in sys.argv[1:]}
for name in os.listdir('/proc'):
    if not name.isdigit():
        continue
    try:
        argv = open(f'/proc/{name}/cmdline', 'rb').read().split(b'\0')
        exe = os.path.realpath(f'/proc/{name}/exe')
    except OSError:
        continue
    if argv and argv[0] in wanted and os.fsencode(exe) == argv[0]:
        raise SystemExit(f"owned harness still running as pid {name}")
