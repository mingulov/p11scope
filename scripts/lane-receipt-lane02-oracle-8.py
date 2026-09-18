#!/usr/bin/env python3
"""Task 4 lane 02 wait_root_exit oracle: poll the pinned root observer pidfd for exit with identity check. Oracle extracted from scripts/verify-receipt-lane02.sh (lines 555-566)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 wait_root_exit oracle: poll the pinned root observer pidfd for exit with identity check").print_help()
    raise SystemExit(0)

import os, select, sys
pid, expected, timeout = map(int, sys.argv[1:])
try:
    fd = os.pidfd_open(pid)
    raw = open(f"/proc/{pid}/stat", "rb").read().rsplit(b") ", 1)[1].split()
except (FileNotFoundError, ProcessLookupError):
    raise SystemExit(0)
if len(raw) < 20 or int(raw[19]) != expected:
    raise SystemExit("root observer identity changed")
poller = select.poll(); poller.register(fd, select.POLLIN)
if not poller.poll(timeout * 1000):
    raise SystemExit(1)
