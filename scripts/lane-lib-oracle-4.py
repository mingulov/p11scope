#!/usr/bin/env python3
"""Shared lib user process-session pin oracle: refuse use when the session identity changed. Oracle extracted from scripts/lib.sh (lines 568-585)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Shared lib user process-session pin oracle: refuse use when the session identity changed").print_help()
    raise SystemExit(0)

import sys


def stat(pid):
    raw = open(f"/proc/{pid}/stat", "rb").read()
    _, separator, tail = raw.rpartition(b") ")
    if not separator:
        raise ValueError("malformed proc stat")
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError("short proc stat")
    return int(fields[19]), int(fields[2]), int(fields[3])


pid, starttime, pgid, sid = map(int, sys.argv[1:5])
actual_starttime, actual_pgid, actual_sid = stat(pid)
if actual_starttime != starttime or actual_pgid != pgid or actual_sid != sid or pid != pgid or pid != sid:
    raise SystemExit("user process-session identity changed before use")
