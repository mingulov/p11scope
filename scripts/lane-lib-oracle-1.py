#!/usr/bin/env python3
"""Shared lib signal oracle signal_pinned_process: verify pidfd and starttime identity, then deliver the named signal. Oracle extracted from scripts/lib.sh (lines 416-439)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Shared lib signal oracle signal_pinned_process: verify pidfd and starttime identity, then deliver the named signal").print_help()
    raise SystemExit(0)

import os
import signal
import sys

signals = {
    "CONT": signal.SIGCONT,
    "INT": signal.SIGINT,
    "KILL": signal.SIGKILL,
    "STOP": signal.SIGSTOP,
    "TERM": signal.SIGTERM,
}
if len(sys.argv) not in (4, 5) or sys.argv[1] not in signals:
    raise SystemExit("usage: SIGNAL PID STARTTIME [SID]")

pid, expected = int(sys.argv[2]), int(sys.argv[3])
expected_sid = int(sys.argv[4]) if len(sys.argv) == 5 else None
fd = os.pidfd_open(pid)
raw = open(f"/proc/{pid}/stat", "rb").read()
tail = raw.rsplit(b") ", 1)[1].split()
if len(tail) < 20 or int(tail[19]) != expected:
    raise SystemExit(f"refusing changed process identity {pid}")
if expected_sid is not None and int(tail[3]) != expected_sid:
    raise SystemExit(f"refusing changed process session {pid}")
signal.pidfd_send_signal(fd, signals[sys.argv[1]], None, 0)
