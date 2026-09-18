#!/usr/bin/env python3
"""Task 4 lane 02 owned-harness termination oracle: SIGTERM then SIGKILL owned harnesses via pidfds and refuse survivors. Oracle extracted from scripts/verify-receipt-lane02.sh (lines 518-549)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 owned-harness termination oracle: SIGTERM then SIGKILL owned harnesses via pidfds and refuse survivors").print_help()
    raise SystemExit(0)

import os, select, signal, sys
wanted = {os.fsencode(path) for path in sys.argv[1:]}

def owned():
    result = []
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        try:
            fd = os.pidfd_open(int(name))
            argv = open(f'/proc/{name}/cmdline', 'rb').read().split(b'\0')
            exe = os.path.realpath(f'/proc/{name}/exe')
        except OSError:
            continue
        if argv and argv[0] in wanted and os.fsencode(exe) == argv[0]:
            result.append((int(name), fd))
    return result

targets = owned()
for pid, fd in targets:
    poller = select.poll(); poller.register(fd, select.POLLIN)
    try:
        signal.pidfd_send_signal(fd, signal.SIGTERM, None, 0)
    except ProcessLookupError:
        continue
    if not poller.poll(5000):
        signal.pidfd_send_signal(fd, signal.SIGKILL, None, 0)
        if not poller.poll(5000):
            raise SystemExit(f"owned harness {pid} did not exit")
if owned():
    raise SystemExit("owned harness remains after termination")
print(len(targets))
