# SPDX-License-Identifier: GPL-3.0-or-later
"""Trusted native fixture: descendants never leave their inherited group."""

import json
import os
from pathlib import Path
import signal
import sys
import time


mode, ready = sys.argv[1:]
# Even a broken runner cannot leave these test processes alive indefinitely.
signal.signal(signal.SIGALRM, signal.SIG_DFL)
signal.alarm(8)
print("fixture stdout", flush=True)
print("fixture stderr", file=sys.stderr, flush=True)
if mode in ("orphan", "timeout", "cancel", "zombie"):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        signal.alarm(8)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        os.write(write_fd, b"R")
        os.close(write_fd)
        if mode == "zombie":
            os._exit(7)
        while True:
            signal.pause()
    os.close(write_fd)
    assert os.read(read_fd, 1) == b"R"
    os.close(read_fd)
    if mode == "zombie":
        os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
    if mode in ("timeout", "cancel"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path(ready).write_text(json.dumps({"leader": os.getpid(), "child": child,
                                      "pgid": os.getpgrp(), "sid": os.getsid(0)}))
    if mode in ("orphan", "zombie"):
        os._exit(0)
    while True:
        signal.pause()
Path(ready).write_text(json.dumps({"leader": os.getpid(), "pgid": os.getpgrp(), "sid": os.getsid(0)}))
if mode == "late_exit":
    while not Path(ready + ".release").exists():
        time.sleep(0.01)
    Path(ready + ".exiting").write_text("exiting zero after external release\n")
    os._exit(0)
if mode == "survivor":
    while True:
        signal.pause()
if mode == "nonzero":
    sys.exit(23)
if mode == "binary":
    os.write(1, b"\x00\xff")
sys.exit(0)
