"""Inject an OS primitive failure while executing the actual helper source."""

import os
from pathlib import Path
import runpy
import sys


mode, target, *args = sys.argv[1:]
sys.argv = [target, *args]
if mode == "pidfd":
    def denied(*args, **kwargs):
        raise PermissionError("injected pidfd_open denial")
    os.pidfd_open = denied
else:
    original = Path.read_bytes

    def denied(self):
        if str(self).startswith("/proc/"):
            raise PermissionError("injected proc stat denial")
        return original(self)

    Path.read_bytes = denied
if target == "/dev/stdin":
    exec(compile(sys.stdin.read(), target, "exec"), {"__name__": "__main__"})
else:
    runpy.run_path(target, run_name="__main__")
