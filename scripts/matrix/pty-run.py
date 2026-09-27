#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run one command with a pseudo-terminal as its stdin/stdout/stderr.

`p11scope profile` draws its live frame only when stdout is a terminal
(cb59e2e). The matrix lanes use the first frame, which is drawn only after
every probe is attached, as their attach-before-run barrier, so the observer
runs under a pty whose output is copied to this process's stdout. Output
post-processing is off on the pty, so the log keeps plain `\\n` line ends.

SIGINT, SIGTERM and SIGHUP received here are forwarded exactly once each to
the child. The exit status is the child's (128 + signal when it was killed).

usage: pty-run.py COMMAND [ARG...]
"""

import os
import pty
import signal
import sys
import termios


def main(argv):
    if not argv:
        raise SystemExit(__doc__.strip().splitlines()[-1])
    pid, master = pty.fork()
    if pid == 0:
        try:
            attributes = termios.tcgetattr(1)
            attributes[1] &= ~termios.OPOST
            termios.tcsetattr(1, termios.TCSANOW, attributes)
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)

    def forward(signum, _frame):
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, forward)

    out = sys.stdout.buffer
    while True:
        try:
            chunk = os.read(master, 65536)
        except InterruptedError:
            continue
        except OSError:
            break
        if not chunk:
            break
        out.write(chunk)
        out.flush()
    os.close(master)
    while True:
        try:
            _, status = os.waitpid(pid, 0)
            break
        except InterruptedError:
            continue
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return os.WEXITSTATUS(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
