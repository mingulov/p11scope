#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exec a child with default SIGINT/SIGQUIT dispositions.

A POSIX shell without job control starts every `&` background job with
SIGINT and SIGQUIT ignored, and a non-interactive shell cannot trap an
ignored signal back. The key-operations cells stop their observer with
exactly one SIGINT, so the observer subtree must not inherit that
ignore: this helper restores both dispositions with sigaction (which,
unlike the shell builtin, overrides an inherited ignore) and execs its
arguments. SIGTERM and SIGHUP pass through untouched: cleanup still
TERMs, and the observer's deliberate inherited-HUP preservation keeps
working.

Usage: run_default_signals.py COMMAND [ARGS...]
"""
import os
import signal
import sys


def main(argv):
    if len(argv) < 2:
        print("usage: run_default_signals.py COMMAND [ARGS...]",
              file=sys.stderr)
        return 2
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGQUIT, signal.SIG_DFL)
    os.execvp(argv[1], argv[1:])
    return 1  # Unreached; exec failure raises.


if __name__ == "__main__":
    sys.exit(main(sys.argv))
