#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared lib recorded-process launcher oracle: record the launcher identity to an exclusive 0600 pidfile, then exec the user command. Oracle extracted from scripts/lib.sh (lines 466-509)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Shared lib recorded-process launcher oracle: record the launcher identity to an exclusive 0600 pidfile, then exec the user command").print_help()
    raise SystemExit(0)

import json
import os
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


pidfile, command = sys.argv[1], sys.argv[2:]
if not command:
    raise SystemExit("missing command")
os.umask(0o077)
os.setsid()
pid = os.getpid()
starttime, pgid, sid = stat(pid)
if pid != pgid or pid != sid:
    raise SystemExit("new session leader does not lead its session and process group")
record = json.dumps(
    {"pid": pid, "starttime": starttime, "pgid": pgid, "sid": sid, "argv": command},
    separators=(",", ":"),
).encode() + b"\n"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(pidfile, flags, 0o600)
try:
    os.write(fd, record)
    os.fsync(fd)
finally:
    os.close(fd)
directory = os.open(os.path.dirname(os.path.abspath(pidfile)) or ".", os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
os.execvp(command[0], command)
