#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared lib user process-group identity oracle: validate the recorded pid, starttime, pgid, sid, and argv identity. Oracle extracted from scripts/lib.sh (lines 535-553)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Shared lib user process-group identity oracle: validate the recorded pid, starttime, pgid, sid, and argv identity").print_help()
    raise SystemExit(0)

import json
import sys


record = json.load(open(sys.argv[1], encoding="utf-8"))
launcher = int(sys.argv[2])
initial_starttime = int(sys.argv[3])
expected_argv = sys.argv[4:]
if set(record) != {"pid", "starttime", "pgid", "sid", "argv"}:
    raise SystemExit("malformed user process-group identity")
if not all(isinstance(record[name], int) and record[name] > 0 for name in ("pid", "starttime", "pgid", "sid")):
    raise SystemExit("malformed user process-group identity")
if not isinstance(record["argv"], list) or not all(isinstance(item, str) for item in record["argv"]):
    raise SystemExit("malformed user process-group argv")
if record["pid"] != launcher or record["starttime"] != initial_starttime:
    raise SystemExit("user process-group identity does not match launch")
if record["pid"] != record["pgid"] or record["pid"] != record["sid"] or record["argv"] != expected_argv:
    raise SystemExit("user process-group identity does not match launch")
print(record["pid"], record["starttime"], record["pgid"], record["sid"])
