#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""sudo tripwire for the canary observer-verbosity probe.

Records every privileged invocation and succeeds without privilege. For
a stopped-canary launch it also plants the START mapdump the harness
links after safe-start lanes, since no real acquisition runs.
"""
import json
import os
from pathlib import Path
import sys

config = json.loads(Path(os.environ["P11SCOPE_CANARY_ARGV_CONFIG"]).read_text())
row = {"kind": "sudo", "argv": sys.argv[1:], "cwd": os.getcwd()}
with Path(config["events"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")

arguments = sys.argv[1:]
if "scripts/capture-stopped-canary.py" in arguments:
    lane, out_dir = None, None
    for index, token in enumerate(arguments):
        if token == "--lane" and index + 1 < len(arguments):
            lane = arguments[index + 1]
        elif token == "--out-dir" and index + 1 < len(arguments):
            out_dir = arguments[index + 1]
    if lane is None or out_dir is None:
        raise SystemExit("sudo stub: canary launch without --lane/--out-dir")
    (Path(out_dir) / f"mapdump_START_{lane}.json").write_text("{}\n", encoding="utf-8")
