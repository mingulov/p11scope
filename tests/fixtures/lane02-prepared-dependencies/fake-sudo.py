#!/usr/bin/env python3
"""Controlled sudo sentinel for Lane02 integration tests."""

import json
import os
from pathlib import Path
import sys


config = json.loads(Path(os.environ["P11SCOPE_LANE02_FIXTURE"]).read_text())
arguments = sys.argv[1:]
if arguments[:1] == ["-n"]:
    arguments = arguments[1:]
with Path(config["events"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"kind": "sudo", "argv": arguments}, sort_keys=True) + "\n")
if arguments == ["true"]:
    raise SystemExit(0)
raise SystemExit(96)
