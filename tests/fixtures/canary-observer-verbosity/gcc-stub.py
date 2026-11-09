#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""gcc tripwire for the canary observer-verbosity probe.

Records the invocation and succeeds; the workload and provider outputs
are pre-planted by the test, so no compilation happens here.
"""
import json
import os
from pathlib import Path
import sys

config = json.loads(Path(os.environ["P11SCOPE_CANARY_ARGV_CONFIG"]).read_text())
row = {"kind": "gcc", "argv": sys.argv[1:], "cwd": os.getcwd()}
with Path(config["events"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
