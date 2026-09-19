#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run real Python and optionally make the final prepared ledger duplicate tracked input."""

import json
import os
from pathlib import Path
import subprocess
import sys


result = subprocess.run([sys.executable, *sys.argv[1:]])
if result.returncode == 0 and os.environ.get("P11SCOPE_CORRUPT_FINAL_LEDGER") == "1":
    arguments = sys.argv[1:]
    if "recheck" in arguments and "prepared-dependency-evidence.py" in " ".join(arguments):
        config = json.loads(Path(os.environ["P11SCOPE_FOUR_CALLERS_FIXTURE"]).read_text())
        ledger = Path(config["prefix"] + ".final.ledger.sha256")
        tracked = Path(os.environ["P11SCOPE_DUPLICATE_TRACKED"])
        import hashlib
        with ledger.open("a", encoding="utf-8") as stream:
            stream.write(f"{hashlib.sha256(tracked.read_bytes()).hexdigest()}  {tracked.name}\n")
raise SystemExit(result.returncode)
