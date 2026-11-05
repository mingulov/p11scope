#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe host Cargo's real caller environment without compiling anything."""

import json
import os
from pathlib import Path
import sys


with Path(sys.argv[1]).open("a") as stream:
    stream.write(json.dumps({
        "argv": sys.argv[2:], "build_jobs": os.environ.get("CARGO_BUILD_JOBS"),
        "makeflags": os.environ.get("MAKEFLAGS"),
        "cargo_makeflags": os.environ.get("CARGO_MAKEFLAGS"),
        "num_jobs": os.environ.get("NUM_JOBS"),
    }) + "\n")
# Stop at the official Cargo child before a binary or live test is needed.
raise SystemExit(77 if "--target" in sys.argv[2:] else 0)
