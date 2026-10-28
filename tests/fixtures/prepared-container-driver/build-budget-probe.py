#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Harmless child commands for executing the actual container build prefix."""

import json
import os
from pathlib import Path
import sys


name = Path(sys.argv[0]).name
if name == "cargo":
    config = json.loads(Path(os.environ["P11SCOPE_CONTAINER_FIXTURE"]).read_text())
    with Path(config["events"]).open("a") as stream:
        stream.write(json.dumps({
            "kind": "container_cargo", "argv": sys.argv[1:],
            "build_jobs": os.environ.get("CARGO_BUILD_JOBS"),
            "container": os.environ["P11SCOPE_PROBE_CONTAINER"],
        }) + "\n")
    target = sys.argv[sys.argv.index("--target-dir") + 1]
    fails = config.get("container_cargo_fail_target") in (None, Path(target).name)
    raise SystemExit(config.get("container_cargo_status", 0) if fails else 0)
if name == "stat":
    print(f"{os.getuid()}:{os.getgid()}")
elif name == "sort":
    sys.stdout.write(sys.stdin.read())
elif name not in ("mkdir", "cp", "apk", "cat", "chown"):
    raise SystemExit("unsupported container build probe: " + name)
