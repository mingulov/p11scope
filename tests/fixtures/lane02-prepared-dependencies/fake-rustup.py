#!/usr/bin/env python3
"""Controlled rustup selector for Lane02 integration tests."""

import json
import os
from pathlib import Path
import sys


if sys.argv[1:] == ["--version"]:
    # The tool pinning layer identifies its executables by behaviour (it runs
    # `rustup --version` and requires a `rustup ` banner), so a stub standing
    # in for rustup must answer as rustup. Answer before any selection event
    # is written: the probe is a capability check, not a tool selection.
    print("rustup 1.99.0 (p11scope test fixture)")
    raise SystemExit(0)
config = json.loads(Path(os.environ["P11SCOPE_LANE02_FIXTURE"]).read_text())
if len(sys.argv) != 5 or sys.argv[1:3] != ["which", "--toolchain"]:
    raise SystemExit(97)
toolchain, program = sys.argv[3:]
key = ("stable" if toolchain == "1.88" else "bpf") + "_" + program
with Path(config["events"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"kind": "select", "key": key}, sort_keys=True) + "\n")
print(config[key])
