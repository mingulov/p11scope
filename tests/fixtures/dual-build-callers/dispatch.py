#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
from pathlib import Path
import sys

config = json.loads(Path(os.environ["P11SCOPE_DUAL_BUILD_CONFIG"]).read_text())
kind = "cargo" if Path(sys.argv[0]).name in ("cargo", "stable cargo") else Path(sys.argv[0]).name
events = Path(config["events"])
previous = [] if not events.exists() else [json.loads(row) for row in events.read_text().splitlines()]
row = {"kind": kind, "argv": sys.argv[1:], "cwd": os.getcwd(),
       "executable": str(Path(sys.argv[0]).resolve()),
       "rustc": os.environ.get("RUSTC"),
       "bpf_cargo": os.environ.get("P11SCOPE_PREPARED_BPF_CARGO"),
       "bpf_rustc": os.environ.get("P11SCOPE_PREPARED_BPF_RUSTC")}
with events.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
if kind == "cargo":
    index = sum(item["kind"] == "cargo" for item in previous)
    raise SystemExit(config["cargo_statuses"][index])
raise SystemExit(97)
