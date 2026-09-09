#!/usr/bin/env python3
"""Fixed-query rustup fixture."""

import json
import os
from pathlib import Path
import sys


control_path = Path.cwd() / "test-control.json"
control = json.loads(control_path.read_text(encoding="utf-8")) if control_path.exists() else {}
record = Path.cwd() / "test-record"
if record.is_dir():
    with (record / "rustup.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps({"argv": sys.argv[1:],
                                 "auto_install": os.environ.get("RUSTUP_AUTO_INSTALL")},
                                sort_keys=True) + "\n")
mapping = {
    ("1.88", "cargo"): "stable-cargo",
    ("1.88", "rustc"): "stable-rustc",
    ("nightly-2026-05-20", "cargo"): "bpf-cargo",
    ("nightly-2026-05-20", "rustc"): "bpf-rustc",
}
map_path = Path(__file__).resolve().parent / "tool-map.json"
if map_path.exists():
    external = json.loads(map_path.read_text(encoding="utf-8"))
    mapping = {tuple(key.split(":")): value for key, value in external.items()}
if len(sys.argv) != 5 or sys.argv[1:3] != ["which", "--toolchain"]:
    raise SystemExit(70)
key = (sys.argv[3], sys.argv[4])
if control.get("rustup_fail") == ":".join(key):
    raise SystemExit(71)
selected = Path(mapping[key])
print(selected if selected.is_absolute() else Path(__file__).resolve().parent / selected)
