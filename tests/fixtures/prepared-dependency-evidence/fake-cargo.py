#!/usr/bin/env python3
"""Data-driven Cargo metadata stand-in for native evidence-helper tests."""

import json
import os
from pathlib import Path
import sys


config = json.loads(Path(os.environ["P11SCOPE_FAKE_CARGO_CONFIG"]).read_text(encoding="utf-8"))
manifest = sys.argv[sys.argv.index("--manifest-path") + 1]
context = "root" if manifest == "Cargo.toml" else "bpf"
record = {
    "argv": sys.argv[1:],
    "cargo": str(Path(sys.argv[0]).resolve()),
    "cwd": os.getcwd(),
    "rustc": os.environ.get("RUSTC"),
    "context": context,
}
with Path(config["log"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(record, sort_keys=True) + "\n")
marker = config.get(f"{context}_marker")
if marker:
    Path(marker).touch()
for mutation in config.get(f"{context}_mutations", []):
    path = Path(mutation["path"])
    if mutation["action"] == "append":
        with path.open("ab") as stream:
            stream.write(mutation["content"].encode("utf-8"))
    elif mutation["action"] == "create":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(mutation["content"], encoding="utf-8")
    else:
        raise ValueError(f"unsupported fixture mutation {mutation['action']}")
status = config.get(f"{context}_status", 0)
if status:
    sys.stdout.write(config.get(f"{context}_stdout", "failed stdout\n"))
    sys.stderr.write(config.get(f"{context}_stderr", "failed stderr\n"))
    raise SystemExit(status)
selection_file = config.get("selection_file")
if selection_file:
    selection = json.loads(Path(selection_file).read_text(encoding="utf-8"))
    metadata_path = selection[context]
else:
    metadata_path = config[f"{context}_metadata"]
sys.stdout.buffer.write(Path(metadata_path).read_bytes())
