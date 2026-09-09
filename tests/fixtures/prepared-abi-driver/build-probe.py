#!/usr/bin/env python3
"""Record extracted ABI Cargo builds and require all admitted tools."""

import json
import os
from pathlib import Path
import sys


record = Path(os.environ["P11SCOPE_ABI_BUILD_RECORD"])
tools = {
    "rustc": os.environ.get("RUSTC"),
    "bpf_cargo": os.environ.get("P11SCOPE_PREPARED_BPF_CARGO"),
    "bpf_rustc": os.environ.get("P11SCOPE_PREPARED_BPF_RUSTC"),
}
if not all(tools.values()):
    raise SystemExit(88)
row = {
    "argv": sys.argv[1:],
    "cargo": str(Path(sys.argv[0]).resolve()),
    "target": os.environ.get("CARGO_TARGET_DIR"),
    **tools,
}
with record.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
