#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

record = {
    "cargo": str(Path(sys.argv[0]).resolve()),
    "argv": sys.argv[1:],
    "cargo_target_dir": os.environ.get("CARGO_TARGET_DIR"),
    "rustflags": os.environ.get("RUSTFLAGS"),
    "rustc": os.environ.get("RUSTC"),
    "bpf_cargo": os.environ.get("P11SCOPE_PREPARED_BPF_CARGO"),
    "bpf_rustc": os.environ.get("P11SCOPE_PREPARED_BPF_RUSTC"),
}
Path(os.environ["P11SCOPE_RELEASE_BUILD_RECORD"]).write_text(
    json.dumps(record, sort_keys=True), encoding="utf-8")
