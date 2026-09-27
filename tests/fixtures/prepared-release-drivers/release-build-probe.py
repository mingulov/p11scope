#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
from pathlib import Path
import sys

record = {
    "cargo": str(Path(sys.argv[0]).resolve()),
    "argv": sys.argv[1:],
    "cargo_target_dir": os.environ.get("CARGO_TARGET_DIR"),
    "rustflags": os.environ.get("RUSTFLAGS"),
    "cargo_encoded_rustflags": os.environ.get("CARGO_ENCODED_RUSTFLAGS", "").split("\x1f"),
    "rustc": os.environ.get("RUSTC"),
    "bpf_cargo": os.environ.get("P11SCOPE_PREPARED_BPF_CARGO"),
    "bpf_rustc": os.environ.get("P11SCOPE_PREPARED_BPF_RUSTC"),
}
Path(os.environ["P11SCOPE_RELEASE_BUILD_RECORD"]).write_text(
    json.dumps(record, sort_keys=True), encoding="utf-8")
