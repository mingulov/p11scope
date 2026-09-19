#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record wrapper dispatch without invoking Cargo or a toolchain."""

import json
import os
from pathlib import Path
import sys


base = Path(__file__).resolve().parents[1]
config = json.loads((base / "cargo-config.json").read_text(encoding="utf-8"))
source = base / "source" / "third-party" / "src" / "demo-1.0.0-p1"
value = source / "value.txt"
record = {
    "argv": sys.argv[1:],
    "cwd": os.getcwd(),
    "prepared_value": value.read_text(encoding="utf-8") if value.is_file() else None,
    "prepared_receipt": (source / ".p11scope-prepared.json").is_file(),
    "environment": {key: os.environ.get(key) for key in config["environment_keys"]},
}
(base / "cargo-executed").touch()
(base / "cargo.json").write_text(json.dumps(record) + "\n", encoding="utf-8")
sys.stdout.write(config.get("stdout", ""))
sys.stderr.write(config.get("stderr", ""))
raise SystemExit(config.get("status", 0))
