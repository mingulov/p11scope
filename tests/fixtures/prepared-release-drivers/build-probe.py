#!/usr/bin/env python3
"""Record the one extracted Lane16 Cargo build invocation without compiling."""

import json
import os
from pathlib import Path
import sys

Path(__file__).with_suffix(".json").write_text(json.dumps({
    "argv": sys.argv[1:], "cargo": str(Path(__file__).resolve()),
    "rustc": os.environ.get("RUSTC"), "target": os.environ.get("CARGO_TARGET_DIR"),
}) + "\n")
