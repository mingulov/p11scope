#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
from pathlib import Path
import sys


names = ("RUSTC", "P11SCOPE_PREPARED_STABLE_CARGO",
         "P11SCOPE_PREPARED_STABLE_RUSTC", "P11SCOPE_PREPARED_BPF_CARGO",
         "P11SCOPE_PREPARED_BPF_RUSTC")
record = {
    "argv": sys.argv[1:],
    "cwd": os.getcwd(),
    "environment": {name: os.environ[name] for name in names if name in os.environ},
}
Path(os.environ["P11SCOPE_PRODUCT_BUILD_RECORD"]).write_text(
    json.dumps(record, sort_keys=True), encoding="utf-8")
sys.stdout.write(os.environ.get("P11SCOPE_PRODUCT_BUILD_STDOUT", ""))
sys.stderr.write(os.environ.get("P11SCOPE_PRODUCT_BUILD_STDERR", ""))
raise SystemExit(int(os.environ.get("P11SCOPE_PRODUCT_BUILD_STATUS", "0")))
