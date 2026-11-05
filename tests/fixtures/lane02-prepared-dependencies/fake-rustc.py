#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled selected rustc for Lane02 integration tests."""

import json
import os
from pathlib import Path
import sys


config = json.loads(Path(os.environ["P11SCOPE_LANE02_FIXTURE"]).read_text())


if sys.argv[1:] == ["--version"]:
    release = Path(".release-rust-version").read_text(encoding="utf-8").strip()
    print(f"rustc {release} (lane02 fixture)")
    status = config.get("rustc_version_status", 0)
    if status:
        print("controlled selected rustc version failure", file=sys.stderr)
    raise SystemExit(status)
raise SystemExit(97)
