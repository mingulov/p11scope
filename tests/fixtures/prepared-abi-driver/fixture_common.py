# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared event and configuration support for ABI actual-CLI fixtures."""

import json
import os
from pathlib import Path
import sys


CONFIG = json.loads(Path(os.environ["P11SCOPE_ABI_FIXTURE"]).read_text(encoding="utf-8"))


def record(kind, **details):
    prefix = CONFIG["prefix"]
    row = {
        "kind": kind,
        "argv": sys.argv[1:],
        "cwd": os.getcwd(),
        "executable": str(Path(sys.argv[0]).resolve()),
        "rustc": os.environ.get("RUSTC"),
        "auto_install": os.environ.get("RUSTUP_AUTO_INSTALL"),
        "initial_ready": all(
            Path(prefix + suffix).is_file()
            for suffix in (".initial.receipt.json", ".initial.ledger.sha256")
        ),
        "final_ready": all(
            Path(prefix + suffix).is_file()
            for suffix in (".final.receipt.json", ".final.ledger.sha256")
        ),
        "driver_status_present": Path(CONFIG["driver_status"]).exists(),
        **details,
    }
    with Path(CONFIG["events"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")


def refuse(message):
    print("ABI fixture refusal: " + message, file=sys.stderr)
    raise SystemExit(88)
