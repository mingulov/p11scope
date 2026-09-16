"""Event/configuration support for four-caller native fixtures."""

import json
import os
from pathlib import Path
import sys


CONFIG = json.loads(Path(os.environ["P11SCOPE_FOUR_CALLERS_FIXTURE"]).read_text())


def record(kind, **details):
    prefix = CONFIG["prefix"]
    row = {
        "kind": kind,
        "argv": sys.argv[1:],
        "cwd": os.getcwd(),
        "executable": str(Path(sys.argv[0]).resolve()),
        "rustc": os.environ.get("RUSTC"),
        "bpf_cargo": os.environ.get("P11SCOPE_PREPARED_BPF_CARGO"),
        "bpf_rustc": os.environ.get("P11SCOPE_PREPARED_BPF_RUSTC"),
        "auto_install": os.environ.get("RUSTUP_AUTO_INSTALL"),
        "small_ring": os.environ.get("P11SCOPE_SMALL_RING"),
        "small_state": os.environ.get("P11SCOPE_SMALL_STATE_MAPS"),
        "initial_ready": Path(prefix + ".initial.ledger.sha256").is_file(),
        "final_ready": Path(prefix + ".final.ledger.sha256").is_file(),
        "cleanup_ready": Path(CONFIG.get("cleanup_marker", "/missing")).is_file(),
        "status_present": Path(CONFIG["driver_status"]).exists(),
        **details,
    }
    with Path(CONFIG["events"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")


def refuse(message, status=88):
    print("four callers fixture refusal: " + message, file=sys.stderr)
    raise SystemExit(status)
