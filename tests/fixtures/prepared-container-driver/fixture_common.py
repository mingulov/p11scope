"""Shared data and event recording for the native container-driver fixtures."""

import json
import os
from pathlib import Path
import sys


CONFIG = json.loads(Path(os.environ["P11SCOPE_CONTAINER_FIXTURE"]).read_text())


def state():
    return json.loads(Path(CONFIG["state"]).read_text())


def save(value):
    Path(CONFIG["state"]).write_text(json.dumps(value))


def record(kind, **details):
    facts = Path(CONFIG["facts"])
    fact_lines = facts.read_text().splitlines() if facts.exists() else []
    prefix = CONFIG["prefix"]
    row = {
        "kind": kind, "argv": sys.argv[1:], "cwd": os.getcwd(),
        "executable": str(Path(sys.argv[0]).resolve()),
        "rustc": os.environ.get("RUSTC"),
        "initial_ready": all(Path(prefix + suffix).is_file() for suffix in (
            ".initial.receipt.json", ".initial.ledger.sha256")),
        "child_exit_present": any(line.startswith("child_exit\t") for line in fact_lines),
        "recorded_ids": [line.split("\t")[1] for line in fact_lines if line.startswith("container_")],
        "remaining_ids": sorted(state()["ids"]),
        **details,
    }
    with Path(CONFIG["events"]).open("a") as stream:
        stream.write(json.dumps(row) + "\n")


def refuse(message):
    print("container fixture: " + message, file=sys.stderr)
    raise SystemExit(88)
