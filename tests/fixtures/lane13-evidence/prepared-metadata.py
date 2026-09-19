#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Lane-13 Cargo metadata stand-in with cleanup-boundary observations."""

import json
import os
from pathlib import Path
import sys


config = json.loads(Path(os.environ["P11SCOPE_FAKE_CARGO_CONFIG"]).read_text(encoding="utf-8"))
manifest = sys.argv[sys.argv.index("--manifest-path") + 1]
context = "root" if manifest == "Cargo.toml" else "bpf"
log = Path(config["log"])
query_index = len(log.read_text(encoding="utf-8").splitlines()) if log.exists() else 0
evidence = Path(os.environ["P11SCOPE_LANE_EVIDENCE_DIR"])
status_path = evidence / "status"
work_path = Path(os.environ["KUBECONFIG"]).parent
record = {
    "argv": sys.argv[1:],
    "cargo": str(Path(sys.argv[0]).resolve()),
    "cwd": os.getcwd(),
    "rustc": os.environ.get("RUSTC"),
    "context": context,
    "lane13_phase": "initial" if query_index < 2 else "final",
    "lane13_work_absent": not work_path.exists(),
    "lane13_status_unpublished": (
        not status_path.exists() or status_path.read_bytes() == b""
    ),
}
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(record, sort_keys=True) + "\n")

marker = config.get(f"{context}_marker")
if marker:
    Path(marker).touch()
for mutation in config.get(f"{context}_mutations", []):
    path = Path(mutation["path"])
    if mutation["action"] == "append":
        with path.open("ab") as stream:
            stream.write(mutation["content"].encode("utf-8"))
    elif mutation["action"] == "create":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(mutation["content"], encoding="utf-8")
    else:
        raise ValueError(f"unsupported fixture mutation {mutation['action']}")
status = config.get(f"{context}_status", 0)
if status:
    sys.stdout.write(config.get(f"{context}_stdout", "failed stdout\n"))
    sys.stderr.write(config.get(f"{context}_stderr", "failed stderr\n"))
    raise SystemExit(status)

selection = json.loads(Path(config["selection_file"]).read_text(encoding="utf-8"))
metadata_path = selection[context]
cargo_config = Path(config["lane13_cargo_config"])
if context == "root" and cargo_config.exists():
    if cargo_config.read_text(encoding="utf-8") != (
        '[source.crates-io]\nreplace-with = "redirected"\n'
    ):
        raise SystemExit("unsupported lane-13 Cargo config fixture")
    metadata_path = config["lane13_redirected_root_metadata"]
sys.stdout.buffer.write(Path(metadata_path).read_bytes())
