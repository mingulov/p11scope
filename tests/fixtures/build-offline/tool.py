#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cargo/rustc/linker stand-in with explicit mutation controls."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


root = Path.cwd()
record = root / "test-record"
control = json.loads((root / "test-control.json").read_text(encoding="utf-8"))
role = Path(sys.argv[0]).name
with (record / "tools.jsonl").open("a", encoding="utf-8") as output:
    output.write(json.dumps({"role": role, "argv": sys.argv[1:],
                            "environment": dict(os.environ)}, sort_keys=True) + "\n")
if role != "stable-cargo":
    raise SystemExit(0)
if control.get("build_fail"):
    raise SystemExit(31)
if control.get("hold"):
    (record / "child-pid").write_text(str(os.getpid()), encoding="ascii")
    signal.signal(signal.SIGHUP, lambda n, f: sys.exit(128 + n))
    signal.signal(signal.SIGINT, lambda n, f: sys.exit(128 + n))
    signal.signal(signal.SIGTERM, lambda n, f: sys.exit(128 + n))
    while True:
        time.sleep(0.1)
if control.get("lookup_bpf_linker"):
    subprocess.run(["bpf-linker"], check=True)
if control.get("swap_root_foreign"):
    work = Path(os.environ["CARGO_HOME"]).parent
    moved = work.with_name(work.name + "-original")
    work.rename(moved)
    work.mkdir(mode=0o700)
    (work / "foreign-sentinel").write_text("keep", encoding="utf-8")
    raise SystemExit(32)
if control.get("coherent_mutation"):
    (root / "bound-input").write_text("changed", encoding="utf-8")
    manifest = root / ".p11scope-source-export.json"
    manifest.write_text(manifest.read_text(encoding="utf-8") + "changed", encoding="utf-8")
if control.get("payload_mutation"):
    (root / "third-party/offline/marker").write_text("changed", encoding="utf-8")
if control.get("tool_mutation"):
    (root / "stable-rustc").write_text("changed tool", encoding="utf-8")
if control.get("unknown_sibling"):
    sibling = root / "third-party/src/unknown"
    sibling.mkdir(parents=True, exist_ok=True)
    (sibling / "sentinel").write_text("keep", encoding="utf-8")
swap = control.get("swap_private")
if swap:
    work = Path(os.environ["CARGO_HOME"]).parent
    victim = work / swap
    moved = (work.with_name(work.name + "-original") if swap == "." else
             work / (swap.replace("/", "-") + "-original"))
    victim.rename(moved)
    victim.symlink_to(moved, target_is_directory=True)
if control.get("chmod_private"):
    work = Path(os.environ["CARGO_HOME"]).parent
    (work / control["chmod_private"]).chmod(0o755)
collision = control.get("evidence_collision")
if collision:
    evidence = Path(os.environ["CARGO_HOME"]).parent / "evidence/build-offline.json"
    if collision == "regular":
        evidence.write_text("sentinel", encoding="utf-8")
    elif collision == "symlink":
        evidence.symlink_to(root / "external-sentinel")
    elif collision == "fifo":
        os.mkfifo(evidence)
    elif collision == "directory":
        evidence.mkdir()
target = Path(sys.argv[sys.argv.index("--target-dir") + 1])
target.joinpath("built").write_text("yes", encoding="utf-8")
