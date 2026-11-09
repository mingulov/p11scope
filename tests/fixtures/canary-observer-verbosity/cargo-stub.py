#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""cargo tripwire for the canary observer-verbosity probe.

Records the invocation, then materializes the build outputs the harness
expects (observer/discover binaries plus the BPF object globs) as copies
of prebuilt fixtures, so verify-canaries.sh reaches its lanes without a
real build. Configuration arrives in P11SCOPE_CANARY_ARGV_CONFIG.
"""
import json
import os
from pathlib import Path
import shutil
import sys

config = json.loads(Path(os.environ["P11SCOPE_CANARY_ARGV_CONFIG"]).read_text())
row = {"kind": "cargo", "argv": sys.argv[1:], "cwd": os.getcwd()}
with Path(config["events"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")

arguments, target = sys.argv[1:], None
for index, token in enumerate(arguments):
    if token == "--target-dir" and index + 1 < len(arguments):
        target = Path(arguments[index + 1])
if target is None:
    raise SystemExit("cargo stub: no --target-dir")

elf = Path(config["elf"])
discover = Path(config["discover"])
release = target / "release"
release.mkdir(parents=True, exist_ok=True)
if target.name == "default-build":
    shutil.copy2(elf, release / "p11scope")
    shutil.copy2(discover, release / "p11scope-discover")
    channel = release / "build/p11scope-fixture/out"
    channel.mkdir(parents=True, exist_ok=True)
    (channel / "p11scope-ebpf").write_bytes(b"")
    journal = channel / "journal-v1"
    journal.mkdir(exist_ok=True)
    (journal / "p11scope-ebpf-journal-v1").write_bytes(b"")
elif target.name == "feature-build":
    shutil.copy2(elf, release / "p11scope")
    channel = release / "build/p11scope-fixture/out"
    channel.mkdir(parents=True, exist_ok=True)
    (channel / "p11scope-ebpf").write_bytes(b"")
else:
    raise SystemExit(f"cargo stub: unexpected target dir {target}")
