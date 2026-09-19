#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Serve fixed Cargo metadata without invoking Cargo or rustc."""

import sys
from pathlib import Path

from fixture_common import CONFIG, record, refuse


arguments = sys.argv[1:]
if arguments == ["--version"]:
    record("cargo_version")
    status = CONFIG.get("cargo_version_status", 0)
    if status:
        print("fixture Cargo version refusal", file=sys.stderr)
        raise SystemExit(status)
    print(CONFIG.get("cargo_version", "cargo 1.88.0 (fixture)"))
    raise SystemExit(0)
expected = [
    "metadata",
    "--locked",
    "--offline",
    "--all-features",
    "--format-version",
    "1",
    "--manifest-path",
]
if len(arguments) != 8 or arguments[:-1] != expected:
    refuse("unsupported Cargo arguments")
if arguments[-1] == "Cargo.toml":
    context = "root"
elif arguments[-1] == "crates/ebpf/Cargo.toml":
    context = "bpf"
else:
    refuse("unsupported metadata workspace")
phase = "final" if Path(CONFIG["prefix"] + ".final.root.command.json").exists() else "initial"
record("metadata", context=context, phase=phase)
status = CONFIG.get(context + "_status", 0)
if status:
    print(f"fixture {context} metadata refusal", file=sys.stderr)
    raise SystemExit(status)
sys.stdout.buffer.write(Path(CONFIG[context + "_metadata"]).read_bytes())
