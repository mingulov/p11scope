#!/usr/bin/env python3
"""Serve fixed metadata, then record and refuse a caller build."""

from pathlib import Path
import sys

from fixture_common import CONFIG, record, refuse


arguments = sys.argv[1:]
metadata = [
    "metadata", "--locked", "--offline", "--all-features",
    "--format-version", "1", "--manifest-path",
]
if len(arguments) == 8 and arguments[:-1] == metadata:
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
    metadata_path = CONFIG[context + "_metadata"]
    trigger = CONFIG.get("config_trigger")
    redirected = CONFIG.get("redirect_" + context + "_metadata")
    if phase == "final" and trigger and redirected and Path(trigger).exists():
        metadata_path = redirected
    sys.stdout.buffer.write(Path(metadata_path).read_bytes())
    raise SystemExit(0)
if arguments and arguments[0] == "build":
    record("build")
    print("prepared four callers fixture build refusal", file=sys.stderr)
    raise SystemExit(83)
refuse("unsupported Cargo arguments")
