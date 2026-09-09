#!/usr/bin/env python3
"""Serve fixed metadata and vendor config without running Cargo or rustc."""

from pathlib import Path
import sys
from fixture_common import CONFIG, record, refuse


arguments = sys.argv[1:]
vendor_arguments = arguments[1:] if arguments[:1] == ["+1.88"] else arguments
if vendor_arguments[:1] == ["vendor"]:
    # The legacy spelling is admitted solely to expose the driver's RED behavior.
    if not (len(vendor_arguments) == 3 and vendor_arguments[1] == "--locked"
            or len(vendor_arguments) == 4 and vendor_arguments[1:3] == ["--locked", "--offline"]):
        refuse("unsupported vendor arguments")
    record("vendor")
    print('[source.vendored-sources]\ndirectory = "/fixture/vendor"')
elif arguments[:1] == ["metadata"]:
    expected = ["metadata", "--locked", "--offline", "--all-features", "--format-version", "1", "--manifest-path"]
    if len(arguments) != 8 or arguments[:-1] != expected:
        refuse("unsupported metadata arguments")
    if arguments[-1] not in ("Cargo.toml", "crates/ebpf/Cargo.toml"):
        refuse("unsupported workspace")
    context = "root" if arguments[-1] == "Cargo.toml" else "bpf"
    phase = "final" if Path(CONFIG["prefix"] + ".final.root.command.json").exists() else "initial"
    record("metadata", context=context, phase=phase)
    status = CONFIG.get(context + "_status", 0)
    if status:
        print("fixture " + context + " metadata stdout")
        print("fixture " + context + " metadata refusal", file=sys.stderr)
        raise SystemExit(status)
    sys.stdout.buffer.write(Path(CONFIG[context + "_metadata"]).read_bytes())
else:
    refuse("unsupported cargo arguments")
