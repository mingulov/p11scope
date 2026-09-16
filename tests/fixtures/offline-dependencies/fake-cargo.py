#!/usr/bin/env python3
"""Controlled Cargo stand-in for offline dependency payload tests."""

import json
import os
from pathlib import Path
import shutil
import sys


fixture = Path(__file__).resolve().with_name("fixture.json")
configuration = json.loads(fixture.read_text(encoding="utf-8"))
log = Path(configuration["log"])
call = len(log.read_text(encoding="utf-8").splitlines()) + 1 if log.exists() else 1
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({
        "argv": sys.argv[1:],
        "cargo_net_offline": os.environ.get("CARGO_NET_OFFLINE"),
        "program": Path(sys.argv[0]).name,
        "rustc": os.environ.get("RUSTC"),
    }) + "\n")

mutation = configuration.get("cargo_mutation")
if mutation and mutation["call"] == call:
    target = Path(mutation["path"])
    target.write_text(target.read_text(encoding="utf-8") + mutation["append"], encoding="utf-8")

if sys.argv[1:2] == ["metadata"]:
    manifest = Path(sys.argv[sys.argv.index("--manifest-path") + 1])
    context = "bpf" if manifest.name == "Cargo.toml" and manifest.parent.name == "ebpf" else "root"
    status = configuration.get(f"{context}_status", 0)
    if status:
        sys.stderr.write(f"controlled {context} metadata failure\n")
        raise SystemExit(status)
    value = Path(configuration[f"{context}_metadata"]).read_text(encoding="utf-8")
    sys.stdout.write(value.replace("@SOURCE_ROOT@", configuration["source_root"]))
elif sys.argv[1:2] == ["vendor"]:
    status = configuration.get("vendor_status", 0)
    if status:
        sys.stderr.write("controlled vendor failure\n")
        raise SystemExit(status)
    destination = Path(sys.argv[-1])
    shutil.copytree(configuration["vendor_template"], destination)
    for checksum_path in destination.glob("*/.cargo-checksum.json"):
        checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
        checksum["$comment"] = (
            "This file only protects against accidental modifications. It is not a security "
            "mechanism and does not protect against malicious changes."
        )
        checksum.update(configuration.get("vendor_checksum_mutation", {}))
        checksum_path.write_text(json.dumps(checksum, sort_keys=True) + "\n", encoding="utf-8")
    sys.stdout.write("# controlled cargo vendor configuration\n")
else:
    sys.stderr.write("unsupported controlled Cargo invocation\n")
    raise SystemExit(97)
