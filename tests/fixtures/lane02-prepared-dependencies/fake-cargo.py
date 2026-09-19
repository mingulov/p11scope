#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled Cargo for Lane02 prepared-dependency integration tests."""

import json
import os
from pathlib import Path
import shutil
import sys


config = json.loads(Path(os.environ["P11SCOPE_LANE02_FIXTURE"]).read_text())


def event(kind: str, **values) -> None:
    with Path(config["events"]).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"kind": kind, **values}, sort_keys=True) + "\n")


if sys.argv[1:] == ["--version"]:
    print("cargo 1.88.0 (lane02 fixture)")
    status = config.get("cargo_version_status", 0)
    if status:
        print("controlled selected cargo version failure", file=sys.stderr)
    raise SystemExit(status)

if sys.argv[1:2] == ["metadata"]:
    manifest = sys.argv[sys.argv.index("--manifest-path") + 1]
    context = "root" if manifest == "Cargo.toml" else "bpf"
    phase = "final" if Path(config["initial_receipt"]).exists() else "initial"
    event("metadata", phase=phase, context=context, argv=sys.argv[1:],
          rustc=os.environ.get("RUSTC"),
          build_exists=Path(config["build_root"]).exists())
    mutation = config.get(f"{phase}_{context}_mutation")
    if mutation:
        path = Path(mutation)
        path.write_text(path.read_text() + "# controlled mutation\n", encoding="utf-8")
    status = config.get(f"{phase}_{context}_status", 0)
    if status:
        print(f"controlled {phase} {context} query failure", file=sys.stderr)
        raise SystemExit(status)
    sys.stdout.buffer.write(Path(config[f"{context}_metadata"]).read_bytes())
    raise SystemExit(0)

if sys.argv[1:2] == ["build"]:
    event("build", argv=sys.argv[1:], rustc=os.environ.get("RUSTC"),
          bpf_cargo=os.environ.get("P11SCOPE_PREPARED_BPF_CARGO"),
          bpf_rustc=os.environ.get("P11SCOPE_PREPARED_BPF_RUSTC"))
    target = Path(sys.argv[sys.argv.index("--target-dir") + 1])
    output = target / "release/p11scope"
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(config["built_responder"], output)
    output.chmod(0o700)
    raise SystemExit(config.get("build_status", 83))

print("unsupported controlled Cargo command", file=sys.stderr)
raise SystemExit(97)
