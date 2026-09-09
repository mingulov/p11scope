#!/usr/bin/env python3
"""Controlled rustc stand-in that exposes one fixed sysroot."""

import json
import hashlib
from pathlib import Path
import sys


configuration = json.loads(Path(__file__).resolve().with_name("fixture.json").read_text(encoding="utf-8"))
counter = Path(__file__).with_name(Path(__file__).name + ".calls")
call = int(counter.read_text(encoding="ascii")) + 1 if counter.exists() else 1
counter.write_text(str(call), encoding="ascii")
mutation = configuration.get("rustc_payload_mutation")
if mutation and mutation["program"] == Path(__file__).name and mutation["call"] == call:
    package = Path(mutation["payload"]) / "vendor/shared-0.1.0"
    changed = package / "src.rs"
    changed.write_text(changed.read_text(encoding="utf-8") + mutation["append"], encoding="utf-8")
    checksum_path = package / ".cargo-checksum.json"
    checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
    checksum["files"]["src.rs"] = hashlib.sha256(changed.read_bytes()).hexdigest()
    checksum_path.write_text(json.dumps(checksum, sort_keys=True) + "\n", encoding="utf-8")
if sys.argv[1:] != ["--print", "sysroot"]:
    sys.stderr.write("unsupported controlled rustc invocation\n")
    raise SystemExit(97)
sys.stdout.write(configuration["sysroot"] + "\n")
