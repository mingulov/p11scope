#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pinned-rustc stand-in that mutates private export staging on a fixed call."""

import hashlib
import json
from pathlib import Path
import sys


configuration_path = Path(__file__).resolve().with_name("fixture.json")
configuration = json.loads(configuration_path.read_text(encoding="utf-8"))
counter = Path(__file__).with_name(Path(__file__).name + ".calls")
call = int(counter.read_text(encoding="ascii")) + 1 if counter.exists() else 1
counter.write_text(str(call), encoding="ascii")
if call == configuration["export_mutation_call"]:
    candidates = list(Path(configuration["export_parent"]).glob(
        ".stream-mutated.tar.gz.export-*/private-payload/vendor/shared-0.1.0"
    ))
    if len(candidates) != 1:
        sys.stderr.write("private export staging was not uniquely available\n")
        raise SystemExit(96)
    package = candidates[0]
    changed = package / "src.rs"
    changed.write_text(changed.read_text(encoding="utf-8") + "stream mutation\n",
                       encoding="utf-8")
    checksum_path = package / ".cargo-checksum.json"
    checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
    checksum["files"]["src.rs"] = hashlib.sha256(changed.read_bytes()).hexdigest()
    checksum_path.write_text(json.dumps(checksum, sort_keys=True) + "\n", encoding="utf-8")
if sys.argv[1:] != ["--print", "sysroot"]:
    sys.stderr.write("unsupported controlled rustc invocation\n")
    raise SystemExit(97)
sys.stdout.write(configuration["sysroot"] + "\n")
