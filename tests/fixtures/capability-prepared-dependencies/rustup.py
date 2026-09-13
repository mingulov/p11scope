#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

config = json.loads(Path(os.environ["P11SCOPE_CAPABILITY_FIXTURE"]).read_text(encoding="utf-8"))
args = sys.argv[1:]
if args == ["--version"]:
    # The tool pinning layer identifies its executables by behaviour (it runs
    # `rustup --version` and requires a `rustup ` banner), so a stub standing
    # in for rustup must answer as rustup. The probe is a capability check,
    # not a tool selection.
    print("rustup 1.99.0 (p11scope test fixture)")
    raise SystemExit(0)
if len(args) != 4 or args[:2] != ["which", "--toolchain"]:
    raise SystemExit(88)
print(config["tools"][f"{args[2]}:{args[3]}"])
