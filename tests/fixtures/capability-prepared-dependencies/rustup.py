#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

config = json.loads(Path(os.environ["P11SCOPE_CAPABILITY_FIXTURE"]).read_text(encoding="utf-8"))
args = sys.argv[1:]
if len(args) != 4 or args[:2] != ["which", "--toolchain"]:
    raise SystemExit(88)
print(config["tools"][f"{args[2]}:{args[3]}"])
