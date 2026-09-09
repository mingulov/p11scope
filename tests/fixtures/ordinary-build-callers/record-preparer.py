#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys


config = json.loads(Path(os.environ["P11SCOPE_ORDINARY_CALLERS_CONFIG"]).read_text())
row = {"kind": "prepare", "argv": sys.argv[1:], "cwd": os.getcwd(),
       "isolated": int(sys.flags.isolated)}
with Path(config["events"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
raise SystemExit(config.get("prepare_status", 0))
