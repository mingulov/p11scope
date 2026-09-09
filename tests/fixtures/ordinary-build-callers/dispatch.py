#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys


config = json.loads(Path(os.environ["P11SCOPE_ORDINARY_CALLERS_CONFIG"]).read_text())
kind = Path(sys.argv[0]).name
row = {"kind": kind, "argv": sys.argv[1:], "cwd": os.getcwd()}
with Path(config["events"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")

if kind == "timeout":
    arguments = sys.argv[1:]
    index = 0
    while index < len(arguments) and arguments[index].startswith("-"):
        index += 1
    index += 1
    os.execvp(arguments[index], arguments[index:])
if kind == "cargo":
    raise SystemExit(config.get("cargo_status", 83))
raise SystemExit(97)
