#!/usr/bin/env python3
import sys
from fixture_common import CONFIG, record, refuse

arguments = sys.argv[1:]
record("rustup")
if len(arguments) != 4 or arguments[:2] != ["which", "--toolchain"]:
    refuse("unsupported rustup arguments")
key = ":".join(arguments[2:])
if key not in CONFIG["tools"]:
    refuse("unsupported tool selection")
print(CONFIG["tools"][key])
