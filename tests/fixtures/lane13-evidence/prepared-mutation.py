#!/usr/bin/python3 -I
# SPDX-License-Identifier: GPL-3.0-or-later
"""Apply one fixed post-admission mutation for lane-13 native tests."""

import json
import os
from pathlib import Path


config = json.loads(Path(os.environ["D2_MUTATION_CONFIG"]).read_text(encoding="utf-8"))
mode = os.environ["D2_MODE"]
targets = {
    "mutate-prepared-generated": config["generated"],
    "mutate-prepared-recipe": config["recipe"],
    "mutate-prepared-patch": config["patch"],
    "mutate-prepared-script": config["script"],
}
if mode in targets:
    with Path(targets[mode]).open("ab") as stream:
        stream.write(b"post-admission mutation\n")
elif mode == "mutate-prepared-final-graph":
    selection = Path(config["selection"])
    values = json.loads(selection.read_text(encoding="utf-8"))
    values["root"] = config["alternate_root_metadata"]
    selection.write_text(json.dumps(values), encoding="utf-8")
elif mode == "mutate-prepared-config-redirect":
    cargo_config = Path(config["cargo_config"])
    cargo_config.parent.mkdir(parents=True, exist_ok=True)
    cargo_config.write_text('[source.crates-io]\nreplace-with = "redirected"\n', encoding="utf-8")
else:
    raise SystemExit(f"unsupported prepared mutation mode: {mode}")
