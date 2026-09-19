# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic boundary injection around the actual native helper."""

import json
import os
from pathlib import Path
import sys
import time


operation, context, *args = sys.argv[1:]
work = Path(os.environ["CASE_DIR"])
phase = args[0] if args else ""
if operation != os.environ.get("HOOK_OPERATION") or phase != os.environ.get("HOOK_PHASE", ""):
    raise SystemExit(0)
ctx = json.loads(context)
path = Path(ctx["path"])
snapshot = {name: value for name, value in os.environ.items()
            if name.startswith(("ROOT_", "USER_"))}
(work / "snapshot.json").write_text(json.dumps(snapshot))
action = os.environ.get("HOOK_ACTION", "fail")
if action == "hold":
    temporary = work / "hook.waiting.tmp"
    temporary.write_text(json.dumps({"pid": int(os.environ["FIXTURE_OWN_PID"]),
                                     "starttime": int(os.environ["FIXTURE_OWN_STARTTIME"])}))
    temporary.replace(work / "hook.waiting")
    deadline = time.monotonic() + 5
    while not (work / "hook.release").exists():
        if time.monotonic() >= deadline:
            raise SystemExit(78)
        time.sleep(0.01)
elif action == "replace-directory":
    path.rename(str(path) + ".old")
    path.mkdir(mode=0o700)
    (path / "foreign").write_text("retain me")
elif action == "corrupt-self":
    (path / (phase + ".self")).write_text('{"pid":')
elif action == "mismatched-self":
    source = path / (phase + ".self")
    deadline = time.monotonic() + 3
    while not source.exists():
        if time.monotonic() >= deadline:
            raise SystemExit(78)
        time.sleep(0.01)
    record = json.loads(source.read_text())
    record["pid"] += 1
    source.write_text(json.dumps(record) + "\n")
elif action == "public-self":
    (path / (phase + ".self")).chmod(0o644)
elif action == "fail":
    raise SystemExit(79)
