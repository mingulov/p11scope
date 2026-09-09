#!/usr/bin/env python3
"""Native offline verifier/preparer stand-in for coordinator tests."""

import json
import os
from pathlib import Path
import sys


root = Path.cwd()
record = root / "test-record"
control = json.loads((root / "test-control.json").read_text(encoding="utf-8"))
with (record / "offline.jsonl").open("a", encoding="utf-8") as output:
    output.write(json.dumps({"argv": sys.argv[1:], "environment": dict(os.environ)},
                            sort_keys=True) + "\n")
if (record / "final-validation-returned").exists():
    (record / "callback-after-final").write_text("bad", encoding="utf-8")
check = "--check-prepared" in sys.argv
generated = root / "third-party/src/demo-1.0/content"
lock = root / "third-party/.prepare-dependencies.lock"
if check:
    if control.get("late_config_mutation"):
        (root / ".cargo/config.toml").write_text("late mutation", encoding="utf-8")
    if not generated.is_file() or generated.read_text(encoding="utf-8") != "prepared":
        raise SystemExit(23)
    if control.get("prepared_mtime_mutation"):
        os.utime(generated, ns=(generated.stat().st_atime_ns, generated.stat().st_mtime_ns + 1))
else:
    generated.parent.mkdir(parents=True, exist_ok=True)
    if not generated.exists():
        generated.write_text("prepared", encoding="utf-8")
        generated.chmod(0o644)
    (root / "third-party/src").chmod(0o755)
    generated.parent.chmod(0o755)
    if not lock.exists():
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
if control.get("offline_fail") == ("check" if check else "reconstruct"):
    raise SystemExit(24)
