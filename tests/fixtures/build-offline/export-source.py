#!/usr/bin/env python3
"""Native extracted-validator stand-in for coordinator tests."""

import hashlib
import json
import os
from pathlib import Path


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_extracted(root, cargo_home=None, *, prepared="forbid"):
    root = Path(root)
    record = root / "test-record"
    calls = record / "validate.jsonl"
    rows = [] if not calls.exists() else calls.read_text(encoding="utf-8").splitlines()
    call = len(rows) + 1
    row = {"call": call, "prepared": prepared, "environment": dict(os.environ),
           "cargo_home": str(cargo_home)}
    with calls.open("a", encoding="utf-8") as output:
        output.write(json.dumps(row, sort_keys=True) + "\n")
    control = json.loads((root / "test-control.json").read_text(encoding="utf-8"))
    if control.get("validator_fail") == call:
        raise RuntimeError("synthetic validator failure")
    generated = root / "third-party/src/demo-1.0/content"
    lock = root / "third-party/.prepare-dependencies.lock"
    allowed = {root / "third-party/src/demo-1.0"}
    source_root = root / "third-party/src"
    if source_root.exists():
        observed = set(source_root.iterdir())
        if not observed.issubset(allowed):
            raise RuntimeError("unknown generated sibling")
    if prepared == "forbid" and (generated.exists() or lock.exists()):
        raise RuntimeError("prepared output forbidden")
    if prepared == "require" and (not generated.is_file() or not lock.is_file()):
        raise RuntimeError("prepared output incomplete")
    if lock.exists() and (lock.is_symlink() or lock.stat().st_mode & 0o777 != 0o600
                          or lock.stat().st_size != 0):
        raise RuntimeError("unsafe preparation lock")
    identity = {name: _hash(root / name) for name in
                (".p11scope-source-export.json", ".cargo/config.toml",
                 "third-party/offline-dependencies.json", "third-party/offline/marker",
                 "bound-input")}
    identity["revision"] = "1" * 40
    if call == 3:
        (record / "final-validation-returned").write_text("yes", encoding="utf-8")
    custody = {"present": generated.exists(), "lock": None, "generated": None}
    if generated.exists():
        metadata = generated.stat()
        custody["generated"] = {"device": metadata.st_dev, "inode": metadata.st_ino,
                                "mode": metadata.st_mode & 0o777,
                                "mtime_ns": metadata.st_mtime_ns,
                                "sha256": _hash(generated)}
    if lock.exists():
        metadata = lock.stat()
        custody["lock"] = {"device": metadata.st_dev, "inode": metadata.st_ino,
                           "mode": metadata.st_mode & 0o777,
                           "mtime_ns": metadata.st_mtime_ns}
    return {"identity": identity, "prepared": custody}
