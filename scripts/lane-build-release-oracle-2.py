#!/usr/bin/env python3
"""Release tree-digest transcript oracle: join the sorted tree listing with sha256 records into a validated transcript. Oracle extracted from scripts/build-release.sh (lines 359-406)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Release tree-digest transcript oracle: join the sorted tree listing with sha256 records into a validated transcript").print_help()
    raise SystemExit(0)

import os
import stat
import sys

root = os.path.realpath(os.fsencode(sys.argv[1]))
with open(sys.argv[2], "rb") as source:
    paths = [path for path in source.read().split(b"\0") if path]
with open(sys.argv[3], "rb") as source:
    hashes = {}
    for record in source.read().split(b"\0"):
        if not record:
            continue
        if len(record) < 67 or record[64:66] != b"  ":
            raise SystemExit(1)
        hashes[record[66:]] = record[:64]

def reject_text(value):
    if b"\t" in value or b"\n" in value:
        raise SystemExit(1)

for path in paths:
    relative = os.path.relpath(path, root)
    reject_text(relative)
    if os.path.islink(path):
        raw = os.readlink(path)
        reject_text(raw)
        canonical = os.path.realpath(path)
        reject_text(canonical)
        if os.path.commonpath((root, canonical)) != root:
            raise SystemExit(1)
        try:
            mode = os.stat(canonical, follow_symlinks=False).st_mode
        except OSError:
            raise SystemExit(1)
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise SystemExit(1)
        target = hashes.get(canonical, b"directory" if stat.S_ISDIR(mode) else b"")
        if not target:
            raise SystemExit(1)
        sys.stdout.buffer.write(b"L\0" + relative + b"\0" + raw + b"\0" + target + b"\0")
    elif os.path.isfile(path):
        if path not in hashes:
            raise SystemExit(1)
        sys.stdout.buffer.write(b"F\0" + relative + b"\0" + hashes[path] + b"\0")
    elif os.path.isdir(path):
        sys.stdout.buffer.write(b"D\0" + relative + b"\0")
    else:
        raise SystemExit(1)
