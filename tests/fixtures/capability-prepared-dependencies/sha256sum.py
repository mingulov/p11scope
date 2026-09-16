#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

config = json.loads(Path(os.environ["P11SCOPE_CAPABILITY_FIXTURE"]).read_text(encoding="utf-8"))
target = sys.argv[-1] if len(sys.argv) == 2 else ""
suffixes = {
    "initial-receipt": "dependencies.initial.receipt.json",
    "initial-snapshot": "source.start.tsv",
    "final-receipt": "dependencies.final.receipt.json",
    "final-snapshot": "source.end.tsv",
}
failure = config.get("hash_failure")
if failure and target.endswith(suffixes[failure]):
    print(f"controlled {failure} checksum failure", file=sys.stderr)
    raise SystemExit(41)
os.execv("/usr/bin/sha256sum", ["sha256sum", *sys.argv[1:]])
