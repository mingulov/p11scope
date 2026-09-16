#!/usr/bin/env python3
"""Controlled product-object boundary; reuse the existing inventory fixture."""
import argparse
import json
import os
from pathlib import Path
import runpy

config = json.loads(Path(os.environ["P11SCOPE_LIVE_FREEZE_FIXTURE"]).read_text())
checker = runpy.run_path(config["object_checker"])
test_manifest = checker["test_manifest"]
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("source", "object", "manifest"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    assert args.object.read_bytes() == b"controlled BPF build bytes\n"
    value = test_manifest(args.source, "default", args.source.read_text())
    args.manifest.write_text(json.dumps(value))
