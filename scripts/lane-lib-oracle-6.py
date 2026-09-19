#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared lib container manifest oracle rewrite_container_manifest: rewrite a v5 manifest from the safe root to the target root. Oracle extracted from scripts/lib.sh (lines 772-802)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Shared lib container manifest oracle rewrite_container_manifest: rewrite a v5 manifest from the safe root to the target root").print_help()
    raise SystemExit(0)

import json
import sys
from pathlib import Path

source, destination, safe_root, target_root = sys.argv[1:5]
safe_root = Path(safe_root).resolve(strict=True)
target_root = Path(target_root)
if not target_root.is_absolute():
    raise SystemExit(f"target root is not absolute: {target_root}")
manifest = json.loads(Path(source).read_text(encoding="utf-8"))
if manifest.get("schema") != "p11scope-manifest/5":
    raise SystemExit(f"container manifest is not schema v5: {manifest.get('schema')!r}")
if not manifest.get("objects"):
    raise SystemExit("container manifest has no attach objects")


def target(path):
    resolved = Path(path).resolve(strict=True)
    try:
        relative = resolved.relative_to(safe_root)
    except ValueError:
        raise SystemExit(f"attach object escapes the copied directory: {resolved}")
    return str(target_root / relative)


manifest["module_path"] = target(manifest["module_path"])
for item in manifest["objects"]:
    item["path"] = target(item["path"])
if manifest["objects"][0]["path"] != manifest["module_path"]:
    raise SystemExit("object zero is not the module")
Path(destination).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
