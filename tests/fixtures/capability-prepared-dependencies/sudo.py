#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

path = Path(os.environ["P11SCOPE_CAPABILITY_FIXTURE"])
config = json.loads(path.read_text(encoding="utf-8"))
Path(config["sudo_marker"]).write_text("sudo\n", encoding="utf-8")
if config.get("final_publication_failure"):
    work = next(Path(config["fixture_root"]).glob("p11scope-verify-*/target/capability-tier"))
    metadata = work / "metadata.txt"
    metadata.unlink()
    metadata.mkdir()
if config.get("full_runtime"):
    if sys.argv[1:] == ["-n", "true"]:
        raise SystemExit(0)
    import re
    match = re.search(r"--pid ['\"]?([0-9]+)", " ".join(sys.argv[1:]))
    if match:
        config.setdefault("target_pids", []).append(int(match.group(1)))
        path.write_text(json.dumps(config), encoding="utf-8")
    row = len(config.get("target_pids", []))
    print("capability tier: T1 host attach (target assessed)" if row == 1
          else "capability tier: T0 offline (target assessed)")
    raise SystemExit(1)
if config.get("mutation_path"):
    target = Path(config["mutation_path"])
    target.write_bytes(target.read_bytes() + b"final mutation\n")
if config.get("final_query_status"):
    config["root_status"] = config["final_query_status"]
    path.write_text(json.dumps(config), encoding="utf-8")
raise SystemExit(1)
