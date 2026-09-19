#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
from pathlib import Path
import sys

config_path = Path(os.environ["P11SCOPE_CAPABILITY_FIXTURE"])
config = json.loads(config_path.read_text(encoding="utf-8"))
args = sys.argv[1:]
event = {
    "argv": args,
    "cargo": str(Path(sys.argv[0]).resolve()),
    "rustc": os.environ.get("RUSTC"),
    "bpf_cargo": os.environ.get("P11SCOPE_PREPARED_BPF_CARGO"),
    "bpf_rustc": os.environ.get("P11SCOPE_PREPARED_BPF_RUSTC"),
}
if args and args[0] == "metadata":
    stopped = True
    for pid in config.get("target_pids", []):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        stopped = False
    event["targets_stopped"] = stopped
with Path(config["events"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(event, sort_keys=True) + "\n")

metadata = ["metadata", "--locked", "--offline", "--all-features",
            "--format-version", "1", "--manifest-path"]
if len(args) == 8 and args[:-1] == metadata:
    context = "root" if args[-1] == "Cargo.toml" else "bpf" if args[-1] == "crates/ebpf/Cargo.toml" else None
    if context is None:
        raise SystemExit(88)
    status = int(config.get(context + "_status", 0))
    if status:
        print(f"fixture {context} metadata refusal", file=sys.stderr)
        raise SystemExit(status)
    sys.stdout.buffer.write(Path(config[context + "_metadata"]).read_bytes())
    raise SystemExit(0)
if args == ["build", "--locked", "--offline", "--release", "--workspace"]:
    if config.get("initial_publication_failure"):
        work = next(Path(config["fixture_root"]).glob("p11scope-verify-*/target/capability-tier"))
        (work / "metadata.txt").mkdir()
    if config.get("final_publication_failure_after_build"):
        work = next(Path(config["fixture_root"]).glob("p11scope-verify-*/target/capability-tier"))
        (work / "metadata.txt").mkdir()
    raise SystemExit(int(config.get("build_status", 0)))
print("unsupported fixture cargo arguments", file=sys.stderr)
raise SystemExit(88)
