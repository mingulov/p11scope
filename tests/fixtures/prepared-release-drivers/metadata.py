# SPDX-License-Identifier: GPL-3.0-or-later
"""Supply adjacent configuration to the accepted native Cargo metadata fixture."""

import json
import os
from pathlib import Path
import runpy
import sys

config_path, cargo = sys.argv[1:3]
arguments = sys.argv[3:]
expected = ["metadata", "--locked", "--offline", "--all-features", "--format-version", "1", "--manifest-path"]
if arguments[:-1] != expected or arguments[-1] not in ("Cargo.toml", "crates/ebpf/Cargo.toml"):
    raise SystemExit("unsupported fixture metadata command")
config = json.loads(Path(config_path).read_text())
root = Path(config["driver_root"])
row = {"argv": arguments, "cargo": cargo, "rustc": os.environ.get("RUSTC"), "cwd": os.getcwd(),
       "cleanup": (root / "artifacts/cleanup.marker").exists(), "status": (root / "status").exists()}
with Path(config["events"]).open("a") as stream:
    stream.write(json.dumps(row) + "\n")
redirect = Path.cwd() / ".cargo/config.toml"
if redirect.exists() and config.get("redirect_selection"):
    # The one fixed fixture redirect changes actual returned metadata. It is
    # not a Boolean success/failure substitute for the real evidence helper.
    import tomllib
    directive = tomllib.loads(redirect.read_text())["patch"]["crates-io"]["demo"]["path"]
    if directive != "/fixture/redirected-demo":
        raise SystemExit("unsupported fixture source redirect")
    config["selection_file"] = config["redirect_selection"]
    redirected = Path(config_path).with_name("redirected-cargo-config.json")
    redirected.write_text(json.dumps(config))
    config_path = str(redirected)
os.environ["P11SCOPE_FAKE_CARGO_CONFIG"] = config_path
sys.argv = [cargo, *arguments]
runpy.run_path(config["generic_program"], run_name="__main__")
