# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixed native finalizer fixture mutations, applied after actual capture."""

import json
from pathlib import Path
import sys

scenario, config_path, prepared_source, repo = sys.argv[1:]
if scenario == "tree":
    with Path(prepared_source).open("a") as stream:
        stream.write("// persistent prepared source mutation\n")
elif scenario == "metadata":
    path = Path(config_path)
    config = json.loads(path.read_text())
    config["root_status"] = 23
    path.write_text(json.dumps(config))
elif scenario == "config":
    path = Path(repo) / ".cargo/config.toml"
    path.parent.mkdir()
    path.write_text('[patch.crates-io]\ndemo = { path = "/fixture/redirected-demo" }\n')
elif scenario.startswith("artifact-"):
    root = Path(json.loads(Path(config_path).read_text())["driver_root"])
    dist = root / "work/dist"
    if scenario == "artifact-bytes":
        (dist / "p11scope").write_bytes(b"changed observer")
    elif scenario == "artifact-ledger":
        ledger = root / "artifacts/release-artifacts.sha256"
        ledger.write_bytes(ledger.read_bytes() + ledger.read_bytes().splitlines(keepends=True)[0])
    elif scenario == "artifact-alias":
        (dist / "p11scope-discover").write_bytes(b"different glibc helper")
    elif scenario == "artifact-missing":
        (dist / "p11scope").unlink()
    elif scenario == "artifact-symlink":
        (dist / "p11scope").unlink()
        (dist / "p11scope").symlink_to("p11scope-discover")
    else:
        raise SystemExit("unsupported artifact mutation")
elif scenario not in ("success", "cleanup", "admission", "admitted77"):
    raise SystemExit("unsupported fixture mutation")
