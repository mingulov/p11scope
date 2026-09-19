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
elif scenario not in ("success", "cleanup", "admission", "admitted77"):
    raise SystemExit("unsupported fixture mutation")
