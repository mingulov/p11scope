#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact offline curl responder for lane-13 release downloads."""

import os
import json
from pathlib import Path
import shutil
import sys


arguments = sys.argv[1:]
state = Path(os.environ["D2_STATE"])
with (state / "curl-argv.jsonl").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(arguments) + "\n")
fixed = [
    "--fail", "--silent", "--show-error", "--retry", "0",
    "--connect-timeout", "30", "--max-time", "180", "--max-filesize",
    "16777216", "--proto", "=https", "--proto-redir", "=https",
    "--location", "--max-redirs", "1", "--output",
]
if arguments[:len(fixed)] != fixed or len(arguments) != len(fixed) + 4:
    raise SystemExit(f"unsupported lane-13 curl arguments: {arguments!r}")
output, write_flag, write_format, url = arguments[len(fixed):]
if write_flag != "--write-out" or write_format != "%{url_effective}\\n%{num_redirects}":
    raise SystemExit("unsupported lane-13 curl write-out")
name = Path(output).name
owners = {
    "serving-crds.yaml": "knative/serving",
    "serving-core.yaml": "knative/serving",
    "kourier.yaml": "knative-extensions/net-kourier",
}
expected_url = (
    f"https://github.com/{owners.get(name, '')}/releases/download/"
    f"knative-v1.23.0/{name}"
)
work = Path(os.environ["KUBECONFIG"]).parent
if url != expected_url or (Path.cwd() / output).resolve() != work / "releases" / name:
    raise SystemExit("unsupported lane-13 release route")

previous = state / "last-release-path"
if previous.exists():
    previous_path = Path(previous.read_text(encoding="utf-8"))
    if previous_path.exists() or previous_path.is_symlink():
        raise SystemExit("previous lane-13 release was not deleted")
    with (state / "release-deletion-observed").open("a", encoding="utf-8") as stream:
        stream.write(previous_path.name + "\n")
    previous.unlink()

source = Path(os.environ["D2_RELEASE_FIXTURES"]) / name
if (
    os.environ["D2_MODE"] == "pre-apply-release-corruption"
    and name == os.environ["D2_CORRUPT_RELEASE"]
):
    source = Path(os.environ["D2_CORRUPT_RELEASE_FIXTURES"]) / name
shutil.copyfile(source, output)
sys.stdout.write(f"https://release-assets.githubusercontent.com/{name}?secret=fixed\n1\n")
