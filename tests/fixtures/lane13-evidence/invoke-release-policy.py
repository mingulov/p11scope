#!/usr/bin/env python3
"""Invoke the maintained lane-13 release admission function with fixed stubs."""

import argparse
from pathlib import Path
import subprocess
import tempfile


parser = argparse.ArgumentParser()
parser.add_argument("--driver", required=True, type=Path)
parser.add_argument("--url", required=True)
parser.add_argument("--name", required=True)
parser.add_argument("--facts", required=True, type=Path)
parser.add_argument("--calls", required=True, type=Path)
options = parser.parse_args()
source = options.driver.read_text(encoding="utf-8")
start = source.index("lane13_fetch_release() {")
end = source.index("\nlane13_sha256() {", start)
function = source[start:end]
with tempfile.TemporaryDirectory(prefix="lane13-release-policy-") as temporary:
    work = Path(temporary) / "work"
    function_file = Path(temporary) / "lane13-fetch-release.sh"
    function_file.write_text(function + "\n", encoding="utf-8")
    fixture = Path(__file__).resolve().with_name("invoke-release-policy.sh")
    result = subprocess.run(
        [
            "/bin/sh", str(fixture), str(function_file), str(work),
            str(options.facts.resolve()), str(options.calls.resolve()),
            options.url, options.name,
        ],
        cwd=options.driver.parent.parent.parent,
    )
raise SystemExit(result.returncode)
