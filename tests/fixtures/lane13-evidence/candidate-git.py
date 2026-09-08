#!/usr/bin/python3 -I
"""Synthetic tracked-name input for the owned lane-13 candidate fixture."""

import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    candidate = json.loads(Path(os.environ["D2_CANDIDATE_INPUTS"]).read_text())
    args = sys.argv[1:]
    if args[:2] != ["ls-files", "-z"] or "--" not in args:
        raise SystemExit("candidate Git fixture requires a NUL-delimited pathspec query")
    paths = set(subprocess.check_output(
        ["/usr/bin/git", "-C", candidate["root"], *args], timeout=5,
    ).split(b"\0")) - {b""}
    specs = args[args.index("--") + 1:]
    for path in candidate["aya_paths"]:
        if any(path == spec or path.startswith(spec + "/") for spec in specs):
            paths.add(os.fsencode(path))
    sys.stdout.buffer.write(b"".join(path + b"\0" for path in sorted(paths)))


if __name__ == "__main__":
    main()
