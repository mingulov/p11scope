#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate the bounded retained-input tree for Task 4 Lane 02."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


ROWS = {
    "01-initial-set-never", "02-initial-set-auto", "03-initial-set-always",
    "04-dlopen-never", "05-dlopen-auto", "06-dlopen-always",
}
QUERY_KINDS = ("command.json", "context.json", "status", "stdout.json", "stderr")


def validate_terminal_tree(root: Path) -> None:
    required_dirs = {"bin", "prepared", "rows", "tokens"} | {
        f"rows/{row}" for row in ROWS
    }
    required_files = {
        "facts.log", "cargo-configs.tsv", "softhsm2.conf", "bin/p11scope",
        "bin/harness", "bin/harness-initial", "prepared/source.start.tsv",
        "prepared/source.end.tsv",
    }
    required_files |= {f"rows/{row}/observer.log" for row in ROWS}
    required_files |= {f"rows/{row}/checker.log" for row in ROWS}
    for phase in ("initial", "final"):
        required_files |= {
            f"prepared/lane02.{phase}.{context}.{kind}"
            for context in ("root", "bpf") for kind in QUERY_KINDS
        }
        required_files |= {
            f"prepared/lane02.{phase}.ledger.sha256",
            f"prepared/lane02.{phase}.receipt.json",
            f"prepared/source.{phase}.tracked.paths.z",
            f"prepared/source.{phase}.tracked.sorted.z",
            f"prepared/source.{phase}.tracked.ledger.sha256",
        }

    seen_dirs: set[str] = set()
    seen_files: set[str] = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        relative = os.path.relpath(directory, root)
        if relative != ".":
            seen_dirs.add(relative)
            if relative not in required_dirs and not relative.startswith("tokens/"):
                raise ValueError(f"foreign terminal directory: {relative}")
        for name in dirs + files:
            path = Path(directory, name)
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or stat.S_IMODE(mode) & 0o077:
                raise ValueError(f"unsafe terminal artifact: {path.relative_to(root)}")
        for name in files:
            path = Path(directory, name)
            relative_file = path.relative_to(root).as_posix()
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f"non-file terminal artifact: {relative_file}")
            if (
                relative_file not in required_files
                and not relative_file.startswith("tokens/")
                and relative_file not in {f"rows/{row}/observed.json" for row in ROWS}
            ):
                raise ValueError(f"foreign terminal file: {relative_file}")
            seen_files.add(relative_file)
    if not required_dirs.issubset(seen_dirs) or not required_files.issubset(seen_files):
        raise ValueError(
            "terminal evidence tree is incomplete: "
            f"missing_dirs={sorted(required_dirs - seen_dirs)}, "
            f"missing_files={sorted(required_files - seen_files)}"
        )


def main(arguments: list[str]) -> int:
    if len(arguments) != 2 or arguments[0] != "terminal-tree":
        print("usage: lane02-inputs.py terminal-tree EVIDENCE_ROOT", file=sys.stderr)
        return 2
    try:
        validate_terminal_tree(Path(arguments[1]))
    except (OSError, ValueError) as error:
        print(f"lane02 inputs: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
