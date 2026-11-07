#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Insert the project copyright line beside first-party SPDX headers.

Prepared for the end-of-integration per-file pass; not yet applied to
this checkout. For every tracked file whose license header sits on line
1 (line 2 after a kept-as-is interpreter line), the script inserts one
line right below it reusing the header's own comment affixes:

    SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>

Only that header position is ever touched: SPDX mentions quoted inside
strings, templates or patches are reported as unhandled, never edited.
Files that already carry any copyright notice keep it untouched, and
vendored, upstream and generated paths are skipped outright.

Usage:
  python3 -I scripts/add-copyright-headers.py [--root DIR] [--verbose]
  python3 -I scripts/add-copyright-headers.py --apply [--root DIR]

Without --apply nothing is written; the report lists the files the
script could not handle plus a summary count line.
"""

import argparse
import subprocess
import sys
from pathlib import Path

NOTICE = "SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>"
IDENTIFIER = b"SPDX-License-Identifier:"
BOM = b"\xef\xbb\xbf"

# Header prefix -> allowed suffixes, as bytes. Every other shape is
# reported as unhandled for a human to place by hand.
STYLES = {
    b"//! ": (b"",),
    b"// ": (b"",),
    b"# ": (b"",),
    b"/* ": (b" */",),
    b"<!-- ": (b" -->",),
}

# Vendored or upstream trees: patched dependencies, pinned notice
# originals and patch files. Nothing under these is first-party.
SKIP_DIR_PREFIXES = ("third-party/", "preserved/")
# Fixtures copied from upstream keep their own notices; stamping them
# with the project line would misattribute them.
UPSTREAM_FIXTURE_PREFIXES = (
    "tests/fixtures/lane13-evidence/releases/",
    "tests/fixtures/vng-kernel-sha256sums/",
)
# Generated manifests carry no header by convention.
GENERATED_SUFFIXES = (".lock", ".sums")


def plan_for(path, content):
    """Decide what the pass does with one file.

    Returns (action, new_bytes, reason) where action is "change" (with
    the rewritten bytes), "already", "skip" or "unhandled" (both with
    None bytes and a human-readable reason).
    """
    for prefix in SKIP_DIR_PREFIXES:
        if path.startswith(prefix):
            return ("skip", None, "vendored or upstream tree")
    for prefix in UPSTREAM_FIXTURE_PREFIXES:
        if path.startswith(prefix):
            return ("skip", None, "upstream fixture keeps its notices")
    for suffix in GENERATED_SUFFIXES:
        if path.endswith(suffix):
            return ("skip", None, "generated file")
    if b"\x00" in content:
        return ("skip", None, "binary file")
    if NOTICE.encode() in content:
        return ("already", None, "copyright line present")
    if b"SPDX-FileCopyrightText" in content:
        return ("skip", None, "keeps existing copyright notice")
    lines = content.split(b"\n")
    first = lines[0][len(BOM):] if lines[0].startswith(BOM) else lines[0]
    index = 1 if first.startswith(b"#!") else 0
    if index >= len(lines):
        return ("unhandled", None, "no SPDX header on line 2")
    raw = lines[index]
    body = raw[:-1] if raw.endswith(b"\r") else raw
    if index == 0 and body.startswith(BOM):
        body = body[len(BOM):]
    if IDENTIFIER not in body:
        if IDENTIFIER in content:
            return ("unhandled", None, f"no SPDX header on line {index + 1}")
        return ("skip", None, "no SPDX header")
    prefix, _, rest = body.partition(IDENTIFIER)
    if not rest.startswith(b" "):
        return ("unhandled", None, "unrecognized SPDX header shape")
    expression, separator, tail = rest[1:].partition(b" ")
    suffix = separator + tail
    if not expression or prefix not in STYLES or suffix not in STYLES[prefix]:
        return ("unhandled", None, "unrecognized SPDX header shape")
    eol = b"\r\n" if raw.endswith(b"\r") else b"\n"
    inserted = prefix + NOTICE.encode() + suffix + eol
    if index == len(lines) - 1:
        return ("change", content + eol + inserted, "copyright line added")
    offset = sum(len(line) + 1 for line in lines[: index + 1])
    return ("change", content[:offset] + inserted + content[offset:], "copyright line added")


def tracked_files(root):
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise OSError(f"git ls-files failed under {root}: "
                      f"{result.stderr.decode('utf-8', 'replace').strip()}")
    return [entry for entry in result.stdout.decode("utf-8").split("\0") if entry]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="write the insertions (default: dry run)")
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1],
                        help="tree to scan (default: this checkout)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="list every file decision, not just unhandled ones")
    args = parser.parse_args(argv)
    try:
        paths = tracked_files(args.root)
    except OSError as error:
        print(f"add-copyright-headers: {error}", file=sys.stderr)
        return 2
    print(f"add-copyright-headers: root={args.root} "
          f"mode={'apply' if args.apply else 'dry-run'}")
    tally = {"change": 0, "already": 0, "skipped": 0, "unhandled": 0}
    unhandled = []
    for path in paths:
        try:
            content = (args.root / path).read_bytes()
        except OSError as error:
            action, reason = "unhandled", f"unreadable: {error}"
            unhandled.append((path, reason))
            tally["unhandled"] += 1
            if args.verbose:
                print(f"{action}: {path}: {reason}")
            continue
        action, new_bytes, reason = plan_for(path, content)
        if action == "change":
            tally["change"] += 1
            if args.apply:
                (args.root / path).write_bytes(new_bytes)
        elif action == "already":
            tally["already"] += 1
        elif action == "skip":
            tally["skipped"] += 1
        else:
            tally["unhandled"] += 1
            unhandled.append((path, reason))
        if args.verbose or action == "unhandled":
            print(f"{action}: {path}: {reason}")
    print(f"summary: change={tally['change']} already={tally['already']} "
          f"skipped={tally['skipped']} unhandled={tally['unhandled']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
