#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Merge strict repository-relative SHA-256 checksum ledgers."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys
import unicodedata


HEX_DIGITS = frozenset("0123456789abcdef")


class LedgerError(Exception):
    """A malformed or unsafe ledger input."""


def _read_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LedgerError(f"cannot inspect input {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise LedgerError(f"input is a symlink, not a regular file: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise LedgerError(f"input is not a regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise LedgerError(f"cannot read input {path}: {error}") from error


def _canonical_path(value: str, source: Path, row_number: int) -> str:
    label = f"{source}: row {row_number}"
    if not value:
        raise LedgerError(f"{label}: path is empty")
    if value.startswith("/"):
        raise LedgerError(f"{label}: path must be repository-relative")
    if "\\" in value:
        raise LedgerError(f"{label}: path contains a backslash")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise LedgerError(f"{label}: path contains a control or DEL character")
    components = value.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise LedgerError(f"{label}: path is not canonical POSIX spelling: {value!r}")
    return value


def parse_ledger(path: Path) -> list[tuple[str, str]]:
    """Parse one strict ledger, returning path/digest pairs in input order."""
    content = _read_regular_file(path)
    if content and not content.endswith(b"\n"):
        raise LedgerError(f"input {path} is missing its trailing LF")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LedgerError(f"input {path} is not valid UTF-8: {error}") from error
    rows = []
    for row_number, row in enumerate(text.split("\n")[:-1], start=1):
        if not row:
            continue
        if (
            len(row) < 66
            or len(row[:64]) != 64
            or any(character not in HEX_DIGITS for character in row[:64])
            or row[64:66] != "  "
        ):
            raise LedgerError(f"{path}: row {row_number}: invalid digest or separator")
        digest = row[:64]
        repository_path = _canonical_path(row[66:], path, row_number)
        rows.append((repository_path, digest))
    return rows


def merge_ledgers(paths: list[Path]) -> list[tuple[str, str]]:
    """Parse all inputs and return unique rows sorted by UTF-8 path bytes."""
    merged = {}
    for path in paths:
        for repository_path, digest in parse_ledger(path):
            if repository_path in merged:
                raise LedgerError(f"input {path}: duplicate path in checksum ledgers: {repository_path}")
            merged[repository_path] = digest
    return sorted(merged.items(), key=lambda item: item[0].encode("utf-8"))


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", type=Path, nargs="+")
    options = parser.parse_args(arguments)
    try:
        rows = merge_ledgers(options.files)
    except LedgerError as error:
        print(f"merge-checksum-ledgers: refusal: {error}", file=sys.stderr)
        return 1
    output = "".join(f"{digest}  {repository_path}\n" for repository_path, digest in rows)
    sys.stdout.buffer.write(output.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
