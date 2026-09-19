#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record lane-13 tracked and prepared-source checksum snapshots."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from _loader import load_path


PATHSPECS = (
    ".cargo",
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "build_support",
    "rust-toolchain.toml",
    "src",
    "crates",
    "third-party",
    "scripts",
    "spike",
)


class SnapshotError(Exception):
    """A deterministic refusal while recording a source snapshot."""


def _load_merger(root: Path):
    path = root / "scripts/merge-checksum-ledgers.py"
    return load_path(path, "lane13_checksum_merger")


def _absolute(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise SnapshotError(f"{label} must be absolute: {path}")
    return path


def _regular_bytes(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SnapshotError(f"{label} cannot be inspected: {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SnapshotError(f"{label} must be a non-symlink regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise SnapshotError(f"{label} cannot be read: {path}: {error}") from error


def _hash_inventory(root: Path) -> list[tuple[str, str]]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--", *PATHSPECS],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise SnapshotError(f"tracked input inventory could not execute: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise SnapshotError(f"tracked input inventory returned status {result.returncode}: {detail}")
    raw_paths = [value for value in result.stdout.split(b"\0") if value]
    if not raw_paths:
        raise SnapshotError("tracked input inventory is empty")
    if len(raw_paths) != len(set(raw_paths)):
        raise SnapshotError("tracked input inventory contains duplicate paths")
    rows = []
    for raw in sorted(raw_paths):
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SnapshotError(f"tracked input path is not UTF-8: {error}") from error
        if relative.startswith("/") or "\\" in relative or any(
            component in ("", ".", "..") for component in relative.split("/")
        ):
            raise SnapshotError(f"tracked input path is not canonical: {relative!r}")
        value = _regular_bytes(root / relative, f"tracked input {relative}")
        rows.append((relative, hashlib.sha256(value).hexdigest()))
    return rows


def _ledger_bytes(rows: list[tuple[str, str]]) -> bytes:
    return "".join(f"{digest}  {relative}\n" for relative, digest in rows).encode("utf-8")


def snapshot(root: Path, phase: str, generated: Path, output: Path, facts: Path) -> None:
    generated = _absolute(generated, "generated ledger")
    output = _absolute(output, "snapshot output")
    facts = _absolute(facts, "facts output")
    if output.exists() or output.is_symlink():
        raise SnapshotError(f"snapshot output already exists: {output}")
    if facts.is_symlink() or (facts.exists() and not facts.is_file()):
        raise SnapshotError(f"facts output must be a non-symlink regular file: {facts}")
    generated_value = _regular_bytes(generated, "generated ledger")
    if not generated_value:
        raise SnapshotError("generated ledger is empty")
    merger = _load_merger(root)
    try:
        generated_rows = merger.parse_ledger(generated)
    except merger.LedgerError as error:
        raise SnapshotError(f"generated ledger: {error}") from error
    if not generated_rows:
        raise SnapshotError("generated ledger has no checksum rows")
    for relative, expected in generated_rows:
        value = _regular_bytes(root / relative, f"generated input {relative}")
        if hashlib.sha256(value).hexdigest() != expected:
            raise SnapshotError(f"generated input digest changed: {relative}")
    tracked_rows = _hash_inventory(root)
    try:
        output_parent = output.parent.lstat()
        facts_parent = facts.parent.lstat()
    except OSError as error:
        raise SnapshotError(f"snapshot parent cannot be inspected: {error}") from error
    if (
        stat.S_ISLNK(output_parent.st_mode)
        or not stat.S_ISDIR(output_parent.st_mode)
        or stat.S_ISLNK(facts_parent.st_mode)
        or not stat.S_ISDIR(facts_parent.st_mode)
    ):
        raise SnapshotError("snapshot parents must be non-symlink directories")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".lane13-tracked-", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_ledger_bytes(tracked_rows))
        temporary.chmod(0o600)
        try:
            merged = merger.merge_ledgers([temporary, generated])
        except merger.LedgerError as error:
            raise SnapshotError(f"source ledgers cannot be merged: {error}") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    if not merged:
        raise SnapshotError("merged input ledger is empty")
    output_value = _ledger_bytes(merged)
    facts_value = "".join(
        f"input_ledger_{phase}={digest} path={relative}\n"
        for relative, digest in merged
    ).encode("utf-8")
    try:
        with output.open("xb") as stream:
            stream.write(output_value)
        output.chmod(0o600)
        with facts.open("ab") as stream:
            stream.write(facts_value)
    except OSError as error:
        raise SnapshotError(f"cannot publish source snapshot: {error}") from error


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("snapshot")
    command.add_argument("--phase", choices=("start", "end"), required=True)
    command.add_argument("--generated-ledger", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--facts", type=Path, required=True)
    options = parser.parse_args(arguments)
    root = Path(__file__).resolve().parents[1]
    try:
        snapshot(root, options.phase, options.generated_ledger, options.output, options.facts)
    except SnapshotError as error:
        print(f"lane13-input-ledger: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
