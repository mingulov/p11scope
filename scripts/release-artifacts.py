#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind the four release artifacts to a canonical SHA256SUMS ledger."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


ARTIFACTS = (
    "p11scope", "p11scope-discover", "p11scope-discover-glibc",
    "p11scope-discover-musl",
)


def _directory(path: Path) -> None:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError(f"artifact directory must be absolute and canonical: {path}")
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError(f"artifact directory is not a directory: {path}")


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def _read(path: Path, *, ledger: bool = False):
    # O_NONBLOCK prevents a substituted FIFO from hanging before fstat; no
    # symlink is followed and the name must still identify the opened file.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"release artifact is not a regular file: {path}")
        if ledger and before.st_size > 4096:
            raise ValueError("release artifact ledger is too large")
        digest = hashlib.sha256()
        content = bytearray()
        while block := stream.read(1024 * 1024):
            digest.update(block)
            if ledger:
                content.extend(block)
                if len(content) > 4096:
                    raise ValueError("release artifact ledger is too large")
        if (_identity(before) != _identity(os.fstat(stream.fileno()))
                or _identity(before) != _identity(path.lstat())):
            raise ValueError(f"release artifact changed while reading: {path}")
        return bytes(content) if ledger else digest.hexdigest()


def _digests(dist: Path) -> dict[str, str]:
    _directory(dist)
    before = dist.stat()
    if {entry.name for entry in dist.iterdir()} != set(ARTIFACTS):
        raise ValueError("release artifact directory must contain exactly the four expected files")
    digests = {name: _read(dist / name) for name in ARTIFACTS}
    if digests["p11scope-discover"] != digests["p11scope-discover-glibc"]:
        raise ValueError("release artifact helper alias differs from the glibc helper")
    _directory(dist)
    if _identity(before) != _identity(dist.stat()):
        raise ValueError("release artifact directory changed while reading")
    return digests


def _encode(digests: dict[str, str]) -> bytes:
    return "".join(f"{digests[name]}  {name}\n" for name in ARTIFACTS).encode("ascii")


def verify(dist: Path, ledger: Path, expected_digest: str) -> dict[str, str]:
    """Verify receipt-bound bytes, returning basename -> SHA256 on success.

    Raises ValueError or OSError on malformed, replaced, or changed inputs.
    The expected digest must come from the receipt's single
    release_artifacts_sha256 fact, not from the ledger being verified.
    """
    if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise ValueError("invalid release artifact ledger digest")
    _directory(ledger.parent)
    content = _read(ledger, ledger=True)
    if hashlib.sha256(content).hexdigest() != expected_digest:
        raise ValueError("release artifact ledger digest mismatch")
    digests = _digests(dist)
    # Exact serialization rejects duplicate, missing, unknown, reordered,
    # noncanonical and changed rows without accepting alternate parser forms.
    if content != _encode(digests):
        raise ValueError("release artifact ledger does not match the exact artifact bytes")
    return digests


def record(dist: Path, ledger: Path) -> str:
    """Create a new 0600 ledger; never replace an existing receipt file."""
    _directory(ledger.parent)
    content = _encode(_digests(dist))
    descriptor = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    digest = hashlib.sha256(content).hexdigest()
    verify(dist, ledger, digest)
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("record", "verify"))
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--sha256")
    options = parser.parse_args()
    if (options.operation == "verify") != (options.sha256 is not None):
        parser.error("--sha256 is required only for verify")
    try:
        if options.operation == "record":
            digest = record(options.dist, options.ledger)
        else:
            verify(options.dist, options.ledger, options.sha256)
            digest = options.sha256
        print(digest)
    except (ValueError, OSError) as error:
        print(f"release-artifacts: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
