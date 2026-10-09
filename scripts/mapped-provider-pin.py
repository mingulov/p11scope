#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Hash a held provider FD and independently anchor its /proc/maps identity.

As in discovery::identity and manifest::KernelSelfMappingProbe, fstat identity
is a separate domain: Btrfs st_dev can differ from the device maps renders.
Never obtain the expected mapped device from a fixture or capture report.
"""

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import sys

MAX_MAPS_BYTES = 8 * 1024 * 1024
MAPS_LINE = re.compile(
    r"([0-9a-f]+)-([0-9a-f]+)\s+([r-][w-][x-][ps])\s+"
    r"([0-9a-f]+)\s+([0-9a-f]+):([0-9a-f]+)\s+([0-9]+)(?:\s+.*)?")


def file_identity(info):
    return {"dev": [os.major(info.st_dev), os.minor(info.st_dev)],
            "ino": info.st_ino, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def maps_anchor(text, address, length, inode):
    matches = []
    for line in text.splitlines():
        row = MAPS_LINE.fullmatch(line)
        if row is None:
            raise ValueError("malformed self maps line")
        low, high = (int(row[i], 16) for i in (1, 2))
        if high <= low:
            raise ValueError("invalid self maps range")
        if low <= address < high:
            if (address + length > high or row[3] != "r--p"
                    or int(row[4], 16) + address - low != 0
                    or int(row[7]) != inode):
                raise ValueError("self mapping is not the held FD offset-zero anchor")
            matches.append({"dev": [int(row[5], 16), int(row[6], 16)],
                            "ino": int(row[7]), "file_offset": 0,
                            "length": length, "permissions": row[3]})
    if len(matches) != 1:
        raise ValueError("missing or duplicate self mapping anchor")
    return matches[0]


def mapping_from_fd(fd, size):
    length = min(os.sysconf("SC_PAGESIZE"), size)
    if length <= 0:
        raise ValueError("provider has no mappable bytes")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    # PROT_READ, MAP_PRIVATE, offset zero; provider code is never executable.
    address = libc.mmap(None, length, 1, 2, fd, 0)
    if address == ctypes.c_void_p(-1).value:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    try:
        with open("/proc/self/maps", encoding="utf-8") as stream:
            text = stream.read(MAX_MAPS_BYTES + 1)
        if len(text) > MAX_MAPS_BYTES:
            raise ValueError("self maps exceeds size limit")
        return maps_anchor(text, address, length, os.fstat(fd).st_ino)
    finally:
        if libc.munmap(address, length) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))


def pin_fd(fd):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise ValueError("provider must be a nonempty regular file")
    anchor = mapping_from_fd(fd, before.st_size)
    digest = hashlib.sha256()
    offset = 0
    while chunk := os.pread(fd, 1024 * 1024, offset):
        digest.update(chunk)
        offset += len(chunk)
        if offset > before.st_size:
            raise ValueError("provider grew during hash")
    after = os.fstat(fd)
    if offset != before.st_size or file_identity(before) != file_identity(after):
        raise ValueError("provider changed or short read during pin")
    if anchor["ino"] != before.st_ino:
        raise ValueError("provider inode changed during mapping")
    return {"dev": anchor["dev"], "ino": anchor["ino"],
            "sha256": digest.hexdigest(), "mapping": anchor,
            "file_identity": file_identity(before)}


def pin(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        return pin_fd(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider")
    args = parser.parse_args()
    try:
        print(json.dumps(pin(args.provider)))
    except (OSError, ValueError) as error:
        print("provider pin failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
