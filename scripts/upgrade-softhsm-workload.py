#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""SoftHSM workload for the upgrade gates.

The parent keeps one long-lived PKCS#11 session user alive, performs a known
SHA-256 digest, and starts short-lived children that repeat the same known
call sequence.  The workload uses only the public Cryptoki ABI through
ctypes; no PIN, key material or payload bytes leave the process.
"""
from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
import tempfile
import time

CKF_SERIAL_SESSION = 1 << 1
CKF_RW_SESSION = 1 << 2
CKM_SHA256 = 0x250


class Mechanism(ctypes.Structure):
    _fields_ = [
        ("mechanism", ctypes.c_ulong),
        ("parameter", ctypes.c_void_p),
        ("parameter_len", ctypes.c_ulong),
    ]


def token_slot(library):
    count = ctypes.c_ulong()
    rv = library.C_GetSlotList(True, None, ctypes.byref(count))
    if rv != 0 or count.value == 0:
        raise RuntimeError(f"C_GetSlotList count rv=0x{rv:x} count={count.value}")
    slots = (ctypes.c_ulong * count.value)()
    rv = library.C_GetSlotList(True, slots, ctypes.byref(count))
    if rv != 0:
        raise RuntimeError(f"C_GetSlotList rv=0x{rv:x}")
    return slots[0]


def digest_once(library) -> None:
    session = ctypes.c_ulong()
    rv = library.C_OpenSession(token_slot(library), CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session))
    if rv != 0:
        raise RuntimeError(f"C_OpenSession rv=0x{rv:x}")
    try:
        mechanism = Mechanism(CKM_SHA256, None, 0)
        rv = library.C_DigestInit(session, ctypes.byref(mechanism))
        if rv != 0:
            raise RuntimeError(f"C_DigestInit rv=0x{rv:x}")
        data = ctypes.create_string_buffer(b"p11scope upgrade workload")
        digest = ctypes.create_string_buffer(32)
        digest_len = ctypes.c_ulong(32)
        rv = library.C_Digest(
            session,
            data,
            ctypes.c_ulong(len(data.raw)),
            digest,
            ctypes.byref(digest_len),
        )
        if rv != 0 or digest_len.value != 32:
            raise RuntimeError(f"C_Digest rv=0x{rv:x} len={digest_len.value}")
    finally:
        library.C_CloseSession(session)


def open_provider(path: str):
    library = ctypes.CDLL(path)
    rv = library.C_Initialize(None)
    if rv != 0:
        raise RuntimeError(f"C_Initialize rv=0x{rv:x}")
    return library


def prepare_token() -> tempfile.TemporaryDirectory:
    temporary = tempfile.TemporaryDirectory(prefix="p11scope-upgrade-softhsm-")
    root = temporary.name
    tokens = os.path.join(root, "tokens")
    os.mkdir(tokens, 0o700)
    config = os.path.join(root, "softhsm2.conf")
    with open(config, "w", encoding="utf-8") as handle:
        handle.write(
            f"directories.tokendir = {tokens}\n"
            "objectstore.backend = file\n"
            "log.level = ERROR\n"
            "slots.removable = true\n"
        )
    os.chmod(config, 0o600)
    os.environ["SOFTHSM2_CONF"] = config
    # The fixed test-only PINs initialize a disposable token; they are not
    # operator secrets and are never captured by the observer.
    subprocess.run(
        [
            "softhsm2-util",
            "--init-token", "--free", "--label", "p11scope-upgrade",
            "--pin", "24680", "--so-pin", "13579",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return temporary


def child(module: str) -> int:
    temporary = None
    if not os.environ.get("SOFTHSM2_CONF"):
        temporary = prepare_token()
    library = open_provider(module)
    try:
        digest_once(library)
    finally:
        library.C_Finalize(None)
        if temporary is not None:
            temporary.cleanup()
    return 0


def parent(module: str, interval: float) -> int:
    temporary = prepare_token()
    library = open_provider(module)
    print("ready", flush=True)
    deadline = time.monotonic() + 60
    next_child = 0.0
    children: list[subprocess.Popen] = []
    try:
        while time.monotonic() < deadline:
            digest_once(library)
            now = time.monotonic()
            if now >= next_child:
                children.append(
                    subprocess.Popen(
                        [sys.executable, __file__, "--module", module, "--child"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                )
                next_child = now + 0.45
            children = [row for row in children if row.poll() is None]
            time.sleep(interval)
    finally:
        library.C_Finalize(None)
        for row in children:
            row.wait(timeout=2)
        temporary.cleanup()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--interval", type=float, default=0.2)
    args = parser.parse_args()
    try:
        return child(args.module) if args.child else parent(args.module, args.interval)
    except (OSError, RuntimeError) as exc:
        print(f"upgrade workload: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
