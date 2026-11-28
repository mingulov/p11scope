#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""SoftHSM workload for the upgrade gates.

The parent keeps one long-lived PKCS#11 session user alive, performs a known
SHA-256 digest, and starts exactly CHILD_COUNT short-lived children that
repeat the same known call sequence.  Children run under a copy of the
interpreter at a stable path so old and new captures group them identically
while keeping them a separate application group from the long-lived parent.
The fixed count (not cadence-until-deadline) makes admission accounting
deterministic: every run spawns parent + CHILD_COUNT, so gate 6 compares
exact caller/entries closure instead of timing jitter.  The workload uses
only the public Cryptoki ABI through ctypes; no PIN, key material or
payload bytes leave the process.

The parent also emits a ground-truth LEDGER: one typed record per child
(pid, start time, the calls it made, exit status) plus a final record
(children spawned, children completed).  Records are written
incrementally at reap time (the gate kills the parent after capture, so
an end-of-run write would never land); each write is atomic.  The gate
refuses when the ledger is missing, incomplete, or short.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CHILD_COUNT = 10
FIRST_CHILD_DELAY_S = 8.0
CHILD_INTERVAL_S = 0.7
CHILD_DIGESTS = 8
CHILD_DIGEST_INTERVAL_S = 1.0
CALLS_PER_DIGEST = [
    "C_GetSlotList",
    "C_GetSlotList",
    "C_OpenSession",
    "C_DigestInit",
    "C_Digest",
    "C_CloseSession",
]
LEDGER_VERSION = 1

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


def run_child_digests(
    library, count=CHILD_DIGESTS, interval=CHILD_DIGEST_INTERVAL_S
) -> None:
    """Digest repeatedly across the child lifetime so post-admission calls
    are observed. Admission (custody proof, image settle, route binding)
    needs several passes: 2s-lived children shed every call as
    use_before_admission, so children live ~8s with digests spread across
    it. Still short-lived (3x under the 24s capture) and still folded."""
    for _ in range(count):
        digest_once(library)
        time.sleep(interval)


def child(module: str) -> int:
    temporary = None
    if not os.environ.get("SOFTHSM2_CONF"):
        temporary = prepare_token()
    library = open_provider(module)
    try:
        # Stay mapped long enough for several capture passes to observe this
        # caller alive, then exit so the new binary folds it into departed_use
        # while the old binary keeps it a live row. Digests repeat during the
        # lifetime so child usage is measured, not a single pre-admission call
        # that can never be observed.
        run_child_digests(library)
    finally:
        library.C_Finalize(None)
        if temporary is not None:
            temporary.cleanup()
    return 0


def write_json_atomic(path: Path, document: dict) -> None:
    """Write one JSON document atomically (a killed parent leaves either
    the previous complete file or the new one, never a torn write)."""
    staging = path.parent / (path.name + ".tmp")
    staging.write_text(json.dumps(document), encoding="utf-8")
    os.replace(staging, path)


def parent(module: str, interval: float, child_python: str,
           ledger_dir: str) -> int:
    ledger_path = Path(ledger_dir)
    ledger_path.mkdir(parents=True, exist_ok=True)
    temporary = prepare_token()
    library = open_provider(module)
    shutil.copyfile(sys.executable, child_python)
    os.chmod(child_python, 0o755)
    # The copy cannot resolve the installation prefix from its own path, so
    # children inherit the parent's working prefix explicitly.
    child_env = dict(os.environ)
    child_env["PYTHONHOME"] = sys.base_prefix
    probe = subprocess.run(
        [child_python, __file__, "--module", module, "--child"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env=child_env,
    )
    if probe.returncode != 0:
        raise RuntimeError(f"churn child probe failed: {probe.stderr[:200]}")
    # The probe is pre-capture setup, not workload truth: it exits before
    # the observer attaches, so it is deliberately not ledgered.
    print("ready", flush=True)
    deadline = time.monotonic() + 60
    # First spawn waits out cgroup setup and observer attach (first pass
    # lands ~5s in; a child born earlier can exit unseen and break exact
    # closure). With delay 8.0 + 10 children at 0.7s cadence every child is
    # born inside the capture after attach settled, lives ~8s across
    # several passes, and exits with its record reaped before the gate
    # kills the parent after the 24s capture; after CHILD_COUNT the
    # parent idles. Births stay after attach + 5s, so the ledger's
    # before-admission set is empty by construction.
    next_child = time.monotonic() + FIRST_CHILD_DELAY_S
    spawned = 0
    live: list[tuple[int, subprocess.Popen, float, float]] = []
    completed: list[int] = []
    crashed: list[dict] = []

    def record_reap(index: int, row: subprocess.Popen,
                    start_mono: float, start_wall: float) -> None:
        code = row.poll()
        if code is None:
            return
        if code == 0:
            completed.append(index)
        else:
            crashed.append(
                {"index": index, "pid": row.pid, "exit_code": code})
        write_json_atomic(
            ledger_path / f"child-{index:02d}.json",
            {
                "ledger_version": LEDGER_VERSION,
                "index": index,
                "pid": row.pid,
                "start_mono": start_mono,
                "start_wall": start_wall,
                "digests_completed": CHILD_DIGESTS if code == 0 else None,
                "calls_per_digest": list(CALLS_PER_DIGEST),
                "exit_code": code,
            },
        )
        write_json_atomic(
            ledger_path / "final.json",
            {
                "ledger_version": LEDGER_VERSION,
                "child_count": CHILD_COUNT,
                "spawned": spawned,
                "completed": len(completed),
                "children": sorted(completed),
                "crashed": list(crashed),
                "workload_pid": os.getpid(),
            },
        )

    try:
        while time.monotonic() < deadline:
            digest_once(library)
            now = time.monotonic()
            if spawned < CHILD_COUNT and now >= next_child:
                row = subprocess.Popen(
                    [child_python, __file__, "--module", module, "--child"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=child_env,
                )
                live.append((spawned, row, now, time.time()))
                spawned += 1
                next_child = now + CHILD_INTERVAL_S
            still_live = []
            for entry in live:
                record_reap(*entry)
                if entry[1].poll() is None:
                    still_live.append(entry)
            live = still_live
            time.sleep(interval)
    finally:
        library.C_Finalize(None)
        for _, row, _, _ in live:
            row.wait(timeout=6)
        temporary.cleanup()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--child-python", default="")
    parser.add_argument("--ledger-dir", default="")
    parser.add_argument("--interval", type=float, default=0.2)
    args = parser.parse_args()
    try:
        if args.child:
            return child(args.module)
        if not args.child_python:
            raise RuntimeError("parent mode requires --child-python")
        if not args.ledger_dir:
            raise RuntimeError("parent mode requires --ledger-dir")
        return parent(
            args.module, args.interval, args.child_python, args.ledger_dir)
    except (OSError, RuntimeError) as exc:
        print(f"upgrade workload: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
