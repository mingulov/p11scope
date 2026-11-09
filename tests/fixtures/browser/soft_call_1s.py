#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""One-call-per-second PIN-less SoftHSM slot-listing caller.

Test fixture (v0.6.0 F1 / v0.7.0 demo-bootstrap): keeps a
provider-active process on the given module so observer-first cells
must settle their scan seal over a late-arriving browser too. Opens
the module, initializes it, then calls C_GetSlotList
(tokenPresent=0, count-only) every ``interval`` seconds. No PINs,
keys, payloads, or argv/env reads; stdout carries READY/CALLS/STOP
lines only. Exits after ``--max-calls`` when given (self-limiting
under test crashes); SIGTERM/SIGINT stop cleanly.
"""

import ctypes
import os
import signal
import sys
import time

STOP = False


def _on_term(signum, frame):
    global STOP
    STOP = True


def main(argv):
    module = argv[1] if len(argv) > 1 else "/usr/lib64/pkcs11/libsofthsm2.so"
    interval = float(argv[2]) if len(argv) > 2 else 1.0
    max_calls = int(argv[3]) if len(argv) > 3 else 0
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    lib = ctypes.CDLL(module)
    lib.C_Initialize.argtypes = [ctypes.c_void_p]
    lib.C_Initialize.restype = ctypes.c_ulong
    lib.C_Finalize.argtypes = [ctypes.c_void_p]
    lib.C_Finalize.restype = ctypes.c_ulong
    lib.C_GetSlotList.argtypes = [
        ctypes.c_ubyte,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    lib.C_GetSlotList.restype = ctypes.c_ulong
    rv = lib.C_Initialize(None)
    if rv != 0:
        print(f"INIT rv={rv}", flush=True)
        return 2
    print(f"READY module={module} interval={interval} pid={os.getpid()}", flush=True)
    count = ctypes.c_ulong(0)
    n = 0
    while not STOP and (max_calls <= 0 or n < max_calls):
        count.value = 0
        rv = lib.C_GetSlotList(0, None, ctypes.byref(count))
        n += 1
        if n % 30 == 0:
            print(f"CALLS n={n} last_rv={rv} slots={count.value}", flush=True)
        time.sleep(interval)
    lib.C_Finalize(None)
    print(f"STOP n={n}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
