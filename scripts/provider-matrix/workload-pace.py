#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Paced PKCS#11 workload for the provider-matrix inventory leg.

One persistent process: dlopen the provider, C_Initialize, write the READY
file, then loop C_GetSlotList/C_GetSlotInfo/C_GetTokenInfo with a sleep
between iterations (paced callers are admitted; a burst under half a
second is invisible), then C_Finalize. No login, no PINs, no objects.

Usage: workload-pace.py --module PATH --ready PATH
    [--iterations N] [--interval SECONDS]

Exit 0 when every iteration ran, 2 when the provider did not initialise.
SIGTERM finalises quietly and exits 0 (the cell stops the workload once
the inventory window closes).
"""

import argparse
import ctypes
import signal
import sys
import time

CK_RV = ctypes.c_ulong
CK_SLOT_ID = ctypes.c_ulong
CK_ULONG = ctypes.c_ulong
CK_BBOOL = ctypes.c_ubyte

# The 68-entry standard function-list order (PKCS#11 v3.2 §5.5).
FN_NAMES = (
    "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo",
    "C_GetMechanismList", "C_GetMechanismInfo", "C_InitToken",
    "C_InitPIN", "C_SetPIN", "C_OpenSession", "C_CloseSession",
    "C_CloseAllSessions", "C_GetSessionInfo", "C_GetOperationState",
    "C_SetOperationState", "C_Login", "C_Logout", "C_CreateObject",
    "C_CopyObject", "C_DestroyObject", "C_GetObjectSize",
    "C_GetAttributeValue", "C_SetAttributeValue", "C_FindObjectsInit",
    "C_FindObjects", "C_FindObjectsFinal", "C_EncryptInit", "C_Encrypt",
    "C_EncryptUpdate", "C_EncryptFinal", "C_DecryptInit", "C_Decrypt",
    "C_DecryptUpdate", "C_DecryptFinal", "C_DigestInit", "C_Digest",
    "C_DigestUpdate", "C_DigestKey", "C_DigestFinal", "C_SignInit",
    "C_Sign", "C_SignUpdate", "C_SignFinal", "C_SignRecoverInit",
    "C_SignRecover", "C_VerifyInit", "C_Verify", "C_VerifyUpdate",
    "C_VerifyFinal", "C_VerifyRecoverInit", "C_VerifyRecover",
    "C_DigestEncryptUpdate", "C_DecryptDigestUpdate", "C_SignEncryptUpdate",
    "C_DecryptVerifyUpdate", "C_GenerateKey", "C_GenerateKeyPair",
    "C_WrapKey", "C_UnwrapKey", "C_DeriveKey", "C_SeedRandom",
    "C_GenerateRandom", "C_GetFunctionStatus", "C_CancelFunction",
    "C_WaitForSlotEvent",
)
assert len(FN_NAMES) == 68


class CK_VERSION(ctypes.Structure):
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class CK_FUNCTION_LIST(ctypes.Structure):
    _fields_ = [("version", CK_VERSION)] + [
        (name, ctypes.c_void_p) for name in FN_NAMES]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--iterations", type=int, default=60)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args(argv)

    lib = ctypes.CDLL(args.module)
    lib.C_GetFunctionList.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    lib.C_GetFunctionList.restype = CK_RV
    fnlist_ptr = ctypes.c_void_p()
    rv = lib.C_GetFunctionList(ctypes.byref(fnlist_ptr))
    if rv != 0 or not fnlist_ptr.value:
        print(f"workload-pace: C_GetFunctionList rv={rv:#x}", flush=True)
        return 2
    fns = ctypes.cast(fnlist_ptr, ctypes.POINTER(CK_FUNCTION_LIST)).contents
    print(f"workload-pace: function list "
          f"{fns.version.major}.{fns.version.minor}", flush=True)

    c_initialize = ctypes.CFUNCTYPE(CK_RV, ctypes.c_void_p)(
        fns.C_Initialize)
    c_finalize = ctypes.CFUNCTYPE(CK_RV, ctypes.c_void_p)(fns.C_Finalize)
    c_get_slot_list = ctypes.CFUNCTYPE(
        CK_RV, CK_BBOOL, ctypes.POINTER(CK_SLOT_ID),
        ctypes.POINTER(CK_ULONG))(fns.C_GetSlotList)
    c_get_slot_info = ctypes.CFUNCTYPE(
        CK_RV, CK_SLOT_ID, ctypes.c_void_p)(fns.C_GetSlotInfo)
    c_get_token_info = ctypes.CFUNCTYPE(
        CK_RV, CK_SLOT_ID, ctypes.c_void_p)(fns.C_GetTokenInfo)

    rv = c_initialize(None)
    if rv != 0:
        print(f"workload-pace: C_Initialize rv={rv:#x}", flush=True)
        return 2

    stop = {"flag": False}

    def on_term(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, on_term)
    with open(args.ready, "w", encoding="utf-8") as handle:
        handle.write("ready\n")

    slots_seen = 0
    ran = 0
    for _ in range(args.iterations):
        if stop["flag"]:
            break
        count = CK_ULONG(0)
        rv = c_get_slot_list(0, None, ctypes.byref(count))
        if rv == 0 and count.value:
            slots = (CK_SLOT_ID * count.value)()
            rv = c_get_slot_list(0, slots, ctypes.byref(count))
            if rv == 0:
                slots_seen = max(slots_seen, count.value)
                for slot in list(slots)[:4]:
                    c_get_slot_info(slot, ctypes.create_string_buffer(256))
                    c_get_token_info(slot, ctypes.create_string_buffer(1024))
        ran += 1
        time.sleep(args.interval)
    c_finalize(None)
    print(f"workload-pace: {ran} iterations, {slots_seen} slots seen",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
