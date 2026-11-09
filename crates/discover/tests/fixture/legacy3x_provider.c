/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Legacy-only provider stamped with a 3.x version, the Fedora SoftHSM 2.7
 * shape: the frozen 68-slot CK_FUNCTION_LIST carries the library version
 * (STAMP_MAJOR.STAMP_MINOR), every slot is a distinct exported C_ function,
 * and the module exports no C_GetInterfaceList/C_GetInterface at all. Words
 * past slot 68 are adjacent static data, not table: two executable words
 * then unmapped-looking constants, the observed Fedora tail, so the first
 * structural failure is ordinal 70.
 *
 * Test-only knobs for the negative twins:
 *   -DWITH_GETTER   also export a C_GetInterface stub (a conforming 3.x
 *                   route exists, so the 68-slot prefix is not proven);
 *   -DEXEC_TAIL24   24 executable tail words, then data at ordinal 92 (the
 *                   92-wide layout is not refuted). */
#include <stddef.h>
#include <stdint.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;

#ifndef STAMP_MAJOR
#define STAMP_MAJOR 3
#endif
#ifndef STAMP_MINOR
#define STAMP_MINOR 2
#endif

#define STUB(name) CK_RV name(void) { return 6; }
STUB(C_Initialize)
STUB(C_Finalize)
STUB(C_GetInfo)
STUB(C_GetSlotList)
STUB(C_GetSlotInfo)
STUB(C_GetTokenInfo)
STUB(C_GetMechanismList)
STUB(C_GetMechanismInfo)
STUB(C_InitToken)
STUB(C_InitPIN)
STUB(C_SetPIN)
STUB(C_OpenSession)
STUB(C_CloseSession)
STUB(C_CloseAllSessions)
STUB(C_GetSessionInfo)
STUB(C_GetOperationState)
STUB(C_SetOperationState)
STUB(C_Login)
STUB(C_Logout)
STUB(C_CreateObject)
STUB(C_CopyObject)
STUB(C_DestroyObject)
STUB(C_GetObjectSize)
STUB(C_GetAttributeValue)
STUB(C_SetAttributeValue)
STUB(C_FindObjectsInit)
STUB(C_FindObjects)
STUB(C_FindObjectsFinal)
STUB(C_EncryptInit)
STUB(C_Encrypt)
STUB(C_EncryptUpdate)
STUB(C_EncryptFinal)
STUB(C_DecryptInit)
STUB(C_Decrypt)
STUB(C_DecryptUpdate)
STUB(C_DecryptFinal)
STUB(C_DigestInit)
STUB(C_Digest)
STUB(C_DigestUpdate)
STUB(C_DigestKey)
STUB(C_DigestFinal)
STUB(C_SignInit)
STUB(C_Sign)
STUB(C_SignUpdate)
STUB(C_SignFinal)
STUB(C_SignRecoverInit)
STUB(C_SignRecover)
STUB(C_VerifyInit)
STUB(C_Verify)
STUB(C_VerifyUpdate)
STUB(C_VerifyFinal)
STUB(C_VerifyRecoverInit)
STUB(C_VerifyRecover)
STUB(C_DigestEncryptUpdate)
STUB(C_DecryptDigestUpdate)
STUB(C_SignEncryptUpdate)
STUB(C_DecryptVerifyUpdate)
STUB(C_GenerateKey)
STUB(C_GenerateKeyPair)
STUB(C_WrapKey)
STUB(C_UnwrapKey)
STUB(C_DeriveKey)
STUB(C_SeedRandom)
STUB(C_GenerateRandom)
STUB(C_GetFunctionStatus)
STUB(C_CancelFunction)
STUB(C_WaitForSlotEvent)
#ifdef WITH_GETTER
STUB(C_GetInterface)
#endif
#undef STUB

CK_RV C_GetFunctionList(void **out);

/* 68 slots in catalog ordinal order, then the non-table tail. */
static struct {
    CK_VERSION version;
    void *slots[68];
    void *tail[36];
} table = {
    {STAMP_MAJOR, STAMP_MINOR},
    { C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN, C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo, C_GetOperationState, C_SetOperationState, C_Login, C_Logout, C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal, C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal, C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal, C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal, C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, C_SignRecoverInit, C_SignRecover, C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal, C_VerifyRecoverInit, C_VerifyRecover, C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate, C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey, C_SeedRandom, C_GenerateRandom, C_GetFunctionStatus, C_CancelFunction, C_WaitForSlotEvent },
#ifdef EXEC_TAIL24
    { [0 ... 23] = (void *)C_Initialize,
      [24 ... 35] = (void *)(uintptr_t)0xa5a5a5a5a5a5a5a5UL },
#else
    { (void *)C_Initialize, (void *)C_Finalize, (void *)(uintptr_t)7,
      [3 ... 35] = (void *)(uintptr_t)0xa5a5a5a5a5a5a5a5UL },
#endif
};

CK_RV C_GetFunctionList(void **out) {
    if (!out) return 7;
    *out = &table;
    return 0;
}
