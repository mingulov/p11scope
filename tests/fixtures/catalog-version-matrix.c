/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Catalog-only three-table surface. Full mode gives each retained 3.0 target
 * its actual standard export; partial mode keeps only the three getters.
 * The shared ABI matrix remains unchanged for its oversized/sparse tests. */
#include "../../crates/discover/tests/fixture/version_matrix.c"

#ifndef CATALOG_PARTIAL_EXPORTS
#define CATALOG_PARTIAL_EXPORTS 0
#endif

#if !CATALOG_PARTIAL_EXPORTS
/* The three acquisition functions already have their standard exports. */
#define A(name, target) extern __typeof__(target) name __attribute__((alias(#target)));
A(C_Initialize, s00)
A(C_Finalize, s01)
A(C_GetInfo, s02)
A(C_GetSlotList, s04)
A(C_GetSlotInfo, s05)
A(C_GetTokenInfo, s06)
A(C_GetMechanismList, s07)
A(C_GetMechanismInfo, s08)
A(C_InitToken, s09)
A(C_InitPIN, s10)
A(C_SetPIN, s11)
A(C_OpenSession, s12)
A(C_CloseSession, s13)
A(C_CloseAllSessions, s14)
A(C_GetSessionInfo, s15)
A(C_GetOperationState, s16)
A(C_SetOperationState, s17)
A(C_Login, s18)
A(C_Logout, s19)
A(C_CreateObject, s20)
A(C_CopyObject, s21)
A(C_DestroyObject, s22)
A(C_GetObjectSize, s23)
A(C_GetAttributeValue, s24)
A(C_SetAttributeValue, s25)
A(C_FindObjectsInit, s26)
A(C_FindObjects, s27)
A(C_FindObjectsFinal, s28)
A(C_EncryptInit, s29)
A(C_Encrypt, s30)
A(C_EncryptUpdate, s31)
A(C_EncryptFinal, s32)
A(C_DecryptInit, s33)
A(C_Decrypt, s34)
A(C_DecryptUpdate, s35)
A(C_DecryptFinal, s36)
A(C_DigestInit, s37)
A(C_Digest, s38)
A(C_DigestUpdate, s39)
A(C_DigestKey, s40)
A(C_DigestFinal, s41)
A(C_SignInit, s42)
A(C_Sign, s43)
A(C_SignUpdate, s44)
A(C_SignFinal, s45)
A(C_SignRecoverInit, s46)
A(C_SignRecover, s47)
A(C_VerifyInit, s48)
A(C_Verify, s49)
A(C_VerifyUpdate, s50)
A(C_VerifyFinal, s51)
A(C_VerifyRecoverInit, s52)
A(C_VerifyRecover, s53)
A(C_DigestEncryptUpdate, s54)
A(C_DecryptDigestUpdate, s55)
A(C_SignEncryptUpdate, s56)
A(C_DecryptVerifyUpdate, s57)
A(C_GenerateKey, s58)
A(C_GenerateKeyPair, s59)
A(C_WrapKey, s60)
A(C_UnwrapKey, s61)
A(C_DeriveKey, s62)
A(C_SeedRandom, s63)
A(C_GenerateRandom, s64)
A(C_GetFunctionStatus, s65)
A(C_CancelFunction, s66)
A(C_WaitForSlotEvent, s67)
A(C_LoginUser, s70)
A(C_SessionCancel, s71)
A(C_MessageEncryptInit, s72)
A(C_EncryptMessage, s73)
A(C_EncryptMessageBegin, s74)
A(C_EncryptMessageNext, s75)
A(C_MessageEncryptFinal, s76)
A(C_MessageDecryptInit, s77)
A(C_DecryptMessage, s78)
A(C_DecryptMessageBegin, s79)
A(C_DecryptMessageNext, s80)
A(C_MessageDecryptFinal, s81)
A(C_MessageSignInit, s82)
A(C_SignMessage, s83)
A(C_SignMessageBegin, s84)
A(C_SignMessageNext, s85)
A(C_MessageSignFinal, s86)
A(C_MessageVerifyInit, s87)
A(C_VerifyMessage, s88)
A(C_VerifyMessageBegin, s89)
A(C_VerifyMessageNext, s90)
A(C_MessageVerifyFinal, s91)
#undef A
#endif

/* The raw scanner correctly recovers useful entries beyond a version label
 * when their actual exports anchor them. This fixture promises exactly the
 * legacy 68, 2.40/68 and 3.0/92 surface: do not leave the shared matrix's dormant
 * 104-slot tails or partially mapped 3.1 table as additional observations.
 * fill() sets its private done guard before this pruning. Every later getter
 * calls that same guarded fill(), so none can repopulate the cleared data.
 * The owned driver completes this constructor and its getter before READY. */
__attribute__((constructor)) static void catalog_initialize(void) {
    fill();
    memset(legacy.functions + 68, 0,
           sizeof(legacy.functions) - 68 * sizeof(legacy.functions[0]));
    memset(t240.functions + 68, 0,
           sizeof(t240.functions) - 68 * sizeof(t240.functions[0]));
    memset(t30.functions + 92, 0,
           sizeof(t30.functions) - 92 * sizeof(t30.functions[0]));
    memset(&t31, 0, sizeof(t31));
    memset(&t32, 0, sizeof(t32));
    memset(&tfuture, 0, sizeof(tfuture));
    memset(&tunknown, 0, sizeof(tunknown));
    memset(&tbad, 0, sizeof(tbad));
    memset(stubs, 0, sizeof(stubs));
}
