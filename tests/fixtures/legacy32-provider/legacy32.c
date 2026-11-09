/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* legacy32: a SoftHSM 2.7-shaped synthetic PKCS#11 provider.
 *
 * Shape (matches Fedora 44 softhsm-2.7.0-0.1.rc1 as read from the
 * installed library: table version {3,2} over a 68-slot 2.x function
 * list, no C_GetInterface/C_GetInterfaceList exports):
 *   - C_GetFunctionList publishes exactly 68 ordered slots, labelled
 *     {3,2} (overridable with -DLEGACY32_MAJOR= -DLEGACY32_MINOR= for
 *     negative controls; the {3,0} variant is the documented one).
 *     Further negative controls for the --shape-only gate suite
 *     (tests/python/test_legacy32_shape.py), each failing exactly one
 *     gate while every earlier gate still holds: -DLEGACY32_NULL_SLOT66
 *     (NULL slot), -DLEGACY32_ALIAS_SLOT66 (two slots share one
 *     function), -DLEGACY32_EXPORT_INTERFACE (C_GetInterface defined),
 *     -DLEGACY32_HIDE_SLOT67 (slot 67 loses its dynamic export),
 *     -DLEGACY32_EXTRA_EXPORT (one extra non-C_ text export);
 *   - every slot holds a distinct exported C_* function, so the six
 *     workload targets are unambiguous and every entry agrees with its
 *     .dynsym definition, exactly like the real 68-export module;
 *   - no interface getter is defined or exported in any symbol type;
 *   - a 36-word unmapped-valued tail guard sits immediately past slot
 *     67, so a 104-slot read of the {3,2} declared extent fails
 *     structurally at ordinal 68 instead of decoding ambient bytes.
 *
 * Derived in structure from crates/discover/tests/fixture/version_matrix.c
 * (version word + ordered function-pointer table + C_GetFunctionList),
 * but this is a loadable provider with working session/digest/find stubs
 * for every function tests/fixtures/public-cli/gated.c calls, so the
 * workload's LEDGER counts are real successful calls.
 *
 * Build (also what scripts/ci/legacy32-shape.sh runs):
 *   cc -std=c11 -O2 -fPIC -fno-ipa-icf -fno-merge-constants \
 *      -Wall -Wextra -Werror -shared -Wl,-z,defs \
 *      -o legacy32.so legacy32.c
 *
 * x86-64 LP64 only: the table size assertion pins the 8-byte header.
 */
#include <stddef.h>
#include <stdint.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;
typedef struct {
    CK_ULONG mechanism;
    void *pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

#define CKR_OK ((CK_RV)0)

#ifndef LEGACY32_MAJOR
#define LEGACY32_MAJOR 3
#endif
#ifndef LEGACY32_MINOR
#define LEGACY32_MINOR 2
#endif

/* The 68 ordered legacy slots. The wrapper below pins the tail guard
 * immediately after slot 67, so the compiler cannot separate them. */
typedef struct {
    CK_VERSION version;
    void *functions[68];
} Legacy32Table;

_Static_assert(sizeof(Legacy32Table) == 8 + 68 * sizeof(void *),
               "legacy32 table must be exactly a header plus 68 slots");

/* --- Working stubs for the gated.c workload (ordinals in comments). --- */

static CK_SESSION_HANDLE next_session = 1;

CK_RV C_Initialize(void *args) /* 0 */
{
    (void)args;
    return CKR_OK;
}

CK_RV C_Finalize(void *args) /* 1 */
{
    (void)args;
    return CKR_OK;
}

CK_RV C_GetSlotList(unsigned char token_present, CK_SLOT_ID *slots, CK_ULONG *count) /* 4 */
{
    (void)token_present;
    if (count == NULL)
        return 7; /* CKR_ARGUMENTS_BAD */
    if (slots == NULL) {
        *count = 1;
        return CKR_OK;
    }
    if (*count < 1) {
        *count = 1;
        return 0x150; /* CKR_BUFFER_TOO_SMALL */
    }
    slots[0] = 1;
    *count = 1;
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slot, CK_ULONG flags, void *app, void *notify,
                    CK_SESSION_HANDLE *session) /* 12 */
{
    (void)slot;
    (void)flags;
    (void)app;
    (void)notify;
    if (session == NULL)
        return 7;
    *session = __atomic_fetch_add(&next_session, 1, __ATOMIC_RELAXED);
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE session) /* 13 */
{
    (void)session;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE session, CK_ULONG user, unsigned char *pin, CK_ULONG pin_len) /* 18 */
{
    (void)session;
    (void)user;
    (void)pin;
    (void)pin_len;
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE session) /* 19 */
{
    (void)session;
    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session, void *templ, CK_ULONG count) /* 26 */
{
    (void)session;
    (void)templ;
    (void)count;
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *objects, CK_ULONG max,
                    CK_ULONG *count) /* 27 */
{
    (void)session;
    (void)objects;
    (void)max;
    if (count == NULL)
        return 7;
    *count = 0;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session) /* 28 */
{
    (void)session;
    return CKR_OK;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE session, CK_MECHANISM *mech) /* 37 */
{
    (void)session;
    (void)mech;
    return CKR_OK;
}

CK_RV C_Digest(CK_SESSION_HANDLE session, unsigned char *data, CK_ULONG data_len,
               unsigned char *digest, CK_ULONG *digest_len) /* 38 */
{
    /* A real byte-touching stub: fold the input into 32 output bytes. */
    static const CK_ULONG OUT = 32;
    CK_ULONG i, acc = 0x9e3779b9UL;
    (void)session;
    if (digest_len == NULL)
        return 7;
    if (digest == NULL) {
        *digest_len = OUT;
        return CKR_OK;
    }
    if (*digest_len < OUT) {
        *digest_len = OUT;
        return 0x150;
    }
    for (i = 0; i < data_len; i++)
        acc = acc * 31 + data[i];
    for (i = 0; i < OUT; i++)
        digest[i] = (unsigned char)((acc >> ((i % 8) * 8)) ^ (i * 0x5d));
    *digest_len = OUT;
    return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE session, unsigned char *buf, CK_ULONG len) /* 64 */
{
    /* Deterministic but written: every call touches the full buffer. */
    static unsigned long long counter = 0x12345678ULL;
    CK_ULONG i;
    unsigned long long seed;
    (void)session;
    if (len > 0 && buf == NULL)
        return 7;
    seed = (unsigned long long)__atomic_fetch_add(&counter, 1, __ATOMIC_RELAXED);
    for (i = 0; i < len; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (unsigned char)(seed >> 33);
    }
    return CKR_OK;
}

/* --- Distinct CKR_OK stubs for the remaining 55 legacy slots. ---
 * Each body carries its ordinal as an immediate so identical-code
 * folding cannot merge two entries even where the toolchain folds;
 * the build also passes -fno-ipa-icf and the shape probe asserts
 * all 68 table addresses are pairwise distinct. */
#define LEGACY32_STUB(name, n)                                                                     \
    CK_RV name(void)                                                                               \
    {                                                                                              \
        volatile unsigned long mark = (unsigned long)(n);                                          \
        (void)mark;                                                                                \
        return CKR_OK;                                                                             \
    }

LEGACY32_STUB(C_GetInfo, 2)
/* ordinal 3 is C_GetFunctionList, defined with the table below. */
LEGACY32_STUB(C_GetSlotInfo, 5)
LEGACY32_STUB(C_GetTokenInfo, 6)
LEGACY32_STUB(C_GetMechanismList, 7)
LEGACY32_STUB(C_GetMechanismInfo, 8)
LEGACY32_STUB(C_InitToken, 9)
LEGACY32_STUB(C_InitPIN, 10)
LEGACY32_STUB(C_SetPIN, 11)
LEGACY32_STUB(C_CloseAllSessions, 14)
LEGACY32_STUB(C_GetSessionInfo, 15)
LEGACY32_STUB(C_GetOperationState, 16)
LEGACY32_STUB(C_SetOperationState, 17)
LEGACY32_STUB(C_CreateObject, 20)
LEGACY32_STUB(C_CopyObject, 21)
LEGACY32_STUB(C_DestroyObject, 22)
LEGACY32_STUB(C_GetObjectSize, 23)
LEGACY32_STUB(C_GetAttributeValue, 24)
LEGACY32_STUB(C_SetAttributeValue, 25)
LEGACY32_STUB(C_EncryptInit, 29)
LEGACY32_STUB(C_Encrypt, 30)
LEGACY32_STUB(C_EncryptUpdate, 31)
LEGACY32_STUB(C_EncryptFinal, 32)
LEGACY32_STUB(C_DecryptInit, 33)
LEGACY32_STUB(C_Decrypt, 34)
LEGACY32_STUB(C_DecryptUpdate, 35)
LEGACY32_STUB(C_DecryptFinal, 36)
LEGACY32_STUB(C_DigestUpdate, 39)
LEGACY32_STUB(C_DigestKey, 40)
LEGACY32_STUB(C_DigestFinal, 41)
LEGACY32_STUB(C_SignInit, 42)
LEGACY32_STUB(C_Sign, 43)
LEGACY32_STUB(C_SignUpdate, 44)
LEGACY32_STUB(C_SignFinal, 45)
LEGACY32_STUB(C_SignRecoverInit, 46)
LEGACY32_STUB(C_SignRecover, 47)
LEGACY32_STUB(C_VerifyInit, 48)
LEGACY32_STUB(C_Verify, 49)
LEGACY32_STUB(C_VerifyUpdate, 50)
LEGACY32_STUB(C_VerifyFinal, 51)
LEGACY32_STUB(C_VerifyRecoverInit, 52)
LEGACY32_STUB(C_VerifyRecover, 53)
LEGACY32_STUB(C_DigestEncryptUpdate, 54)
LEGACY32_STUB(C_DecryptDigestUpdate, 55)
LEGACY32_STUB(C_SignEncryptUpdate, 56)
LEGACY32_STUB(C_DecryptVerifyUpdate, 57)
LEGACY32_STUB(C_GenerateKey, 58)
LEGACY32_STUB(C_GenerateKeyPair, 59)
LEGACY32_STUB(C_WrapKey, 60)
LEGACY32_STUB(C_UnwrapKey, 61)
LEGACY32_STUB(C_DeriveKey, 62)
LEGACY32_STUB(C_SeedRandom, 63)
LEGACY32_STUB(C_GetFunctionStatus, 65)
LEGACY32_STUB(C_CancelFunction, 66)
#ifndef LEGACY32_HIDE_SLOT67
LEGACY32_STUB(C_WaitForSlotEvent, 67)
#endif

/* Tail guard values: small unmapped addresses, so ordinal 68 fails
 * structurally (never NULL, which would read as a hole). */
#define LEGACY32_G8(a)                                                                              \
    (a), (a) + 1, (a) + 2, (a) + 3, (a) + 4, (a) + 5, (a) + 6, (a) + 7

CK_RV C_GetFunctionList(void **out);

/* Negative-control knobs for the --shape-only gate suite. Slots 66 and
 * 67 are plain stubs outside the gated ordinals, so breaking them leaves
 * every earlier gate holding and fails exactly the targeted one. */
#ifdef LEGACY32_NULL_SLOT66
#define LEGACY32_SLOT66 NULL
#elif defined(LEGACY32_ALIAS_SLOT66)
#define LEGACY32_SLOT66 C_GetFunctionStatus
#else
#define LEGACY32_SLOT66 C_CancelFunction
#endif
#ifdef LEGACY32_HIDE_SLOT67
static CK_RV hidden_slot67(void)
{
    volatile unsigned long mark = 67UL;
    (void)mark;
    return CKR_OK;
}
#define LEGACY32_SLOT67 hidden_slot67
#else
#define LEGACY32_SLOT67 C_WaitForSlotEvent
#endif
#ifdef LEGACY32_EXTRA_EXPORT
CK_RV legacy32_extra_probe(void)
{
    return CKR_OK;
}
#endif
#ifdef LEGACY32_EXPORT_INTERFACE
CK_RV C_GetInterface(void)
{
    volatile unsigned long mark = 68UL;
    (void)mark;
    return CKR_OK;
}
#endif

static const struct {
    Legacy32Table table;
    unsigned long tail[36];
} published = {
    .table = {
        .version = {LEGACY32_MAJOR, LEGACY32_MINOR},
        .functions = {
            [0] = C_Initialize,
            [1] = C_Finalize,
            [2] = C_GetInfo,
            [3] = C_GetFunctionList,
            [4] = C_GetSlotList,
            [5] = C_GetSlotInfo,
            [6] = C_GetTokenInfo,
            [7] = C_GetMechanismList,
            [8] = C_GetMechanismInfo,
            [9] = C_InitToken,
            [10] = C_InitPIN,
            [11] = C_SetPIN,
            [12] = C_OpenSession,
            [13] = C_CloseSession,
            [14] = C_CloseAllSessions,
            [15] = C_GetSessionInfo,
            [16] = C_GetOperationState,
            [17] = C_SetOperationState,
            [18] = C_Login,
            [19] = C_Logout,
            [20] = C_CreateObject,
            [21] = C_CopyObject,
            [22] = C_DestroyObject,
            [23] = C_GetObjectSize,
            [24] = C_GetAttributeValue,
            [25] = C_SetAttributeValue,
            [26] = C_FindObjectsInit,
            [27] = C_FindObjects,
            [28] = C_FindObjectsFinal,
            [29] = C_EncryptInit,
            [30] = C_Encrypt,
            [31] = C_EncryptUpdate,
            [32] = C_EncryptFinal,
            [33] = C_DecryptInit,
            [34] = C_Decrypt,
            [35] = C_DecryptUpdate,
            [36] = C_DecryptFinal,
            [37] = C_DigestInit,
            [38] = C_Digest,
            [39] = C_DigestUpdate,
            [40] = C_DigestKey,
            [41] = C_DigestFinal,
            [42] = C_SignInit,
            [43] = C_Sign,
            [44] = C_SignUpdate,
            [45] = C_SignFinal,
            [46] = C_SignRecoverInit,
            [47] = C_SignRecover,
            [48] = C_VerifyInit,
            [49] = C_Verify,
            [50] = C_VerifyUpdate,
            [51] = C_VerifyFinal,
            [52] = C_VerifyRecoverInit,
            [53] = C_VerifyRecover,
            [54] = C_DigestEncryptUpdate,
            [55] = C_DecryptDigestUpdate,
            [56] = C_SignEncryptUpdate,
            [57] = C_DecryptVerifyUpdate,
            [58] = C_GenerateKey,
            [59] = C_GenerateKeyPair,
            [60] = C_WrapKey,
            [61] = C_UnwrapKey,
            [62] = C_DeriveKey,
            [63] = C_SeedRandom,
            [64] = C_GenerateRandom,
            [65] = C_GetFunctionStatus,
            [66] = LEGACY32_SLOT66,
            [67] = LEGACY32_SLOT67,
        },
    },
    .tail = {LEGACY32_G8(1), LEGACY32_G8(9), LEGACY32_G8(17), LEGACY32_G8(25), 33, 34, 35, 36},
};

_Static_assert(offsetof(__typeof__(published), tail) ==
                   offsetof(__typeof__(published), table) + sizeof(Legacy32Table),
               "tail guard must sit immediately past slot 67");

CK_RV C_GetFunctionList(void **out)
{
    if (out == NULL)
        return 7;
    *out = (void *)&published.table;
    return CKR_OK;
}
