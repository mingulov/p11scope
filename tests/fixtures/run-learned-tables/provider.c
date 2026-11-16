/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* A kryoptic-shaped PKCS#11 provider: a shared object exporting only the
 * three getters (C_GetFunctionList, C_GetInterface,
 * C_GetInterfaceList). Every table function is hidden (default-hidden
 * visibility), reachable only through the published tables, so a
 * default `run` that learns tables from dynamic exports alone sees
 * three slots and stays blind to the table calls.
 *
 * The provider publishes one 2.40 CK_FUNCTION_LIST (68 entries) from
 * C_GetFunctionList and one 3.0 CK_FUNCTION_LIST_3_0 (92 entries)
 * from C_GetInterface("PKCS 11"). Every entry of both tables points
 * at the same hidden stubs, so a call reached through either table
 * runs the same instruction. C_GetInterfaceList reports the single
 * "PKCS 11" interface.
 *
 * Build: cc -std=c11 -O2 -shared -fPIC -fvisibility=hidden -o
 * libtableprov.so provider.c
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_FLAGS;

typedef struct {
    unsigned char major;
    unsigned char minor;
} CK_VERSION;

typedef CK_RV (*StubFn)(void);

typedef struct {
    CK_VERSION version;
    void *functions[68];
} LegacyList;

typedef struct {
    CK_VERSION version;
    void *functions[92];
} List30;

typedef struct {
    const char *name;
    void *functions;
    CK_FLAGS flags;
} CK_INTERFACE;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x54UL

/* Distinct bodies, so identical-code folding never merges two slots. */
static volatile const char *last_called;

/* The order is the standard CK_FUNCTION_LIST_3_0 order; the first 68
 * are the 2.40 CK_FUNCTION_LIST. */
#define FUNCTIONS_240(S, G) \
    S(C_Initialize) S(C_Finalize) S(C_GetInfo) G(C_GetFunctionList) S(C_GetSlotList) \
    S(C_GetSlotInfo) S(C_GetTokenInfo) S(C_GetMechanismList) S(C_GetMechanismInfo) \
    S(C_InitToken) S(C_InitPIN) S(C_SetPIN) S(C_OpenSession) S(C_CloseSession) \
    S(C_CloseAllSessions) S(C_GetSessionInfo) S(C_GetOperationState) \
    S(C_SetOperationState) S(C_Login) S(C_Logout) S(C_CreateObject) S(C_CopyObject) \
    S(C_DestroyObject) S(C_GetObjectSize) S(C_GetAttributeValue) S(C_SetAttributeValue) \
    S(C_FindObjectsInit) S(C_FindObjects) S(C_FindObjectsFinal) S(C_EncryptInit) \
    S(C_Encrypt) S(C_EncryptUpdate) S(C_EncryptFinal) S(C_DecryptInit) S(C_Decrypt) \
    S(C_DecryptUpdate) S(C_DecryptFinal) S(C_DigestInit) S(C_Digest) S(C_DigestUpdate) \
    S(C_DigestKey) S(C_DigestFinal) S(C_SignInit) S(C_Sign) S(C_SignUpdate) \
    S(C_SignFinal) S(C_SignRecoverInit) S(C_SignRecover) S(C_VerifyInit) S(C_Verify) \
    S(C_VerifyUpdate) S(C_VerifyFinal) S(C_VerifyRecoverInit) S(C_VerifyRecover) \
    S(C_DigestEncryptUpdate) S(C_DecryptDigestUpdate) S(C_SignEncryptUpdate) \
    S(C_DecryptVerifyUpdate) S(C_GenerateKey) S(C_GenerateKeyPair) S(C_WrapKey) \
    S(C_UnwrapKey) S(C_DeriveKey) S(C_SeedRandom) S(C_GenerateRandom) \
    S(C_GetFunctionStatus) S(C_CancelFunction) S(C_WaitForSlotEvent)
#define FUNCTIONS_30(S, G) \
    G(C_GetInterfaceList) G(C_GetInterface) S(C_LoginUser) S(C_SessionCancel) \
    S(C_MessageEncryptInit) S(C_EncryptMessage) S(C_EncryptMessageBegin) \
    S(C_EncryptMessageNext) S(C_MessageEncryptFinal) S(C_MessageDecryptInit) \
    S(C_DecryptMessage) S(C_DecryptMessageBegin) S(C_DecryptMessageNext) \
    S(C_MessageDecryptFinal) S(C_MessageSignInit) S(C_SignMessage) \
    S(C_SignMessageBegin) S(C_SignMessageNext) S(C_MessageSignFinal) \
    S(C_MessageVerifyInit) S(C_VerifyMessage) S(C_VerifyMessageBegin) \
    S(C_VerifyMessageNext) S(C_MessageVerifyFinal)

#define NOTHING(name)
#define DEFINE_STUB(name)                                                      \
    static __attribute__((noinline, used)) CK_RV stub_##name(void) {           \
        last_called = #name;                                                   \
        return CKR_OK;                                                         \
    }
FUNCTIONS_240(DEFINE_STUB, NOTHING)
FUNCTIONS_30(DEFINE_STUB, NOTHING)

CK_RV C_GetFunctionList(void **out);
CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count);
CK_RV C_GetInterface(const char *name, CK_VERSION *version, CK_INTERFACE **out,
                     CK_FLAGS flags);

#define STUB_POINTER(name) (void *)&stub_##name,
#define GETTER_POINTER(name) (void *)&name,
static LegacyList legacy_list = {
    .version = {2, 40},
    .functions = {FUNCTIONS_240(STUB_POINTER, GETTER_POINTER)},
};
static List30 list_30 = {
    .version = {3, 0},
    .functions = {FUNCTIONS_240(STUB_POINTER, GETTER_POINTER)
                      FUNCTIONS_30(STUB_POINTER, GETTER_POINTER)},
};
static CK_INTERFACE interface_30 = {"PKCS 11", &list_30, 0};

#define EXPORT __attribute__((visibility("default")))

EXPORT CK_RV C_GetFunctionList(void **out) {
    last_called = "C_GetFunctionList";
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = &legacy_list;
    return CKR_OK;
}

EXPORT CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    last_called = "C_GetInterfaceList";
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (out != NULL) {
        if (*count < 1) {
            *count = 1;
            return 0x150UL; /* CKR_BUFFER_TOO_SMALL */
        }
        out[0] = interface_30;
    }
    *count = 1;
    return CKR_OK;
}

EXPORT CK_RV C_GetInterface(const char *name, CK_VERSION *version, CK_INTERFACE **out,
                            CK_FLAGS flags) {
    last_called = "C_GetInterface";
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if ((name != NULL && strcmp(name, "PKCS 11") != 0) || flags != 0 ||
        (version != NULL && (version->major != 3 || version->minor != 0))) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    *out = &interface_30;
    return CKR_OK;
}
