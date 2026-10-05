/* SPDX-License-Identifier: GPL-3.0-or-later */
/* E16 surface: vendor-only factory and interface names.
 *
 * This provider exports only a vendor factory (`Vendor_GetFunctionList`) and publishes its table through a
 * vendor-named interface record ("VendorKMS 9.9"); none of the five
 * registry factories (C_GetFunctionList / C_GetInterfaceList /
 * C_GetInterface / NSC_GetFunctionList / FC_GetFunctionList) is a
 * dynamic export. The table itself keeps the standard 104-entry layout
 * so the memory scan's signature probe is the only discovery question:
 * does a vendor-published table decode, and if so under what authority.
 *
 * Truth (unless P11SCOPE_E16_QUIET=1):
 *   P11SCOPE_E16 provider vendor <name>
 *
 * Build: gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
 *            -o e16_vendor_only.so e16_vendor_only.c
 */

#include "e16_protocol.h"

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;

typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct {
    char *pInterfaceName;
    void *pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;

typedef struct {
    CK_VERSION version;
    CK_BYTE reserved[6];
    void *functions[104];
} E16VendorTable;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL

#define PROVIDER_EXPORT __attribute__((visibility("default")))

static void emit_provider(const char *name) {
    e16_provider_witness("vendor", name);
}

#define E16_VENDOR_FUNCTIONS(X) \
    X(E16_C_Initialize) X(E16_C_Finalize) X(E16_C_GetInfo) X(E16_P11ScopeSlot3) X(E16_C_GetSlotList) \
    X(E16_C_GetSlotInfo) X(E16_C_GetTokenInfo) X(E16_C_GetMechanismList) \
    X(E16_C_GetMechanismInfo) X(E16_C_InitToken) X(E16_C_InitPIN) X(E16_C_SetPIN) \
    X(E16_C_OpenSession) X(E16_C_CloseSession) X(E16_C_CloseAllSessions) \
    X(E16_C_GetSessionInfo) X(E16_C_GetOperationState) X(E16_C_SetOperationState) \
    X(E16_C_Login) X(E16_C_Logout) X(E16_C_CreateObject) X(E16_C_CopyObject) \
    X(E16_C_DestroyObject) X(E16_C_GetObjectSize) X(E16_C_GetAttributeValue) \
    X(E16_C_SetAttributeValue) X(E16_C_FindObjectsInit) X(E16_C_FindObjects) \
    X(E16_C_FindObjectsFinal) X(E16_C_EncryptInit) X(E16_C_Encrypt) X(E16_C_EncryptUpdate) \
    X(E16_C_EncryptFinal) X(E16_C_DecryptInit) X(E16_C_Decrypt) X(E16_C_DecryptUpdate) \
    X(E16_C_DecryptFinal) X(E16_C_DigestInit) X(E16_C_Digest) X(E16_C_DigestUpdate) \
    X(E16_C_DigestKey) X(E16_C_DigestFinal) X(E16_C_SignInit) X(E16_C_Sign) X(E16_C_SignUpdate) \
    X(E16_C_SignFinal) X(E16_C_SignRecoverInit) X(E16_C_SignRecover) X(E16_C_VerifyInit) \
    X(E16_C_Verify) X(E16_C_VerifyUpdate) X(E16_C_VerifyFinal) X(E16_C_VerifyRecoverInit) \
    X(E16_C_VerifyRecover) X(E16_C_DigestEncryptUpdate) X(E16_C_DecryptDigestUpdate) \
    X(E16_C_SignEncryptUpdate) X(E16_C_DecryptVerifyUpdate) X(E16_C_GenerateKey) \
    X(E16_C_GenerateKeyPair) X(E16_C_WrapKey) X(E16_C_UnwrapKey) X(E16_C_DeriveKey) \
    X(E16_C_SeedRandom) X(E16_C_GenerateRandom) X(E16_C_GetFunctionStatus) \
    X(E16_C_CancelFunction) X(E16_C_WaitForSlotEvent) \
    X(E16_P11ScopeSlot68) X(E16_P11ScopeSlot69) X(E16_P11ScopeSlot70) X(E16_P11ScopeSlot71) \
    X(E16_P11ScopeSlot72) X(E16_P11ScopeSlot73) X(E16_P11ScopeSlot74) X(E16_P11ScopeSlot75) \
    X(E16_P11ScopeSlot76) X(E16_P11ScopeSlot77) X(E16_P11ScopeSlot78) X(E16_P11ScopeSlot79) \
    X(E16_P11ScopeSlot80) X(E16_P11ScopeSlot81) X(E16_P11ScopeSlot82) X(E16_P11ScopeSlot83) \
    X(E16_P11ScopeSlot84) X(E16_P11ScopeSlot85) X(E16_P11ScopeSlot86) X(E16_P11ScopeSlot87) \
    X(E16_P11ScopeSlot88) X(E16_P11ScopeSlot89) X(E16_P11ScopeSlot90) X(E16_P11ScopeSlot91) \
    X(E16_P11ScopeSlot92) X(E16_P11ScopeSlot93) X(E16_P11ScopeSlot94) X(E16_P11ScopeSlot95) \
    X(E16_P11ScopeSlot96) X(E16_P11ScopeSlot97) X(E16_P11ScopeSlot98) X(E16_P11ScopeSlot99) \
    X(E16_P11ScopeSlot100) X(E16_P11ScopeSlot101) X(E16_P11ScopeSlot102) X(E16_P11ScopeSlot103)

#define DEFINE_TABLE_FUNCTION(name)                       \
    static __attribute__((noinline, used)) CK_RV name(void *arg) { \
        (void)arg;                                        \
        emit_provider(#name);                             \
        return CKR_OK;                                    \
    }
E16_VENDOR_FUNCTIONS(DEFINE_TABLE_FUNCTION)

#define POINTER_INIT(name) (void *)&name,
static E16VendorTable e16_vendor_table = {
    .version = {3, 2},
    .reserved = {0},
    .functions = {E16_VENDOR_FUNCTIONS(POINTER_INIT)},
};

static char e16_vendor_interface_name[] = "VendorKMS 9.9";
static CK_INTERFACE e16_vendor_interface = {NULL, NULL, 0};

__attribute__((constructor)) static void e16_vendor_constructor(void) {
    e16_vendor_interface.pInterfaceName = e16_vendor_interface_name;
    e16_vendor_interface.pFunctionList = &e16_vendor_table;
    e16_vendor_interface.flags = 0;
}

/* The only factory: a vendor name no registry hook matches. */
PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
Vendor_GetFunctionList(void **out) {
    emit_provider("Vendor_GetFunctionList");
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = &e16_vendor_table;
    return CKR_OK;
}
