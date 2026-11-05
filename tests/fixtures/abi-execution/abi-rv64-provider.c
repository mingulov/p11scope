/* SPDX-License-Identifier: GPL-3.0-or-later */
/* High-bit stub provider for the abi-104 rv64 installed cell.
 *
 * Build (LP64):  gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared
 *                    -Wl,-z,defs -o rv64-provider.so abi-rv64-provider.c
 * Build (ia32):  the same command with -m32 added.
 *
 * Shape mirrors tests/fixtures/live-discovery-provider.c with
 * P11SCOPE_EXPORT_TABLES=1: a static 104-entry table (version 3.2),
 * one distinct exported noinline function per slot, and the standard
 * "PKCS 11" interface surface. Every slot shares the one-pointer-argument
 * shape, so the abi-104 emitter may call entries 0..3 through its single
 * TableEntry type. Slots 0..2 return full-width high-bit return values
 * (LP64: 0x8000000000000001, 0xFFFFFFFFFFFFFFFF, 0x80000000;
 * ILP32: 0x80000000, 0xFFFFFFFF, 0); every other slot returns CKR_OK.
 * The slot-68 function doubles as the P11ScopeSlot68 stub-family marker,
 * so all 104 dlsym names resolve and the emitter records verified names.
 * Only C_GetFunctionList is ever called (by the emitter at startup); the
 * interface surface exists so discovery links the table exactly as it
 * links the default stub provider. No constructor calls, no output.
 */
#define _GNU_SOURCE
#include <stddef.h>

#define TABLE_SLOTS 104

typedef struct {
    unsigned char major, minor;
#if __SIZEOF_POINTER__ == 8
    unsigned char reserved[6];
#else
    unsigned char reserved[2];
#endif
    void *functions[TABLE_SLOTS];
} Rv64Table;

_Static_assert(offsetof(Rv64Table, functions) == sizeof(void *),
               "function pointers follow CK_VERSION at pointer alignment");
_Static_assert(sizeof(Rv64Table) == sizeof(void *) * 105,
               "version plus 104 function pointers");

typedef struct {
    char *pInterfaceName;
    void *pFunctionList;
    unsigned long flags;
} Rv64Interface;

#if __SIZEOF_LONG__ == 8
#define RV_HI0 0x8000000000000001UL
#define RV_HI1 0xFFFFFFFFFFFFFFFFUL
#define RV_HI2 0x80000000UL
#else
#define RV_HI0 0x80000000UL
#define RV_HI1 0xFFFFFFFFUL
#define RV_HI2 0x0UL
#endif

/* Slot order matches standard_names in abi-104.c: the 68-entry base with
 * P11ScopeSlot3 at index 3, then P11ScopeSlot68..103. Only the first
 * three slots carry high-bit values; the rest spell their zero. */
#define RV_SLOTS(X) \
    X(C_Initialize, RV_HI0) \
    X(C_Finalize, RV_HI1) \
    X(C_GetInfo, RV_HI2) \
    X(P11ScopeSlot3, 0) \
    X(C_GetSlotList, 0) \
    X(C_GetSlotInfo, 0) \
    X(C_GetTokenInfo, 0) \
    X(C_GetMechanismList, 0) \
    X(C_GetMechanismInfo, 0) \
    X(C_InitToken, 0) \
    X(C_InitPIN, 0) \
    X(C_SetPIN, 0) \
    X(C_OpenSession, 0) \
    X(C_CloseSession, 0) \
    X(C_CloseAllSessions, 0) \
    X(C_GetSessionInfo, 0) \
    X(C_GetOperationState, 0) \
    X(C_SetOperationState, 0) \
    X(C_Login, 0) \
    X(C_Logout, 0) \
    X(C_CreateObject, 0) \
    X(C_CopyObject, 0) \
    X(C_DestroyObject, 0) \
    X(C_GetObjectSize, 0) \
    X(C_GetAttributeValue, 0) \
    X(C_SetAttributeValue, 0) \
    X(C_FindObjectsInit, 0) \
    X(C_FindObjects, 0) \
    X(C_FindObjectsFinal, 0) \
    X(C_EncryptInit, 0) \
    X(C_Encrypt, 0) \
    X(C_EncryptUpdate, 0) \
    X(C_EncryptFinal, 0) \
    X(C_DecryptInit, 0) \
    X(C_Decrypt, 0) \
    X(C_DecryptUpdate, 0) \
    X(C_DecryptFinal, 0) \
    X(C_DigestInit, 0) \
    X(C_Digest, 0) \
    X(C_DigestUpdate, 0) \
    X(C_DigestKey, 0) \
    X(C_DigestFinal, 0) \
    X(C_SignInit, 0) \
    X(C_Sign, 0) \
    X(C_SignUpdate, 0) \
    X(C_SignFinal, 0) \
    X(C_SignRecoverInit, 0) \
    X(C_SignRecover, 0) \
    X(C_VerifyInit, 0) \
    X(C_Verify, 0) \
    X(C_VerifyUpdate, 0) \
    X(C_VerifyFinal, 0) \
    X(C_VerifyRecoverInit, 0) \
    X(C_VerifyRecover, 0) \
    X(C_DigestEncryptUpdate, 0) \
    X(C_DecryptDigestUpdate, 0) \
    X(C_SignEncryptUpdate, 0) \
    X(C_DecryptVerifyUpdate, 0) \
    X(C_GenerateKey, 0) \
    X(C_GenerateKeyPair, 0) \
    X(C_WrapKey, 0) \
    X(C_UnwrapKey, 0) \
    X(C_DeriveKey, 0) \
    X(C_SeedRandom, 0) \
    X(C_GenerateRandom, 0) \
    X(C_GetFunctionStatus, 0) \
    X(C_CancelFunction, 0) \
    X(C_WaitForSlotEvent, 0) \
    X(P11ScopeSlot68, 0) \
    X(P11ScopeSlot69, 0) \
    X(P11ScopeSlot70, 0) \
    X(P11ScopeSlot71, 0) \
    X(P11ScopeSlot72, 0) \
    X(P11ScopeSlot73, 0) \
    X(P11ScopeSlot74, 0) \
    X(P11ScopeSlot75, 0) \
    X(P11ScopeSlot76, 0) \
    X(P11ScopeSlot77, 0) \
    X(P11ScopeSlot78, 0) \
    X(P11ScopeSlot79, 0) \
    X(P11ScopeSlot80, 0) \
    X(P11ScopeSlot81, 0) \
    X(P11ScopeSlot82, 0) \
    X(P11ScopeSlot83, 0) \
    X(P11ScopeSlot84, 0) \
    X(P11ScopeSlot85, 0) \
    X(P11ScopeSlot86, 0) \
    X(P11ScopeSlot87, 0) \
    X(P11ScopeSlot88, 0) \
    X(P11ScopeSlot89, 0) \
    X(P11ScopeSlot90, 0) \
    X(P11ScopeSlot91, 0) \
    X(P11ScopeSlot92, 0) \
    X(P11ScopeSlot93, 0) \
    X(P11ScopeSlot94, 0) \
    X(P11ScopeSlot95, 0) \
    X(P11ScopeSlot96, 0) \
    X(P11ScopeSlot97, 0) \
    X(P11ScopeSlot98, 0) \
    X(P11ScopeSlot99, 0) \
    X(P11ScopeSlot100, 0) \
    X(P11ScopeSlot101, 0) \
    X(P11ScopeSlot102, 0) \
    X(P11ScopeSlot103, 0)

static Rv64Table rv64_table;

#define DEFINE_SLOT(name, rv) \
    __attribute__((noinline, used)) unsigned long name(void **out) { \
        if (out != NULL) { \
            *out = &rv64_table; \
        } \
        return (rv); \
    }
RV_SLOTS(DEFINE_SLOT)

#define POINTER_INIT(name, rv) (void *)&name,
static Rv64Table rv64_table = {
    .major = 3,
    .minor = 2,
    .reserved = {0},
    .functions = {RV_SLOTS(POINTER_INIT)},
};

static char rv64_interface_name[] = "PKCS 11";
/* Statically published so discovery links the table exactly as it links
 * the default stub (whose constructor publishes the same triple): an
 * all-zero interface would stay unlinked and every slot unnamed. */
static Rv64Interface rv64_interface = {
    .pInterfaceName = rv64_interface_name,
    .pFunctionList = &rv64_table,
    .flags = 0,
};

__attribute__((noinline, used)) unsigned long
C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &rv64_table;
    return 0;
}

__attribute__((noinline, used)) unsigned long
C_GetInterfaceList(Rv64Interface *out, unsigned long *count) {
    if (count == NULL) {
        return 7;
    }
    if (out == NULL) {
        *count = 1;
        return 0;
    }
    if (*count < 1) {
        *count = 1;
        return 0x150;
    }
    out[0].pInterfaceName = rv64_interface_name;
    out[0].pFunctionList = &rv64_table;
    out[0].flags = 0;
    *count = 1;
    return 0;
}

__attribute__((noinline, used)) unsigned long
C_GetInterface(void *name, void *version, Rv64Interface **out,
               unsigned long flags) {
    (void)name;
    (void)version;
    (void)flags;
    if (out == NULL) {
        return 7;
    }
    rv64_interface.pInterfaceName = rv64_interface_name;
    rv64_interface.pFunctionList = &rv64_table;
    rv64_interface.flags = 0;
    *out = &rv64_interface;
    return 0;
}
