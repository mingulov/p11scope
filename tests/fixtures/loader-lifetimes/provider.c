/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Minimal synthetic provider for loader/image lifetime qualification (G16/G17).
 *
 * One source, one byte identity:
 *
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
 *       -o provider.so provider.c
 *
 * The table is version 3.2 with 104 slots, statically initialized so it
 * lives in file-backed data (relocations, not runtime stores). Slots 2 and
 * 4 are real C_GetInfo and C_GetSlotList implementations with correct
 * PKCS#11 LP64 signatures; every other slot is a valid code address that
 * returns CKR_OK and is never called by the lifetime driver. Only the
 * three standard acquisition exports plus C_GetInfo/C_GetSlotList appear
 * in .dynsym, which is enough to name the two counted calls.
 *
 * The provider is silent: no constructor calls, no markers, no stderr on
 * success. Constructor publication calls would add uncounted loader events
 * and break the exact 2-calls-per-lifetime denominator. Failure returns
 * are deterministic (BAD arguments, BUFFER_TOO_SMALL for a short slot
 * buffer). No PIN, handle, payload or key material is logged.
 *
 * This is the smallest bounded source that exercises the required
 * publication surfaces (FunctionList/InterfaceList/Interface) plus two
 * useful table calls. It is not SoftHSM and does not require Initialize:
 * the driver omits C_Initialize/C_Finalize so the exact per-lifetime
 * denominator stays 2. A real-token variant would need its own exact-count
 * definition and is owned separately. See README.md.
 */

#include <stddef.h>
#include <string.h>

typedef unsigned char CK_BYTE;
typedef unsigned char CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_SLOT_ID;

typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct {
    CK_VERSION cryptokiVersion;
    char manufacturerID[32];
    CK_FLAGS flags;
    char libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;
typedef CK_INFO *CK_INFO_PTR;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;
typedef CK_ULONG *CK_ULONG_PTR;

typedef struct {
    char *pInterfaceName;
    void *pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;
typedef CK_INTERFACE *CK_INTERFACE_PTR;
typedef CK_INTERFACE_PTR *CK_INTERFACE_PTR_PTR;

typedef struct {
    CK_VERSION version;
    CK_BYTE reserved[6];
    void *functions[104];
} P11ScopeTable;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL

#define PROVIDER_EXPORT __attribute__((visibility("default")))

static CK_RV generic_stub(void **out) {
    if (out != NULL) {
        *out = NULL;
    }
    return CKR_OK;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetInfo(CK_INFO_PTR info) {
    if (info == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    static const CK_INFO fixed = {
        .cryptokiVersion = {3, 2},
        .manufacturerID = "p11scope lifetime fixture",
        .flags = 0,
        .libraryDescription = "loader-lifetimes provider",
        .libraryVersion = {3, 2},
    };
    memcpy(info, &fixed, sizeof fixed);
    return CKR_OK;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetSlotList(CK_BBOOL token_present, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count) {
    (void)token_present;
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (slots == NULL) {
        *count = 1;
        return CKR_OK;
    }
    if (*count < 1) {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    slots[0] = 1;
    *count = 1;
    return CKR_OK;
}

#define STUB10 \
    (void *)&generic_stub, (void *)&generic_stub, (void *)&generic_stub, \
    (void *)&generic_stub, (void *)&generic_stub, (void *)&generic_stub, \
    (void *)&generic_stub, (void *)&generic_stub, (void *)&generic_stub, \
    (void *)&generic_stub

static P11ScopeTable provider_table = {
    .version = {3, 2},
    .reserved = {0},
    .functions = {
        (void *)&generic_stub, (void *)&generic_stub, /* 0, 1 */
        (void *)&C_GetInfo, /* 2 */
        (void *)&generic_stub, /* 3 */
        (void *)&C_GetSlotList, /* 4 */
        /* 5..103: 99 stubs. */
        STUB10, STUB10, STUB10, STUB10, STUB10,
        STUB10, STUB10, STUB10, STUB10,
        (void *)&generic_stub, (void *)&generic_stub, (void *)&generic_stub,
        (void *)&generic_stub, (void *)&generic_stub, (void *)&generic_stub,
        (void *)&generic_stub, (void *)&generic_stub, (void *)&generic_stub,
    },
};

_Static_assert(sizeof provider_table.functions / sizeof provider_table.functions[0] == 104,
               "the lifetime provider publishes exactly 104 table slots");

static char provider_interface_name[] = "PKCS 11";
static CK_INTERFACE provider_interface;

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetFunctionList(void **out) {
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = &provider_table;
    return CKR_OK;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (out == NULL) {
        *count = 1;
        return CKR_OK;
    }
    if (*count < 1) {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    out[0].pInterfaceName = provider_interface_name;
    out[0].pFunctionList = &provider_table;
    out[0].flags = 0;
    *count = 1;
    return CKR_OK;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetInterface(void *name, void *version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    (void)name;
    (void)version;
    (void)flags;
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    provider_interface.pInterfaceName = provider_interface_name;
    provider_interface.pFunctionList = &provider_table;
    provider_interface.flags = 0;
    *out = &provider_interface;
    return CKR_OK;
}
