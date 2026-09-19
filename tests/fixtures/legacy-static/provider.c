/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned non-p11-kit legacy provider fixture (system-scale plan Task 1.5
 * case 9). A plain PKCS#11-shaped provider with exactly one static,
 * initialized {2,40} function table: 68 distinct entry points, every
 * slot filled. The table lives in file-backed initialized data (never
 * .bss, never heap), so the memory sweep decodes it; the standard
 * factories publish the same address, so scan and publication instances
 * merge. No templates, no pool, no heap wrappers, no mw_* factory.
 *
 * Calls are recorded through backend.so's mw_log (linked by absolute
 * path, DT_NEEDED, like the multi-wrapper provider) with layer
 * "legacy", func "L<ordinal>", idx 0, via "direct".
 *
 * Build (backend.so built first, see tests/multi_wrapper_oracle.rs):
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
 *       -o provider.so provider.c /abs/path/backend.so
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;
typedef struct {
    char *pInterfaceName;
    void *pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL

#define NENTRY 68

void mw_log(const char *layer, const char *func, CK_ULONG idx, const char *via, CK_RV rv);

#define LS_FN(n)                                                              \
    CK_RV ls_fn_##n(CK_ULONG p0, CK_ULONG p1)                                  \
    {                                                                         \
        (void)p0;                                                             \
        (void)p1;                                                             \
        mw_log("legacy", "L" #n, 0, "direct", CKR_OK);                         \
        return CKR_OK;                                                        \
    }
#define LS10(m) \
    LS_FN(m##0) LS_FN(m##1) LS_FN(m##2) LS_FN(m##3) LS_FN(m##4) LS_FN(m##5) LS_FN(m##6) \
        LS_FN(m##7) LS_FN(m##8) LS_FN(m##9)
LS10() LS10(1) LS10(2) LS10(3) LS10(4) LS10(5)
LS_FN(60) LS_FN(61) LS_FN(62) LS_FN(63) LS_FN(64) LS_FN(65) LS_FN(66) LS_FN(67)

#define LS_REF(n) ls_fn_##n,
#define LS10_REF(m) \
    LS_REF(m##0) LS_REF(m##1) LS_REF(m##2) LS_REF(m##3) LS_REF(m##4) LS_REF(m##5) LS_REF(m##6) \
        LS_REF(m##7) LS_REF(m##8) LS_REF(m##9)

typedef struct {
    CK_VERSION version;
    void *funcs[NENTRY];
} LegacyTable;

/* Initialized: file-backed data, the sweep-visible placement this fixture
 * exists to pin. An uninitialized (common/.bss) table would be anonymous
 * and invisible to the file-backed sweep. Five identical tables: one past
 * the K=4 heuristic cap, so scan-only spills exactly one and publication
 * or manifest agreement must bypass the cap to admit all five. */
#define LS_TABLE(n)                                                             \
    __attribute__((used)) static LegacyTable ls_table_##n = { { 2, 40 },        \
        { LS10_REF() LS10_REF(1) LS10_REF(2) LS10_REF(3) LS10_REF(4) LS10_REF(5)     \
              LS_REF(60) LS_REF(61) LS_REF(62) LS_REF(63) LS_REF(64) LS_REF(65)   \
                  LS_REF(66) LS_REF(67) } }
LS_TABLE(0);
LS_TABLE(1);
LS_TABLE(2);
LS_TABLE(3);
LS_TABLE(4);

CK_RV C_GetFunctionList(void **list)
{
    if (list == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *list = &ls_table_0;
    return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE *list, CK_ULONG *count)
{
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (list == NULL) {
        *count = 1;
        return CKR_OK;
    }
    if (*count < 1) {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    list[0].pInterfaceName = "P11Scope-LS-legacy";
    list[0].pFunctionList = &ls_table_0;
    list[0].flags = 0;
    *count = 1;
    return CKR_OK;
}

CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags)
{
    (void)version;
    (void)flags;
    static CK_INTERFACE found;
    if (name == NULL || out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (strcmp(name, "P11Scope-LS-legacy") != 0) {
        return CKR_ARGUMENTS_BAD;
    }
    found.pInterfaceName = "P11Scope-LS-legacy";
    found.pFunctionList = &ls_table_0;
    found.flags = 0;
    *out = &found;
    return CKR_OK;
}
