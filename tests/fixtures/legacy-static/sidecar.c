/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned sidecar provider fixture (system-scale plan Task 1.5 case 9,
 * PA-9/C1). A minimal PKCS#11-shaped provider with exactly one static,
 * initialized {2,40} function table: 68 distinct entry points, every slot
 * filled. The table lives in file-backed initialized data, so the memory
 * sweep decodes it; the C_GetFunctionList export keeps the object visible
 * to hintless scans. One table is Heuristic class, never a closure array.
 *
 * Preloaded into the legacy holder so the first plan holds a non-closure
 * provider beside the five-table closure array; without it the closure
 * alone would take published-only. Self-contained: no backend link, no
 * interfaces, makes no calls.
 *
 * Build (test-local, see legacy_static_table_scan_manifest_and_live):
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
 *       -o sidecar.so sidecar.c
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned char CK_BYTE;
typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL

#define NENTRY 68

#define SC_FN(n)                 \
    CK_RV sc_fn_##n(void)        \
    {                            \
        return CKR_OK;           \
    }
#define SC10(m) \
    SC_FN(m##0) SC_FN(m##1) SC_FN(m##2) SC_FN(m##3) SC_FN(m##4) SC_FN(m##5) SC_FN(m##6) \
        SC_FN(m##7) SC_FN(m##8) SC_FN(m##9)
SC10() SC10(1) SC10(2) SC10(3) SC10(4) SC10(5)
SC_FN(60) SC_FN(61) SC_FN(62) SC_FN(63) SC_FN(64) SC_FN(65) SC_FN(66) SC_FN(67)

#define SC_REF(n) sc_fn_##n,
#define SC10_REF(m) \
    SC_REF(m##0) SC_REF(m##1) SC_REF(m##2) SC_REF(m##3) SC_REF(m##4) SC_REF(m##5) SC_REF(m##6) \
        SC_REF(m##7) SC_REF(m##8) SC_REF(m##9)

typedef struct {
    CK_VERSION version;
    void *funcs[NENTRY];
} SidecarTable;

/* Initialized: file-backed data, the sweep-visible placement. */
__attribute__((used)) static SidecarTable sc_table_0 = { { 2, 40 },
        { SC10_REF() SC10_REF(1) SC10_REF(2) SC10_REF(3) SC10_REF(4) SC10_REF(5)
              SC_REF(60) SC_REF(61) SC_REF(62) SC_REF(63) SC_REF(64) SC_REF(65)
                  SC_REF(66) SC_REF(67) } };

CK_RV C_GetFunctionList(void **list)
{
    if (list == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *list = &sc_table_0;
    return CKR_OK;
}
