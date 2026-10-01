/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned p11-kit-shaped closure-array provider fixture (module/caller
 * inventory Phase 1): the "second shape" the brief allows beside
 * multi-wrapper.
 *
 * 65 static {3,2} function tables (104 slots each, like the observed
 * p11-kit fixed-closure pool), every entry a valid executable pointer.
 * Each table owns 8 distinct entry targets (520 across the pool) plus 12
 * shared stubs, for 532 distinct endpoints: more than the 512 attach
 * slots, so a shared-scope lowering refuses the provider whole on every
 * machine, whatever else is mapped. Tables and stubs are STATIC
 * INITIALIZERS (file-backed .data.rel.ro/.text), never constructor-
 * filled .bss: the memory scan snapshots only file-backed pages (see
 * `scanned_tables_agree_with_the_helper_manifest_for_every_walked_
 * version`). No interface triple names any table and no table entry
 * points at an exported factory, so all 65 tables stay bare heuristic
 * lookalikes: 65 > MAX_TABLES_PER_OBJECT (4) unresolved lookalikes, and
 * the refusal carries the closure-array class and reason.
 *
 * The constructor only appends this process's pid to
 * $P11SCOPE_CATALOG_MARKER when set (shared E3 contract): the observer
 * must never execute provider code, so its pid must never appear there.
 *
 * Build: gcc -std=c11 -O0 -Wall -Wextra -Werror -fPIC -shared -o closure.so provider.c
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;
typedef struct {
    CK_VERSION version;
    void *funcs[104];
} Table;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL

#define NCLOSE 65

/* Per-table entry targets: table t owns w<t>_0..w<t>_7 (520 distinct
 * addresses pool-wide). Each returns its own address, so no two share
 * an address even under identical-code folding. */
#define U(n) static CK_RV w##n(void) { return (CK_RV)(uintptr_t)&w##n; }
#define U8(m) U(m##_0) U(m##_1) U(m##_2) U(m##_3) U(m##_4) U(m##_5) U(m##_6) U(m##_7)
U8(0) U8(1) U8(2) U8(3) U8(4) U8(5) U8(6) U8(7) U8(8) U8(9)
U8(10) U8(11) U8(12) U8(13) U8(14) U8(15) U8(16) U8(17) U8(18) U8(19)
U8(20) U8(21) U8(22) U8(23) U8(24) U8(25) U8(26) U8(27) U8(28) U8(29)
U8(30) U8(31) U8(32) U8(33) U8(34) U8(35) U8(36) U8(37) U8(38) U8(39)
U8(40) U8(41) U8(42) U8(43) U8(44) U8(45) U8(46) U8(47) U8(48) U8(49)
U8(50) U8(51) U8(52) U8(53) U8(54) U8(55) U8(56) U8(57) U8(58) U8(59)
U8(60) U8(61) U8(62) U8(63) U8(64)

/* Shared tail targets: static (unexported), so no ordinal agrees with
 * .dynsym and every table stays heuristic. */
#define V(n) static CK_RV v##n(void) { return (CK_RV)(uintptr_t)&v##n; }
V(0) V(1) V(2) V(3) V(4) V(5) V(6) V(7) V(8) V(9) V(10) V(11)

#define W8(m) w##m##_0, w##m##_1, w##m##_2, w##m##_3, w##m##_4, w##m##_5, w##m##_6, w##m##_7
#define ROW v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11
#define TAIL ROW, ROW, ROW, ROW, ROW, ROW, ROW, ROW
#define T(t) { { 3, 2 }, { W8(t), TAIL } }

/* 65 tables: 13 rows of 5. 8 + 8*12 = 104 entries each, all non-NULL. */
static Table pool[NCLOSE] = {
    T(0), T(1), T(2), T(3), T(4),
    T(5), T(6), T(7), T(8), T(9),
    T(10), T(11), T(12), T(13), T(14),
    T(15), T(16), T(17), T(18), T(19),
    T(20), T(21), T(22), T(23), T(24),
    T(25), T(26), T(27), T(28), T(29),
    T(30), T(31), T(32), T(33), T(34),
    T(35), T(36), T(37), T(38), T(39),
    T(40), T(41), T(42), T(43), T(44),
    T(45), T(46), T(47), T(48), T(49),
    T(50), T(51), T(52), T(53), T(54),
    T(55), T(56), T(57), T(58), T(59),
    T(60), T(61), T(62), T(63), T(64),
};

__attribute__((constructor)) static void closure_catalog_init(void)
{
    const char *marker = getenv("P11SCOPE_CATALOG_MARKER");
    if (marker != NULL && marker[0] != '\0') {
        FILE *f = fopen(marker, "a");
        if (f != NULL) {
            fprintf(f, "%d\n", (int)getpid());
            fclose(f);
        }
    }
}

CK_RV C_GetFunctionList(void **list)
{
    if (list == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *list = &pool[0];
    return CKR_OK;
}

CK_RV C_GetInterfaceList(void *list, CK_ULONG *count)
{
    (void)list;
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    /* Unactivated closure: no published interfaces in memory. */
    *count = 0;
    return CKR_OK;
}

CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags)
{
    (void)name;
    (void)version;
    (void)flags;
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = NULL;
    return CKR_OK;
}
