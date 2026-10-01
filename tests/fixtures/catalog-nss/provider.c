/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned NSS-softokn-shaped multi-table provider fixture (module/caller
 * inventory Phase 1).
 *
 * A genuine multi-table provider: 8 static {2,40} function tables (68
 * slots each, 544 distinct entry targets), every table named by a
 * standard "PKCS 11" interface triple, plus the NSS `NSC_`/`FC_` export
 * pair beside the standard three. Tables and triples are STATIC
 * INITIALIZERS (file-backed .data.rel.ro/.data), never constructor-
 * filled .bss: the memory scan snapshots only file-backed pages, so a
 * runtime-filled tail past the last file page would be silently absent
 * (see `scanned_tables_agree_with_the_helper_manifest_for_every_walked_
 * version`). Static initialization is also what a real shipped provider
 * looks like. The scan decodes all 8 tables as interface-linked
 * (publication evidence) with no provider call. The 544 distinct
 * endpoints exceed the 512-slot ceiling on their own, so a shared-scope
 * lowering refuses this provider whole *as corroborated* (not as a
 * closure array) on every machine, whatever else is mapped.
 *
 * The constructor only appends this process's pid to
 * $P11SCOPE_CATALOG_MARKER when set (shared E3 contract with the
 * multi-wrapper extension): the observer must never execute provider
 * code, so its pid must never appear there.
 *
 * Build: gcc -std=c11 -O0 -Wall -Wextra -Werror -fPIC -shared -o nss.so provider.c
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    char *pInterfaceName;
    void *pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;
typedef struct {
    CK_VERSION version;
    void *funcs[68];
} Table;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL

#define NSS_TABLES 8
#define NSS_SLOTS 68
#define NSS_STUBS (NSS_TABLES * NSS_SLOTS)

/* 544 distinct entry targets: each returns its own address, so no two
 * share an address even under identical-code folding (merging them would
 * be a contradiction the linker cannot construct). */
#define S(n) static CK_RV s##n(void) { return (CK_RV)(uintptr_t)&s##n; }
#define S10(m) S(m##0) S(m##1) S(m##2) S(m##3) S(m##4) S(m##5) S(m##6) S(m##7) S(m##8) S(m##9)
S10(0) S10(1) S10(2) S10(3) S10(4) S10(5) S10(6) S10(7) S10(8) S10(9)
S10(10) S10(11) S10(12) S10(13) S10(14) S10(15) S10(16) S10(17) S10(18) S10(19)
S10(20) S10(21) S10(22) S10(23) S10(24) S10(25) S10(26) S10(27) S10(28) S10(29)
S10(30) S10(31) S10(32) S10(33) S10(34) S10(35) S10(36) S10(37) S10(38) S10(39)
S10(40) S10(41) S10(42) S10(43) S10(44) S10(45) S10(46) S10(47) S10(48) S10(49)
S10(50) S10(51) S10(52) S10(53)
S(540) S(541) S(542) S(543)

#define L10(m) s##m##0, s##m##1, s##m##2, s##m##3, s##m##4, s##m##5, s##m##6, s##m##7, s##m##8, s##m##9

/* Table t owns stubs [t*68, t*68+67]: 8 slices of 68, spelling the 10-entry
 * groups plus the ragged head/tail around each 68-cut. Each slice lists
 * 68 distinct stub addresses (60 + 8, 2 + 60 + 6, 4 + 60 + 4, 6 + 60 + 2,
 * 8 + 60, 60 + 8, 2 + 60 + 6, 4 + 60 + 4); a miscounted slice would leave
 * NULL holes the catalog reader's 544-endpoint assertion catches. */
static Table tables[NSS_TABLES] = {
    { { 2, 40 }, { L10(0), L10(1), L10(2), L10(3), L10(4), L10(5),
        s60, s61, s62, s63, s64, s65, s66, s67 } },
    { { 2, 40 }, { s68, s69, L10(7), L10(8), L10(9), L10(10), L10(11), L10(12),
        s130, s131, s132, s133, s134, s135 } },
    { { 2, 40 }, { s136, s137, s138, s139, L10(14), L10(15), L10(16), L10(17),
        L10(18), L10(19), s200, s201, s202, s203 } },
    { { 2, 40 }, { s204, s205, s206, s207, s208, s209, L10(21), L10(22), L10(23),
        L10(24), L10(25), L10(26), s270, s271 } },
    { { 2, 40 }, { s272, s273, s274, s275, s276, s277, s278, s279, L10(28),
        L10(29), L10(30), L10(31), L10(32), L10(33) } },
    { { 2, 40 }, { L10(34), L10(35), L10(36), L10(37), L10(38), L10(39),
        s400, s401, s402, s403, s404, s405, s406, s407 } },
    { { 2, 40 }, { s408, s409, L10(41), L10(42), L10(43), L10(44), L10(45),
        L10(46), s470, s471, s472, s473, s474, s475 } },
    { { 2, 40 }, { s476, s477, s478, s479, L10(48), L10(49), L10(50), L10(51),
        L10(52), L10(53), s540, s541, s542, s543 } },
};

static char exact[] = "PKCS 11";

static CK_INTERFACE ifaces[NSS_TABLES] = {
    { exact, &tables[0], 0 },
    { exact, &tables[1], 0 },
    { exact, &tables[2], 0 },
    { exact, &tables[3], 0 },
    { exact, &tables[4], 0 },
    { exact, &tables[5], 0 },
    { exact, &tables[6], 0 },
    { exact, &tables[7], 0 },
};

__attribute__((constructor)) static void nss_catalog_init(void)
{
    /* E3 side-effect marker: proves a constructor ran here (in the
     * fixture process) and pins that the observer never triggers it. */
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
    *list = &tables[0];
    return CKR_OK;
}

CK_RV NSC_GetFunctionList(void **list)
{
    return C_GetFunctionList(list);
}

CK_RV FC_GetFunctionList(void **list)
{
    return C_GetFunctionList(list);
}

CK_RV C_GetInterfaceList(CK_INTERFACE *list, CK_ULONG *count)
{
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (list == NULL) {
        *count = NSS_TABLES;
        return CKR_OK;
    }
    if (*count < NSS_TABLES) {
        *count = NSS_TABLES;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (int t = 0; t < NSS_TABLES; t++) {
        list[t] = ifaces[t];
    }
    *count = NSS_TABLES;
    return CKR_OK;
}

CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags)
{
    (void)name;
    (void)version;
    (void)flags;
    static CK_INTERFACE selected;
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    selected = ifaces[0];
    *out = &selected;
    return CKR_OK;
}
