/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Stub-pool provider fixture: every getter call mints a fresh heap table
 * whose slots point at per-mint stub functions, like the p11-kit
 * proxy/client managed-slot dispatch (p11-kit 0.26 builds interface
 * structs and function tables on the heap at every C_GetInterface /
 * C_GetInterfaceList call, each with distinct code addresses).
 *
 * A mint log records every minted table so a test can map manifest
 * offsets back to mint order: set P11SCOPE_STUB_POOL_LOG to a writable
 * path before discovery. Each line is
 *   MINT <kind> <index> <slot0_addr> <slot68_addr> <slot69_addr>
 * with kind legacy/list/iface, index the shared pool counter, and
 * addresses in %p form (0 for slots past a 68-slot table). The count
 * call of C_GetInterfaceList mints nothing, like the real provider.
 *
 * Struct layout matches cryptoki-sys on linux-x86-64 (natural alignment):
 * CK_VERSION{2 x uchar} + 6 bytes padding, then 8-byte function pointers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL
#define NBASE 68
#define N32 104
/* Enough mints for one discovery (legacy + list + selection probes). */
#define MINTS 24

/* Distinct stub per (mint, slot): M(m) defines s_m_000..s_m_103. */
#define S(m, n) static CK_RV s_##m##_##n(void) { return CKR_OK; }
#define S10(m, t) S(m, t##0) S(m, t##1) S(m, t##2) S(m, t##3) S(m, t##4) S(m, t##5) S(m, t##6) S(m, t##7) S(m, t##8) S(m, t##9)
#define SM(m) S10(m, 0) S10(m, 1) S10(m, 2) S10(m, 3) S10(m, 4) S10(m, 5) S10(m, 6) S10(m, 7) S10(m, 8) S10(m, 9) S(m, 100) S(m, 101) S(m, 102) S(m, 103)
SM(00) SM(01) SM(02) SM(03) SM(04) SM(05) SM(06) SM(07)
SM(08) SM(09) SM(10) SM(11) SM(12) SM(13) SM(14) SM(15)
SM(16) SM(17) SM(18) SM(19) SM(20) SM(21) SM(22) SM(23)
#define L10(m, t) s_##m##_##t##0, s_##m##_##t##1, s_##m##_##t##2, s_##m##_##t##3, s_##m##_##t##4, s_##m##_##t##5, s_##m##_##t##6, s_##m##_##t##7, s_##m##_##t##8, s_##m##_##t##9
#define LM(m) L10(m, 0), L10(m, 1), L10(m, 2), L10(m, 3), L10(m, 4), L10(m, 5), L10(m, 6), L10(m, 7), L10(m, 8), L10(m, 9), s_##m##_100, s_##m##_101, s_##m##_102, s_##m##_103

static void *pool[MINTS][N32] = {
    { LM(00) }, { LM(01) }, { LM(02) }, { LM(03) },
    { LM(04) }, { LM(05) }, { LM(06) }, { LM(07) },
    { LM(08) }, { LM(09) }, { LM(10) }, { LM(11) },
    { LM(12) }, { LM(13) }, { LM(14) }, { LM(15) },
    { LM(16) }, { LM(17) }, { LM(18) }, { LM(19) },
    { LM(20) }, { LM(21) }, { LM(22) }, { LM(23) },
};

static unsigned mint_counter;

static void log_mint(const char *kind, unsigned index, void *slot0, void *slot68, void *slot69) {
    const char *path = getenv("P11SCOPE_STUB_POOL_LOG");
    FILE *log;
    if (!path || !*path)
        return;
    log = fopen(path, "a");
    if (!log)
        return;
    fprintf(log, "MINT %s %u %p %p %p\n", kind, index, slot0, slot68, slot69);
    fclose(log);
}

/* Mint one heap table with `count` slots from the next pool row. Traps
 * past MINTS: discovery must never need that many mints. */
static void *mint(const char *kind, unsigned major, unsigned minor, int count) {
    unsigned char *table;
    void **slots;
    unsigned index;
    int i;
    if (mint_counter >= MINTS)
        __builtin_trap();
    index = mint_counter++;
    table = malloc(sizeof(CK_VERSION) + 6 + (size_t)count * sizeof(void *));
    if (!table)
        __builtin_trap();
    table[0] = (unsigned char)major;
    table[1] = (unsigned char)minor;
    memset(table + 2, 0, 6);
    slots = (void **)(table + sizeof(CK_VERSION) + 6);
    for (i = 0; i < count; i++)
        slots[i] = pool[index][i];
    log_mint(kind, index, slots[0],
             count > NBASE ? slots[NBASE] : NULL,
             count > NBASE + 1 ? slots[NBASE + 1] : NULL);
    return table;
}

CK_RV C_GetFunctionList(void **pp) {
    if (!pp)
        return CKR_ARGUMENTS_BAD;
    *pp = mint("legacy", 2, 40, NBASE);
    return CKR_OK;
}

static char name_std[] = "PKCS 11";

CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    if (!count)
        return CKR_ARGUMENTS_BAD;
    if (!out) {
        *count = 1;
        return CKR_OK;
    }
    if (*count < 1) {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    out[0] = (CK_INTERFACE){ name_std, mint("list", 3, 2, N32), 0 };
    *count = 1;
    return CKR_OK;
}

CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags) {
    CK_VERSION requested;
    (void)name;
    (void)flags;
    if (!out)
        return CKR_ARGUMENTS_BAD;
    if (version) {
        requested = *(CK_VERSION *)version;
        if (requested.major != 3 || requested.minor != 2)
            return CKR_ARGUMENTS_BAD;
    }
    {
        static CK_INTERFACE selected;
        selected = (CK_INTERFACE){ name_std, mint("iface", 3, 2, N32), 0 };
        *out = &selected;
    }
    return CKR_OK;
}
