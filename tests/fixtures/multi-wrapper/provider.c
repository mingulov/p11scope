/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned multi-wrapper provider fixture (system-scale plan Tasks 1.4/1.5/1.6).
 *
 * Models the p11-kit fixed-closure shape the plan verified against upstream
 * 0.26.2 (heap-allocated published tables, first-free-index allocation with
 * holes on release, optional direct backend substitution), scoped to what the
 * workload oracle needs:
 *
 * - 64 contiguous 840-byte {3,2} template tables (53,760 bytes, like the
 *   observed p11-kit instance), each entry a valid executable pointer.
 * - Exercised ordinals {0,5,13,18,43,44} resolve to per-index distinct
 *   closure functions (6 x 64 = 384 unique targets); ordinals 65/66 are the
 *   two shared implementations; every other entry shares one stub.
 * - Published wrappers are heap tables whose entries point at the fixed
 *   closures, at backend.so directly (forwarding), or at failing closures.
 * - One never-called legacy {2,40} static table via C_GetFunctionList.
 * - STRIPPED_VARIANT=1 renames/hides the pool and packs occupancy as a
 *   bitmap instead of a byte array: same workload behavior, unknown layout.
 *
 * Build (provider links backend.so by absolute path, DT_NEEDED):
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
 *       -o provider.so provider.c /abs/path/backend.so
 * Stripped variant adds -DSTRIPPED_VARIANT=1 and is then `strip --strip-all`.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
typedef CK_RV (*EntryFn)(CK_ULONG p0, CK_ULONG p1);
typedef struct {
    CK_VERSION version;
    void *funcs[104];
} Table;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL
#define CKR_DEVICE_ERROR 0x30UL

#define NWRAP 64
#define NENTRY 104
#define NEX 6

static const int EX[NEX] = { 0, 5, 13, 18, 43, 44 };
static const char *EX_NAMES[NEX] = {
    "C_Initialize", "C_GetSlotList", "C_OpenSession", "C_Login", "C_Sign", "C_SignUpdate"
};

/* Backend entry points + shared log writer (defined in backend.so). */
void mw_log(const char *layer, const char *func, CK_ULONG idx, const char *via, CK_RV rv);
CK_RV mw_backend_0(CK_ULONG idx, CK_ULONG via);
CK_RV mw_backend_5(CK_ULONG idx, CK_ULONG via);
CK_RV mw_backend_13(CK_ULONG idx, CK_ULONG via);
CK_RV mw_backend_18(CK_ULONG idx, CK_ULONG via);
CK_RV mw_backend_43(CK_ULONG idx, CK_ULONG via);
CK_RV mw_backend_44(CK_ULONG idx, CK_ULONG via);

static EntryFn back_fn(int ex)
{
    static EntryFn table[NEX] = {
        mw_backend_0, mw_backend_5, mw_backend_13, mw_backend_18, mw_backend_43, mw_backend_44
    };
    return table[ex];
}

static int ex_pos(int ord)
{
    for (int ex = 0; ex < NEX; ex++) {
        if (EX[ex] == ord) {
            return ex;
        }
    }
    return -1;
}

/* Per-index failing ordinal (-1 = none). At most one live wrapper owns an
 * index, so a per-index side table is exact under the single-threaded
 * workload this fixture is built for. */
static int fail_ord[NWRAP];

static CK_RV closure_call(int ex, int idx)
{
    int ord = EX[ex];
    if (fail_ord[idx] == ord) {
        mw_log("wrapper", EX_NAMES[ex], (CK_ULONG)idx, "direct", CKR_DEVICE_ERROR);
        return CKR_DEVICE_ERROR;
    }
    mw_log("wrapper", EX_NAMES[ex], (CK_ULONG)idx, "direct", CKR_OK);
    return back_fn(ex)((CK_ULONG)idx, 1);
}

#define DECL_CLOSURE(o, ex, i)                                              \
    static CK_RV mw_closure_##o##_##i(CK_ULONG p0, CK_ULONG p1)             \
    {                                                                      \
        (void)p0;                                                          \
        (void)p1;                                                          \
        return closure_call(ex, i);                                        \
    }
#define TAKE_ADDR(o, ex, i) mw_closure_##o##_##i,
#define FOR64(M, o, ex)                                                        \
    M(o, ex, 0) M(o, ex, 1) M(o, ex, 2) M(o, ex, 3) M(o, ex, 4) M(o, ex, 5)     \
        M(o, ex, 6) M(o, ex, 7) M(o, ex, 8) M(o, ex, 9) M(o, ex, 10)            \
            M(o, ex, 11) M(o, ex, 12) M(o, ex, 13) M(o, ex, 14) M(o, ex, 15)    \
                M(o, ex, 16) M(o, ex, 17) M(o, ex, 18) M(o, ex, 19)            \
                    M(o, ex, 20) M(o, ex, 21) M(o, ex, 22) M(o, ex, 23)        \
                        M(o, ex, 24) M(o, ex, 25) M(o, ex, 26) M(o, ex, 27)    \
                            M(o, ex, 28) M(o, ex, 29) M(o, ex, 30)            \
                                M(o, ex, 31) M(o, ex, 32) M(o, ex, 33)        \
                                    M(o, ex, 34) M(o, ex, 35) M(o, ex, 36)    \
                                        M(o, ex, 37) M(o, ex, 38)            \
                                            M(o, ex, 39) M(o, ex, 40)        \
                                                M(o, ex, 41) M(o, ex, 42)    \
                                                    M(o, ex, 43) M(o, ex, 44) \
                                                        M(o, ex, 45)          \
                                                            M(o, ex, 46)      \
                                                                M(o, ex, 47)  \
                                                                    M(o, ex, 48) \
                                                                        M(o, ex, 49) \
                                                                            M(o, ex, 50) \
                                                                                M(o, ex, 51) \
                                                                                    M(o, ex, 52) \
                                                                                        M(o, ex, 53) \
                                                                                            M(o, ex, 54) \
                                                                                                M(o, ex, 55) \
                                                                                                    M(o, ex, 56) \
                                                                                                        M(o, ex, 57) \
                                                                                                            M(o, ex, 58) \
                                                                                                                M(o, ex, 59) \
                                                                                                                    M(o, ex, 60) \
                                                                                                                        M(o, ex, 61) \
                                                                                                                            M(o, ex, 62) \
                                                                                                                                M(o, ex, 63)

FOR64(DECL_CLOSURE, 0, 0)
FOR64(DECL_CLOSURE, 5, 1)
FOR64(DECL_CLOSURE, 13, 2)
FOR64(DECL_CLOSURE, 18, 3)
FOR64(DECL_CLOSURE, 43, 4)
FOR64(DECL_CLOSURE, 44, 5)

static EntryFn closures_0[NWRAP] = { FOR64(TAKE_ADDR, 0, 0) };
static EntryFn closures_5[NWRAP] = { FOR64(TAKE_ADDR, 5, 1) };
static EntryFn closures_13[NWRAP] = { FOR64(TAKE_ADDR, 13, 2) };
static EntryFn closures_18[NWRAP] = { FOR64(TAKE_ADDR, 18, 3) };
static EntryFn closures_43[NWRAP] = { FOR64(TAKE_ADDR, 43, 4) };
static EntryFn closures_44[NWRAP] = { FOR64(TAKE_ADDR, 44, 5) };

static EntryFn closure_fn(int ex, int idx)
{
    switch (ex) {
    case 0:
        return closures_0[idx];
    case 1:
        return closures_5[idx];
    case 2:
        return closures_13[idx];
    case 3:
        return closures_18[idx];
    case 4:
        return closures_43[idx];
    default:
        return closures_44[idx];
    }
}

static CK_RV mw_shared(CK_ULONG p0, CK_ULONG p1)
{
    (void)p0;
    (void)p1;
    mw_log("shared", "C_Unknown", 0, "direct", CKR_OK);
    return CKR_OK;
}

static CK_RV mw_shared_status(CK_ULONG p0, CK_ULONG p1)
{
    (void)p0;
    (void)p1;
    mw_log("shared", "C_GetFunctionStatus", 0, "direct", CKR_OK);
    return CKR_OK;
}

static CK_RV mw_shared_cancel(CK_ULONG p0, CK_ULONG p1)
{
    (void)p0;
    (void)p1;
    mw_log("shared", "C_CancelFunction", 0, "direct", CKR_OK);
    return CKR_OK;
}

static CK_RV mw_legacy(CK_ULONG p0, CK_ULONG p1)
{
    (void)p0;
    (void)p1;
    mw_log("legacy", "C_Legacy", 0, "direct", CKR_OK);
    return CKR_OK;
}

#ifdef STRIPPED_VARIANT
static Table s9e2_pool[NWRAP];
static uint64_t s9e2_bits;
static Table *pool_at(int idx)
{
    return &s9e2_pool[idx];
}
static int pool_occupied(int idx)
{
    return (s9e2_bits >> idx) & 1U;
}
static void pool_set(int idx, int occupied)
{
    if (occupied) {
        s9e2_bits |= 1ULL << idx;
    } else {
        s9e2_bits &= ~(1ULL << idx);
    }
}
#else
Table p11scope_fixed[NWRAP];
static unsigned char occ_byte[NWRAP];
static Table *pool_at(int idx)
{
    return &p11scope_fixed[idx];
}
static int pool_occupied(int idx)
{
    return occ_byte[idx] != 0;
}
static void pool_set(int idx, int occupied)
{
    occ_byte[idx] = occupied ? 1 : 0;
}
#endif

static int first_free(void)
{
    for (int idx = 0; idx < NWRAP; idx++) {
        if (!pool_occupied(idx)) {
            return idx;
        }
    }
    return -1;
}

/* Never-called legacy static table: real {2,40} shape, 68 entries. */
typedef struct {
    CK_VERSION version;
    void *funcs[68];
} LegacyTable;
static LegacyTable legacy_table;

static char iface_names[NWRAP][32];

__attribute__((constructor)) static void mw_init(void)
{
    for (int idx = 0; idx < NWRAP; idx++) {
        Table *t = pool_at(idx);
        t->version.major = 3;
        t->version.minor = 2;
        for (int o = 0; o < NENTRY; o++) {
            int ex = ex_pos(o);
            if (o == 65) {
                t->funcs[o] = mw_shared_status;
            } else if (o == 66) {
                t->funcs[o] = mw_shared_cancel;
            } else if (ex < 0) {
                t->funcs[o] = mw_shared;
            } else {
                t->funcs[o] = closure_fn(ex, idx);
            }
        }
        fail_ord[idx] = -1;
        snprintf(iface_names[idx], sizeof iface_names[idx], "P11Scope-MW-%d", idx);
    }
    legacy_table.version.major = 2;
    legacy_table.version.minor = 40;
    for (int o = 0; o < 68; o++) {
        legacy_table.funcs[o] = mw_legacy;
    }
}

typedef struct {
    int index;
    Table bound;
} Wrapper;

void *mw_alloc(int fwd_mask, int fail_arg)
{
    int idx = first_free();
    if (idx < 0) {
        return NULL;
    }
    Wrapper *w = calloc(1, sizeof *w);
    if (w == NULL) {
        return NULL;
    }
    w->index = idx;
    w->bound.version.major = 3;
    w->bound.version.minor = 2;
    for (int o = 0; o < NENTRY; o++) {
        int ex = ex_pos(o);
        if (o == 65) {
            w->bound.funcs[o] = mw_shared_status;
        } else if (o == 66) {
            w->bound.funcs[o] = mw_shared_cancel;
        } else if (ex < 0) {
            w->bound.funcs[o] = mw_shared;
        } else if ((fwd_mask & (1 << ex)) != 0) {
            w->bound.funcs[o] = back_fn(ex);
        } else {
            w->bound.funcs[o] = closure_fn(ex, idx);
        }
    }
    pool_set(idx, 1);
    fail_ord[idx] = fail_arg;
    return w;
}

void mw_free(void *handle)
{
    Wrapper *w = handle;
    if (w == NULL) {
        return;
    }
    pool_set(w->index, 0);
    fail_ord[w->index] = -1;
    free(w);
}

int mw_index(void *handle)
{
    const Wrapper *w = handle;
    return w == NULL ? -1 : w->index;
}

void *mw_table(void *handle)
{
    Wrapper *w = handle;
    return w == NULL ? NULL : &w->bound;
}

int mw_occupied(int idx)
{
    if (idx < 0 || idx >= NWRAP) {
        return 0;
    }
    return pool_occupied(idx);
}

CK_RV C_GetFunctionList(void **list)
{
    if (list == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *list = &legacy_table;
    return CKR_OK;
}

static CK_ULONG interface_count(void)
{
    CK_ULONG n = 1; /* legacy record */
    for (int idx = 0; idx < NWRAP; idx++) {
        if (pool_occupied(idx)) {
            n++;
        }
    }
    return n;
}

CK_RV C_GetInterfaceList(CK_INTERFACE *list, CK_ULONG *count)
{
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    CK_ULONG need = interface_count();
    if (list == NULL) {
        *count = need;
        return CKR_OK;
    }
    if (*count < need) {
        *count = need;
        return CKR_BUFFER_TOO_SMALL;
    }
    CK_ULONG at = 0;
    for (int idx = 0; idx < NWRAP; idx++) {
        if (pool_occupied(idx)) {
            list[at].pInterfaceName = iface_names[idx];
            list[at].pFunctionList = pool_at(idx);
            list[at].flags = 0;
            at++;
        }
    }
    list[at].pInterfaceName = "P11Scope-MW-legacy";
    list[at].pFunctionList = &legacy_table;
    list[at].flags = 0;
    *count = need;
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
    if (strcmp(name, "P11Scope-MW-legacy") == 0) {
        found.pInterfaceName = "P11Scope-MW-legacy";
        found.pFunctionList = &legacy_table;
        found.flags = 0;
        *out = &found;
        return CKR_OK;
    }
    for (int idx = 0; idx < NWRAP; idx++) {
        if (strcmp(name, iface_names[idx]) == 0) {
            if (!pool_occupied(idx)) {
                return CKR_ARGUMENTS_BAD;
            }
            found.pInterfaceName = iface_names[idx];
            found.pFunctionList = pool_at(idx);
            found.flags = 0;
            *out = &found;
            return CKR_OK;
        }
    }
    return CKR_ARGUMENTS_BAD;
}
