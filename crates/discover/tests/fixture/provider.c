/* Controlled PKCS#11 provider fixture. Exercises what SoftHSM2 (2.40-only)
 * cannot: a 3.0 interface, a vendor interface, a "PKCS 11" interface with a
 * NULL function list, a NULL table entry, a cross-surface alias, and a
 * pointer into another object (helper.so).
 *
 * Struct layout matches cryptoki-sys on linux-x86-64 (natural alignment):
 * CK_VERSION{2 x uchar} + 6 bytes padding, then 8-byte function pointers.
 */
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;

#define CKR_OK 0UL
#define CKR_GENERAL_ERROR 5UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL
#ifndef CONFLICT_FIXTURE
#define CONFLICT_FIXTURE 0
#endif
#ifndef POST_FAILURE_FIXTURE
#define POST_FAILURE_FIXTURE 0
#endif
#ifndef NO_GET_INTERFACE
#define NO_GET_INTERFACE 0
#endif
#ifndef UNKNOWN_FLAGS_FIXTURE
#define UNKNOWN_FLAGS_FIXTURE 0
#endif
#ifndef SHORT_TABLE_FIXTURE
#define SHORT_TABLE_FIXTURE 0
#endif
#define NBASE 68
#define N30 (68 + 24)

CK_RV helper_fn(void); /* lives in helper.so */

/* 92 distinct stubs s00..s91 — distinct so nothing aliases by accident. */
#define S(n) static CK_RV s##n(void) { return CKR_OK; }
#define S10(m) S(m##0) S(m##1) S(m##2) S(m##3) S(m##4) S(m##5) S(m##6) S(m##7) S(m##8) S(m##9)
S10(0) S10(1) S10(2) S10(3) S10(4) S10(5) S10(6) S10(7) S10(8) S(90) S(91)
#define L10(m) s##m##0, s##m##1, s##m##2, s##m##3, s##m##4, s##m##5, s##m##6, s##m##7, s##m##8, s##m##9

static void *stubs[N30] = { L10(0), L10(1), L10(2), L10(3), L10(4), L10(5), L10(6), L10(7), L10(8), s90, s91 };

static struct { CK_VERSION v; void *f[NBASE]; } legacy;
static struct { CK_VERSION v; void *f[N30]; } v30;
#if CONFLICT_FIXTURE
static struct { CK_VERSION v; void *f[N30]; } v30_alt_a;
static struct { CK_VERSION v; void *f[N30]; } v30_alt_b;
#endif
#if POST_FAILURE_FIXTURE
static struct { CK_VERSION v; void *f[N30]; } v30_bad;
#endif
#if SHORT_TABLE_FIXTURE
static void *short_table;
#endif

#if SHORT_TABLE_FIXTURE
static void make_short_table(void) {
    long page = sysconf(_SC_PAGESIZE);
    unsigned char *region = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) __builtin_trap();
    unsigned char *base = region + page - sizeof(CK_VERSION);
    memcpy(base, &v30.v, sizeof(CK_VERSION));
    if (munmap(region + page, (size_t)page) != 0) __builtin_trap();
    short_table = base;
}
#endif

static void fill(void) {
    static int done;
    if (done) return;
    done = 1;
    legacy.v = (CK_VERSION){2, 40};
    for (int i = 0; i < NBASE; i++) legacy.f[i] = stubs[i];
    legacy.f[64] = (void *)helper_fn; /* C_GenerateRandom -> cross-object   */
    legacy.f[65] = 0;                 /* C_GetFunctionStatus -> NULL entry  */
    legacy.f[66] = legacy.f[67];      /* C_CancelFunction aliases C_WaitForSlotEvent */
    v30.v = (CK_VERSION){3, 0};
    /* Same base stubs (same names, same targets — corroboration, not an
     * alias) plus 24 distinct 3.0 entries. */
    for (int i = 0; i < N30; i++) v30.f[i] = stubs[i];
#if CONFLICT_FIXTURE
    v30_alt_a.v = v30.v;
    v30_alt_b.v = v30.v;
    memcpy(v30_alt_a.f, v30.f, sizeof(v30.f));
    memcpy(v30_alt_b.f, v30.f, sizeof(v30.f));
#endif
#if POST_FAILURE_FIXTURE
    v30_bad.v = v30.v;
    memcpy(v30_bad.f, v30.f, sizeof(v30.f));
    v30_bad.f[0] = (void *)helper_fn;
#endif
#if SHORT_TABLE_FIXTURE
    make_short_table();
#endif
}

CK_RV C_GetFunctionList(void **pp) {
    fill();
    *pp = &legacy;
    return CKR_OK;
}

static char name_std[] = "PKCS 11";
static char name_vendor[] = "Vendor NetHSM-Ext";
static unsigned char vendor_blob[64]; /* opaque vendor "table": never walked */

CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    fill();
    if (!count) return CKR_ARGUMENTS_BAD;
    if (!out) { *count = 3; return CKR_OK; }
    if (*count < 3) { *count = 3; return CKR_BUFFER_TOO_SMALL; }
    out[0] = (CK_INTERFACE){ name_std, &v30, 0 };
    out[1] = (CK_INTERFACE){ name_vendor, vendor_blob, 0 };
    out[2] = (CK_INTERFACE){ name_std, 0, 0 };
    *count = 3;
    return CKR_OK;
}

#if !NO_GET_INTERFACE
CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags) {
    static unsigned calls;
    unsigned position = calls++;
    unsigned selector = position / 2;
    unsigned expected_flags = position % 2;
    int expected_name = selector != 0;
    int expected_version = selector >= 2;
    if ((flags != expected_flags) || ((name != 0) != expected_name)
        || ((version != 0) != expected_version)) return CKR_GENERAL_ERROR;
    if (expected_version) {
        CK_VERSION requested = *(CK_VERSION *)version;
        if (requested.major != 3 || requested.minor != selector - 2)
            return CKR_GENERAL_ERROR;
    }
#if !CONFLICT_FIXTURE
    if (!name && !version && flags) return CKR_ARGUMENTS_BAD;
#endif
    fill();
    if (!out) return CKR_ARGUMENTS_BAD;
    static CK_INTERFACE selected;
#if POST_FAILURE_FIXTURE
    selected = (CK_INTERFACE){name_std, &v30_bad, 0};
#elif SHORT_TABLE_FIXTURE
    selected = (CK_INTERFACE){name_std, short_table, 0};
#elif CONFLICT_FIXTURE
    static unsigned table_calls;
    void *table = selector == 1
        ? ((table_calls++ & 1) ? (void *)&v30_alt_b : (void *)&v30_alt_a)
        : (void *)&v30;
    selected = (CK_INTERFACE){name_std, table, 0};
#else
    selected = (CK_INTERFACE){name_std, &v30, flags};
#endif
#if UNKNOWN_FLAGS_FIXTURE
    selected.flags |= ((CK_FLAGS)1 << (sizeof(CK_FLAGS) * 8 - 1));
#endif
    *out = &selected;
    return CKR_OK;
}
#endif
