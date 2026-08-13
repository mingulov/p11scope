/* Function-table ABI fixture. Names come from the shared Rust field arrays;
 * this file supplies only the published slot counts and pointer mechanics. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;
typedef struct { CK_VERSION version; void *functions[104]; } Table;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL
#ifndef LEGACY_MAJOR
#define LEGACY_MAJOR 2
#endif
#ifndef LEGACY_MINOR
#define LEGACY_MINOR 40
#endif
#ifndef MATRIX_INTERFACES
#define MATRIX_INTERFACES 1
#endif
#ifndef SHORT_LEGACY
#define SHORT_LEGACY 0
#endif
#ifndef PRIVACY_FIXTURE
#define PRIVACY_FIXTURE 0
#endif
#ifndef PRIVACY_BLOCKS
#define PRIVACY_BLOCKS 0
#endif
#ifndef UNTRUSTED_TARGETS
#define UNTRUSTED_TARGETS 0
#endif

#define S(n) static CK_RV s##n(void) { return CKR_OK; }
#define S10(m) S(m##0) S(m##1) S(m##2) S(m##3) S(m##4) S(m##5) S(m##6) S(m##7) S(m##8) S(m##9)
S10(0) S10(1) S10(2) S10(3) S10(4) S10(5) S10(6) S10(7) S10(8) S10(9)
S(100) S(101) S(102) S(103)
#define L10(m) s##m##0, s##m##1, s##m##2, s##m##3, s##m##4, s##m##5, s##m##6, s##m##7, s##m##8, s##m##9
static void *stubs[104] = {
    L10(0), L10(1), L10(2), L10(3), L10(4),
    L10(5), L10(6), L10(7), L10(8), L10(9),
    s100, s101, s102, s103
};

#if PRIVACY_FIXTURE
#define TEN_ARGS CK_ULONG a0, CK_ULONG a1, CK_ULONG a2, CK_ULONG a3, CK_ULONG a4, CK_ULONG a5, CK_ULONG a6, CK_ULONG a7, CK_ULONG a8, CK_ULONG a9
#define PRIVACY_FN(n) static CK_RV privacy_##n(TEN_ARGS) { \
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; \
    (void)a6; (void)a7; (void)a8; (void)a9; \
    if (PRIVACY_BLOCKS) sleep(60); \
    return CKR_OK; \
}
PRIVACY_FN(18) PRIVACY_FN(58) PRIVACY_FN(59) PRIVACY_FN(70) PRIVACY_FN(72)
PRIVACY_FN(94) PRIVACY_FN(99) PRIVACY_FN(102) PRIVACY_FN(103)
#endif

CK_RV C_GetFunctionList(void **out);
CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count);
CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags);

static Table legacy;
static Table t240;
static Table t30;
static Table t31;
static Table t32;
static Table tfuture;
static Table tunknown;
static Table tbad;
static void *short_legacy;
static char *boundary_name;

static void fill_table(Table *table, CK_BYTE major, CK_BYTE minor, int anchors) {
    table->version = (CK_VERSION){major, minor};
    for (int i = 0; i < 104; i++) table->functions[i] = stubs[i];
    table->functions[3] = (void *)C_GetFunctionList;
    if (anchors) {
        table->functions[68] = (void *)C_GetInterfaceList;
        table->functions[69] = (void *)C_GetInterface;
    }
#if UNTRUSTED_TARGETS
    table->functions[0] = (void *)write; /* preloaded libc, not provider-owned */
    table->functions[1] = (void *)&legacy; /* mapped, but not executable */
#endif
#if PRIVACY_FIXTURE
    if (major == 3 && minor == 2) {
        table->functions[18] = (void *)privacy_18;   /* C_Login */
        table->functions[58] = (void *)privacy_58;   /* C_GenerateKey */
        table->functions[59] = (void *)privacy_59;   /* C_GenerateKeyPair */
        table->functions[70] = (void *)privacy_70;   /* C_LoginUser */
        table->functions[72] = (void *)privacy_72;   /* C_MessageEncryptInit */
        table->functions[94] = (void *)privacy_94;   /* C_VerifySignatureInit */
        table->functions[99] = (void *)privacy_99;   /* C_AsyncComplete */
        table->functions[102] = (void *)privacy_102; /* C_WrapKeyAuthenticated */
        table->functions[103] = (void *)privacy_103; /* C_UnwrapKeyAuthenticated */
    }
#endif
}

static void make_short_legacy(void) {
    long page = sysconf(_SC_PAGESIZE);
    size_t wanted = offsetof(Table, functions) + 68 * sizeof(void *);
    unsigned char *region = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) __builtin_trap();
    unsigned char *base = region + page - (wanted - 1);
    memcpy(base, &legacy, wanted - 1);
    if (munmap(region + page, (size_t)page) != 0) __builtin_trap();
    short_legacy = base;
}

static void make_boundary_name(void) {
    long page = sysconf(_SC_PAGESIZE);
    unsigned char *region = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) __builtin_trap();
    boundary_name = (char *)(region + page - sizeof("PKCS 11"));
    memcpy(boundary_name, "PKCS 11", sizeof("PKCS 11"));
    if (munmap(region + page, (size_t)page) != 0) __builtin_trap();
}

static void fill(void) {
    static int done;
    if (done) return;
    done = 1;
    fill_table(&legacy, LEGACY_MAJOR, LEGACY_MINOR, 0);
    fill_table(&t240, 2, 40, 0);
    fill_table(&t30, 3, 0, 1);
    fill_table(&t31, 3, 1, 1);
    fill_table(&t32, 3, 2, 1);
    fill_table(&tfuture, 3, 9, 1);
    fill_table(&tunknown, 4, 0, 1);
    fill_table(&tbad, 3, 2, 0);
    make_boundary_name();
    if (SHORT_LEGACY) make_short_legacy();
}

CK_RV C_GetFunctionList(void **out) {
    fill();
    if (!out) return CKR_ARGUMENTS_BAD;
    *out = SHORT_LEGACY ? short_legacy : (void *)&legacy;
    return CKR_OK;
}

static char exact[] = "PKCS 11";
static char alternate[] = "Acme Standard ABI";
static char deceptive[] = "Vendor Pretend";

CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    fill();
    if (!count) return CKR_ARGUMENTS_BAD;
    CK_ULONG needed = MATRIX_INTERFACES ? 13 : 0;
    if (!out) { *count = needed; return CKR_OK; }
    if (*count < needed) { *count = needed; return CKR_BUFFER_TOO_SMALL; }
    if (MATRIX_INTERFACES) {
        out[0] = (CK_INTERFACE){exact, &t240, 0};
        out[1] = (CK_INTERFACE){exact, &t30, 0};
        out[2] = (CK_INTERFACE){exact, &t31, 0};
        out[3] = (CK_INTERFACE){exact, &t32, 0};
        out[4] = (CK_INTERFACE){exact, &tfuture, 0};
        out[5] = (CK_INTERFACE){exact, &tunknown, 0};
        out[6] = (CK_INTERFACE){alternate, &t32, 0};
        out[7] = (CK_INTERFACE){0, &t30, 0};
        out[8] = (CK_INTERFACE){(char *)(uintptr_t)1, &t31, 0};
        out[9] = (CK_INTERFACE){deceptive, &tbad, 0};
        out[10] = (CK_INTERFACE){alternate, &legacy, 0};
        out[11] = (CK_INTERFACE){exact, 0, 0};
        out[12] = (CK_INTERFACE){boundary_name, &t32, 0};
    }
    *count = needed;
    return CKR_OK;
}

/* Discovery may compare this address but must never call the entry point. */
CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags) {
    (void)name; (void)version; (void)out; (void)flags;
    __builtin_trap();
}
