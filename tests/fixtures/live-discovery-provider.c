/* Slice 1b-2 production live-discovery provider fixture.
 *
 * Written for this campaign; it adapts the reviewed research behaviour of
 * spike/slice1b2-loader-host/fixture-provider.c and
 * crates/discover/tests/fixture/version_matrix.c in source form only. No
 * research binary and no historical campaign row is an input here.
 *
 * One source, exactly two reviewed byte identities:
 *
 *   exported: gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC \
 *                 -DP11SCOPE_EXPORT_TABLES=1 -shared -Wl,-z,defs \
 *                 -o provider-exported.so live-discovery-provider.c
 *   hidden:   the same command with -DP11SCOPE_EXPORT_TABLES=0
 *
 * Both identities export the three standard entry points and implement all
 * three standard return ABIs; P11SCOPE_EXPORT_TABLES only decides whether the
 * 104 table functions themselves are dynamic symbols. Each surface emits a
 * distinct constructor marker and a distinct application marker, so a campaign
 * row can tell "the loader ran it" from "the child called it" per surface
 * without any timing inference.
 *
 * Runtime knobs (deterministic, and declared per lane in the execution
 * manifest, so the two byte identities stay fixed):
 *   P11SCOPE_FIXTURE_TRUNCATE=1  C_GetFunctionList returns a table that ends
 *                                one byte before an unmapped page, so a
 *                                bounded 896-byte read must truncate.
 *   P11SCOPE_FIXTURE_QUIET=1     suppress markers (loss lanes call surfaces in
 *                                a tight loop and must not be rate-limited by
 *                                stderr).
 *   P11SCOPE_FIXTURE_INTERFACES=N
 *                                use exactly N interface records for N in
 *                                {0, 1, 16, 17}; absent/invalid values use 1.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;

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
    CK_BYTE reserved[6];
    void *functions[104];
} P11ScopeTable;

#define P11SCOPE_FIXTURE_MAX_INTERFACES 17

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL

#ifndef P11SCOPE_EXPORT_TABLES
#error "define P11SCOPE_EXPORT_TABLES=1 (exported tables) or =0 (hidden tables)"
#endif

#if P11SCOPE_EXPORT_TABLES
#define TABLE_FN
#else
#define TABLE_FN static
#endif

#define PROVIDER_EXPORT __attribute__((visibility("default")))

/* Marker vocabulary. The execution manifest freezes these exact strings; the
 * campaign validator rejects a row whose required markers are missing. */
#define MARKER_PREFIX "P11SCOPE_FIXTURE "

static int provider_quiet(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *value = getenv("P11SCOPE_FIXTURE_QUIET");
        cached = (value != NULL && value[0] == '1') ? 1 : 0;
    }
    return cached;
}

static CK_ULONG fixture_interface_count(void) {
    const char *value = getenv("P11SCOPE_FIXTURE_INTERFACES");
    if (value != NULL) {
        if (strcmp(value, "0") == 0) {
            return 0;
        }
        if (strcmp(value, "1") == 0) {
            return 1;
        }
        if (strcmp(value, "16") == 0) {
            return 16;
        }
        if (strcmp(value, "17") == 0) {
            return 17;
        }
    }
    return 1;
}

/* write(2) is warn_unused_result under glibc; -Werror needs the result read. */
static void emit(const char *phase, const char *surface) {
    if (provider_quiet()) {
        return;
    }
    char line[128];
    size_t used = 0;
    const char *parts[5] = {MARKER_PREFIX, phase, " ", surface, "\n"};
    for (int i = 0; i < 5; i++) {
        size_t length = strlen(parts[i]);
        if (used + length >= sizeof(line)) {
            return;
        }
        memcpy(line + used, parts[i], length);
        used += length;
    }
    ssize_t written = write(STDERR_FILENO, line, used);
    (void)written;
}

/* 0 while the loader is still running this object's constructor, 1 afterwards.
 * The constructor sets it last, so every surface call it makes is attributed to
 * the constructor and every later call to the application. */
static int provider_application_phase;

static const char *phase_name(void) {
    return provider_application_phase ? "app" : "ctor";
}

#define PROVIDER_FUNCTIONS(X) \
    X(C_Initialize) X(C_Finalize) X(C_GetInfo) X(P11ScopeSlot3) X(C_GetSlotList) \
    X(C_GetSlotInfo) X(C_GetTokenInfo) X(C_GetMechanismList) \
    X(C_GetMechanismInfo) X(C_InitToken) X(C_InitPIN) X(C_SetPIN) \
    X(C_OpenSession) X(C_CloseSession) X(C_CloseAllSessions) \
    X(C_GetSessionInfo) X(C_GetOperationState) X(C_SetOperationState) \
    X(C_Login) X(C_Logout) X(C_CreateObject) X(C_CopyObject) \
    X(C_DestroyObject) X(C_GetObjectSize) X(C_GetAttributeValue) \
    X(C_SetAttributeValue) X(C_FindObjectsInit) X(C_FindObjects) \
    X(C_FindObjectsFinal) X(C_EncryptInit) X(C_Encrypt) X(C_EncryptUpdate) \
    X(C_EncryptFinal) X(C_DecryptInit) X(C_Decrypt) X(C_DecryptUpdate) \
    X(C_DecryptFinal) X(C_DigestInit) X(C_Digest) X(C_DigestUpdate) \
    X(C_DigestKey) X(C_DigestFinal) X(C_SignInit) X(C_Sign) X(C_SignUpdate) \
    X(C_SignFinal) X(C_SignRecoverInit) X(C_SignRecover) X(C_VerifyInit) \
    X(C_Verify) X(C_VerifyUpdate) X(C_VerifyFinal) X(C_VerifyRecoverInit) \
    X(C_VerifyRecover) X(C_DigestEncryptUpdate) X(C_DecryptDigestUpdate) \
    X(C_SignEncryptUpdate) X(C_DecryptVerifyUpdate) X(C_GenerateKey) \
    X(C_GenerateKeyPair) X(C_WrapKey) X(C_UnwrapKey) X(C_DeriveKey) \
    X(C_SeedRandom) X(C_GenerateRandom) X(C_GetFunctionStatus) \
    X(C_CancelFunction) X(C_WaitForSlotEvent) \
    X(P11ScopeSlot68) X(P11ScopeSlot69) X(P11ScopeSlot70) X(P11ScopeSlot71) \
    X(P11ScopeSlot72) X(P11ScopeSlot73) X(P11ScopeSlot74) X(P11ScopeSlot75) \
    X(P11ScopeSlot76) X(P11ScopeSlot77) X(P11ScopeSlot78) X(P11ScopeSlot79) \
    X(P11ScopeSlot80) X(P11ScopeSlot81) X(P11ScopeSlot82) X(P11ScopeSlot83) \
    X(P11ScopeSlot84) X(P11ScopeSlot85) X(P11ScopeSlot86) X(P11ScopeSlot87) \
    X(P11ScopeSlot88) X(P11ScopeSlot89) X(P11ScopeSlot90) X(P11ScopeSlot91) \
    X(P11ScopeSlot92) X(P11ScopeSlot93) X(P11ScopeSlot94) X(P11ScopeSlot95) \
    X(P11ScopeSlot96) X(P11ScopeSlot97) X(P11ScopeSlot98) X(P11ScopeSlot99) \
    X(P11ScopeSlot100) X(P11ScopeSlot101) X(P11ScopeSlot102) X(P11ScopeSlot103)

static P11ScopeTable provider_table;

/* Every table slot shares C_GetFunctionList's one-pointer-argument shape, so
 * the production entry/return probe pair can be attached at any slot and every
 * return record's 104-pointer copy stays readable. */
#define DEFINE_TABLE_FUNCTION(name) \
    TABLE_FN __attribute__((noinline, used)) CK_RV name(void **out) { \
        if (out != NULL) { \
            *out = &provider_table; \
        } \
        return CKR_OK; \
    }
PROVIDER_FUNCTIONS(DEFINE_TABLE_FUNCTION)

/* Static initialiser: the 104 slots become R_X86_64_RELATIVE relocations the
 * dynamic loader applies before any constructor runs, not runtime stores. */
#define POINTER_INIT(name) (void *)&name,
static P11ScopeTable provider_table = {
    .version = {3, 2},
    .reserved = {0},
    .functions = {PROVIDER_FUNCTIONS(POINTER_INIT)},
};

static char provider_interface_name[] = "PKCS 11";

/* A table whose last byte sits one byte before an unmapped page, so the
 * production bounded read must report truncation rather than a short copy. */
static void *truncated_table(void) {
    static void *cached;
    if (cached != NULL) {
        return cached;
    }
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        return &provider_table;
    }
    unsigned char *region = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        return &provider_table;
    }
    unsigned char *base = region + (size_t)page - (sizeof(P11ScopeTable) - 1);
    memcpy(base, &provider_table, sizeof(P11ScopeTable) - 1);
    if (munmap(region + page, (size_t)page) != 0) {
        return &provider_table;
    }
    cached = base;
    return cached;
}

static void *published_table(void) {
    const char *truncate = getenv("P11SCOPE_FIXTURE_TRUNCATE");
    if (truncate != NULL && truncate[0] == '1') {
        return truncated_table();
    }
    return &provider_table;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetFunctionList(void **out) {
    emit(phase_name(), "C_GetFunctionList");
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = published_table();
    return CKR_OK;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    emit(phase_name(), "C_GetInterfaceList");
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    CK_ULONG interface_count = fixture_interface_count();
    if (out == NULL) {
        *count = interface_count;
        return CKR_OK;
    }
    if (*count < interface_count) {
        *count = interface_count;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (CK_ULONG index = 0; index < interface_count; index++) {
        out[index].pInterfaceName = provider_interface_name;
        out[index].pFunctionList = published_table();
        out[index].flags = 0;
    }
    *count = interface_count;
    return CKR_OK;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags) {
    (void)name;
    (void)version;
    (void)flags;
    emit(phase_name(), "C_GetInterface");
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = published_table();
    return CKR_OK;
}

__attribute__((constructor)) static void provider_constructor(void) {
    void *table = NULL;
    (void)C_GetFunctionList(&table);
    CK_INTERFACE interfaces[P11SCOPE_FIXTURE_MAX_INTERFACES];
    CK_ULONG count = P11SCOPE_FIXTURE_MAX_INTERFACES;
    (void)C_GetInterfaceList(interfaces, &count);
    if (count != 0) {
        (void)C_GetInterface(provider_interface_name, NULL, &table, 0);
    }
    provider_application_phase = 1;
}
