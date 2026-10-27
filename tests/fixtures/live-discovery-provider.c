/* Slice 1b-2 production live-discovery provider fixture.
 *
 * Written for this campaign; it adapts the reviewed research behaviour of
 * preserved/2026-09-15-spike-slice1b2/slice1b2-loader-host/fixture-provider.c
 * (formerly spike/slice1b2-loader-host/) and
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
 *                                bounded 920-byte read must truncate.
 *   P11SCOPE_FIXTURE_QUIET=1     suppress markers (loss lanes call surfaces in
 *                                a tight loop and must not be rate-limited by
 *                                stderr).
 *   P11SCOPE_FIXTURE_INTERFACES=N
 *                                use exactly N interface records for N in
 *                                {0, 1, 16, 17}; absent/invalid values use 1.
 *   P11SCOPE_FIXTURE_BLOCK_RELEASE=PATH
 *   P11SCOPE_FIXTURE_BLOCK_ENTERED=PATH
 *                                the abi-104 "blocked" handshake: slot 10
 *                                touches ENTERED from inside the call and
 *                                waits for RELEASE to appear. Absent paths
 *                                keep every slot non-blocking.
 *   P11SCOPE_FIXTURE_BLOCK_TIMEOUT_MS=N
 *                                ceiling for that wait in milliseconds
 *                                (default 300000); on expiry the slot
 *                                returns CKR_OK after naming the expiry on
 *                                stderr, so a cell whose release never
 *                                comes fails honestly at the in-flight
 *                                proof instead of hanging. Absent or
 *                                invalid values keep the default.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
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
typedef CK_INTERFACE *CK_INTERFACE_PTR;
typedef CK_INTERFACE_PTR *CK_INTERFACE_PTR_PTR;

typedef struct {
    CK_VERSION version;
#if __SIZEOF_POINTER__ == 8
    CK_BYTE reserved[6];
#else
    CK_BYTE reserved[2];
#endif
    void *functions[104];
} P11ScopeTable;

_Static_assert(offsetof(P11ScopeTable, functions) == sizeof(void *),
               "function pointers follow CK_VERSION at pointer alignment");
_Static_assert(sizeof(P11ScopeTable) == sizeof(void *) * 105,
               "version plus 104 function pointers");

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

/* Ceiling for the slot-10 block wait: 300 s at 10 ms a step,
 * comfortably above the driver's 60 s entry backstop plus stop time, so
 * only a dead or released-never driver ever trips it. */
#define BLOCK_WAIT_DEFAULT_MS 300000L
#define BLOCK_WAIT_STEP_MS 10L

static long block_wait_budget_ms(void) {
    const char *text = getenv("P11SCOPE_FIXTURE_BLOCK_TIMEOUT_MS");
    if (text == NULL || text[0] == '\0') {
        return BLOCK_WAIT_DEFAULT_MS;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 0) {
        return BLOCK_WAIT_DEFAULT_MS;
    }
    return value;
}

/* Blocked-cell support for the abi-104 "blocked" workload: when
 * P11SCOPE_FIXTURE_BLOCK_RELEASE names a path, the slot-10 entry
 * (C_InitPIN) touches P11SCOPE_FIXTURE_BLOCK_ENTERED from inside the call
 * and waits for the release path to appear, so the driver can stop its
 * capture with a real provider call in flight. Every other slot, and
 * slot 10 without the handshake, returns at once. The wait is bounded:
 * on expiry the slot names the expiry and returns CKR_OK, so the cell
 * fails honestly at the in-flight proof (nothing in flight) instead of
 * hanging, and a dead driver never orphans a spinner. */
static void block_until_released(const char *slot) {
    if (strcmp(slot, "C_InitPIN") != 0) {
        return;
    }
    const char *release = getenv("P11SCOPE_FIXTURE_BLOCK_RELEASE");
    if (release == NULL || release[0] == '\0') {
        return;
    }
    const char *entered = getenv("P11SCOPE_FIXTURE_BLOCK_ENTERED");
    if (entered != NULL && entered[0] != '\0') {
        FILE *proof = fopen(entered, "w");
        if (proof != NULL) {
            fclose(proof);
        }
    }
    long budget = block_wait_budget_ms();
    long waited = 0;
    while (access(release, F_OK) != 0) {
        if (waited >= budget) {
            fprintf(stderr, "P11SCOPE_FIXTURE block wait expired without release\n");
            return;
        }
        usleep((useconds_t)(BLOCK_WAIT_STEP_MS * 1000));
        waited += BLOCK_WAIT_STEP_MS;
    }
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
        block_until_released(#name); \
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
static CK_INTERFACE provider_interface;

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
C_GetInterface(void *name, void *version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    (void)name;
    (void)version;
    (void)flags;
    emit(phase_name(), "C_GetInterface");
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    provider_interface.pInterfaceName = provider_interface_name;
    provider_interface.pFunctionList = published_table();
    provider_interface.flags = 0;
    *out = &provider_interface;
    return CKR_OK;
}

__attribute__((constructor)) static void provider_constructor(void) {
    void *table = NULL;
    (void)C_GetFunctionList(&table);
    CK_INTERFACE interfaces[P11SCOPE_FIXTURE_MAX_INTERFACES];
    CK_ULONG count = P11SCOPE_FIXTURE_MAX_INTERFACES;
    (void)C_GetInterfaceList(interfaces, &count);
    if (count != 0) {
        CK_INTERFACE_PTR interface = NULL;
        (void)C_GetInterface(provider_interface_name, NULL, &interface, 0);
    }
    provider_application_phase = 1;
}
