/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Test-only PKCS#11 auto-login shim for the Chromium client-cert demo.
 *
 * Headless Chromium cannot enter a token PIN, so a stock SoftHSM token never
 * signs during TLS client authentication (the browser enumerates the token,
 * then refuses at the login boundary). This shim forwards every PKCS#11
 * call to a real upstream module (SoftHSM) and performs a real C_Login with
 * the test PIN whenever it opens a session (and again before C_SignInit),
 * exactly as a user typing the PIN would. The application therefore sees an
 * already-logged-in token and signs normally; nothing is lied about (token
 * flags, objects and return codes all come from upstream).
 *
 * Build (no system PKCS#11 headers needed; declarations are embedded):
 *
 *   cc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
 *      -o autologin-shim.so autologin-shim.c -ldl
 *
 * Runtime knobs (environment, read by this module in the browser process):
 *   P11SCOPE_CLIENTAUTH_UPSTREAM  path to the real PKCS#11 module (required;
 *                                 without it every call fails CKR_GENERAL_ERROR)
 *   P11SCOPE_CLIENTAUTH_PIN       user PIN for the auto-login (default "1234",
 *                                 the harness test PIN; test tokens only)
 *
 * Login semantics: C_OpenSession logs the new session in and ignores
 * CKR_USER_ALREADY_LOGGED_IN (sessions of one application share one login).
 * C_Login forwards, mapping only already-logged-in to OK (a wrong PIN still
 * fails honestly). C_Logout is a no-op returning OK so the token stays
 * logged in; any later explicit login re-syncs through C_Login.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_USER_TYPE;
typedef void (*CK_NOTIFY)(CK_SESSION_HANDLE, unsigned long, void *);

typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

/* PKCS#11 v2.40 function table: version at pointer alignment, then the 68
 * entry points in specification order (same embedded-declaration pattern as
 * tests/fixtures/live-discovery-provider.c). */
typedef struct {
    CK_VERSION version;
    CK_BYTE reserved[6];
    void *functions[68];
} ShimTable;

/* Every v2.40 entry point except C_GetFunctionList (3), C_OpenSession (12),
 * C_Login (18), C_Logout (19) and C_SignInit (42), which are hooked below. */
#define SHIM_FWD_LIST                                               \
    X(0, Initialize) X(1, Finalize) X(2, GetInfo)                   \
    X(4, GetSlotList) X(5, GetSlotInfo) X(6, GetTokenInfo)           \
    X(7, GetMechanismList) X(8, GetMechanismInfo) X(9, InitToken)    \
    X(10, InitPIN) X(11, SetPIN) X(13, CloseSession)                 \
    X(14, CloseAllSessions) X(15, GetSessionInfo)                   \
    X(16, GetOperationState) X(17, SetOperationState)               \
    X(20, CreateObject) X(21, CopyObject) X(22, DestroyObject)       \
    X(23, GetObjectSize) X(24, GetAttributeValue)                   \
    X(25, SetAttributeValue) X(26, FindObjectsInit) X(27, FindObjects) \
    X(28, FindObjectsFinal) X(29, EncryptInit) X(30, Encrypt)        \
    X(31, EncryptUpdate) X(32, EncryptFinal) X(33, DecryptInit)      \
    X(34, Decrypt) X(35, DecryptUpdate) X(36, DecryptFinal)          \
    X(37, DigestInit) X(38, Digest) X(39, DigestUpdate)              \
    X(40, DigestKey) X(41, DigestFinal) X(43, Sign)                  \
    X(44, SignUpdate) X(45, SignFinal) X(46, SignRecoverInit)        \
    X(47, SignRecover) X(48, VerifyInit) X(49, Verify)               \
    X(50, VerifyUpdate) X(51, VerifyFinal) X(52, VerifyRecoverInit)  \
    X(53, VerifyRecover) X(54, DigestEncryptUpdate)                 \
    X(55, DecryptDigestUpdate) X(56, SignEncryptUpdate)             \
    X(57, DecryptVerifyUpdate) X(58, GenerateKey)                   \
    X(59, GenerateKeyPair) X(60, WrapKey) X(61, UnwrapKey)           \
    X(62, DeriveKey) X(63, SeedRandom) X(64, GenerateRandom)         \
    X(65, GetFunctionStatus) X(66, CancelFunction)                  \
    X(67, WaitForSlotEvent)

enum {
    SHIM_OPENSESSION = 12,
    SHIM_LOGIN = 18,
    SHIM_LOGOUT = 19,
    SHIM_SIGNINIT = 42,
};

#define CKR_OK 0UL
#define CKR_GENERAL_ERROR 5UL
#define CKR_USER_ALREADY_LOGGED_IN 0x100UL
#define CKU_USER 1UL

#define SHIM_ENV_UPSTREAM "P11SCOPE_CLIENTAUTH_UPSTREAM"
#define SHIM_ENV_PIN "P11SCOPE_CLIENTAUTH_PIN"
#define SHIM_DEFAULT_PIN "1234"

static void *shim_upstream[68];
static pthread_once_t shim_once = PTHREAD_ONCE_INIT;
static int shim_ready;
static CK_BYTE shim_major = 2;
static CK_BYTE shim_minor = 40;

static void shim_load_upstream(void) {
    const char *path = getenv(SHIM_ENV_UPSTREAM);
    if (path == NULL || path[0] == '\0') {
        return;
    }
    /* RTLD_LOCAL keeps our own C_* symbols from interposing upstream's. */
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        return;
    }
    CK_RV (*getlist)(ShimTable **) = dlsym(handle, "C_GetFunctionList");
    if (getlist == NULL) {
        return;
    }
    ShimTable *table = NULL;
    if (getlist(&table) != CKR_OK || table == NULL) {
        return;
    }
    memcpy(shim_upstream, table->functions, sizeof(shim_upstream));
    shim_major = table->version.major;
    shim_minor = table->version.minor;
    shim_ready = 1;
    (void)handle; /* intentionally leaked: lives for the process lifetime */
}

static int shim_ensure_ready(void) {
    pthread_once(&shim_once, shim_load_upstream);
    return shim_ready;
}

static void shim_ensure_login(CK_SESSION_HANDLE session) {
    const char *pin = getenv(SHIM_ENV_PIN);
    if (pin == NULL) {
        pin = SHIM_DEFAULT_PIN;
    }
    CK_RV (*login)(CK_SESSION_HANDLE, CK_USER_TYPE, const char *, CK_ULONG) =
        shim_upstream[SHIM_LOGIN];
    if (login == NULL) {
        return;
    }
    CK_RV rv = login(session, CKU_USER, pin, (CK_ULONG)strlen(pin));
    (void)rv; /* CKR_OK and CKR_USER_ALREADY_LOGGED_IN both mean usable;
               * anything else surfaces at the real operation. */
}

/* Generic forwarder: every v2.40 call takes only word-sized arguments
 * (at most 7), so one 8-word shape forwards all of them on LP64. Each
 * entry point is also a dynamic symbol, matching stock modules. */
#define X(i, name)                                                      \
    __attribute__((visibility("default"))) CK_RV C_##name(              \
        CK_ULONG a, CK_ULONG b, CK_ULONG c, CK_ULONG d, CK_ULONG e,      \
        CK_ULONG f, CK_ULONG g, CK_ULONG h) {                           \
        if (!shim_ensure_ready()) {                                     \
            return CKR_GENERAL_ERROR;                                   \
        }                                                               \
        CK_RV (*fn)(CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG,    \
                    CK_ULONG, CK_ULONG, CK_ULONG) = shim_upstream[i];   \
        if (fn == NULL) {                                               \
            return CKR_GENERAL_ERROR;                                   \
        }                                                               \
        return fn(a, b, c, d, e, f, g, h);                              \
    }
SHIM_FWD_LIST
#undef X

__attribute__((visibility("default"))) CK_RV
C_OpenSession(CK_SLOT_ID slot, CK_ULONG flags, void *application,
              CK_NOTIFY notify, CK_SESSION_HANDLE *session) {
    if (!shim_ensure_ready()) {
        return CKR_GENERAL_ERROR;
    }
    CK_RV (*fn)(CK_SLOT_ID, CK_ULONG, void *, CK_NOTIFY, CK_SESSION_HANDLE *) =
        shim_upstream[SHIM_OPENSESSION];
    if (fn == NULL) {
        return CKR_GENERAL_ERROR;
    }
    CK_RV rv = fn(slot, flags, application, notify, session);
    if (rv == CKR_OK) {
        shim_ensure_login(*session);
    }
    return rv;
}

__attribute__((visibility("default"))) CK_RV
C_Login(CK_SESSION_HANDLE session, CK_USER_TYPE user_type, const char *pin,
        CK_ULONG pin_len) {
    if (!shim_ensure_ready()) {
        return CKR_GENERAL_ERROR;
    }
    CK_RV (*fn)(CK_SESSION_HANDLE, CK_USER_TYPE, const char *, CK_ULONG) =
        shim_upstream[SHIM_LOGIN];
    if (fn == NULL) {
        return CKR_GENERAL_ERROR;
    }
    CK_RV rv = fn(session, user_type, pin, pin_len);
    if (rv == CKR_USER_ALREADY_LOGGED_IN) {
        return CKR_OK;
    }
    return rv;
}

__attribute__((visibility("default"))) CK_RV C_Logout(CK_SESSION_HANDLE session) {
    (void)session;
    if (!shim_ensure_ready()) {
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

__attribute__((visibility("default"))) CK_RV
C_SignInit(CK_SESSION_HANDLE session, void *mechanism, CK_ULONG key) {
    if (!shim_ensure_ready()) {
        return CKR_GENERAL_ERROR;
    }
    CK_RV (*fn)(CK_SESSION_HANDLE, void *, CK_ULONG) =
        shim_upstream[SHIM_SIGNINIT];
    if (fn == NULL) {
        return CKR_GENERAL_ERROR;
    }
    shim_ensure_login(session);
    return fn(session, mechanism, key);
}

static ShimTable shim_table;
static pthread_once_t shim_table_once = PTHREAD_ONCE_INIT;

__attribute__((visibility("default"))) CK_RV C_GetFunctionList(ShimTable **out);

static void shim_build_table(void) {
    if (!shim_ensure_ready()) {
        return;
    }
    shim_table.version.major = shim_major;
    shim_table.version.minor = shim_minor;
    memset(shim_table.reserved, 0, sizeof(shim_table.reserved));
#define X(i, name) shim_table.functions[i] = C_##name;
    SHIM_FWD_LIST
#undef X
    shim_table.functions[3] = C_GetFunctionList;
    shim_table.functions[SHIM_OPENSESSION] = C_OpenSession;
    shim_table.functions[SHIM_LOGIN] = C_Login;
    shim_table.functions[SHIM_LOGOUT] = C_Logout;
    shim_table.functions[SHIM_SIGNINIT] = C_SignInit;
}

__attribute__((visibility("default"))) CK_RV C_GetFunctionList(ShimTable **out) {
    pthread_once(&shim_table_once, shim_build_table);
    if (!shim_ensure_ready() || out == NULL) {
        return CKR_GENERAL_ERROR;
    }
    *out = &shim_table;
    return CKR_OK;
}
