/* SPDX-License-Identifier: GPL-3.0-or-later */
/* E16 surface: a SYNTHETIC client-side HSM proxy with a standard shape.
 *
 * This provider keeps the fully standard file-backed surface (exported
 * C_GetFunctionList / C_GetInterfaceList / C_GetInterface, interface name
 * "PKCS 11", static 104-entry table), but every table entry forwards its
 * request over a socket instead of doing local crypto. The transport is an
 * AF_UNIX SOCK_DGRAM socketpair created by this object's constructor; the
 * same thread sends the request and receives it back from the other end.
 * There is no server, no network, no remote HSM and no helper thread: the
 * fixture reproduces only what a client-side probe can see of a proxy (the
 * client call happened, its return value), never anything server-side.
 * Truth (unless P11SCOPE_E16_QUIET=1):
 *   P11SCOPE_E16 provider proxy <name>
 *
 * Build: gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
 *            -o e16_hsm_proxy.so e16_hsm_proxy.c
 */

#include "e16_protocol.h"

#include <sys/socket.h>

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
    CK_BYTE reserved[6];
    void *functions[104];
} E16ProxyTable;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL
#define CKR_DEVICE_ERROR 0x30UL

#define PROVIDER_EXPORT __attribute__((visibility("default")))

static int proxy_sockets[2] = {-1, -1};

static void emit_provider(const char *name) {
    e16_provider_witness("proxy", name);
}

/* Forward one request to the socketpair peer and receive it back. SOCK_DGRAM
 * preserves message boundaries, so one send is one whole datagram; EINTR is
 * retried and anything short or different is a device error. */
static CK_RV proxy_forward(const char *name) {
    emit_provider(name);
    if (proxy_sockets[0] < 0) {
        return CKR_DEVICE_ERROR;
    }
    size_t length = strlen(name) + 1;
    if (length > 64) {
        return CKR_DEVICE_ERROR;
    }
    ssize_t sent;
    do {
        sent = send(proxy_sockets[0], name, length, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)length) {
        return CKR_DEVICE_ERROR;
    }
    char echo[64];
    ssize_t received;
    do {
        received = recv(proxy_sockets[1], echo, sizeof(echo), 0);
    } while (received < 0 && errno == EINTR);
    if (received != (ssize_t)length || memcmp(echo, name, length) != 0) {
        return CKR_DEVICE_ERROR;
    }
    return CKR_OK;
}

#define E16_PROXY_FUNCTIONS(X) \
    X(E16_C_Initialize) X(E16_C_Finalize) X(E16_C_GetInfo) X(E16_P11ScopeSlot3) X(E16_C_GetSlotList) \
    X(E16_C_GetSlotInfo) X(E16_C_GetTokenInfo) X(E16_C_GetMechanismList) \
    X(E16_C_GetMechanismInfo) X(E16_C_InitToken) X(E16_C_InitPIN) X(E16_C_SetPIN) \
    X(E16_C_OpenSession) X(E16_C_CloseSession) X(E16_C_CloseAllSessions) \
    X(E16_C_GetSessionInfo) X(E16_C_GetOperationState) X(E16_C_SetOperationState) \
    X(E16_C_Login) X(E16_C_Logout) X(E16_C_CreateObject) X(E16_C_CopyObject) \
    X(E16_C_DestroyObject) X(E16_C_GetObjectSize) X(E16_C_GetAttributeValue) \
    X(E16_C_SetAttributeValue) X(E16_C_FindObjectsInit) X(E16_C_FindObjects) \
    X(E16_C_FindObjectsFinal) X(E16_C_EncryptInit) X(E16_C_Encrypt) X(E16_C_EncryptUpdate) \
    X(E16_C_EncryptFinal) X(E16_C_DecryptInit) X(E16_C_Decrypt) X(E16_C_DecryptUpdate) \
    X(E16_C_DecryptFinal) X(E16_C_DigestInit) X(E16_C_Digest) X(E16_C_DigestUpdate) \
    X(E16_C_DigestKey) X(E16_C_DigestFinal) X(E16_C_SignInit) X(E16_C_Sign) X(E16_C_SignUpdate) \
    X(E16_C_SignFinal) X(E16_C_SignRecoverInit) X(E16_C_SignRecover) X(E16_C_VerifyInit) \
    X(E16_C_Verify) X(E16_C_VerifyUpdate) X(E16_C_VerifyFinal) X(E16_C_VerifyRecoverInit) \
    X(E16_C_VerifyRecover) X(E16_C_DigestEncryptUpdate) X(E16_C_DecryptDigestUpdate) \
    X(E16_C_SignEncryptUpdate) X(E16_C_DecryptVerifyUpdate) X(E16_C_GenerateKey) \
    X(E16_C_GenerateKeyPair) X(E16_C_WrapKey) X(E16_C_UnwrapKey) X(E16_C_DeriveKey) \
    X(E16_C_SeedRandom) X(E16_C_GenerateRandom) X(E16_C_GetFunctionStatus) \
    X(E16_C_CancelFunction) X(E16_C_WaitForSlotEvent) \
    X(E16_P11ScopeSlot68) X(E16_P11ScopeSlot69) X(E16_P11ScopeSlot70) X(E16_P11ScopeSlot71) \
    X(E16_P11ScopeSlot72) X(E16_P11ScopeSlot73) X(E16_P11ScopeSlot74) X(E16_P11ScopeSlot75) \
    X(E16_P11ScopeSlot76) X(E16_P11ScopeSlot77) X(E16_P11ScopeSlot78) X(E16_P11ScopeSlot79) \
    X(E16_P11ScopeSlot80) X(E16_P11ScopeSlot81) X(E16_P11ScopeSlot82) X(E16_P11ScopeSlot83) \
    X(E16_P11ScopeSlot84) X(E16_P11ScopeSlot85) X(E16_P11ScopeSlot86) X(E16_P11ScopeSlot87) \
    X(E16_P11ScopeSlot88) X(E16_P11ScopeSlot89) X(E16_P11ScopeSlot90) X(E16_P11ScopeSlot91) \
    X(E16_P11ScopeSlot92) X(E16_P11ScopeSlot93) X(E16_P11ScopeSlot94) X(E16_P11ScopeSlot95) \
    X(E16_P11ScopeSlot96) X(E16_P11ScopeSlot97) X(E16_P11ScopeSlot98) X(E16_P11ScopeSlot99) \
    X(E16_P11ScopeSlot100) X(E16_P11ScopeSlot101) X(E16_P11ScopeSlot102) X(E16_P11ScopeSlot103)

#define DEFINE_TABLE_FUNCTION(name)                       \
    static __attribute__((noinline, used)) CK_RV name(void *arg) { \
        (void)arg;                                        \
        return proxy_forward(#name);                      \
    }
E16_PROXY_FUNCTIONS(DEFINE_TABLE_FUNCTION)

#define POINTER_INIT(name) (void *)&name,
static E16ProxyTable e16_proxy_table = {
    .version = {3, 2},
    .reserved = {0},
    .functions = {E16_PROXY_FUNCTIONS(POINTER_INIT)},
};

static char e16_proxy_interface_name[] = "PKCS 11";
static CK_INTERFACE e16_proxy_interface;

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetFunctionList(void **out) {
    emit_provider("C_GetFunctionList");
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = &e16_proxy_table;
    return CKR_OK;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    emit_provider("C_GetInterfaceList");
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (out == NULL) {
        *count = 1;
        return CKR_OK;
    }
    if (*count < 1) {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    out[0].pInterfaceName = e16_proxy_interface_name;
    out[0].pFunctionList = &e16_proxy_table;
    out[0].flags = 0;
    *count = 1;
    return CKR_OK;
}

PROVIDER_EXPORT __attribute__((noinline, used)) CK_RV
C_GetInterface(void *name, void *version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    (void)name;
    (void)version;
    (void)flags;
    emit_provider("C_GetInterface");
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    e16_proxy_interface.pInterfaceName = e16_proxy_interface_name;
    e16_proxy_interface.pFunctionList = &e16_proxy_table;
    e16_proxy_interface.flags = 0;
    *out = &e16_proxy_interface;
    return CKR_OK;
}

__attribute__((constructor)) static void e16_proxy_constructor(void) {
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, proxy_sockets) != 0) {
        proxy_sockets[0] = -1;
        proxy_sockets[1] = -1;
    }
}
