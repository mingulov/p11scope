/* SPDX-License-Identifier: GPL-3.0-or-later */
/* C_GetInterface-needy fixture: C_GetInterface needs an AF_INET socket
 * and fails with CKR_DEVICE_ERROR when creation fails. Trusted records
 * every selection query with its result; isolated records each failure
 * per query (rv 0x30, no result). Neither hides nor crashes.
 * C_GetFunctionList stays healthy so selection runs in both profiles.
 *
 * Struct layout matches cryptoki-sys on linux-x86-64 (natural alignment):
 * CK_VERSION{2 x uchar} + 6 bytes padding, then 8-byte function pointers.
 */
#include <sys/socket.h>
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_UTF8CHAR;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;

#define CKR_OK 0UL
#define CKR_DEVICE_ERROR 0x30UL
#define NBASE 68

static CK_RV stub(void) { return CKR_OK; }

static struct { CK_VERSION v; void *f[NBASE]; } legacy;
static char name_std[] = "PKCS 11";
static CK_INTERFACE iface;

__attribute__((constructor)) static void fill(void) {
    legacy.v = (CK_VERSION){2, 40};
    for (int i = 0; i < NBASE; i++) legacy.f[i] = (void *)stub;
    iface = (CK_INTERFACE){ name_std, &legacy, 0 };
}

CK_RV C_GetFunctionList(void **pp) {
    *pp = &legacy;
    return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR *name, CK_VERSION *version, CK_INTERFACE **out, CK_FLAGS flags) {
    (void)name;
    (void)version;
    (void)flags;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return CKR_DEVICE_ERROR;
    close(s);
    *out = &iface;
    return CKR_OK;
}
