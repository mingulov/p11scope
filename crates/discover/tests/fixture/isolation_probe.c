/* Isolation probe fixture: the constructor probes two accesses the isolated
 * profile fences (AF_INET socket creation, file write beside the provider)
 * and reports each as a stderr marker. The provider itself is healthy: a
 * sparse 2.40 legacy table, one all-NULL "PKCS 11" interface, and a lazily
 * dlopen'd backend (never DT_NEEDED; link with -Wl,-rpath,$ORIGIN).
 *
 * Struct layout matches cryptoki-sys on linux-x86-64 (natural alignment):
 * CK_VERSION{2 x uchar} + 6 bytes padding, then 8-byte function pointers.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

__attribute__((constructor)) static void ctor(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) {
        fprintf(stderr, "ISOLATION_SOCKET=allowed\n");
        close(s);
    } else {
        fprintf(stderr, "ISOLATION_SOCKET=denied(errno=%d)\n", errno);
    }
    Dl_info info;
    if (dladdr((void *)ctor, &info) && info.dli_fname) {
        char path[4096];
        const char *base = strrchr(info.dli_fname, '/');
        size_t dirlen = base ? (size_t)(base - info.dli_fname) : 0;
        if (dirlen > 0 && dirlen + sizeof("/isolation-probe.tmp") <= sizeof(path)) {
            memcpy(path, info.dli_fname, dirlen);
            strcpy(path + dirlen, "/isolation-probe.tmp");
            int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (fd >= 0) {
                fprintf(stderr, "ISOLATION_WRITE=allowed\n");
                close(fd);
                unlink(path);
            } else {
                fprintf(stderr, "ISOLATION_WRITE=denied(errno=%d)\n", errno);
            }
        } else {
            fprintf(stderr, "ISOLATION_WRITE=unknown(path too long)\n");
        }
    } else {
        fprintf(stderr, "ISOLATION_WRITE=unknown(dladdr failed)\n");
    }
    fflush(stderr);
}

static CK_RV stub(void) { return CKR_OK; }

static struct { CK_VERSION v; void *f[NBASE]; } legacy;
static int filled;

static void fill(void) {
    if (filled) return;
    filled = 1;
    legacy.v = (CK_VERSION){2, 40};
    for (int i = 0; i < NBASE; i++) legacy.f[i] = (void *)stub;
    legacy.f[5] = 0;
    legacy.f[17] = 0;
    legacy.f[42] = 0;
    /* Lazy backend: resolved here in the getter, never via DT_NEEDED. */
    void *backend = dlopen("isolation-backend.so", RTLD_NOW | RTLD_LOCAL);
    if (backend) {
        void *b0 = dlsym(backend, "isolation_backend_fn0");
        void *b1 = dlsym(backend, "isolation_backend_fn1");
        if (b0) legacy.f[10] = b0;
        if (b1) legacy.f[11] = b1;
    }
}

CK_RV C_GetFunctionList(void **pp) {
    fill();
    *pp = &legacy;
    return CKR_OK;
}

static char name_std[] = "PKCS 11";

CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    if (!count) return CKR_ARGUMENTS_BAD;
    if (!out) { *count = 1; return CKR_OK; }
    if (*count < 1) { *count = 1; return CKR_BUFFER_TOO_SMALL; }
    out[0] = (CK_INTERFACE){ name_std, 0, 0 };
    *count = 1;
    return CKR_OK;
}
