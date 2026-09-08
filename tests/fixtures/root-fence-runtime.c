/* Native x86-64 PKCS#11 3.2 provider and post-exec two-call driver.
 * Compile with ROOT_RUNTIME_DRIVER for the driver. Neither program is a
 * retirement witness: the Rust owner must genuinely reap before dequeue. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "root-fence-runtime requires Linux x86-64 native ABI"
#endif
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE, CK_ULONG, void *);
typedef struct { unsigned char major, minor; } CK_VERSION;
typedef struct { CK_VERSION version; void *functions[104]; } Table;
typedef struct { CK_ULONG type; void *value; CK_ULONG length; } CK_ATTRIBUTE;
_Static_assert(sizeof(CK_ULONG) == 8 && sizeof(void *) == 8, "native widths");
_Static_assert(offsetof(Table, functions) == 8, "native table alignment");
#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_PENDING 0x204UL
#define SESSION 0x517UL
#define SESSION_FLAGS (4UL | 8UL)

#ifndef ROOT_RUNTIME_DRIVER
CK_RV C_GetFunctionList(Table **out);

__attribute__((noinline))
CK_RV C_OpenSession(CK_ULONG slot, CK_ULONG flags, void *application,
                    CK_NOTIFY notify, CK_SESSION_HANDLE *out) {
    if (slot != 0 || flags != SESSION_FLAGS || application || notify || !out)
        return CKR_ARGUMENTS_BAD;
    *out = SESSION;
    return CKR_OK;
}

__attribute__((noinline))
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE *attributes,
                        CK_ULONG count) {
    if (session != SESSION || attributes || count != 0)
        return CKR_ARGUMENTS_BAD;
    return CKR_PENDING;
}

static Table table = {
    .version = {3, 2},
    .functions = {
        [3] = (void *)C_GetFunctionList,
        [12] = (void *)C_OpenSession,
        [26] = (void *)C_FindObjectsInit,
    },
};

CK_RV C_GetFunctionList(Table **out) {
    if (!out) return CKR_ARGUMENTS_BAD;
    *out = &table;
    return CKR_OK;
}
#else
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "root-fence-runtime: %s\n", message);
    _exit(1);
}

static void timeout_exit(int signal_number) {
    (void)signal_number;
    static const char message[] = "root-fence-runtime: protocol deadline\n";
    ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
    (void)written;
    _exit(124);
}

static void send_all(int fd, const char *message, size_t size) {
    while (size != 0) {
        ssize_t n = send(fd, message, size, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("protocol send failed");
        message += n;
        size -= (size_t)n;
    }
}

int main(int argc, char **argv) {
    if (argc != 3) fail("usage: driver PROVIDER CONTROL_SOCKET");
    struct sigaction action = {.sa_handler = timeout_exit};
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGALRM, &action, NULL) != 0) fail("deadline setup failed");
    alarm(30);
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) fail(dlerror());
    CK_RV (*open_session)(CK_ULONG, CK_ULONG, void *, CK_NOTIFY,
                          CK_SESSION_HANDLE *) = dlsym(module, "C_OpenSession");
    CK_RV (*find_init)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG) =
        dlsym(module, "C_FindObjectsInit");
    if (!open_session || !find_init) fail("required native entrypoint missing");

    /* All socket creation occurs after exec and after loading the provider. */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) fail("socket failed");
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(argv[2]) >= sizeof(address.sun_path)) fail("socket path too long");
    memcpy(address.sun_path, argv[2], strlen(argv[2]) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0)
        fail("connect failed");
    send_all(fd, "READY\n", 6);
    char command[3];
    size_t got = 0;
    while (got < sizeof(command)) {
        ssize_t n = read(fd, command + got, sizeof(command) - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("GO EOF or read failure");
        got += (size_t)n;
    }
    if (memcmp(command, "GO\n", sizeof(command)) != 0) fail("malformed GO");
    /* Observer half-closes after GO: refuse trailing protocol bytes. */
    char extra;
    ssize_t end;
    do { end = read(fd, &extra, 1); } while (end < 0 && errno == EINTR);
    if (end != 0) fail("unexpected command tail");

    CK_SESSION_HANDLE session = 0;
    CK_RV opened = open_session(0, SESSION_FLAGS, NULL, NULL, &session);
    if (opened != CKR_OK || session != SESSION) fail("OpenSession result");
    CK_RV pending = find_init(session, NULL, 0);
    if (pending != CKR_PENDING) fail("FindObjectsInit result");
    char done[64];
    int count = snprintf(done, sizeof(done), "DONE 2 %lu %lu\n", opened, pending);
    if (count <= 0 || (size_t)count >= sizeof(done)) fail("DONE encoding");
    send_all(fd, done, (size_t)count);
    if (close(fd) != 0) fail("control close failed");
    /* Intentionally no provider close/finalize, dlclose, or exit callback. */
    _exit(0);
}
#endif
