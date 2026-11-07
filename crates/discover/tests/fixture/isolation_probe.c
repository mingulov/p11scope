/* Isolation probe fixture: the constructor probes accesses the isolated
 * profile fences (AF_INET socket creation, file creation beside the provider,
 * overwrite of a test-owned sibling) and reports each as a stderr marker,
 * plus the review-PoC probes: io_uring setup, AF_UNIX connect to a
 * test-owned listener, execve of /bin/true in a child, chmod of a
 * test-owned path outside the output, overwrite beneath the -o
 * directory, and in-place overwrite without O_TRUNC. The ISOLATION_*_PATH
 * environment variables name test-owned scratch paths only; without them
 * the matching probe reports unknown.
 * The provider itself is healthy: a
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
#include <linux/io_uring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
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
    /* Overwrite probe: opening an existing sibling for write needs
     * WRITE_FILE, while creation above only needs MAKE_REG. The test
     * owns "isolation-overwrite.tmp"; without it there is nothing to
     * open, so a missing file is unknown rather than denied. */
    if (dladdr((void *)ctor, &info) && info.dli_fname) {
        char opath[4096];
        const char *obase = strrchr(info.dli_fname, '/');
        size_t odirlen = obase ? (size_t)(obase - info.dli_fname) : 0;
        if (odirlen > 0 && odirlen + sizeof("/isolation-overwrite.tmp") <= sizeof(opath)) {
            memcpy(opath, info.dli_fname, odirlen);
            strcpy(opath + odirlen, "/isolation-overwrite.tmp");
            int ofd = open(opath, O_WRONLY);
            if (ofd >= 0) {
                fprintf(stderr, "ISOLATION_OVERWRITE=allowed\n");
                close(ofd);
            } else if (errno == ENOENT) {
                fprintf(stderr, "ISOLATION_OVERWRITE=unknown(no scratch file)\n");
            } else {
                fprintf(stderr, "ISOLATION_OVERWRITE=denied(errno=%d)\n", errno);
            }
        } else {
            fprintf(stderr, "ISOLATION_OVERWRITE=unknown(path too long)\n");
        }
    } else {
        fprintf(stderr, "ISOLATION_OVERWRITE=unknown(dladdr failed)\n");
    }
    /* Review-PoC probes: io_uring setup would bypass the seccomp network
     * denials, so it must fail closed like the plain socket above. */
    {
        struct io_uring_params params;
        memset(&params, 0, sizeof params);
        int ring = syscall(__NR_io_uring_setup, 4, &params);
        if (ring >= 0) {
            fprintf(stderr, "ISOLATION_URING_SETUP=allowed\n");
            close(ring);
        } else {
            fprintf(stderr, "ISOLATION_URING_SETUP=denied(errno=%d)\n", errno);
        }
    }
    /* AF_UNIX creation stays allowed for the loader, but connect must not:
     * the test owns a listener at ISOLATION_UNIX_PATH. */
    {
        const char *upath = getenv("ISOLATION_UNIX_PATH");
        if (!upath) {
            fprintf(stderr, "ISOLATION_UNIX_CONNECT=unknown(no listener)\n");
        } else {
            int ufd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (ufd < 0) {
                fprintf(stderr, "ISOLATION_UNIX_CONNECT=unknown(socket errno=%d)\n", errno);
            } else {
                struct sockaddr_un sun;
                memset(&sun, 0, sizeof sun);
                sun.sun_family = AF_UNIX;
                strncpy(sun.sun_path, upath, sizeof sun.sun_path - 1);
                int connected = connect(ufd, (struct sockaddr *)&sun, sizeof sun);
                if (connected == 0) {
                    fprintf(stderr, "ISOLATION_UNIX_CONNECT=allowed\n");
                } else {
                    fprintf(stderr, "ISOLATION_UNIX_CONNECT=denied(errno=%d)\n", errno);
                }
                close(ufd);
            }
        }
    }
    /* execve runs in a child so an allowed call cannot replace this image:
     * exit 0 means the child ran /bin/true, 42 means it reported denial. */
    {
        pid_t child = fork();
        if (child < 0) {
            fprintf(stderr, "ISOLATION_EXECVE=unknown(fork errno=%d)\n", errno);
        } else if (child == 0) {
            char *const argv[] = { "true", NULL };
            execve("/bin/true", argv, NULL);
            fprintf(stderr, "ISOLATION_EXECVE=denied(errno=%d)\n", errno);
            _exit(42);
        } else {
            int status = 0;
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) { }
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                fprintf(stderr, "ISOLATION_EXECVE=allowed\n");
            } else if (!(WIFEXITED(status) && WEXITSTATUS(status) == 42)) {
                fprintf(stderr, "ISOLATION_EXECVE=unknown(status=%d)\n", status);
            }
        }
    }
    /* chmod outside the output must fail: Landlock cannot restrict it, so
     * the seccomp denylist must. The test owns ISOLATION_CHMOD_PATH. */
    {
        const char *target = getenv("ISOLATION_CHMOD_PATH");
        if (!target) {
            fprintf(stderr, "ISOLATION_CHMOD=unknown(no target)\n");
        } else if (chmod(target, 0666) == 0) {
            fprintf(stderr, "ISOLATION_CHMOD=allowed\n");
        } else {
            fprintf(stderr, "ISOLATION_CHMOD=denied(errno=%d)\n", errno);
        }
    }
    /* Overwrite beneath the -o directory: the fence grants the -o parent
     * as a subtree, so the helper only accepts a dedicated directory and
     * this probe must never run against a foreign victim. */
    {
        const char *target = getenv("ISOLATION_SUBTREE_PATH");
        if (!target) {
            fprintf(stderr, "ISOLATION_SUBTREE=unknown(no target)\n");
        } else {
            int sfd = open(target, O_WRONLY | O_TRUNC);
            if (sfd >= 0) {
                ssize_t written = write(sfd, "pwned\n", 6);
                close(sfd);
                if (written == 6) {
                    fprintf(stderr, "ISOLATION_SUBTREE=allowed\n");
                } else {
                    fprintf(stderr, "ISOLATION_SUBTREE=unknown(short write)\n");
                }
            } else if (errno == ENOENT) {
                fprintf(stderr, "ISOLATION_SUBTREE=unknown(no target file)\n");
            } else {
                fprintf(stderr, "ISOLATION_SUBTREE=denied(errno=%d)\n", errno);
            }
        }
    }
    /* In-place overwrite without O_TRUNC: WRITE_FILE alone suffices,
     * so a writable subtree lets this clobber a victim even though
     * TRUNCATE is never granted (N1 hard-link/dir-target escape). */
    {
        const char *target = getenv("ISOLATION_NOTRUNC_PATH");
        if (!target) {
            fprintf(stderr, "ISOLATION_NOTRUNC=unknown(no target)\n");
        } else {
            int nfd = open(target, O_WRONLY);
            if (nfd >= 0) {
                ssize_t written = pwrite(nfd, "PWNED", 5, 0);
                close(nfd);
                if (written == 5) {
                    fprintf(stderr, "ISOLATION_NOTRUNC=allowed\n");
                } else {
                    fprintf(stderr, "ISOLATION_NOTRUNC=unknown(short write)\n");
                }
            } else if (errno == ENOENT) {
                fprintf(stderr, "ISOLATION_NOTRUNC=unknown(no target file)\n");
            } else {
                fprintf(stderr, "ISOLATION_NOTRUNC=denied(errno=%d)\n", errno);
            }
        }
    }
    /* Terminal-injection ioctls on a pipe: a non-device fd Landlock's
     * IOCTL_DEV does not mediate, so the calls reach the kernel as
     * ENOTTY unless the seccomp filter denies them with EACCES first. */
    {
        int pair[2] = { -1, -1 };
        if (pipe(pair) != 0) {
            fprintf(stderr, "ISOLATION_TIOCSTI=unknown(pipe errno=%d)\n", errno);
            fprintf(stderr, "ISOLATION_TIOCLINUX=unknown(pipe errno=%d)\n", errno);
        } else {
            if (ioctl(pair[0], TIOCSTI, "x") == 0) {
                fprintf(stderr, "ISOLATION_TIOCSTI=allowed\n");
            } else {
                fprintf(stderr, "ISOLATION_TIOCSTI=denied(errno=%d)\n", errno);
            }
            if (ioctl(pair[0], TIOCLINUX, "x") == 0) {
                fprintf(stderr, "ISOLATION_TIOCLINUX=allowed\n");
            } else {
                fprintf(stderr, "ISOLATION_TIOCLINUX=denied(errno=%d)\n", errno);
            }
            close(pair[0]);
            close(pair[1]);
        }
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
