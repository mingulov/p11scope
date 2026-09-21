/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned multi-wrapper backend fixture (system-scale plan Tasks 1.4/1.5/1.6).
 *
 * Separate shared object so "direct backend forwarding" is a real
 * cross-object target: a heap wrapper entry may point here instead of at a
 * wrapper closure in provider.c. Also hosts mw_log, the single call-record
 * writer shared by both objects (same inode identity, one log format).
 *
 * Build (see tests/multi_wrapper_oracle.rs for the exact commands):
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
 *       -o backend.so backend.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;

#define CKR_OK 0UL

/* Log line format (shared contract with provider.c and workload.c; the
 * oracle reproduces these bytes exactly):
 *   "<pid> <tid> <layer> <func> <idx> <via> <rv>\n"
 */
void mw_log(const char *layer, const char *func, CK_ULONG idx, const char *via, CK_RV rv)
{
    const char *path = getenv("P11SCOPE_MW_LOG");
    if (path == NULL || path[0] == '\0') {
        return;
    }
    char line[256];
    int len = snprintf(line, sizeof line, "%d %d %s %s %lu %s %lu\n", (int)getpid(),
        (int)gettid(), layer, func, idx, via, rv);
    if (len <= 0 || (size_t)len >= sizeof line) {
        return;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    size_t off = 0;
    while (off < (size_t)len) {
        ssize_t wrote = write(fd, line + off, (size_t)len - off);
        if (wrote <= 0) {
            break;
        }
        off += (size_t)wrote;
    }
    close(fd);
}

/* Backend entry points. p0 is the wrapper index (forwarded by the closure
 * for nested calls, supplied by the driver for direct-forwarded calls);
 * p1 selects the via label: 0 = direct, anything else = nested. */
#define BACKEND(ord, name)                                        \
    CK_RV mw_backend_##ord(CK_ULONG idx, CK_ULONG via)           \
    {                                                           \
        mw_log("backend", name, idx, via == 0 ? "direct" : "nested", CKR_OK); \
        return CKR_OK;                                          \
    }

BACKEND(0, "C_Initialize")
BACKEND(5, "C_GetSlotList")
BACKEND(13, "C_OpenSession")
BACKEND(18, "C_Login")
BACKEND(43, "C_Sign")
BACKEND(44, "C_SignUpdate")
