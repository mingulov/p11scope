/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Each fixture runs in a separate helper process; none executes mapped scratch bytes. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef PROVENANCE_MODE
#define PROVENANCE_MODE 0
#endif

typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef struct { unsigned char major, minor; } CK_VERSION;
static struct { CK_VERSION version; void *functions[68]; } table;
static char backend_path[4096];

CK_RV C_GetFunctionList(void **output);

static void fail(const char *operation) {
    perror(operation);
    _exit(71);
}

static CK_RV initialize(void) { return 0; }

static const char *module_path(void) {
    Dl_info info;
    if (!dladdr((void *)C_GetFunctionList, &info) || !info.dli_fname)
        fail("dladdr fixture module");
    return info.dli_fname;
}

__attribute__((constructor)) static void prepare(void) {
    table.version = (CK_VERSION){2, 40};
    table.functions[0] = (void *)initialize;
    if (PROVENANCE_MODE == 1 || PROVENANCE_MODE == 2) {
        char scratch[4096];
        int length = snprintf(scratch, sizeof(scratch), "%s.scratch-XXXXXX", module_path());
        if (length < 0 || (size_t)length >= sizeof(scratch)) fail("scratch pathname");
        int fd = mkstemp(scratch);
        if (fd < 0) fail("mkstemp scratch");
        long page = sysconf(_SC_PAGESIZE);
        if (page <= 0 || ftruncate(fd, page)) fail("size scratch");
        void *mapping = mmap(NULL, (size_t)page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (mapping == MAP_FAILED) fail("mmap scratch");
        if (unlink(scratch) || close(fd)) fail("unlink scratch");
        if (PROVENANCE_MODE == 2) table.functions[1] = mapping;
    }
    if (PROVENANCE_MODE == 3 || PROVENANCE_MODE == 5) {
        int length = snprintf(backend_path, sizeof(backend_path), "%s", module_path());
        if (length < 0 || (size_t)length >= sizeof(backend_path)) fail("backend pathname");
        char *basename = strrchr(backend_path, '/');
        if (!basename) fail("absolute backend pathname");
        size_t left = sizeof(backend_path) - (size_t)(basename + 1 - backend_path);
        if (snprintf(basename + 1, left, "backend.so") >= (int)left) fail("backend basename");
        void *backend = dlopen(backend_path, RTLD_NOW | RTLD_LOCAL);
        if (!backend) fail("dlopen backend");
        table.functions[1] = dlsym(backend, "provenance_backend");
        if (!table.functions[1]) fail("dlsym backend");
    }
}

CK_RV C_GetFunctionList(void **output) {
    *output = &table;
    return 0;
}

/* Selection follows legacy resolution, so these modes remove an already
 * resolved object's path before final provenance validation. */
CK_RV C_GetInterface(void *name, void *version, void **output, CK_FLAGS flags) {
    (void)name; (void)version; (void)output; (void)flags;
    static int changed;
    if (!changed++) {
        if (PROVENANCE_MODE == 3 && unlink(backend_path)) fail("unlink required backend");
        if (PROVENANCE_MODE == 4 && unlink(module_path())) fail("unlink required module");
        if (PROVENANCE_MODE == 5) {
            int fd = open(backend_path, O_WRONLY | O_APPEND);
            if (fd < 0 || write(fd, "x", 1) != 1 || close(fd)) fail("change required backend");
        }
    }
    return 0x54UL;
}
