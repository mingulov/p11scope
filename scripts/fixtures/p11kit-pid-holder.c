/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* p11kit-pid-holder: lazy p11-kit holder for
 * scripts/verify-p11kit-pid-startup.sh. libp11-kit is mapped before the
 * observer attaches, its managed modules load only after the observer
 * signals readiness (`go` file), then a fixed call count per module once
 * `calls` appears, and the modules release after `done`.
 *
 * Usage: p11kit-pid-holder DIR CALLS
 *
 * The observer runs `profile --pid` on this process: the capture must
 * start beside the unpublished closure array (PARTIAL, no capacity text)
 * and attach each managed module below the proxy as it loads. Every
 * managed module gets exactly CALLS C_GetInfo calls plus one release, so
 * the observer must count exactly (CALLS + 1) calls per backend.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef struct { unsigned char major, minor; } CK_VERSION;
typedef struct {
    CK_VERSION cryptokiVersion;
    unsigned char manufacturerID[32];
    CK_ULONG flags;
    unsigned char libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;
typedef CK_RV (*fn_t)(void *);
typedef struct { CK_VERSION version; fn_t f[]; } FL; /* f[2] = C_GetInfo */

static void wait_for(const char *path) {
    while (access(path, F_OK) != 0) usleep(50000);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: holder DIR CALLS\n"); return 2; }
    const char *dir = argv[1];
    int calls = atoi(argv[2]);
    char go[512], start[512], done[512], ready[512];
    snprintf(go, sizeof go, "%s/go", dir);
    snprintf(start, sizeof start, "%s/calls", dir);
    snprintf(done, sizeof done, "%s/done", dir);
    snprintf(ready, sizeof ready, "%s/loaded", dir);
    void *kit = dlopen("libp11-kit.so.0", RTLD_NOW);
    if (!kit) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    FL **(*load)(int) = (FL **(*)(int))dlsym(kit, "p11_kit_modules_load_and_initialize");
    void (*release)(FL **) = (void (*)(FL **))dlsym(kit, "p11_kit_modules_finalize_and_release");
    char *(*name)(FL *) = (char *(*)(FL *))dlsym(kit, "p11_kit_module_get_name");
    if (!load || !release || !name) { fprintf(stderr, "dlsym failed\n"); return 1; }
    printf("mapped\n"); fflush(stdout);
    wait_for(go);
    FL **modules = load(0);
    if (!modules) { fprintf(stderr, "load failed\n"); return 1; }
    int n = 0;
    for (FL **m = modules; *m; m++) {
        char *label = name(*m);
        printf("module %d %s\n", n++, label ? label : "?");
        free(label);
    }
    fflush(stdout);
    FILE *f = fopen(ready, "w"); if (f) fclose(f);
    wait_for(start);
    for (FL **m = modules; *m; m++) {
        for (int i = 0; i < calls; i++) {
            CK_INFO info;
            CK_RV rv = (*m)->f[2](&info);
            if (rv != 0) { fprintf(stderr, "C_GetInfo rv=%lu\n", rv); return 1; }
        }
    }
    printf("called %d x %d\n", n, calls); fflush(stdout);
    wait_for(done);
    release(modules);
    return 0;
}
