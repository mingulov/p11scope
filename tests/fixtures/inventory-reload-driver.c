/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned inventory fixture: map a provider, unload it, map it again.
 *
 *   inventory-reload-driver --ready <file> <provider.so>
 *
 * dlopens the provider (RTLD_NOW), calls its C_GetFunctionList once,
 * appends "READY <pid>", sleeps 4 seconds (mapped passes), dlcloses the
 * provider, sleeps 3 seconds (unloaded passes), dlopens it again, and
 * sleeps so the observer records the reload.
 *
 * Exit codes: 0 ready (after sleeping), 2 usage, 3 dlopen failure,
 * 4 the call surface failed, 5 the ready file could not be written.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef CK_RV (*get_function_list_fn)(void **);

static int reopen_and_call(const char *provider)
{
    void *handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "inventory-reload-driver: reopen %s: %s\n", provider,
                dlerror());
        return 3;
    }
    dlerror();
    void *symbol = dlsym(handle, "C_GetFunctionList");
    const char *error = dlerror();
    if (error != NULL || symbol == NULL) {
        fprintf(stderr,
                "inventory-reload-driver: dlsym C_GetFunctionList in %s: %s\n",
                provider, error != NULL ? error : "missing");
        return 4;
    }
    void *list = NULL;
    CK_RV rv = ((get_function_list_fn)symbol)(&list);
    if (rv != 0 || list == NULL) {
        fprintf(stderr, "inventory-reload-driver: C_GetFunctionList in %s failed\n",
                provider);
        return 4;
    }
    (void)handle;
    return 0;
}

int main(int argc, char **argv)
{
    const char *ready_path = NULL;
    const char *provider = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ready") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "usage: %s --ready <file> <provider.so>\n",
                        argv[0]);
                return 2;
            }
            ready_path = argv[i];
        } else if (provider == NULL) {
            provider = argv[i];
        } else {
            fprintf(stderr, "usage: %s --ready <file> <provider.so>\n", argv[0]);
            return 2;
        }
    }
    if (ready_path == NULL || provider == NULL) {
        fprintf(stderr, "usage: %s --ready <file> <provider.so>\n", argv[0]);
        return 2;
    }

    void *first = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (first == NULL) {
        fprintf(stderr, "inventory-reload-driver: dlopen %s: %s\n", provider,
                dlerror());
        return 3;
    }

    FILE *ready = fopen(ready_path, "a");
    if (ready == NULL) {
        fprintf(stderr, "inventory-reload-driver: cannot write %s\n", ready_path);
        return 5;
    }
    fprintf(ready, "READY %d\n", (int)getpid());
    if (fclose(ready) != 0) {
        fprintf(stderr, "inventory-reload-driver: cannot write %s\n", ready_path);
        return 5;
    }

    sleep(4);
    if (dlclose(first) != 0) {
        fprintf(stderr, "inventory-reload-driver: dlclose %s: %s\n", provider,
                dlerror());
        return 3;
    }
    sleep(3);
    int rc = reopen_and_call(provider);
    if (rc != 0)
        return rc;
    sleep(30);
    return 0;
}
