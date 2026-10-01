/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned inventory fixture: map a provider, then exec another image.
 *
 *   inventory-exec-driver --ready <file> <provider.so> <new-image> [args...]
 *
 * dlopens the provider (RTLD_NOW), calls its C_GetFunctionList once
 * (fills lazily-populated tables), appends "READY <pid>" to the ready
 * file, sleeps 4 seconds so the observer records pre-exec passes, then
 * execs <new-image> with the remaining arguments: the same pid with a
 * new executable image (leader exec from the observer's view).
 *
 * Exit codes: 0 exec completed (unreachable), 2 usage, 3 dlopen failure,
 * 4 the call surface failed, 5 the ready file could not be written,
 * 6 the exec failed.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef CK_RV (*get_function_list_fn)(void **);

int main(int argc, char **argv)
{
    const char *ready_path = NULL;
    const char *provider = NULL;
    int exec_at = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ready") == 0) {
            if (++i >= argc || ready_path != NULL) {
                fprintf(stderr, "usage: %s --ready <file> <provider.so> <image> [args...]\n",
                        argv[0]);
                return 2;
            }
            ready_path = argv[i];
        } else if (provider == NULL) {
            provider = argv[i];
        } else if (exec_at == 0) {
            exec_at = i;
            break;
        }
    }
    if (ready_path == NULL || provider == NULL || exec_at == 0) {
        fprintf(stderr, "usage: %s --ready <file> <provider.so> <image> [args...]\n",
                argv[0]);
        return 2;
    }

    void *handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "inventory-exec-driver: dlopen %s: %s\n", provider, dlerror());
        return 3;
    }
    dlerror();
    void *symbol = dlsym(handle, "C_GetFunctionList");
    const char *error = dlerror();
    if (error != NULL || symbol == NULL) {
        fprintf(stderr, "inventory-exec-driver: dlsym C_GetFunctionList in %s: %s\n",
                provider, error != NULL ? error : "missing");
        return 4;
    }
    void *list = NULL;
    CK_RV rv = ((get_function_list_fn)symbol)(&list);
    if (rv != 0 || list == NULL) {
        fprintf(stderr, "inventory-exec-driver: C_GetFunctionList in %s failed\n",
                provider);
        return 4;
    }

    FILE *ready = fopen(ready_path, "a");
    if (ready == NULL) {
        fprintf(stderr, "inventory-exec-driver: cannot write %s\n", ready_path);
        return 5;
    }
    fprintf(ready, "READY %d\n", (int)getpid());
    if (fclose(ready) != 0) {
        fprintf(stderr, "inventory-exec-driver: cannot write %s\n", ready_path);
        return 5;
    }

    sleep(4);
    execv(argv[exec_at], &argv[exec_at]);
    fprintf(stderr, "inventory-exec-driver: exec %s failed\n", argv[exec_at]);
    return 6;
}
