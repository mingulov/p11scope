/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned catalog fixture driver: map providers, then sleep for the observer.
 *
 *   catalog-driver --ready <file> [--call] [--sleep <secs>] <provider.so>...
 *
 * dlopens every provider (RTLD_NOW, so constructors run — the fixture
 * application loading its providers, not the observer executing anything),
 * optionally resolves and calls each handle's C_GetFunctionList once (fills
 * lazily-populated tables like version_matrix.c), appends "READY <pid>" to
 * the ready file, then sleeps so `inspect --system` can scan this process
 * as a descendant of the observing helper.
 *
 * Exit codes: 0 ready (after sleeping), 2 usage, 3 dlopen failure, 4 the
 * --call surface failed, 5 the ready file could not be written.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef CK_RV (*get_function_list_fn)(void **);

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s --ready <file> [--call] [--sleep <secs>] <provider.so>...\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *ready_path = NULL;
    int call = 0;
    long sleep_secs = 300;
    int first_so = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ready") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            ready_path = argv[i];
        } else if (strcmp(argv[i], "--call") == 0) {
            call = 1;
        } else if (strcmp(argv[i], "--sleep") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            sleep_secs = strtol(argv[i], NULL, 10);
            if (sleep_secs <= 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (first_so == 0) {
            first_so = i;
        }
    }
    if (ready_path == NULL || first_so == 0) {
        usage(argv[0]);
        return 2;
    }

    for (int i = first_so; i < argc; i++) {
        void *handle = dlopen(argv[i], RTLD_NOW | RTLD_LOCAL);
        if (handle == NULL) {
            fprintf(stderr, "catalog-driver: dlopen %s: %s\n", argv[i], dlerror());
            return 3;
        }
        if (call) {
            dlerror();
            void *symbol = dlsym(handle, "C_GetFunctionList");
            const char *error = dlerror();
            if (error != NULL || symbol == NULL) {
                fprintf(stderr, "catalog-driver: dlsym C_GetFunctionList in %s: %s\n",
                        argv[i], error != NULL ? error : "missing");
                return 4;
            }
            void *list = NULL;
            CK_RV rv = ((get_function_list_fn)symbol)(&list);
            if (rv != 0 || list == NULL) {
                fprintf(stderr, "catalog-driver: C_GetFunctionList in %s failed\n", argv[i]);
                return 4;
            }
        }
    }

    FILE *ready = fopen(ready_path, "a");
    if (ready == NULL) {
        fprintf(stderr, "catalog-driver: cannot write %s\n", ready_path);
        return 5;
    }
    fprintf(ready, "READY %d\n", (int)getpid());
    if (fclose(ready) != 0) {
        fprintf(stderr, "catalog-driver: cannot write %s\n", ready_path);
        return 5;
    }

    sleep((unsigned int)sleep_secs);
    return 0;
}
