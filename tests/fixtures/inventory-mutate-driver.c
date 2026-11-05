/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned provider-mutation fixture driver: map a provider, then dlclose and
 * dlopen the same path on signal so the observer watches one path resolve
 * to two distinct physical module instances across passes.
 *
 *   inventory-mutate-driver [--map-only] --ready <file> --go <file> --done <file> <provider.so>
 *
 * dlopens the provider (RTLD_NOW), invokes C_GetFunctionList to populate its
 * lazily initialized table, then publishes READY to the ready file,
 * polls for the go file, dlcloses, dlopens the same path again (the test
 * atomically replaces the file between the passes, so the second mapping
 * is a new (device, inode)), invokes the replacement's getter, publishes DONE
 * to the done file, then sleeps for the observer. --map-only skips both
 * getter calls for the uninitialized-table negative control.
 *
 * Exit codes: 0 ready (after sleeping), 2 usage, 3 dlopen failure, 4 the
 * ready/done file could not be written, 5 the go file never arrived,
 * 6 the getter lookup/acquisition failed.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--map-only] --ready <file> --go <file> --done <file> <provider.so>\n",
            argv0);
}

static int publish_line(const char *path, const char *tag, int getter_calls)
{
    size_t length = strlen(path) + sizeof(".tmp");
    char *staging = malloc(length);
    if (staging == NULL) {
        return -1;
    }
    snprintf(staging, length, "%s.tmp", path);
    FILE *file = fopen(staging, "w");
    if (file == NULL) {
        free(staging);
        return -1;
    }
    int written = fprintf(file, "%s %d getter_calls=%d\n", tag, (int)getpid(), getter_calls) >= 0;
    if (fclose(file) != 0) {
        written = 0;
    }
    /* Path existence acknowledges a complete, closed file, even if the
     * observer reads it immediately after its bounded existence wait. */
    int result = written ? rename(staging, path) : -1;
    if (result != 0) {
        unlink(staging);
    }
    free(staging);
    return result;
}

static int acquire_table(void *handle)
{
    typedef unsigned long (*get_function_list_fn)(void **);
    dlerror();
    get_function_list_fn getter = (get_function_list_fn)dlsym(handle, "C_GetFunctionList");
    if (dlerror() != NULL || getter == NULL) {
        fprintf(stderr, "mutate-driver: C_GetFunctionList lookup failed\n");
        return -1;
    }
    void *table = NULL;
    unsigned long result = getter(&table);
    if (result != 0 || table == NULL) {
        fprintf(stderr, "mutate-driver: C_GetFunctionList did not publish a table (rv=%lu)\n", result);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *ready_path = NULL;
    const char *go_path = NULL;
    const char *done_path = NULL;
    const char *provider = NULL;
    int map_only = 0;
    int getter_calls = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--map-only") == 0) {
            map_only = 1;
        } else if (strcmp(argv[i], "--ready") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            ready_path = argv[i];
        } else if (strcmp(argv[i], "--go") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            go_path = argv[i];
        } else if (strcmp(argv[i], "--done") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            done_path = argv[i];
        } else if (provider == NULL) {
            provider = argv[i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (ready_path == NULL || go_path == NULL || done_path == NULL ||
        provider == NULL) {
        usage(argv[0]);
        return 2;
    }

    void *first = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (first == NULL) {
        fprintf(stderr, "mutate-driver: dlopen %s: %s\n", provider, dlerror());
        return 3;
    }
    if (!map_only) {
        if (acquire_table(first) != 0) {
            return 6;
        }
        getter_calls++;
    }
    if (publish_line(ready_path, "READY", getter_calls) != 0) {
        fprintf(stderr, "mutate-driver: cannot write %s\n", ready_path);
        return 4;
    }

    for (int i = 0; i < 3000; i++) {
        if (access(go_path, F_OK) == 0) {
            break;
        }
        if (i == 2999) {
            fprintf(stderr, "mutate-driver: go file never arrived\n");
            return 5;
        }
        {
            struct timespec wait = {0, 100 * 1000 * 1000};
            nanosleep(&wait, NULL);
        }
    }

    /* The test replaced the file at this path while the first mapping was
     * live; closing and reopening resolves the new bytes. */
    dlclose(first);
    void *second = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (second == NULL) {
        fprintf(stderr, "mutate-driver: second dlopen %s: %s\n", provider,
                dlerror());
        return 3;
    }
    if (!map_only) {
        if (acquire_table(second) != 0) {
            return 6;
        }
        getter_calls++;
    }
    if (publish_line(done_path, "DONE", getter_calls) != 0) {
        fprintf(stderr, "mutate-driver: cannot write %s\n", done_path);
        return 4;
    }

    sleep(300);
    return 0;
}
