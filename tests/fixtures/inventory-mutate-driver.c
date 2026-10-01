/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned provider-mutation fixture driver: map a provider, then dlclose and
 * dlopen the same path on signal so the observer watches one path resolve
 * to two distinct physical module instances across passes.
 *
 *   inventory-mutate-driver --ready <file> --go <file> --done <file> <provider.so>
 *
 * dlopens the provider (RTLD_NOW), appends "READY <pid>" to the ready file,
 * polls for the go file, dlcloses, dlopens the same path again (the test
 * atomically replaces the file between the passes, so the second mapping
 * is a new (device, inode)), appends "DONE <pid>" to the done file, then
 * sleeps for the observer.
 *
 * Exit codes: 0 ready (after sleeping), 2 usage, 3 dlopen failure, 4 the
 * ready/done file could not be written, 5 the go file never arrived.
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
            "usage: %s --ready <file> --go <file> --done <file> <provider.so>\n",
            argv0);
}

static int append_line(const char *path, const char *tag)
{
    FILE *file = fopen(path, "a");
    if (file == NULL) {
        return -1;
    }
    fprintf(file, "%s %d\n", tag, (int)getpid());
    return fclose(file) == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *ready_path = NULL;
    const char *go_path = NULL;
    const char *done_path = NULL;
    const char *provider = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ready") == 0) {
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
    if (append_line(ready_path, "READY") != 0) {
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
    if (append_line(done_path, "DONE") != 0) {
        fprintf(stderr, "mutate-driver: cannot write %s\n", done_path);
        return 4;
    }

    sleep(300);
    return 0;
}
