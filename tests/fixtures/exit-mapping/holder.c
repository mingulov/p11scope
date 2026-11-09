/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* exit-mapping holder: maps the watched provider in a slow dlopen/dlclose
 * loop until killed, so discovery and the loader flow observe the mapping
 * after admission. Prints one READY line before the first dlopen, so the
 * test can gate on the watch instead of the mapping. usage: holder
 * PROVIDER (absolute path). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    void *h;

    if (argc != 2) {
        fprintf(stderr, "usage: holder PROVIDER\n");
        return 2;
    }
    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    for (;;) {
        h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return 1;
        }
        sleep(2);
        if (dlclose(h) != 0) {
            fprintf(stderr, "dlclose failed\n");
            return 1;
        }
        sleep(2);
    }
    return 0;
}
