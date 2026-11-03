/* SPDX-License-Identifier: GPL-3.0-or-later */
/* exit-mapping mapper: single-threaded dlopen/dlclose cycles over the watched
 * provider, then exits. Each cycle is an independent mapping event and slots
 * are sticky, so any localized cycle names the slot at exit. usage: mapper
 * PROVIDER (absolute path of the watched provider .so). Exit 0 on success. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    void *h;

    if (argc != 2) {
        fprintf(stderr, "usage: mapper PROVIDER\n");
        return 2;
    }
    for (int i = 0; i < 5; i++) {
        h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return 1;
        }
        if (dlclose(h) != 0) {
            fprintf(stderr, "dlclose failed\n");
            return 1;
        }
    }
    return 0;
}
