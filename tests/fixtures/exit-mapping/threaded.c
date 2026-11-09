/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* exit-mapping threaded mapper: a live second thread spans the dlopen cycles,
 * so every mapping event sees mm_users > 1, globalizes, and the exit summary
 * stays empty (reads unknown). A pipe proves the thread is alive before the
 * first dlopen; the leader exits while it still sleeps. usage: threaded
 * PROVIDER (absolute path of the watched provider .so). Exit 0 on success. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static int ready[2];

static void *spinner(void *arg)
{
    (void)arg;
    if (write(ready[1], "r", 1) != 1)
        _exit(3);
    usleep(300000);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t th;
    char b;
    void *h;

    if (argc != 2) {
        fprintf(stderr, "usage: threaded PROVIDER\n");
        return 2;
    }
    if (pipe(ready) != 0)
        return 2;
    if (pthread_create(&th, NULL, spinner, NULL) != 0)
        return 2;
    if (read(ready[0], &b, 1) != 1)
        return 2;
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
