/* SPDX-License-Identifier: GPL-3.0-or-later */
/* chain-client: short-lived SoftHSM client for launcher-chain tests.
 * Usage: chain-client MODULE READY GATE
 * dlopens MODULE, writes "READY <pid>" to READY, waits for GATE to appear
 * (30 s ceiling), then exits. The client lives only for one capture. */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s MODULE READY GATE\n", argv[0]);
        return 2;
    }
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen %s: %s\n", argv[1], dlerror());
        return 3;
    }
    FILE *ready = fopen(argv[2], "w");
    if (!ready) {
        perror("ready");
        return 3;
    }
    fprintf(ready, "READY %d\n", (int)getpid());
    fclose(ready);
    struct timespec tick = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
    for (int i = 0; i < 600; i++) {
        if (access(argv[3], F_OK) == 0) {
            break;
        }
        nanosleep(&tick, NULL);
    }
    if (access(argv[3], F_OK) != 0) {
        fprintf(stderr, "gate never opened\n");
        return 3;
    }
    dlclose(handle);
    return 0;
}
