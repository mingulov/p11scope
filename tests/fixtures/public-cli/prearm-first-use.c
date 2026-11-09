/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Minimal SoftHSM first-use workload for the run-prearm public cell
 * (scripts/qualify-public-cli.sh): dlopen the provider given on argv,
 * publish its function list, then run N C_Initialize/C_Finalize pairs at
 * start, ledgering every call. No sleeps, no gates: first use happens as
 * early as the loader can do it. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) {
        perror("clock_gettime");
        exit(90);
    }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

typedef unsigned long (*get_list_fn)(void **);
typedef unsigned long (*init_fn)(void *);
typedef unsigned long (*fini_fn)(void *);

int main(int argc, char **argv) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: %s provider.so ledger.jsonl [pairs] [settle_ms]\n", argv[0]);
        return 2;
    }
    int pairs = argc >= 4 ? atoi(argv[3]) : 3;
    if (pairs < 1 || pairs > 100) {
        fprintf(stderr, "pairs must be 1..100\n");
        return 2;
    }
    int settle_ms = argc == 5 ? atoi(argv[4]) : 0;
    if (settle_ms < 0 || settle_ms > 60000) {
        fprintf(stderr, "settle_ms must be 0..60000\n");
        return 2;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    get_list_fn publish = (get_list_fn)dlsym(handle, "C_GetFunctionList");
    if (!publish) {
        fprintf(stderr, "dlsym C_GetFunctionList: %s\n", dlerror());
        return 3;
    }
    FILE *ledger = fopen(argv[2], "w");
    if (!ledger) {
        perror("ledger open");
        return 4;
    }
    void *table_ptr = NULL;
    unsigned long rv = publish(&table_ptr);
    if (rv || !table_ptr) {
        fprintf(stderr, "C_GetFunctionList rv=%lu\n", rv);
        return 5;
    }
    /* CK_FUNCTION_LIST layout: CK_VERSION (2 bytes + padding) then
     * function pointers. C_Initialize is entry 0, C_Finalize entry 1. */
    struct ck_function_list {
        unsigned char major, minor;
        void *functions[68];
    };
    _Static_assert(__builtin_offsetof(struct ck_function_list, functions) == 8,
                   "LP64 function table ABI");
    struct ck_function_list *table = table_ptr;
    init_fn initialize = (init_fn)table->functions[0];
    fini_fn finalize = (fini_fn)table->functions[1];
    int done_init = 0, done_fini = 0;
    for (int i = 0; i < pairs; i++) {
        uint64_t before = now_ns();
        unsigned long init_rv = initialize(NULL);
        uint64_t after_init = now_ns();
        if (init_rv) {
            fprintf(stderr, "C_Initialize rv=%lu\n", init_rv);
            return 6;
        }
        done_init++;
        unsigned long fini_rv = finalize(NULL);
        uint64_t after_fini = now_ns();
        if (fini_rv) {
            fprintf(stderr, "C_Finalize rv=%lu\n", fini_rv);
            return 6;
        }
        done_fini++;
        fprintf(ledger,
                "{\"pair\":%d,\"init_ns\":%" PRIu64 ",\"init_returned_ns\":%" PRIu64
                ",\"fini_returned_ns\":%" PRIu64 "}\n",
                i, before, after_init, after_fini);
    }
    fprintf(ledger, "{\"initializes\":%d,\"finalizes\":%d}\n", done_init, done_fini);
    if (fclose(ledger)) return 4;
    /* Settle with the provider still mapped so the terminal scan admits
     * it the same way with and without the pause gate; first use is
     * already ledgered above and unaffected. */
    if (settle_ms > 0) {
        struct timespec settle = {
            .tv_sec = settle_ms / 1000,
            .tv_nsec = (long)(settle_ms % 1000) * 1000000L,
        };
        nanosleep(&settle, NULL);
    }
    if (dlclose(handle)) return 7;
    return 0;
}
