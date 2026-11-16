/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* A short-lived pkcs11-check-shaped worker: dlopens the provider,
 * negotiates the 3.0 interface through C_GetInterfaceList +
 * C_GetInterface (like the kryoptic/haskoki matrix legs), calls
 * table functions per round, prints a DONE ledger line, and
 * exits. An optional linger keeps the provider mapped for about a
 * second first, matching the matrix unit workers' lifetime (fast
 * workers would exit between observer ticks and prove nothing
 * about table learning).
 *
 * Usage: worker <provider.so> <rounds> [linger_ms] [ordinal]
 * Without an ordinal the worker calls three table functions per
 * round (C_Initialize, C_GetSlotList, C_LoginUser). With one it
 * calls only that 3.0-table slot per round, so each sequential
 * worker's calls are distinguishable in the observed profile and
 * the cell can pin every miss to its worker's burst window.
 * Prints: DONE worker=<pid> table_calls=<n> burst_start_ns=<t0>
 *   burst_end_ns=<t1> ordinal=<o>
 * (table_calls counts table calls only, never the getter calls;
 * the burst stamps are CLOCK_MONOTONIC nanoseconds around the call
 * loop; ordinal is -1 without the ordinal argument).
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_FLAGS;

typedef struct {
    unsigned char major;
    unsigned char minor;
} CK_VERSION;

typedef struct {
    const char *name;
    void *functions;
    CK_FLAGS flags;
} CK_INTERFACE;

typedef CK_RV (*StubFn)(void);
typedef CK_RV (*GetInterfaceListFn)(CK_INTERFACE *, CK_ULONG *);
typedef CK_RV (*GetInterfaceFn)(const char *, CK_VERSION *, CK_INTERFACE **, CK_FLAGS);

#define CKR_OK 0UL

static void *slot(void *table, unsigned index) {
    /* Past the 8-byte version prefix (2 version bytes + padding). */
    return ((void **)((char *)table + sizeof(void *)))[index];
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: worker <provider.so> <rounds> [linger_ms] [ordinal]\n");
        return 2;
    }
    char *end = NULL;
    long rounds = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || rounds < 1 || rounds > 1000000) {
        return 2;
    }
    long linger_ms = 0;
    if (argc >= 4) {
        linger_ms = strtol(argv[3], &end, 10);
        if (end == argv[3] || *end != '\0' || linger_ms < 0 || linger_ms > 60000) {
            return 2;
        }
    }
    long ordinal = -1;
    if (argc == 5) {
        ordinal = strtol(argv[4], &end, 10);
        if (end == argv[4] || *end != '\0' || ordinal < 0 || ordinal >= 92) {
            return 2;
        }
    }
    /* RTLD_LAZY like the Python loaders in the matrix legs. */
    void *handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    GetInterfaceListFn list = (GetInterfaceListFn)dlsym(handle, "C_GetInterfaceList");
    GetInterfaceFn get = (GetInterfaceFn)dlsym(handle, "C_GetInterface");
    if (list == NULL || get == NULL) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 3;
    }
    CK_ULONG count = 0;
    if (list(NULL, &count) != CKR_OK || count < 1) {
        return 4;
    }
    CK_INTERFACE *interface = NULL;
    if (get("PKCS 11", NULL, &interface, 0) != CKR_OK || interface == NULL) {
        return 4;
    }
    void *table = interface->functions;
    struct timespec burst_start;
    if (clock_gettime(CLOCK_MONOTONIC, &burst_start) != 0) {
        return 6;
    }
    long table_calls = 0;
    for (long round = 0; round < rounds; round++) {
        if (ordinal >= 0) {
            if (((StubFn)slot(table, (unsigned)ordinal))() != CKR_OK) {
                return 5;
            }
            table_calls++;
            continue;
        }
        /* C_Initialize (0), C_GetSlotList (4), C_LoginUser (70). */
        if (((StubFn)slot(table, 0))() != CKR_OK) {
            return 5;
        }
        table_calls++;
        if (((StubFn)slot(table, 4))() != CKR_OK) {
            return 5;
        }
        table_calls++;
        if (((StubFn)slot(table, 70))() != CKR_OK) {
            return 5;
        }
        table_calls++;
    }
    struct timespec burst_end;
    if (clock_gettime(CLOCK_MONOTONIC, &burst_end) != 0) {
        return 6;
    }
    if (linger_ms > 0) {
        struct timespec linger = {
            .tv_sec = linger_ms / 1000,
            .tv_nsec = (linger_ms % 1000) * 1000000L,
        };
        nanosleep(&linger, NULL);
    }
    unsigned long long start_ns =
        (unsigned long long)burst_start.tv_sec * 1000000000ULL + (unsigned long long)burst_start.tv_nsec;
    unsigned long long end_ns =
        (unsigned long long)burst_end.tv_sec * 1000000000ULL + (unsigned long long)burst_end.tv_nsec;
    printf(
        "DONE worker=%ld table_calls=%ld burst_start_ns=%llu burst_end_ns=%llu ordinal=%ld\n",
        (long)getpid(),
        table_calls,
        start_ns,
        end_ns,
        ordinal);
    fflush(stdout);
    return 0;
}
