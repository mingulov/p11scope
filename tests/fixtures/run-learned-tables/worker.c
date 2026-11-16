/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* A short-lived pkcs11-check-shaped worker: dlopens the provider,
 * negotiates the 3.0 interface through C_GetInterfaceList +
 * C_GetInterface (like the kryoptic/haskoki matrix legs), calls
 * three table functions per round, prints a DONE ledger line, and
 * exits within milliseconds.
 *
 * Usage: worker <provider.so> <rounds>
 * Prints: DONE worker=<pid> table_calls=<n>
 * (table_calls counts table calls only, never the getter calls).
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
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
    if (argc != 3) {
        fprintf(stderr, "usage: worker <provider.so> <rounds>\n");
        return 2;
    }
    char *end = NULL;
    long rounds = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || rounds < 1 || rounds > 1000000) {
        return 2;
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
    long table_calls = 0;
    for (long round = 0; round < rounds; round++) {
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
    printf("DONE worker=%ld table_calls=%ld\n", (long)getpid(), table_calls);
    fflush(stdout);
    return 0;
}
