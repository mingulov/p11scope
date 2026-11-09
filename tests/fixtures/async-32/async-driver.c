/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* async-32 driver: scripted caller for the async-32 stub provider (link
 * -ldl). Binds through C_GetFunctionList like a real application and
 * cross-checks the table entries against dlsym.
 *
 *   async-driver cmd PROVIDER
 *       Single-byte commands on stdin, one reply line each on stdout:
 *       i  C_Initialize                          -> INIT rv
 *       o  C_OpenSession (next slot: s1, s2)      -> SESSION n handle rv
 *       t  C_SignInit(s1, CKM_RSA_PKCS, key 1)    -> SIGNINIT rv
 *       n  C_Sign(s1)                             -> SIGN rv
 *       g  C_AsyncGetID(s1, "C_Sign", &id)        -> GETID rv id
 *       G  C_AsyncGetID(s1, "C_Sign", NULL)       -> GETID_NULL rv
 *       j  C_AsyncJoin(s2, "C_Sign", id, NULL, 0) -> JOIN rv
 *       c  C_AsyncComplete(holder, "C_Sign", &)   -> COMPLETE rv
 *       x  exit
 *       The holder starts at s1 and moves to s2 after j. Join and
 *       complete require the sessions they name; misuse exits nonzero.
 *       Every line is this process's own ledger; it never reads
 *       observer state. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "async-32.h"

static Async32FunctionList *table;
static CK_SESSION_HANDLE s1;
static CK_SESSION_HANDLE s2;
static int have_s1;
static int have_s2;
static CK_ULONG last_id;
static CK_SESSION_HANDLE holder;

static void fail(const char *what) {
    fprintf(stderr, "async-driver: %s\n", what);
    exit(1);
}

static void check_table(void *handle) {
    struct {
        const char *name;
        void *entry;
    } bindings[] = {
        {"C_Initialize", (void *)table->C_Initialize},
        {"C_Finalize", (void *)table->C_Finalize},
        {"C_OpenSession", (void *)table->C_OpenSession},
        {"C_CloseSession", (void *)table->C_CloseSession},
        {"C_SignInit", (void *)table->C_SignInit},
        {"C_Sign", (void *)table->C_Sign},
        {"C_AsyncComplete", (void *)table->C_AsyncComplete},
        {"C_AsyncGetID", (void *)table->C_AsyncGetID},
        {"C_AsyncJoin", (void *)table->C_AsyncJoin},
    };
    for (size_t i = 0; i < sizeof bindings / sizeof bindings[0]; i++) {
        void *symbol = dlsym(handle, bindings[i].name);
        if (symbol == NULL || symbol != bindings[i].entry)
            fail("table entry does not match its exported symbol");
    }
    if (table->major != 3 || table->minor != 2)
        fail("provider is not version 3.2");
}

static int cmd_mode(const char *provider) {
    static char target[] = "C_Sign";
    void *handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        fail(dlerror());
    CK_RV (*get_list)(void **) = dlsym(handle, "C_GetFunctionList");
    if (get_list == NULL)
        fail("C_GetFunctionList missing");
    void *raw = NULL;
    if (get_list(&raw) != ASYNC32_CKR_OK || raw == NULL)
        fail("C_GetFunctionList refused");
    table = raw;
    check_table(handle);
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("READY %d\n", (int)getpid());
    for (;;) {
        int command = getchar();
        if (command == EOF || command == 'x')
            return 0;
        switch (command) {
        case 'i': {
            CK_RV rv = table->C_Initialize(NULL);
            printf("INIT %lu\n", rv);
            break;
        }
        case 'o': {
            CK_SESSION_HANDLE h = 0;
            CK_RV rv = table->C_OpenSession(
                0, ASYNC32_CKF_SERIAL_SESSION | ASYNC32_CKF_RW_SESSION, NULL,
                NULL, &h);
            if (rv == ASYNC32_CKR_OK) {
                if (!have_s1) {
                    s1 = h;
                    have_s1 = 1;
                    holder = h;
                    printf("SESSION 1 %lu %lu\n", h, rv);
                } else if (!have_s2) {
                    s2 = h;
                    have_s2 = 1;
                    printf("SESSION 2 %lu %lu\n", h, rv);
                } else {
                    printf("SESSION 3 %lu %lu\n", h, rv);
                }
            } else {
                printf("SESSION 0 0 %lu\n", rv);
            }
            break;
        }
        case 't': {
            if (!have_s1)
                fail("signinit without s1");
            CK_MECHANISM mech;
            memset(&mech, 0, sizeof mech);
            mech.mechanism = ASYNC32_CKM_RSA_PKCS;
            CK_RV rv = table->C_SignInit(s1, &mech, 1);
            printf("SIGNINIT %lu\n", rv);
            break;
        }
        case 'n': {
            if (!have_s1)
                fail("sign without s1");
            static unsigned char data[4] = {'d', 'a', 't', 'a'};
            unsigned char sig[64];
            CK_ULONG sig_len = sizeof sig;
            CK_RV rv = table->C_Sign(s1, data, sizeof data, sig, &sig_len);
            printf("SIGN %lu\n", rv);
            break;
        }
        case 'g': {
            if (!have_s1)
                fail("getid without s1");
            CK_ULONG id = 0;
            CK_RV rv = table->C_AsyncGetID(s1, target, &id);
            if (rv == ASYNC32_CKR_OK)
                last_id = id;
            printf("GETID %lu %lu\n", rv, id);
            break;
        }
        case 'G': {
            if (!have_s1)
                fail("getid-null without s1");
            CK_RV rv = table->C_AsyncGetID(s1, target, NULL);
            printf("GETID_NULL %lu\n", rv);
            break;
        }
        case 'j': {
            if (!have_s2)
                fail("join without s2");
            CK_RV rv = table->C_AsyncJoin(s2, target, last_id, NULL, 0);
            if (rv == ASYNC32_CKR_OK)
                holder = s2;
            printf("JOIN %lu\n", rv);
            break;
        }
        case 'c': {
            if (!have_s1)
                fail("complete without s1");
            CK_ASYNC_DATA data;
            memset(&data, 0, sizeof data);
            CK_RV rv = table->C_AsyncComplete(holder, target, &data);
            printf("COMPLETE %lu\n", rv);
            break;
        }
        default:
            break;
        }
    }
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "cmd") == 0)
        return cmd_mode(argv[2]);
    fprintf(stderr, "usage: async-driver cmd PROVIDER\n");
    return 2;
}
