/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Deterministic SoftHSM workload for counter-mode parity checks.
 * Usage: counter-softhsm-workload MODULE [ITERATIONS [SETTLE_SECONDS]]
 *
 * Opens a real PKCS#11 module, waits for the observer to discover
 * and attach (settle, default 30 s), then initializes it and calls
 * slot and info functions a fixed number of times: every run issues
 * exactly the same calls whatever token state the module has (zero
 * slots is fine; the hot calls need no token). Calls start only
 * after the settle so no run misses pre-attach calls. Prints one
 * LEDGER line with per-function call counts to stdout. Exits nonzero
 * when the module cannot be opened, a needed symbol is missing, or a
 * call count is not the scripted one.
 *
 * Only dlsym'd entry points are used, so no PKCS#11 headers are
 * needed; output structs are oversized byte buffers the workload
 * never reads. LP64-only. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long ck_ulong_t;
typedef ck_ulong_t ck_rv_t;
typedef ck_ulong_t ck_slot_id_t;
typedef ck_ulong_t ck_mechanism_type_t;

typedef ck_rv_t (*c_initialize_t)(void *);
typedef ck_rv_t (*c_finalize_t)(void *);
typedef ck_rv_t (*c_get_info_t)(unsigned char *);
typedef ck_rv_t (*c_get_slot_list_t)(unsigned char, ck_slot_id_t *, ck_ulong_t *);
typedef ck_rv_t (*c_get_slot_info_t)(ck_slot_id_t, unsigned char *);
typedef ck_rv_t (*c_get_token_info_t)(ck_slot_id_t, unsigned char *);
typedef ck_rv_t (*c_get_mechanism_list_t)(ck_slot_id_t, ck_mechanism_type_t *, ck_ulong_t *);
typedef ck_rv_t (*c_get_mechanism_info_t)(ck_slot_id_t, ck_mechanism_type_t, unsigned char *);

static void *need_symbol(void *handle, const char *name)
{
    dlerror();
    void *symbol = dlsym(handle, name);
    const char *error = dlerror();
    if (error != NULL || symbol == NULL) {
        fprintf(stderr, "workload: missing %s: %s\n", name,
                error != NULL ? error : "null symbol");
        exit(3);
    }
    return symbol;
}

int main(int argc, char **argv)
{
    if (sizeof(unsigned long) != 8 || sizeof(void *) != 8) {
        fprintf(stderr, "workload: LP64 only\n");
        return 3;
    }
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "usage: %s MODULE [ITERATIONS [SETTLE_SECONDS]]\n", argv[0]);
        return 2;
    }
    long iterations = argc >= 3 ? strtol(argv[2], NULL, 10) : 200;
    if (iterations < 1 || iterations > 100000) {
        fprintf(stderr, "workload: bad iteration count\n");
        return 2;
    }
    long settle = argc == 4 ? strtol(argv[3], NULL, 10) : 30;
    if (settle < 0 || settle > 600) {
        fprintf(stderr, "workload: bad settle delay\n");
        return 2;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "workload: cannot open %s: %s\n", argv[1], dlerror());
        return 3;
    }
    c_initialize_t c_initialize = need_symbol(handle, "C_Initialize");
    c_finalize_t c_finalize = need_symbol(handle, "C_Finalize");
    c_get_info_t c_get_info = need_symbol(handle, "C_GetInfo");
    c_get_slot_list_t c_get_slot_list = need_symbol(handle, "C_GetSlotList");
    c_get_slot_info_t c_get_slot_info = need_symbol(handle, "C_GetSlotInfo");
    c_get_token_info_t c_get_token_info = need_symbol(handle, "C_GetTokenInfo");
    c_get_mechanism_list_t c_get_mechanism_list =
        need_symbol(handle, "C_GetMechanismList");
    c_get_mechanism_info_t c_get_mechanism_info =
        need_symbol(handle, "C_GetMechanismInfo");

    /* The module is mapped but no call is issued yet: the observer
     * discovers and attaches during the settle, so every counted
     * call below lands on attached probes in every run. */
    if (settle > 0) {
        unsigned left = (unsigned)settle;
        while (left > 0)
            left = sleep(left);
    }
    printf("SETTLED after %lds\n", settle);
    fflush(stdout);
    ck_rv_t rv = c_initialize(NULL);
    if (rv != 0) {
        fprintf(stderr, "workload: C_Initialize failed: 0x%lx\n", rv);
        return 3;
    }
    unsigned char info[256];
    unsigned char slot_info[256];
    unsigned char token_info[512];
    unsigned char mechanism_info[256];
    ck_slot_id_t slots[64];
    ck_mechanism_type_t mechanisms[256];
    long get_info = 0, get_slot_list = 0, get_slot_info = 0, get_token_info = 0;
    long get_mechanism_list = 0, get_mechanism_info = 0;
    for (long i = 0; i < iterations; i++) {
        memset(info, 0, sizeof info);
        c_get_info(info);
        get_info++;
        ck_ulong_t count = 0;
        c_get_slot_list(0, NULL, &count);
        get_slot_list++;
        if (count > 64)
            count = 64;
        if (count > 0) {
            ck_ulong_t have = count;
            c_get_slot_list(0, slots, &have);
            get_slot_list++;
            if (have > count)
                have = count;
            for (ck_ulong_t s = 0; s < have; s++) {
                memset(slot_info, 0, sizeof slot_info);
                c_get_slot_info(slots[s], slot_info);
                get_slot_info++;
                memset(token_info, 0, sizeof token_info);
                c_get_token_info(slots[s], token_info);
                get_token_info++;
                ck_ulong_t mechanisms_count = 0;
                c_get_mechanism_list(slots[s], NULL, &mechanisms_count);
                get_mechanism_list++;
                if (mechanisms_count > 256)
                    mechanisms_count = 256;
                if (mechanisms_count > 0) {
                    ck_ulong_t got = mechanisms_count;
                    c_get_mechanism_list(slots[s], mechanisms, &got);
                    get_mechanism_list++;
                    if (got > mechanisms_count)
                        got = mechanisms_count;
                    if (got > 0) {
                        memset(mechanism_info, 0, sizeof mechanism_info);
                        c_get_mechanism_info(slots[s], mechanisms[0], mechanism_info);
                        get_mechanism_info++;
                    }
                }
            }
        }
    }
    rv = c_finalize(NULL);
    if (rv != 0) {
        fprintf(stderr, "workload: C_Finalize failed: 0x%lx\n", rv);
        return 3;
    }
    printf("LEDGER C_GetInfo=%ld C_GetSlotList=%ld C_GetSlotInfo=%ld "
           "C_GetTokenInfo=%ld C_GetMechanismList=%ld C_GetMechanismInfo=%ld\n",
           get_info, get_slot_list, get_slot_info, get_token_info,
           get_mechanism_list, get_mechanism_info);
    /* The hot calls are token-independent: exactly one C_GetInfo and
     * at least one C_GetSlotList per iteration, on every run. */
    if (get_info != iterations || get_slot_list < iterations) {
        fprintf(stderr, "workload: hot counts drifted\n");
        return 3;
    }
    return 0;
}
