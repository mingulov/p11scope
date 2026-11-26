/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Upgrade-fixture key-operations anchor: map the provider, wait for a gate,
 * then steadily sign with a fresh key until the window ends.
 *
 * Usage: steady-keys PROVIDER PIN SECONDS HEXID
 * Env: STEADY_GO (path): the capture script touches this file once the
 * observer's semantic lane is ready; key creation waits for it.
 *
 * dlopens PROVIDER, C_Initialize, opens a read-write session on the
 * first slot with a token and logs in as CKU_USER, then prints
 * "mapped pid=<pid>" so the capture script knows the anchor is
 * resident. When STEADY_GO names a path, creation waits (100 ms
 * poll) until that path exists, at most SECONDS; a missing gate at
 * the deadline fails loudly (exit 1), because an ungated run would
 * silently produce a keyless capture. Then it generates an RSA-2048
 * key pair with the CKA_ID given as even-length hex (1..64 chars)
 * and signs 32 bytes with CKM_SHA256_RSA_PKCS about once a second
 * until SECONDS elapse from process start. Prints
 * "created id=<hex> signs=<n>". Exit 0 on a full window, 1 when a
 * PKCS#11 call (or the gate wait) fails, 2 on usage/setup failure.
 *
 * Run against a fresh token (see tests/fixtures/upgrade/README.md,
 * "Regenerate"). Compiled against a real pkcs11.h; needs
 * C_GenerateKeyPair, past the hand-rolled ABI subset. LP64 only.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <pkcs11.h>

static uint64_t clock_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int main(int argc, char **argv) {
    uint64_t t0 = clock_ms();
    if (argc != 5) {
        fprintf(stderr, "usage: %s PROVIDER PIN SECONDS HEXID\n",
                argc > 0 ? argv[0] : "steady-keys");
        return 2;
    }
    char *end = NULL;
    unsigned long seconds = strtoul(argv[3], &end, 10);
    if (*end != '\0' || seconds == 0 || seconds > 600) {
        fprintf(stderr, "steady-keys: SECONDS must be 1..600\n");
        return 2;
    }
    size_t hex_len = strlen(argv[4]);
    if (hex_len == 0 || hex_len > 64 || hex_len % 2 != 0) {
        fprintf(stderr, "steady-keys: HEXID must be even-length hex, 1..64 chars\n");
        return 2;
    }
    CK_BYTE key_id[32];
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = hex_value(argv[4][i]);
        int lo = hex_value(argv[4][i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "steady-keys: HEXID must be hex\n");
            return 2;
        }
        key_id[i / 2] = (CK_BYTE)((hi << 4) | lo);
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "steady-keys: cannot open provider: %s\n", dlerror());
        return 2;
    }
    CK_C_GetFunctionList get_list =
        (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR fl = NULL;
    if (get_list == NULL || get_list(&fl) != CKR_OK || fl == NULL) {
        fprintf(stderr, "steady-keys: C_GetFunctionList failed\n");
        return 2;
    }
#define CHECK(call, what)                                                  \
    do {                                                                   \
        CK_RV rv = (call);                                                 \
        if (rv != CKR_OK) {                                                \
            fprintf(stderr, "steady-keys: %s failed rv=0x%lx\n", what,      \
                    (unsigned long)rv);                                    \
            return 1;                                                      \
        }                                                                  \
    } while (0)
    CHECK(fl->C_Initialize(NULL), "C_Initialize");
    CK_ULONG slot_count = 0;
    CHECK(fl->C_GetSlotList(CK_TRUE, NULL, &slot_count), "C_GetSlotList(count)");
    if (slot_count == 0) {
        fprintf(stderr, "steady-keys: no token slot\n");
        return 1;
    }
    CK_SLOT_ID *slots = calloc(slot_count, sizeof(*slots));
    if (slots == NULL) {
        return 2;
    }
    CHECK(fl->C_GetSlotList(CK_TRUE, slots, &slot_count), "C_GetSlotList");
    CK_SESSION_HANDLE session = 0;
    CHECK(fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL, NULL, &session),
          "C_OpenSession");
    free(slots);
    size_t pin_len = strlen(argv[2]);
    CHECK(fl->C_Login(session, CKU_USER, (CK_CHAR_PTR)argv[2],
                      (CK_ULONG)pin_len),
          "C_Login");
    printf("mapped pid=%d\n", (int)getpid());
    fflush(stdout);
    const char *gate = getenv("STEADY_GO");
    if (gate != NULL && gate[0] != '\0') {
        uint64_t deadline = t0 + seconds * 1000u;
        for (;;) {
            if (access(gate, F_OK) == 0) {
                break;
            }
            if (clock_ms() >= deadline) {
                fprintf(stderr, "steady-keys: gate %s never appeared\n", gate);
                return 1;
            }
            usleep(100 * 1000);
        }
    }
    CK_BBOOL ck_true = CK_TRUE;
    CK_ULONG bits = 2048;
    CK_BYTE exponent[3] = {0x01, 0x00, 0x01};
    CK_MECHANISM gen = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_ID, key_id, (CK_ULONG)(hex_len / 2)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)},
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_SIGN, &ck_true, sizeof(ck_true)},
        {CKA_ID, key_id, (CK_ULONG)(hex_len / 2)},
    };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CHECK(fl->C_GenerateKeyPair(session, &gen, pub_tmpl, 4, priv_tmpl, 5,
                                &pub, &priv),
          "C_GenerateKeyPair");
    CK_ULONG klass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE find_tmpl[2] = {
        {CKA_CLASS, &klass, sizeof(klass)},
        {CKA_ID, key_id, (CK_ULONG)(hex_len / 2)},
    };
    CHECK(fl->C_FindObjectsInit(session, find_tmpl, 2), "C_FindObjectsInit");
    CK_OBJECT_HANDLE key = 0;
    CK_ULONG found = 0;
    CHECK(fl->C_FindObjects(session, &key, 1, &found), "C_FindObjects");
    CHECK(fl->C_FindObjectsFinal(session), "C_FindObjectsFinal");
    if (found == 0) {
        fprintf(stderr, "steady-keys: fresh key not found\n");
        return 1;
    }
    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, NULL, 0};
    CK_BYTE data[32];
    memset(data, 0xA5, sizeof(data));
    unsigned long signs = 0;
    uint64_t end_at = t0 + seconds * 1000u;
    while (clock_ms() < end_at) {
        CHECK(fl->C_SignInit(session, &mech, key), "C_SignInit");
        CK_BYTE sig[512];
        CK_ULONG sig_len = sizeof(sig);
        CHECK(fl->C_Sign(session, data, sizeof(data), sig, &sig_len), "C_Sign");
        if (sig_len == 0) {
            fprintf(stderr, "steady-keys: empty signature\n");
            return 1;
        }
        signs++;
        if (clock_ms() + 1000u < end_at) {
            sleep(1);
        } else {
            break;
        }
    }
    CHECK(fl->C_Logout(session), "C_Logout");
    CHECK(fl->C_CloseSession(session), "C_CloseSession");
    CHECK(fl->C_Finalize(NULL), "C_Finalize");
    if (signs == 0) {
        fprintf(stderr, "steady-keys: no signs completed in the window\n");
        return 1;
    }
    printf("created id=");
    for (size_t i = 0; i < hex_len / 2; i++) {
        printf("%02x", key_id[i]);
    }
    printf(" signs=%lu\n", signs);
    return 0;
}
