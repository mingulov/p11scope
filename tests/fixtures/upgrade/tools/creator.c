/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Upgrade-fixture key setup: generate the RSA key a capture workload uses.
 *
 * Usage: creator PROVIDER PIN HEXID
 *
 * dlopens PROVIDER, C_Initialize, opens a read-write session on the
 * first slot with a token, logs in as CKU_USER and generates an
 * RSA-2048 key pair with the CKA_ID given as even-length hex
 * (1..64 characters, e.g. "b302"). Prints "created id=<hex>" on
 * success. Exit 0 on success, 1 when a PKCS#11 call fails, 2 on
 * usage/setup failure.
 *
 * This is shortlived-keygen with a caller-chosen id: the upgrade
 * captures share one SoftHSM token across workloads, so each
 * workload needs its own id. Run against a fresh token (see
 * tests/fixtures/upgrade/README.md, "Regenerate").
 *
 * Compiled against a real pkcs11.h; needs C_GenerateKeyPair, past
 * the hand-rolled ABI subset. LP64 only.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkcs11.h>

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
    if (argc != 4) {
        fprintf(stderr, "usage: %s PROVIDER PIN HEXID\n",
                argc > 0 ? argv[0] : "creator");
        return 2;
    }
    size_t hex_len = strlen(argv[3]);
    if (hex_len == 0 || hex_len > 64 || hex_len % 2 != 0) {
        fprintf(stderr, "creator: HEXID must be even-length hex, 1..64 chars\n");
        return 2;
    }
    CK_BYTE key_id[32];
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = hex_value(argv[3][i]);
        int lo = hex_value(argv[3][i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "creator: HEXID must be hex\n");
            return 2;
        }
        key_id[i / 2] = (CK_BYTE)((hi << 4) | lo);
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "creator: cannot open provider: %s\n", dlerror());
        return 2;
    }
    CK_C_GetFunctionList get_list =
        (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR fl = NULL;
    if (get_list == NULL || get_list(&fl) != CKR_OK || fl == NULL) {
        fprintf(stderr, "creator: C_GetFunctionList failed\n");
        return 2;
    }
#define CHECK(call, what)                                                \
    do {                                                                 \
        CK_RV rv = (call);                                               \
        if (rv != CKR_OK) {                                              \
            fprintf(stderr, "creator: %s failed rv=0x%lx\n", what,        \
                    (unsigned long)rv);                                  \
            return 1;                                                    \
        }                                                                \
    } while (0)
    CHECK(fl->C_Initialize(NULL), "C_Initialize");
    CK_ULONG slot_count = 0;
    CHECK(fl->C_GetSlotList(CK_TRUE, NULL, &slot_count), "C_GetSlotList(count)");
    if (slot_count == 0) {
        fprintf(stderr, "creator: no token slot\n");
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
    CK_BBOOL ck_true = CK_TRUE;
    CK_ULONG bits = 2048;
    CK_BYTE exponent[3] = {0x01, 0x00, 0x01};
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
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
    CHECK(fl->C_GenerateKeyPair(session, &mech, pub_tmpl, 4, priv_tmpl, 5,
                                &pub, &priv),
          "C_GenerateKeyPair");
    CHECK(fl->C_Logout(session), "C_Logout");
    CHECK(fl->C_CloseSession(session), "C_CloseSession");
    CHECK(fl->C_Finalize(NULL), "C_Finalize");
    printf("created id=");
    for (size_t i = 0; i < hex_len / 2; i++) {
        printf("%02x", key_id[i]);
    }
    printf("\n");
    return 0;
}
