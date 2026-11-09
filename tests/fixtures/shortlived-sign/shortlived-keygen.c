/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Short-lived cell key setup: generate the RSA key the signer finds.
 *
 * Usage: shortlived-keygen PROVIDER PIN
 *
 * dlopens PROVIDER, C_Initialize, opens a read-write session on the
 * first slot with a token, logs in as CKU_USER and generates an
 * RSA-2048 key pair with CKA_ID 01:02 (the id shortlived-sign looks
 * up). Prints "keygen ok id=0102" on success. Exit 0 on success, 1
 * when a PKCS#11 call fails, 2 on usage/setup failure.
 *
 * Compiled against a real pkcs11.h (see scripts/ci/find_header_dir in
 * the key-operations cells); unlike shortlived-sign it needs
 * C_GenerateKeyPair, past the hand-rolled ABI subset. LP64 only.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkcs11.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s PROVIDER PIN\n",
                argc > 0 ? argv[0] : "shortlived-keygen");
        return 2;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "shortlived-keygen: cannot open provider: %s\n",
                dlerror());
        return 2;
    }
    CK_C_GetFunctionList get_list =
        (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR fl = NULL;
    if (get_list == NULL || get_list(&fl) != CKR_OK || fl == NULL) {
        fprintf(stderr, "shortlived-keygen: C_GetFunctionList failed\n");
        return 2;
    }
#define CHECK(call, what)                                                  \
    do {                                                                   \
        CK_RV rv = (call);                                                 \
        if (rv != CKR_OK) {                                                \
            fprintf(stderr, "shortlived-keygen: %s failed rv=0x%lx\n", what, \
                    (unsigned long)rv);                                    \
            return 1;                                                      \
        }                                                                  \
    } while (0)
    CHECK(fl->C_Initialize(NULL), "C_Initialize");
    CK_ULONG slot_count = 0;
    CHECK(fl->C_GetSlotList(CK_TRUE, NULL, &slot_count), "C_GetSlotList(count)");
    if (slot_count == 0) {
        fprintf(stderr, "shortlived-keygen: no token slot\n");
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
    CK_BYTE key_id[2] = {0x01, 0x02};
    CK_BBOOL ck_true = CK_TRUE;
    CK_ULONG bits = 2048;
    CK_BYTE exponent[3] = {0x01, 0x00, 0x01};
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_ID, key_id, sizeof(key_id)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)},
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_SIGN, &ck_true, sizeof(ck_true)},
        {CKA_ID, key_id, sizeof(key_id)},
    };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CHECK(fl->C_GenerateKeyPair(session, &mech, pub_tmpl, 4, priv_tmpl, 5,
                                &pub, &priv),
          "C_GenerateKeyPair");
    CHECK(fl->C_Logout(session), "C_Logout");
    CHECK(fl->C_CloseSession(session), "C_CloseSession");
    CHECK(fl->C_Finalize(NULL), "C_Finalize");
    printf("keygen ok id=0102\n");
    return 0;
}
