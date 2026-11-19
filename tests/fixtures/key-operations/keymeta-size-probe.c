/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/*
 * keymeta-size-probe: run real RSA signs against a SoftHSM token and print
 * the observed (mechanism, signature length) pairs, one JSON object per
 * line on stdout:
 *
 *   {"fn":"C_Sign","mechanism":1,"length":256,"rv":0}
 *
 * Usage: keymeta-size-probe MODULE (PIN in P11SCOPE_KEY_FIXTURE_PIN,
 * token config in SOFTHSM2_CONF). The keymeta end-to-end test feeds the
 * observed lengths through genuine 648-byte journal END wire records into
 * the seal, the key-use reducer and the v7 projection, so the lengths
 * must be observed provider outputs, never fixture constants: the only
 * assertion here is that each PKCS#11 call returned CKR_OK.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pkcs11.h>

static CK_FUNCTION_LIST_PTR api;

#define CALL(member, ...)                                                      \
    do {                                                                       \
        CK_RV result = api->member(__VA_ARGS__);                               \
        if (result != CKR_OK) {                                                \
            fprintf(stderr, "size probe call %s returned CK_RV 0x%lx\n",       \
                    #member, (unsigned long)result);                           \
            goto failed;                                                       \
        }                                                                      \
    } while (0)

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("usage: keymeta-size-probe MODULE (PIN in P11SCOPE_KEY_FIXTURE_PIN)\n",
              stderr);
        return 2;
    }
    const char *pin = getenv("P11SCOPE_KEY_FIXTURE_PIN");
    if (!pin || !*pin || strlen(pin) > 256) {
        fputs("size probe PIN is missing or invalid\n", stderr);
        return 2;
    }
    alarm(60);
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) {
        fputs("size probe provider could not load\n", stderr);
        return 1;
    }
    void *symbol = dlsym(module, "C_GetFunctionList");
    CK_C_GetFunctionList get_function_list = NULL;
    _Static_assert(sizeof get_function_list == sizeof symbol, "POSIX function pointer ABI");
    memcpy(&get_function_list, &symbol, sizeof symbol);
    if (!get_function_list) {
        fputs("size probe provider has no function list\n", stderr);
        dlclose(module);
        return 1;
    }
    if (get_function_list(&api) != CKR_OK || !api) {
        fputs("size probe C_GetFunctionList failed\n", stderr);
        dlclose(module);
        return 1;
    }
#define REQUIRED(member)                                                       \
    if (!api->member) {                                                        \
        fputs("size probe provider lacks " #member "\n", stderr);              \
        dlclose(module);                                                       \
        return 1;                                                              \
    }
    REQUIRED(C_Initialize);
    REQUIRED(C_Finalize);
    REQUIRED(C_GetSlotList);
    REQUIRED(C_OpenSession);
    REQUIRED(C_CloseSession);
    REQUIRED(C_Login);
    REQUIRED(C_Logout);
    REQUIRED(C_GenerateKeyPair);
    REQUIRED(C_DestroyObject);
    REQUIRED(C_SignInit);
    REQUIRED(C_Sign);
#undef REQUIRED

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE, private_key = CK_INVALID_HANDLE;
    int initialized = 0, logged_in = 0, have_keys = 0;
    int exit_code = 1;

    CALL(C_Initialize, NULL);
    initialized = 1;
    CK_SLOT_ID slots[64];
    CK_ULONG slot_count = 64;
    CALL(C_GetSlotList, CK_TRUE, slots, &slot_count);
    if (!slot_count || slot_count > 64) {
        fputs("size probe found no token slot\n", stderr);
        goto failed;
    }
    CALL(C_OpenSession, slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
         &session);
    CALL(C_Login, session, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    logged_in = 1;

    CK_ULONG bits = 2048;
    CK_ULONG public_class = CKO_PUBLIC_KEY, private_class = CKO_PRIVATE_KEY,
             key_type = CKK_RSA;
    CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
    CK_BYTE exponent[] = {1, 0, 1};
    CK_ATTRIBUTE public_template[] = {
        {CKA_CLASS, &public_class, sizeof public_class},
        {CKA_KEY_TYPE, &key_type, sizeof key_type},
        {CKA_TOKEN, &no, sizeof no},
        {CKA_VERIFY, &yes, sizeof yes},
        {CKA_MODULUS_BITS, &bits, sizeof bits},
        {CKA_PUBLIC_EXPONENT, exponent, sizeof exponent},
    };
    CK_ATTRIBUTE private_template[] = {
        {CKA_CLASS, &private_class, sizeof private_class},
        {CKA_KEY_TYPE, &key_type, sizeof key_type},
        {CKA_TOKEN, &no, sizeof no},
        {CKA_PRIVATE, &yes, sizeof yes},
        {CKA_SIGN, &yes, sizeof yes},
        {CKA_SENSITIVE, &yes, sizeof yes},
        {CKA_EXTRACTABLE, &no, sizeof no},
    };
    CK_MECHANISM generation = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    CALL(C_GenerateKeyPair, session, &generation, public_template,
         sizeof public_template / sizeof public_template[0], private_template,
         sizeof private_template / sizeof private_template[0], &public_key,
         &private_key);
    if (!public_key || !private_key || public_key == private_key) {
        fputs("size probe key handles are invalid\n", stderr);
        goto failed;
    }
    have_keys = 1;

    CK_MECHANISM rsa = {CKM_RSA_PKCS, NULL, 0};
    for (unsigned i = 0; i < 3; i++) {
        CK_BYTE message[32], signature[512];
        CK_ULONG length = sizeof signature;
        memset(message, 0x41 + (int)i, sizeof message);
        CALL(C_SignInit, session, &rsa, private_key);
        CALL(C_Sign, session, message, sizeof message, signature, &length);
        printf("{\"fn\":\"C_Sign\",\"mechanism\":%lu,\"length\":%lu,\"rv\":0}\n",
               (unsigned long)rsa.mechanism, (unsigned long)length);
        fflush(stdout);
        memset(signature, 0, sizeof signature);
        memset(message, 0, sizeof message);
    }

    exit_code = 0;
failed:
    if (have_keys) {
        if (public_key) api->C_DestroyObject(session, public_key);
        if (private_key) api->C_DestroyObject(session, private_key);
    }
    if (logged_in) api->C_Logout(session);
    if (session) api->C_CloseSession(session);
    if (initialized) api->C_Finalize(NULL);
    dlclose(module);
    return exit_code;
}
