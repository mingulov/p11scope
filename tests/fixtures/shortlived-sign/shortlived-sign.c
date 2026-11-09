/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Short-lived SoftHSM caller: init, login, RSA signs, exit.
 *
 * Usage: shortlived-sign PROVIDER PIN SLEEP_MS [ITERS INTERVAL_MS]
 *
 * dlopens PROVIDER (SoftHSM), C_Initialize, opens a read-write session on
 * the first slot with a token, logs in as CKU_USER with the PIN passed as
 * argv[2], finds the private key with CKA_ID 01:02, performs ITERS
 * CKM_SHA256_RSA_PKCS C_Sign calls over 32 bytes (default 1) spaced
 * INTERVAL_MS apart (default 0), sleeps SLEEP_MS milliseconds, then logs
 * out and exits. Prints "lifetime_ms=<n> signs=<n>" (CLOCK_MONOTONIC from
 * process start to just before exit) on stdout for the harness.
 *
 * Exit 0 on verified signs, 1 when a PKCS#11 call fails, 2 on
 * usage/setup failure. LP64 only.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Minimal PKCS#11 ABI subset (cryptoki 2.x/3.x LP64). */
typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_CHAR;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef unsigned char CK_BBOOL;
typedef void *CK_VOID_PTR;
typedef CK_CHAR *CK_CHAR_PTR;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST **CK_FUNCTION_LIST_PTR_PTR;
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);

#define CKR_OK 0UL
#define CKU_USER 1UL
#define CKF_RW_SESSION 0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL
#define CKO_PRIVATE_KEY 0x00000003UL
#define CKA_CLASS 0x00000000UL
#define CKA_ID 0x00000102UL
#define CKM_SHA256_RSA_PKCS 0x00000040UL

struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(CK_VOID_PTR);
    CK_RV (*C_Finalize)(CK_VOID_PTR);
    CK_RV (*C_GetInfo)(void *);
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
    CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG_PTR);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, void *);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, void *);
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE *, CK_ULONG_PTR);
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, void *);
    CK_RV (*C_InitToken)(CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG);
    CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR,
                      CK_ULONG);
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_ULONG, CK_VOID_PTR, CK_VOID_PTR,
                           void *);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_CloseAllSessions)(CK_SLOT_ID);
    CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE, void *);
    CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                 CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG, void *);
    CK_RV (*C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *,
                          CK_ULONG, void *);
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                 CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                 CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG,
                           CK_ULONG_PTR);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                       CK_ULONG_PTR);
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                             CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                       CK_ULONG_PTR);
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                             CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM *);
    CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                      CK_ULONG_PTR);
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_DigestKey)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                    CK_ULONG_PTR);
};

static uint64_t clock_ns(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
}

int main(int argc, char **argv) {
    uint64_t t0 = clock_ns();
    if (argc != 4 && argc != 6) {
        fprintf(stderr, "usage: %s PROVIDER PIN SLEEP_MS [ITERS INTERVAL_MS]\n",
                argc > 0 ? argv[0] : "shortlived-sign");
        return 2;
    }
    char *end = NULL;
    unsigned long sleep_ms = strtoul(argv[3], &end, 10);
    if (*end != '\0' || sleep_ms > 60000) {
        fprintf(stderr, "shortlived-sign: SLEEP_MS must be 0..60000\n");
        return 2;
    }
    /* Map-only mode: PIN "-" maps the provider, makes no PKCS#11 call,
     * sleeps, exits. Tests discovery/admission without observed calls. */
    int map_only = strcmp(argv[2], "-") == 0;
    unsigned long iters = 1, interval_ms = 0;
    if (argc == 6) {
        iters = strtoul(argv[4], &end, 10);
        if (*end != '\0' || iters == 0 || iters > 100000) {
            fprintf(stderr, "shortlived-sign: ITERS must be 1..100000\n");
            return 2;
        }
        interval_ms = strtoul(argv[5], &end, 10);
        if (*end != '\0' || interval_ms > 60000) {
            fprintf(stderr, "shortlived-sign: INTERVAL_MS must be 0..60000\n");
            return 2;
        }
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "shortlived-sign: cannot open provider: %s\n",
                dlerror());
        return 2;
    }
    CK_C_GetFunctionList get_list =
        (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    CK_FUNCTION_LIST *fl = NULL;
    if (map_only) {
        /* Note: C_GetFunctionList itself would be an observed call
         * (entry uprobe), so map-only mode never invokes it. */
        if (sleep_ms > 0) {
            usleep(sleep_ms * 1000);
        }
        dlclose(handle);
        uint64_t map_elapsed_ms = (clock_ns() - t0) / 1000000u;
        printf("lifetime_ms=%lu signs=map-only\n",
               (unsigned long)map_elapsed_ms);
        return 0;
    }
    if (get_list == NULL || get_list(&fl) != CKR_OK || fl == NULL) {
        fprintf(stderr, "shortlived-sign: C_GetFunctionList failed\n");
        return 2;
    }
#define CHECK(call, what)                                                  \
    do {                                                                   \
        CK_RV rv = (call);                                                 \
        if (rv != CKR_OK) {                                                \
            fprintf(stderr, "shortlived-sign: %s failed rv=0x%lx\n", what, \
                    (unsigned long)rv);                                    \
            return 1;                                                      \
        }                                                                  \
    } while (0)
    CHECK(fl->C_Initialize(NULL), "C_Initialize");
    CK_ULONG slot_count = 0;
    CHECK(fl->C_GetSlotList(1, NULL, &slot_count), "C_GetSlotList(count)");
    if (slot_count == 0) {
        fprintf(stderr, "shortlived-sign: no token slot\n");
        return 1;
    }
    CK_SLOT_ID *slots = calloc(slot_count, sizeof(*slots));
    if (slots == NULL) {
        return 2;
    }
    CHECK(fl->C_GetSlotList(1, slots, &slot_count), "C_GetSlotList");
    CK_SESSION_HANDLE session = 0;
    CHECK(fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                            NULL, &session),
          "C_OpenSession");
    free(slots);
    size_t pin_len = strlen(argv[2]);
    CHECK(fl->C_Login(session, CKU_USER, (CK_CHAR_PTR)argv[2],
                      (CK_ULONG)pin_len),
          "C_Login");
    CK_BYTE key_id[2] = {0x01, 0x02};
    CK_ULONG klass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE tmpl[2] = {
        {CKA_CLASS, &klass, sizeof(klass)},
        {CKA_ID, key_id, sizeof(key_id)},
    };
    CHECK(fl->C_FindObjectsInit(session, tmpl, 2), "C_FindObjectsInit");
    CK_OBJECT_HANDLE key = 0;
    CK_ULONG found = 0;
    CHECK(fl->C_FindObjects(session, &key, 1, &found), "C_FindObjects");
    CHECK(fl->C_FindObjectsFinal(session), "C_FindObjectsFinal");
    if (found == 0) {
        fprintf(stderr, "shortlived-sign: key id 0102 not found\n");
        return 1;
    }
    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, NULL, 0};
    CK_BYTE data[32];
    memset(data, 0xA5, sizeof(data));
    for (unsigned long i = 0; i < iters; i++) {
        CHECK(fl->C_SignInit(session, &mech, key), "C_SignInit");
        CK_BYTE sig[512];
        CK_ULONG sig_len = sizeof(sig);
        CHECK(fl->C_Sign(session, data, sizeof(data), sig, &sig_len), "C_Sign");
        if (sig_len == 0) {
            fprintf(stderr, "shortlived-sign: empty signature\n");
            return 1;
        }
        if (interval_ms > 0 && i + 1 < iters) {
            usleep(interval_ms * 1000);
        }
    }
    if (sleep_ms > 0) {
        usleep(sleep_ms * 1000);
    }
    CHECK(fl->C_Logout(session), "C_Logout");
    CHECK(fl->C_CloseSession(session), "C_CloseSession");
    CHECK(fl->C_Finalize(NULL), "C_Finalize");
    uint64_t elapsed_ms = (clock_ns() - t0) / 1000000u;
    printf("lifetime_ms=%lu signs=%lu\n", (unsigned long)elapsed_ms,
           (unsigned long)iters);
    return 0;
}
