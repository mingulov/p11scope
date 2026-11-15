/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* A statically linked application with an embedded PKCS#11 provider and
 * no PKCS#11 dynamic exports (no .so, no dlopen, no .dynsym getter).
 *
 * The provider publishes two standard tables over one set of functions:
 * a 2.40 CK_FUNCTION_LIST from C_GetFunctionList and a 3.0
 * CK_FUNCTION_LIST_3_0 from C_GetInterface("PKCS 11"). Every entry of
 * both tables points at the same code, so a call reached through either
 * table runs the same instruction.
 *
 * Usage: static_getter_app N list|interface|both
 *
 * Protocol (stdin gate bytes, stdout lines):
 *   READY pid=<pid>          then waits for 'G'
 *   PUBLISHED getters=<k> <name>=<address>...
 *                            after calling the selected getters once
 *                            each, naming the code each round reaches
 *                            (a name twice when both tables reach it);
 *                            then waits for 'C'
 *   DONE <ledger>            after N rounds of table calls; then waits
 *                            for 'X' and exits 0
 * A round calls, through the legacy table (list/both): C_Initialize,
 * C_GetInfo; through the 3.0 table (interface/both): C_Initialize,
 * C_GetSlotList, C_LoginUser. The DONE line names every per-function
 * total the round loop made, plus the getter calls, as name=count.
 *
 * Build: cc -std=c11 -O2 -static -o static_getter_app static_getter_app.c
 * (no -rdynamic: the missing dynamic export is the shape under test).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_FLAGS;

typedef struct {
    unsigned char major;
    unsigned char minor;
} CK_VERSION;

typedef CK_RV (*StubFn)(void *, void *, void *, void *);

typedef struct {
    CK_VERSION version;
    void *functions[68];
} LegacyList;

typedef struct {
    CK_VERSION version;
    void *functions[92];
} List30;

typedef struct {
    const char *name;
    void *functions;
    CK_FLAGS flags;
} CK_INTERFACE;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x54UL

/* Distinct bodies, so identical-code folding never merges two slots. */
static volatile const char *last_called;

/* S(name): a provider stub; G(name): a getter defined below. The order
 * is the standard CK_FUNCTION_LIST_3_0 order; the first 68 are the 2.40
 * CK_FUNCTION_LIST. */
#define FUNCTIONS_240(S, G) \
    S(C_Initialize) S(C_Finalize) S(C_GetInfo) G(C_GetFunctionList) S(C_GetSlotList) \
    S(C_GetSlotInfo) S(C_GetTokenInfo) S(C_GetMechanismList) S(C_GetMechanismInfo) \
    S(C_InitToken) S(C_InitPIN) S(C_SetPIN) S(C_OpenSession) S(C_CloseSession) \
    S(C_CloseAllSessions) S(C_GetSessionInfo) S(C_GetOperationState) \
    S(C_SetOperationState) S(C_Login) S(C_Logout) S(C_CreateObject) S(C_CopyObject) \
    S(C_DestroyObject) S(C_GetObjectSize) S(C_GetAttributeValue) S(C_SetAttributeValue) \
    S(C_FindObjectsInit) S(C_FindObjects) S(C_FindObjectsFinal) S(C_EncryptInit) \
    S(C_Encrypt) S(C_EncryptUpdate) S(C_EncryptFinal) S(C_DecryptInit) S(C_Decrypt) \
    S(C_DecryptUpdate) S(C_DecryptFinal) S(C_DigestInit) S(C_Digest) S(C_DigestUpdate) \
    S(C_DigestKey) S(C_DigestFinal) S(C_SignInit) S(C_Sign) S(C_SignUpdate) \
    S(C_SignFinal) S(C_SignRecoverInit) S(C_SignRecover) S(C_VerifyInit) S(C_Verify) \
    S(C_VerifyUpdate) S(C_VerifyFinal) S(C_VerifyRecoverInit) S(C_VerifyRecover) \
    S(C_DigestEncryptUpdate) S(C_DecryptDigestUpdate) S(C_SignEncryptUpdate) \
    S(C_DecryptVerifyUpdate) S(C_GenerateKey) S(C_GenerateKeyPair) S(C_WrapKey) \
    S(C_UnwrapKey) S(C_DeriveKey) S(C_SeedRandom) S(C_GenerateRandom) \
    S(C_GetFunctionStatus) S(C_CancelFunction) S(C_WaitForSlotEvent)
#define FUNCTIONS_30(S, G) \
    G(C_GetInterfaceList) G(C_GetInterface) S(C_LoginUser) S(C_SessionCancel) \
    S(C_MessageEncryptInit) S(C_EncryptMessage) S(C_EncryptMessageBegin) \
    S(C_EncryptMessageNext) S(C_MessageEncryptFinal) S(C_MessageDecryptInit) \
    S(C_DecryptMessage) S(C_DecryptMessageBegin) S(C_DecryptMessageNext) \
    S(C_MessageDecryptFinal) S(C_MessageSignInit) S(C_SignMessage) \
    S(C_SignMessageBegin) S(C_SignMessageNext) S(C_MessageSignFinal) \
    S(C_MessageVerifyInit) S(C_VerifyMessage) S(C_VerifyMessageBegin) \
    S(C_VerifyMessageNext) S(C_MessageVerifyFinal)

#define NOTHING(name)
#define DEFINE_STUB(name)                                                      \
    static __attribute__((noinline, used)) CK_RV stub_##name(void *a, void *b,  \
                                                             void *c, void *d) { \
        (void)a;                                                               \
        (void)b;                                                               \
        (void)c;                                                               \
        (void)d;                                                               \
        last_called = #name;                                                   \
        return CKR_OK;                                                         \
    }
FUNCTIONS_240(DEFINE_STUB, NOTHING)
FUNCTIONS_30(DEFINE_STUB, NOTHING)

CK_RV C_GetFunctionList(void **out);
CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count);
CK_RV C_GetInterface(const char *name, CK_VERSION *version, CK_INTERFACE **out,
                     CK_FLAGS flags);

#define STUB_POINTER(name) (void *)&stub_##name,
#define GETTER_POINTER(name) (void *)&name,
static LegacyList legacy_list = {
    .version = {2, 40},
    .functions = {FUNCTIONS_240(STUB_POINTER, GETTER_POINTER)},
};
static List30 list_30 = {
    .version = {3, 0},
    .functions = {FUNCTIONS_240(STUB_POINTER, GETTER_POINTER)
                      FUNCTIONS_30(STUB_POINTER, GETTER_POINTER)},
};
static CK_INTERFACE interface_30 = {"PKCS 11", &list_30, 0};

__attribute__((noinline, used)) CK_RV C_GetFunctionList(void **out) {
    last_called = "C_GetFunctionList";
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = &legacy_list;
    return CKR_OK;
}

__attribute__((noinline, used)) CK_RV C_GetInterfaceList(CK_INTERFACE *out,
                                                        CK_ULONG *count) {
    last_called = "C_GetInterfaceList";
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (out != NULL) {
        if (*count < 1) {
            *count = 1;
            return 0x150UL; /* CKR_BUFFER_TOO_SMALL */
        }
        out[0] = interface_30;
    }
    *count = 1;
    return CKR_OK;
}

__attribute__((noinline, used)) CK_RV C_GetInterface(const char *name,
                                                    CK_VERSION *version,
                                                    CK_INTERFACE **out,
                                                    CK_FLAGS flags) {
    last_called = "C_GetInterface";
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if ((name != NULL && strcmp(name, "PKCS 11") != 0) || flags != 0 ||
        (version != NULL && (version->major != 3 || version->minor != 0))) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    *out = &interface_30;
    return CKR_OK;
}

static void gate(char expected) {
    char byte = 0;
    for (;;) {
        ssize_t got = read(STDIN_FILENO, &byte, 1);
        if (got == 1 && byte == expected) {
            return;
        }
        if (got <= 0) {
            exit(3);
        }
    }
}

static void *slot(void *table, unsigned index) {
    return ((void **)((char *)table + sizeof(void *)))[index];
}

static CK_RV call(void *table, unsigned index) {
    StubFn fn = (StubFn)slot(table, index);
    return fn(NULL, NULL, NULL, NULL);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: static_getter_app N list|interface|both\n");
        return 2;
    }
    char *end = NULL;
    long rounds = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || rounds < 0 || rounds > 1000000) {
        return 2;
    }
    int use_list = strcmp(argv[2], "list") == 0 || strcmp(argv[2], "both") == 0;
    int use_interface =
        strcmp(argv[2], "interface") == 0 || strcmp(argv[2], "both") == 0;
    if (!use_list && !use_interface) {
        return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("READY pid=%ld\n", (long)getpid());
    gate('G');
    void *list = NULL;
    CK_INTERFACE *interface = NULL;
    if (use_list && (C_GetFunctionList(&list) != CKR_OK || list == NULL)) {
        return 4;
    }
    if (use_interface &&
        (C_GetInterface("PKCS 11", NULL, &interface, 0) != CKR_OK ||
         interface == NULL)) {
        return 4;
    }
    void *list30 = interface != NULL ? interface->functions : NULL;
    /* The code each round reaches, as the tables hand it out: the cell
     * waits until every one of these is probed before releasing 'C'. */
    printf("PUBLISHED getters=%d", use_list + use_interface);
    if (use_list) {
        printf(" C_Initialize=%p C_GetInfo=%p", slot(list, 0), slot(list, 2));
    }
    if (use_interface) {
        printf(" C_Initialize=%p C_GetSlotList=%p C_LoginUser=%p", slot(list30, 0),
               slot(list30, 4), slot(list30, 70));
    }
    printf("\n");
    gate('C');
    for (long round = 0; round < rounds; round++) {
        CK_RV rv = CKR_OK;
        if (use_list) {
            rv |= call(list, 0);  /* C_Initialize */
            rv |= call(list, 2);  /* C_GetInfo */
        }
        if (use_interface) {
            rv |= call(list30, 0);  /* C_Initialize */
            rv |= call(list30, 4);  /* C_GetSlotList */
            rv |= call(list30, 70); /* C_LoginUser */
        }
        if (rv != CKR_OK) {
            return 5;
        }
    }
    printf("DONE C_GetFunctionList=%d C_GetInterface=%d C_Initialize=%ld "
           "C_GetInfo=%ld C_GetSlotList=%ld C_LoginUser=%ld\n",
           use_list, use_interface, rounds * (use_list + use_interface),
           use_list ? rounds : 0, use_interface ? rounds : 0,
           use_interface ? rounds : 0);
    gate('X');
    return 0;
}
