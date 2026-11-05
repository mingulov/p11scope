/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Controlled application ledger only: this is no observer/bootstrap proof.
 * Use one disposable, initialized token with P11SCOPE_KEY_FIXTURE_PIN set.
 * stdin G starts calls; F after DONE releases the retained provider mapping.
 * The absolute process/control deadline never renews. No payload is logged.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pkcs11.h>

_Static_assert(sizeof(void *) == 8 && sizeof(CK_ULONG) == 8,
               "this fixture qualifies Linux LP64 only");
_Static_assert(sizeof(CK_ATTRIBUTE) == 24 && sizeof(CK_MECHANISM) == 24,
               "use the actual conventional PKCS#11 LP64 header");

static CK_FUNCTION_LIST_PTR api;
static uint64_t sequence, deadline_ns;
static const char *const functions[] = {
    "C_GetFunctionList", "C_Initialize", "C_GetSlotList", "C_OpenSession", "C_Login",
    "C_GenerateKeyPair", "C_GetAttributeValue", "C_SignInit", "C_Sign", "C_SignUpdate",
    "C_SignFinal", "C_VerifyInit", "C_Verify", "C_DestroyObject", "C_Logout",
    "C_CloseSession", "C_Finalize"
};
static unsigned counts[sizeof functions / sizeof functions[0]];

static uint64_t now_ns(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time)) _exit(90);
    return (uint64_t)time.tv_sec * UINT64_C(1000000000) + (uint64_t)time.tv_nsec;
}

static void flushed(void) {
    if (ferror(stdout) || fflush(stdout)) _exit(91);
}

static void row(const char *kind) {
    printf("{\"seq\":%" PRIu64 ",\"kind\":\"%s\",\"time_ns\":%" PRIu64,
           ++sequence, kind, now_ns());
}

static void marker(const char *kind) {
    row(kind); puts("}"); flushed();
}

static int control(char expected) {
    for (;;) {
        uint64_t now = now_ns();
        if (now >= deadline_ns) return 0;
        uint64_t milliseconds = (deadline_ns - now + 999999) / 1000000;
        struct pollfd fd = {STDIN_FILENO, POLLIN, 0};
        int ready = poll(&fd, 1, milliseconds > INT_MAX ? INT_MAX : (int)milliseconds);
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) continue;
        if (ready < 0 || (fd.revents & (POLLERR | POLLNVAL)) || now_ns() >= deadline_ns)
            return 0;
        char byte;
        ssize_t got = read(STDIN_FILENO, &byte, 1);
        if (got < 0 && errno == EINTR) continue;
        return got == 1 && byte == expected && now_ns() < deadline_ns;
    }
}

static void call(const char *function, unsigned operation, const char *phase,
                 const char *key, uint64_t start, CK_RV result) {
    uint64_t end = now_ns();
    size_t index;
    for (index = 0; index < sizeof functions / sizeof functions[0]; index++)
        if (!strcmp(functions[index], function)) break;
    if (index == sizeof functions / sizeof functions[0]) _exit(92);
    counts[index]++;
    printf("{\"seq\":%" PRIu64 ",\"kind\":\"call\",\"operation\":%u,"
           "\"phase\":\"%s\",\"fn\":\"%s\",\"rv\":%lu,"
           "\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64,
           ++sequence, operation, phase, function, result, start, end);
    if (key) printf(",\"key\":\"%s\"", key);
    puts("}"); flushed();
}

#define CALL(member, operation, phase, expected, ...) do { \
    if (now_ns() >= deadline_ns) goto failed; \
    uint64_t start = now_ns(); \
    CK_RV result = api->member(__VA_ARGS__); \
    call(#member, operation, phase, NULL, start, result); \
    if (result != (expected)) { \
        fprintf(stderr, "application call %s returned unexpected CK_RV 0x%lx\n", #member, result); \
        goto failed; \
    } \
} while (0)

static void begin(unsigned operation, int multipart, unsigned sign_operation, int invalid) {
    row("operation");
    printf(",\"event\":\"begin\",\"operation\":%u,\"category\":\"%s\","
           "\"mode\":\"%s\",\"key\":\"%s\"", operation,
           sign_operation ? "verify" : "sign", multipart ? "multipart" : "one_shot",
           sign_operation ? "public" : "private");
    if (sign_operation)
        printf(",\"sign_operation\":%u,\"expectation\":\"%s\"",
               sign_operation, invalid ? "invalid" : "valid");
    puts("}"); flushed();
}

static void ended(unsigned operation, int invalid) {
    row("operation");
    printf(",\"event\":\"end\",\"operation\":%u,\"outcome\":\"%s\"}\n",
           operation, invalid ? "failed" : "completed");
    flushed();
}

static int finite_word(CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
    switch (type) {
        case CKA_CLASS: return value <= 4;
        case CKA_KEY_TYPE:
            return value <= 4 || value == 0x10 || value == 0x1f || value == 0x40 || value == 0x41;
        case CKA_MODULUS_BITS:
            return value == 1024 || value == 2048 || value == 3072 || value == 4096 || value == 8192;
        default: return 0;
    }
}

static int metadata(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, const char *key) {
    CK_ULONG class_id = 0, key_type = 0, modulus_bits = 0;
    CK_BBOOL token = CK_FALSE;
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &class_id, sizeof class_id},
        {CKA_KEY_TYPE, &key_type, sizeof key_type},
        {CKA_TOKEN, &token, sizeof token},
        {CKA_MODULUS_BITS, &modulus_bits, sizeof modulus_bits}
    };
    const char *const names[] = {"class", "key_type", "token", "modulus_bits"};
    uint64_t start = now_ns();
    CK_RV result = api->C_GetAttributeValue(session, object, attributes, 4);
    call("C_GetAttributeValue", 0, "metadata", key, start, result);
    if (result != CKR_OK && result != CKR_ATTRIBUTE_SENSITIVE
        && result != CKR_ATTRIBUTE_TYPE_INVALID && result != CKR_BUFFER_TOO_SMALL) return 0;
    row("metadata");
    printf(",\"key\":\"%s\",\"origin\":\"provider_query\",\"attributes\":{", key);
    for (unsigned i = 0; i < 4; i++) {
        if (i) putchar(',');
        printf("\"%s\":{\"status\":\"", names[i]);
        if (attributes[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
            fputs(result == CKR_ATTRIBUTE_TYPE_INVALID ? "unsupported\"}" : "unavailable\"}", stdout);
        } else if (i == 2 && attributes[i].ulValueLen == sizeof token && token <= CK_TRUE) {
            printf("value\",\"value\":%s}", token ? "true" : "false");
        } else if (i != 2 && attributes[i].ulValueLen == sizeof(CK_ULONG)
                   && finite_word(attributes[i].type, *(CK_ULONG *)attributes[i].pValue)) {
            printf("value\",\"value\":%lu}", *(CK_ULONG *)attributes[i].pValue);
        } else {
            fputs("invalid\"}", stdout);
        }
    }
    puts("}}"); flushed();
    return 1;
}

static void done(void) {
    unsigned total = 0;
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) total += counts[i];
    row("done");
    printf(",\"api_calls\":%u,\"calls_by_function\":{", total);
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++)
        printf("%s\"%s\":%u", i ? "," : "", functions[i], counts[i]);
    fputs("},\"operations\":{\"sign\":{\"completed\":10,\"failed\":0},"
          "\"verify\":{\"completed\":10,\"failed\":2}}}\n", stdout);
    flushed();
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("usage: rsa-ledger MODULE (PIN in P11SCOPE_KEY_FIXTURE_PIN; stdin G then F)\n", stderr);
        return 2;
    }
    const char *pin = getenv("P11SCOPE_KEY_FIXTURE_PIN");
    if (!pin || !*pin || strlen(pin) > 256) {
        fputs("application fixture PIN is missing or invalid\n", stderr); return 2;
    }
    unsigned long timeout_ms = 30000;
    const char *timeout_text = getenv("P11SCOPE_KEY_FIXTURE_TIMEOUT_MS");
    if (timeout_text) {
        char *end;
        errno = 0;
        timeout_ms = strtoul(timeout_text, &end, 10);
        if (errno || !*timeout_text || *end || timeout_ms == 0 || timeout_ms > 90000) {
            fputs("application fixture deadline is invalid\n", stderr); return 2;
        }
    }
    deadline_ns = now_ns() + timeout_ms * UINT64_C(1000000);
    alarm((unsigned)((timeout_ms + 999) / 1000));
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) { fputs("application provider could not load\n", stderr); return 1; }
    void *symbol = dlsym(module, "C_GetFunctionList");
    CK_C_GetFunctionList get_function_list = NULL;
    _Static_assert(sizeof get_function_list == sizeof symbol, "POSIX function pointer ABI");
    memcpy(&get_function_list, &symbol, sizeof symbol);
    if (!get_function_list) { fputs("application provider has no function list\n", stderr); dlclose(module); return 1; }
    row("header");
    fputs(",\"version\":1,\"layout\":\"lp64\",\"mechanism\":\"CKM_SHA256_RSA_PKCS\","
          "\"requested\":{\"public\":{\"class\":2,\"key_type\":0,\"token\":false,\"modulus_bits\":2048},"
          "\"private\":{\"class\":3,\"key_type\":0,\"token\":false}}}\n", stdout);
    flushed(); marker("ready");
    if (!control('G')) { fputs("application GO control failed\n", stderr); dlclose(module); return 1; }
    marker("go");
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE, private_key = CK_INVALID_HANDLE;
    int initialized = 0, logged_in = 0;
    uint64_t start = now_ns();
    CK_RV result = get_function_list(&api);
    call("C_GetFunctionList", 0, "setup", NULL, start, result);
    if (result != CKR_OK || !api) goto failed;
#define REQUIRED(member) if (!api->member) goto failed
    REQUIRED(C_Initialize); REQUIRED(C_Finalize); REQUIRED(C_GetSlotList);
    REQUIRED(C_OpenSession); REQUIRED(C_CloseSession); REQUIRED(C_Login); REQUIRED(C_Logout);
    REQUIRED(C_GenerateKeyPair); REQUIRED(C_GetAttributeValue); REQUIRED(C_DestroyObject);
    REQUIRED(C_SignInit); REQUIRED(C_Sign); REQUIRED(C_SignUpdate); REQUIRED(C_SignFinal);
    REQUIRED(C_VerifyInit); REQUIRED(C_Verify);
#undef REQUIRED
    CALL(C_Initialize, 0, "setup", CKR_OK, NULL); initialized = 1;
    CK_SLOT_ID slots[64]; CK_ULONG slot_count = 64;
    CALL(C_GetSlotList, 0, "setup", CKR_OK, CK_TRUE, slots, &slot_count);
    if (!slot_count || slot_count > 64) goto failed;
    CALL(C_OpenSession, 0, "setup", CKR_OK, slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
         NULL, NULL, &session);
    CALL(C_Login, 0, "setup", CKR_OK, session, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    logged_in = 1;
    CK_ULONG bits = 2048;
    CK_ULONG public_class = CKO_PUBLIC_KEY, private_class = CKO_PRIVATE_KEY, key_type = CKK_RSA;
    CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
    CK_BYTE exponent[] = {1, 0, 1};
    CK_ATTRIBUTE public_template[] = {
        {CKA_CLASS, &public_class, sizeof public_class}, {CKA_KEY_TYPE, &key_type, sizeof key_type},
        {CKA_TOKEN, &no, sizeof no}, {CKA_PRIVATE, &no, sizeof no},
        {CKA_VERIFY, &yes, sizeof yes}, {CKA_MODULUS_BITS, &bits, sizeof bits},
        {CKA_PUBLIC_EXPONENT, exponent, sizeof exponent}
    };
    CK_ATTRIBUTE private_template[] = {
        {CKA_CLASS, &private_class, sizeof private_class}, {CKA_KEY_TYPE, &key_type, sizeof key_type},
        {CKA_TOKEN, &no, sizeof no}, {CKA_PRIVATE, &yes, sizeof yes},
        {CKA_SIGN, &yes, sizeof yes}, {CKA_SENSITIVE, &yes, sizeof yes},
        {CKA_EXTRACTABLE, &no, sizeof no}
    };
    CK_MECHANISM generation = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    CALL(C_GenerateKeyPair, 0, "setup", CKR_OK, session, &generation,
         public_template, sizeof public_template / sizeof public_template[0],
         private_template, sizeof private_template / sizeof private_template[0],
         &public_key, &private_key);
    if (!public_key || !private_key || public_key == private_key) goto failed;
    if (!metadata(session, public_key, "public") || !metadata(session, private_key, "private")) goto failed;
    CK_MECHANISM rsa = {CKM_SHA256_RSA_PKCS, NULL, 0};
    CK_BYTE messages[10][32], signatures[10][256];
    CK_ULONG lengths[10];
    for (unsigned i = 0; i < 10; i++) {
        memcpy(messages[i], "p11scope RSA fixture message....", 32);
        messages[i][31] = (CK_BYTE)(i + 1);
        unsigned operation = i + 1;
        int multipart = i >= 7;
        begin(operation, multipart, 0, 0);
        CALL(C_SignInit, operation, "init", CKR_OK, session, &rsa, private_key);
        if (i == 0) {
            CK_ULONG needed = 0;
            CALL(C_Sign, operation, "query", CKR_OK, session, messages[i], 32, NULL, &needed);
            if (needed != sizeof signatures[i]) goto failed;
            needed = 1;
            CALL(C_Sign, operation, "too_small", CKR_BUFFER_TOO_SMALL,
                 session, messages[i], 32, signatures[i], &needed);
            if (needed != sizeof signatures[i]) goto failed;
        }
        lengths[i] = sizeof signatures[i];
        if (multipart) {
            CALL(C_SignUpdate, operation, "update", CKR_OK, session, messages[i], 7);
            CALL(C_SignUpdate, operation, "update", CKR_OK, session, messages[i] + 7, 11);
            CALL(C_SignUpdate, operation, "update", CKR_OK, session, messages[i] + 18, 14);
            CALL(C_SignFinal, operation, "terminal", CKR_OK, session, signatures[i], &lengths[i]);
        } else {
            CALL(C_Sign, operation, "terminal", CKR_OK,
                 session, messages[i], 32, signatures[i], &lengths[i]);
        }
        if (lengths[i] != sizeof signatures[i]) goto failed;
        ended(operation, 0);
    }
    for (unsigned i = 0; i < 12; i++) {
        unsigned operation = i + 11, origin = i < 10 ? i : i - 10;
        int invalid = i >= 10;
        CK_BYTE signature[256];
        memcpy(signature, signatures[origin], sizeof signature);
        if (invalid) signature[0] ^= 1;
        begin(operation, 0, origin + 1, invalid);
        CALL(C_VerifyInit, operation, "init", CKR_OK, session, &rsa, public_key);
        CALL(C_Verify, operation, "terminal", invalid ? CKR_SIGNATURE_INVALID : CKR_OK,
             session, messages[origin], 32, signature, sizeof signature);
        ended(operation, invalid);
        memset(signature, 0, sizeof signature);
    }
    memset(signatures, 0, sizeof signatures); memset(messages, 0, sizeof messages);
    CALL(C_DestroyObject, 0, "cleanup", CKR_OK, session, public_key); public_key = CK_INVALID_HANDLE;
    CALL(C_DestroyObject, 0, "cleanup", CKR_OK, session, private_key); private_key = CK_INVALID_HANDLE;
    CALL(C_Logout, 0, "cleanup", CKR_OK, session); logged_in = 0;
    CALL(C_CloseSession, 0, "cleanup", CKR_OK, session); session = CK_INVALID_HANDLE;
    CALL(C_Finalize, 0, "cleanup", CKR_OK, NULL); initialized = 0;
    done();
    if (!control('F')) { fputs("application FINISH control failed\n", stderr); dlclose(module); return 1; }
    dlclose(module); alarm(0); return 0;
failed:
    fputs("application fixture incomplete\n", stderr);
    /* Best-effort cleanup of this application's session objects only. Every
     * actual call is still logged; failure never gains a DONE certificate. */
#define CLEANUP(member, ...) do { \
    uint64_t cleanup_start = now_ns(); \
    CK_RV cleanup_result = api->member(__VA_ARGS__); \
    call(#member, 0, "cleanup", NULL, cleanup_start, cleanup_result); \
} while (0)
    if (api && session != CK_INVALID_HANDLE) {
        if (public_key && api->C_DestroyObject) CLEANUP(C_DestroyObject, session, public_key);
        if (private_key && api->C_DestroyObject) CLEANUP(C_DestroyObject, session, private_key);
        if (logged_in && api->C_Logout) CLEANUP(C_Logout, session);
        if (api->C_CloseSession) CLEANUP(C_CloseSession, session);
    }
    if (api && initialized && api->C_Finalize) CLEANUP(C_Finalize, NULL);
#undef CLEANUP
    dlclose(module); return 1;
}
