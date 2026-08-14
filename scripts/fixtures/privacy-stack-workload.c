/* Nine concurrent PKCS #11 2.40/3.0/3.2 calls covering allowlisted argument
 * words 0..6. Arguments 7..9 and every pointed-to secret carry canaries. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG, CK_RV, CK_FLAGS;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *name; void *table; CK_FLAGS flags; } CK_INTERFACE;
typedef struct { CK_ULONG mechanism; void *parameter; CK_ULONG parameter_len; } CK_MECHANISM;
typedef struct { CK_ULONG type; void *value; CK_ULONG value_len; } CK_ATTRIBUTE;
typedef CK_RV (*fn10)(CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG,
                      CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG);

enum {
    I_Login = 18,
    I_GenerateKey = 58,
    I_GenerateKeyPair = 59,
    I_LoginUser = 70,
    I_MessageEncryptInit = 72,
    I_VerifySignatureInit = 94,
    I_AsyncComplete = 99,
    I_WrapKeyAuthenticated = 102,
    I_UnwrapKeyAuthenticated = 103,
};

static const char PIN[] = "CANARY_PIN_e68d21cf481bb1efcc17dab7c0183bdd";
static const char USERNAME[] = "CANARY_USERNAME_e2df5c11270a7b893619aa831b78fc18";
static const char KEY[] = "CANARY_KEY_58fa8b6832cfa111313260aa3314ad0f";
static const char LABEL[] = "CANARY_LABEL_5527f89ff269f233a661f5d3a11d082e";
static const char SIGNATURE[] = "CANARY_SIGNATURE_a578d332cab775078a719c4c520bfd8c";
static const char ASYNC_DATA[] = "CANARY_ASYNC_ef239b70be4c0e1d5cb234a225fe1ff7";
static const char OUTPUT[] = "CANARY_OUTPUT_5391960450406458bc83e37c2b43b80b";
static const char ARG7[] = "CANARY_ARG7_b2747079a35f10aba729f83ff3285ddc";
static const char ARG8[] = "CANARY_ARG8_1752403b4bb53924b6881d095e3e9198";
static const char ARG9[] = "CANARY_ARG9_8f119353c9e69ce4f2f3b9a4d2aa2fab";

struct async_data { CK_ULONG words[3]; };
struct call { fn10 function; CK_ULONG a[10]; CK_RV rv; };

static void *invoke(void *opaque)
{
    struct call *call = opaque;
    call->rv = call->function(call->a[0], call->a[1], call->a[2], call->a[3],
                             call->a[4], call->a[5], call->a[6], call->a[7],
                             call->a[8], call->a[9]);
    return NULL;
}

static CK_ULONG ptr(const void *value) { return (CK_ULONG)value; }

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3 || (argc == 3 && strcmp(argv[2], "sequential") != 0)) {
        fprintf(stderr, "usage: %s /absolute/provider.so [sequential]\n", argv[0]);
        return 2;
    }
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    CK_RV (*get_interfaces)(CK_INTERFACE *, CK_ULONG *) = dlsym(module, "C_GetInterfaceList");
    if (!get_interfaces) { fprintf(stderr, "no C_GetInterfaceList\n"); return 1; }

    CK_ULONG count = 0;
    if (get_interfaces(NULL, &count) != 0 || !count) return 1;
    CK_INTERFACE *interfaces = calloc(count, sizeof(*interfaces));
    if (!interfaces || get_interfaces(interfaces, &count) != 0) return 1;
    void *table = NULL;
    for (CK_ULONG i = 0; i < count; i++) {
        CK_VERSION version;
        if (!interfaces[i].name || strcmp(interfaces[i].name, "PKCS 11") != 0 || !interfaces[i].table)
            continue;
        memcpy(&version, interfaces[i].table, sizeof(version));
        if (version.major == 3 && version.minor == 2) { table = interfaces[i].table; break; }
    }
    free(interfaces);
    if (!table) { fprintf(stderr, "no exact PKCS 11 v3.2 table\n"); return 1; }
    void **functions = (void **)((char *)table + 8);

    CK_MECHANISM mechanism = {0x8000cafeUL, (void *)KEY, sizeof(KEY) - 1};
    CK_ATTRIBUTE private_template[] = {
        {0x11, (void *)KEY, sizeof(KEY) - 1},
        {0x03, (void *)LABEL, sizeof(LABEL) - 1},
    };
    CK_ATTRIBUTE public_template[] = {{0x03, (void *)LABEL, sizeof(LABEL) - 1}};
    struct async_data async = {{ptr(ASYNC_DATA), sizeof(ASYNC_DATA) - 1, 0x42}};
    static const char async_name[] = "C_MessageEncryptInit";

#define P7 ptr(ARG7), ptr(ARG8), ptr(ARG9)
    struct call calls[] = {
        {(fn10)functions[I_Login], {0x101, 1, ptr(PIN), sizeof(PIN) - 1, ptr(KEY), ptr(LABEL), ptr(OUTPUT), P7}, 0},
        {(fn10)functions[I_GenerateKey], {0x102, ptr(&mechanism), ptr(private_template), 2, ptr(KEY), ptr(OUTPUT), ptr(SIGNATURE), P7}, 0},
        {(fn10)functions[I_GenerateKeyPair], {0x103, ptr(&mechanism), ptr(public_template), 1, ptr(private_template), 2, ptr(OUTPUT), P7}, 0},
        {(fn10)functions[I_LoginUser], {0x104, 1, ptr(PIN), sizeof(PIN) - 1, ptr(USERNAME), sizeof(USERNAME) - 1, ptr(OUTPUT), P7}, 0},
        {(fn10)functions[I_MessageEncryptInit], {0x105, ptr(&mechanism), ptr(KEY), ptr(SIGNATURE), ptr(OUTPUT), ptr(ASYNC_DATA), ptr(LABEL), P7}, 0},
        {(fn10)functions[I_VerifySignatureInit], {0x106, ptr(&mechanism), ptr(KEY), ptr(SIGNATURE), ptr(OUTPUT), ptr(ASYNC_DATA), ptr(LABEL), P7}, 0},
        {(fn10)functions[I_AsyncComplete], {0x107, ptr(async_name), ptr(&async), ptr(PIN), ptr(KEY), ptr(SIGNATURE), ptr(OUTPUT), P7}, 0},
        {(fn10)functions[I_WrapKeyAuthenticated], {0x108, ptr(&mechanism), ptr(KEY), ptr(SIGNATURE), ptr(ASYNC_DATA), ptr(LABEL), ptr(OUTPUT), P7}, 0},
        {(fn10)functions[I_UnwrapKeyAuthenticated], {0x109, ptr(&mechanism), ptr(KEY), ptr(SIGNATURE), ptr(ASYNC_DATA), ptr(private_template), 2, P7}, 0},
    };
#undef P7

    size_t count_calls = sizeof(calls) / sizeof(calls[0]);
    if (argc == 3) {
        for (size_t i = 0; i < count_calls; i++) invoke(&calls[i]);
    } else {
        pthread_t threads[sizeof(calls) / sizeof(calls[0])];
        for (size_t i = 0; i < count_calls; i++) {
            if (pthread_create(&threads[i], NULL, invoke, &calls[i]) != 0) {
                fprintf(stderr, "pthread_create %zu failed\n", i);
                return 1;
            }
        }
        fprintf(stderr, "privacy-stack workload started %zu calls\n", count_calls);
        for (size_t i = 0; i < count_calls; i++) pthread_join(threads[i], NULL);
    }
    for (size_t i = 0; i < count_calls; i++) {
        if (calls[i].rv != 0) { fprintf(stderr, "call %zu returned 0x%lx\n", i, calls[i].rv); return 1; }
    }
    printf("privacy-stack workload: all %zu calls returned\n", count_calls);
    fflush(stdout);
    if (getenv("P11SCOPE_HOLD") && raise(SIGSTOP) != 0) return 1;
    return 0;
}
