/* The deterministic fixture matrix plants ordinary pointer sentinels plus
 * every diagnostic scalar decoder, readable/faulting controls, and v3.2-only
 * functions. Provider success is not capture evidence; the verification
 * scripts own all output, map, and non-disclosure assertions. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef CK_BYTE *CK_BYTE_PTR;
typedef unsigned long CK_RV, CK_ULONG, CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE, CK_ATTRIBUTE_TYPE;
typedef unsigned long CK_FLAGS;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *name; void *table; CK_FLAGS flags; } CK_INTERFACE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ATTRIBUTE_TYPE type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;

/* CK_GCM_PARAMS, legacy PKCS#11 v2.20 layout: pIv@0, ulIvLen@8, pAAD@16,
 * ulAADLen@24, ulTagBits@32 — 40 bytes, five 8-byte fields. */
typedef struct {
    CK_BYTE_PTR pIv;
    CK_ULONG ulIvLen;
    CK_BYTE_PTR pAAD;
    CK_ULONG ulAADLen;
    CK_ULONG ulTagBits;
} CK_GCM_PARAMS;

/* CK_GCM_PARAMS, current v2.40/OASIS layout — what cryptoki_sys's binding
 * actually is: ulIvBits inserted at offset 16 pushes pAAD/ulAADLen/
 * ulTagBits to 24/32/40 — 48 bytes, six 8-byte fields. */
typedef struct {
    CK_BYTE_PTR pIv;
    CK_ULONG ulIvLen;
    CK_ULONG ulIvBits;
    CK_BYTE_PTR pAAD;
    CK_ULONG ulAADLen;
    CK_ULONG ulTagBits;
} CK_GCM_PARAMS_V240;

/* CK_RSA_PKCS_PSS_PARAMS: three CK_ULONGs, 24 bytes, one layout. */
typedef struct {
    CK_ULONG hashAlg;
    CK_ULONG mgf;
    CK_ULONG sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#define CKU_USER 1UL
#define CKR_OK 0UL
#define CKM_SHA256 0x250UL
#define CKM_AES_GCM 0x1087UL
#define CKM_RSA_PKCS_PSS 0x0DUL

#define CKA_CLASS 0x00000000UL
#define CKA_TOKEN 0x00000001UL
#define CKA_PRIVATE 0x00000002UL
#define CKA_LABEL 0x00000003UL
#define CKA_VALUE 0x00000011UL
#define CKA_KEY_TYPE 0x00000100UL
#define CKA_ID 0x00000102UL
#define CKA_SENSITIVE 0x00000103UL
#define CKA_ENCRYPT 0x00000104UL
#define CKA_DECRYPT 0x00000105UL
#define CKA_WRAP 0x00000106UL
#define CKA_UNWRAP 0x00000107UL
#define CKA_SIGN 0x00000108UL
#define CKA_VERIFY 0x0000010aUL
#define CKA_DERIVE 0x0000010cUL
#define CKA_EXTRACTABLE 0x00000162UL

#define CKO_SECRET_KEY 0x00000004UL
#define CKK_GENERIC_SECRET 0x00000010UL

/* CK_FUNCTION_LIST indices (v2.40 order, see spike/discover.c) */
enum {
    I_Login = 18,
    I_CreateObject = 20, I_CopyObject = 21, I_SetAttributeValue = 25,
    I_EncryptInit = 29, I_Encrypt = 30,
    I_DecryptInit = 33,
    I_DigestInit = 37, I_Digest = 38, I_SignInit = 42,
    I_Sign = 43, I_WrapKey = 60, I_GenerateRandom = 64,
    I_LoginUser = 70, I_AsyncComplete = 99,
    I_WrapKeyAuthenticated = 102,
};

typedef CK_RV (*fn10)(CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG,
                      CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG);

/* Sentinels — must match the copies scripts/verify-canaries.sh scans for.
 * Each is a distinct 16+ byte high-entropy pattern (random per-field hex
 * suffix), easy to grep as ASCII. */
static const char SENT_PIN[]       = "CANARY_PIN_e68d21cf481bb1efcc17dab7c0183bdd";
static const char SENT_KEY[]       = "CANARY_KEY_58fa8b6832cfa111313260aa3314ad0f";
static const char SENT_LABEL[]     = "CANARY_LABEL_5527f89ff269f233a661f5d3a11d082e";
static const char SENT_ID[]        = "CANARY_ID_d4875f5041bd7364aee7c2d625bb57f7";
static const char SENT_PLAINTEXT[] = "CANARY_PLAINTEXT_64193ef05a68b3de185c0f430c8190ba";
static const char SENT_IV[]        = "CANARY_IV_d81e4ec085489f1adfcf4729eadd745d";
static const char SENT_AAD[]       = "CANARY_AAD_5b1502ea971ec81f4b974fe84d62a22f";
static const char SENT_BOOLLONG[]  = "CANARY_BOOLLONG_7cd9f6ab17348ba2e65a43d173f9ea1d";
static const char SENT_USERNAME[]  = "CANARY_USERNAME_e2df5c11270a7b893619aa831b78fc18";
static const char SENT_CIPHERTEXT[] = "CANARY_CIPHERTEXT_c01ee2e83e86bb323d3c44ffb2f04296";
static const char SENT_SIGNATURE[] = "CANARY_SIGNATURE_a578d332cab775078a719c4c520bfd8c";
static const char SENT_WRAPPED[]   = "CANARY_WRAPPED_a7048bd887266e35062ac8d42d0197cc";
static const char SENT_RANDOM[]    = "CANARY_RANDOM_0f433fc130b6af2d4f5128d91a652d31";
static const char SENT_OUTPUT[]    = "CANARY_OUTPUT_5391960450406458bc83e37c2b43b80b";
static const char SENT_ARG7[]      = "CANARY_ARG7_b2747079a35f10aba729f83ff3285ddc";
static const char SENT_ARG8[]      = "CANARY_ARG8_1752403b4bb53924b6881d095e3e9198";
static const char SENT_ARG9[]      = "CANARY_ARG9_8f119353c9e69ce4f2f3b9a4d2aa2fab";

/* Benign scalar aliases for every diagnostic pointer decoder. Safe mode may
 * retain only finite catalog matches; diagnostic mode must reproduce the
 * pre-design scalar metadata, never the pointed-to ordinary buffers above. */
#define ALIAS_MECHANISM_ID          0xf001000000000101UL
#define ALIAS_PSS_HASH              0xf002000000000201UL
#define ALIAS_PSS_MGF               0xf003000000000301UL
#define ALIAS_PSS_SALT              0xf004000000000401UL
#define ALIAS_GCM_V220_IV_LEN       0xf005000000000501UL
#define ALIAS_GCM_V220_AAD_LEN      0xf006000000000601UL
#define ALIAS_GCM_V220_TAG_BITS     0xf007000000000701UL
#define ALIAS_GCM_V240_IV_LEN       0xf008000000000801UL
#define ALIAS_GCM_V240_AAD_LEN      0xf009000000000901UL
#define ALIAS_GCM_V240_TAG_BITS     0xf00a000000000a01UL
#define ALIAS_TEMPLATE_TYPE         0xf00b000000000b01UL
#define REGISTERED_MECHANISM_CONTROL CKM_SHA256
#define UNKNOWN_MECHANISM_CONTROL   ALIAS_MECHANISM_ID
#define MAXIMUM_MECHANISM_CONTROL   (~0UL)
#define OVERFLOW_PARAMETER_POINTER  ((void *)(uintptr_t)(UINTPTR_MAX - 4))

static CK_BYTE ALIAS_POLICY_VALUES[11] = {
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
};
static const char ALIAS_ASYNC_NAME[] = "AliasAsync_7a91c45d";
/* The release contract injects the old candidate id for this non-catalog
 * same-length name and proves the byte-exact key still rejects it. */
static const char LEGACY_HASH_CANDIDATE[] = "C_Encrypu";

static CK_ULONG ptr(const void *value) { return (CK_ULONG)(uintptr_t)value; }

static void **matrix_functions(void *module)
{
    CK_RV (*get_interfaces)(CK_INTERFACE *, CK_ULONG *) =
        (CK_RV (*)(CK_INTERFACE *, CK_ULONG *))dlsym(module, "C_GetInterfaceList");
    if (!get_interfaces) { fprintf(stderr, "no C_GetInterfaceList\n"); return NULL; }
    CK_ULONG count = 0;
    if (get_interfaces(NULL, &count) != 0 || count == 0) return NULL;
    CK_INTERFACE *interfaces = calloc(count, sizeof(*interfaces));
    if (!interfaces || get_interfaces(interfaces, &count) != 0) return NULL;
    void **functions = NULL;
    for (CK_ULONG i = 0; i < count; i++) {
        CK_VERSION version;
        if (!interfaces[i].name || strcmp(interfaces[i].name, "PKCS 11") != 0 ||
            !interfaces[i].table) continue;
        memcpy(&version, interfaces[i].table, sizeof(version));
        if (version.major == 3 && version.minor == 2) {
            functions = (void **)((char *)interfaces[i].table + 8);
            break;
        }
    }
    free(interfaces);
    if (!functions) fprintf(stderr, "no exact PKCS 11 v3.2 table\n");
    return functions;
}

static CK_ATTRIBUTE *metadata_fault_template(void **mapping, size_t *length)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return NULL;
    *length = (size_t)page * 2;
    *mapping = mmap(NULL, *length, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*mapping == MAP_FAILED ||
        mprotect((char *)*mapping + page, (size_t)page, PROT_NONE) != 0) return NULL;
    CK_ATTRIBUTE_TYPE *type = (CK_ATTRIBUTE_TYPE *)((char *)*mapping + page - sizeof(*type));
    *type = CKA_PRIVATE;
    return (CK_ATTRIBUTE *)type;
}

struct concurrent_call {
    fn10 function;
    CK_ULONG args[10];
    CK_RV rv;
};

static void *invoke(void *opaque)
{
    struct concurrent_call *call = opaque;
    call->rv = call->function(call->args[0], call->args[1], call->args[2], call->args[3],
                             call->args[4], call->args[5], call->args[6], call->args[7],
                             call->args[8], call->args[9]);
    return NULL;
}

static int run_concurrent(struct concurrent_call *calls, size_t count, const char *label)
{
    pthread_t threads[4];
    if (count > sizeof(threads) / sizeof(threads[0])) return 1;
    for (size_t i = 0; i < count; i++) {
        if (pthread_create(&threads[i], NULL, invoke, &calls[i]) != 0) return 1;
    }
    fprintf(stderr, "%s started %zu calls\n", label, count);
    for (size_t i = 0; i < count; i++) pthread_join(threads[i], NULL);
    for (size_t i = 0; i < count; i++) if (calls[i].rv != CKR_OK) return 1;
    printf("%s: all calls CKR_OK\n", label);
    return 0;
}

static int matrix_call(void **functions, unsigned index, const char *label,
                       const CK_ULONG args[10])
{
    CK_RV rv = ((fn10)functions[index])(args[0], args[1], args[2], args[3], args[4],
                                        args[5], args[6], args[7], args[8], args[9]);
    printf("%s -> 0x%lx\n", label, rv);
    return rv == 0 ? 0 : 1;
}

#define MATRIX_CALL(index, label, ...) do { \
    failures += matrix_call(functions, (index), (label), (CK_ULONG[10]){__VA_ARGS__}); \
} while (0)

static int wait_for_gate(const char *ready, const char *gate)
{
    if (!gate) return 0;
    FILE *handle = fopen(ready, "w");
    if (!handle) return 1;
    if (fputs("ready\n", handle) < 0 || fclose(handle) != 0) return 1;
    while (access(gate, F_OK) != 0) usleep(50000);
    return 0;
}

static int run_matrix(void *module, const char *ready, const char *gate)
{
    void **functions = matrix_functions(module);
    if (!functions || wait_for_gate(ready, gate) != 0) return 1;

    int failures = 0;
    CK_ULONG session = 0x101;
    CK_ULONG output_len = sizeof(SENT_OUTPUT) - 1;
    CK_OBJECT_HANDLE object = 0;
    CK_ULONG cls = CKO_SECRET_KEY, keytype = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE ordinary[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
        {CKA_VALUE, (void *)SENT_KEY, sizeof(SENT_KEY) - 1},
        {CKA_LABEL, (void *)SENT_LABEL, sizeof(SENT_LABEL) - 1},
        {CKA_ID, (void *)SENT_ID, sizeof(SENT_ID) - 1},
        {CKA_TOKEN, (void *)SENT_BOOLLONG, sizeof(SENT_BOOLLONG) - 1},
    };
    CK_MECHANISM registered = {REGISTERED_MECHANISM_CONTROL, NULL, 0};

    MATRIX_CALL(I_Login, "ordinary PIN", session, CKU_USER, ptr(SENT_PIN),
                sizeof(SENT_PIN) - 1);
    MATRIX_CALL(I_LoginUser, "ordinary username", session, CKU_USER, ptr(SENT_PIN),
                sizeof(SENT_PIN) - 1, ptr(SENT_USERNAME), sizeof(SENT_USERNAME) - 1);
    MATRIX_CALL(I_CreateObject, "ordinary template", session, ptr(ordinary),
                sizeof(ordinary) / sizeof(ordinary[0]), ptr(&object));
    MATRIX_CALL(I_Digest, "ordinary plaintext", session, ptr(SENT_PLAINTEXT),
                sizeof(SENT_PLAINTEXT) - 1, ptr(SENT_OUTPUT), ptr(&output_len));
    MATRIX_CALL(I_Encrypt, "ordinary ciphertext", session, ptr(SENT_PLAINTEXT),
                sizeof(SENT_PLAINTEXT) - 1, ptr(SENT_CIPHERTEXT), ptr(&output_len));
    MATRIX_CALL(I_Sign, "ordinary signature", session, ptr(SENT_PLAINTEXT),
                sizeof(SENT_PLAINTEXT) - 1, ptr(SENT_SIGNATURE), ptr(&output_len));
    MATRIX_CALL(I_WrapKey, "ordinary wrapped object", session, ptr(&registered),
                0x201, 0x202, ptr(SENT_WRAPPED), ptr(&output_len));
    MATRIX_CALL(I_GenerateRandom, "ordinary random output", session, ptr(SENT_RANDOM),
                sizeof(SENT_RANDOM) - 1);
    MATRIX_CALL(I_WrapKeyAuthenticated, "ordinary stack arguments", session,
                ptr(&registered), ptr(SENT_KEY), ptr(SENT_SIGNATURE), ptr(SENT_WRAPPED),
                ptr(SENT_OUTPUT), ptr(SENT_RANDOM), ptr(SENT_ARG7), ptr(SENT_ARG8),
                ptr(SENT_ARG9));

    MATRIX_CALL(I_DigestInit, "registered mechanism control", session, ptr(&registered));
    CK_MECHANISM unknown = {UNKNOWN_MECHANISM_CONTROL, NULL, 0};
    MATRIX_CALL(I_EncryptInit, "readable unknown mechanism control", session, ptr(&unknown),
                object);
    CK_MECHANISM maximum = {MAXIMUM_MECHANISM_CONTROL, NULL, 0};
    MATRIX_CALL(I_DecryptInit, "maximum mechanism control", session, ptr(&maximum),
                object);

    CK_RSA_PKCS_PSS_PARAMS pss = {ALIAS_PSS_HASH, ALIAS_PSS_MGF, ALIAS_PSS_SALT};
    CK_MECHANISM pss_mech = {CKM_RSA_PKCS_PSS, &pss, sizeof(pss)};
    MATRIX_CALL(I_SignInit, "aliased PSS words", session, ptr(&pss_mech), object);
    CK_GCM_PARAMS gcm220 = {(CK_BYTE_PTR)SENT_IV, ALIAS_GCM_V220_IV_LEN,
                            (CK_BYTE_PTR)SENT_AAD, ALIAS_GCM_V220_AAD_LEN,
                            ALIAS_GCM_V220_TAG_BITS};
    CK_MECHANISM gcm220_mech = {CKM_AES_GCM, &gcm220, sizeof(gcm220)};
    MATRIX_CALL(I_EncryptInit, "aliased GCM v2.20 words", session, ptr(&gcm220_mech),
                object);
    CK_GCM_PARAMS_V240 gcm240 = {(CK_BYTE_PTR)SENT_IV, ALIAS_GCM_V240_IV_LEN,
                                ALIAS_GCM_V240_IV_LEN * 8, (CK_BYTE_PTR)SENT_AAD,
                                ALIAS_GCM_V240_AAD_LEN, ALIAS_GCM_V240_TAG_BITS};
    CK_MECHANISM gcm240_mech = {CKM_AES_GCM, &gcm240, sizeof(gcm240)};
    MATRIX_CALL(I_EncryptInit, "aliased GCM v2.40 words", session, ptr(&gcm240_mech),
                object);

    CK_ULONG policy_types[] = {CKA_TOKEN, CKA_PRIVATE, CKA_SENSITIVE, CKA_ENCRYPT,
        CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, CKA_SIGN, CKA_VERIFY, CKA_DERIVE,
        CKA_EXTRACTABLE};
    /* Keep each call within the eight-attribute capture bound so every
     * policy-boolean decoder is actually exercised. The profile combines
     * the two calls' requested-type/boolean unions for C_CreateObject. */
    CK_ATTRIBUTE aliases_a[7] = {{ALIAS_TEMPLATE_TYPE, NULL, 0}};
    CK_ATTRIBUTE aliases_b[6] = {{ALIAS_TEMPLATE_TYPE, NULL, 0}};
    for (size_t i = 0; i < 6; i++) {
        aliases_a[i + 1] = (CK_ATTRIBUTE){policy_types[i], &ALIAS_POLICY_VALUES[i], 1};
    }
    for (size_t i = 6; i < 11; i++) {
        aliases_b[i - 5] = (CK_ATTRIBUTE){policy_types[i], &ALIAS_POLICY_VALUES[i], 1};
    }
    MATRIX_CALL(I_CreateObject, "aliased template and policy values A", session, ptr(aliases_a),
                sizeof(aliases_a) / sizeof(aliases_a[0]), ptr(&object));
    MATRIX_CALL(I_CreateObject, "aliased template and policy values B", session, ptr(aliases_b),
                sizeof(aliases_b) / sizeof(aliases_b[0]), ptr(&object));
    void *fault_mapping = NULL;
    size_t fault_mapping_len = 0;
    CK_ATTRIBUTE *metadata_fault = metadata_fault_template(&fault_mapping, &fault_mapping_len);
    if (!metadata_fault) return 1;
    MATRIX_CALL(I_CopyObject, "template metadata fault", session, object,
                ptr(metadata_fault), 1, ptr(&object));
    CK_ATTRIBUTE value_fault = {CKA_TOKEN, (void *)(uintptr_t)1, 1};
    MATRIX_CALL(I_SetAttributeValue, "template boolean value fault", session, object,
                ptr(&value_fault), 1);
    munmap(fault_mapping, fault_mapping_len);

    CK_MECHANISM overflow = {CKM_AES_GCM, OVERFLOW_PARAMETER_POINTER, sizeof(CK_GCM_PARAMS)};
    MATRIX_CALL(I_EncryptInit, "overflow parameter pointer", session, ptr(&overflow), object);
    CK_MECHANISM unreadable = {CKM_AES_GCM, (void *)(uintptr_t)1, sizeof(CK_GCM_PARAMS)};
    MATRIX_CALL(I_EncryptInit, "unreadable parameter pointer", session, ptr(&unreadable), object);
    MATRIX_CALL(I_EncryptInit, "unreadable mechanism pointer", session, 1, object);

    static const char exact_async[] = "C_Encrypt";
    MATRIX_CALL(I_AsyncComplete, "exact async name", 0x11d, ptr(exact_async), 0,
                0);
    MATRIX_CALL(I_AsyncComplete, "noncatalog legacy candidate", 0x11e,
                ptr(LEGACY_HASH_CANDIDATE), 0);
    MATRIX_CALL(I_AsyncComplete, "aliased async name", 0x11f, ptr(ALIAS_ASYNC_NAME), 0,
                0);

    printf("canary_workload matrix: %s\n", failures == 0 ? "all calls CKR_OK" : "FAILED");
    return failures == 0 ? 0 : 1;
}

static int run_blocked(void *module)
{
    void **functions = matrix_functions(module);
    if (!functions) return 1;
    CK_MECHANISM unknown = {UNKNOWN_MECHANISM_CONTROL, NULL, 0};
    static const char exact[] = "C_Encrypt";
    struct concurrent_call calls[] = {
        {(fn10)functions[I_EncryptInit], {0x301, ptr(&unknown)}, 0},
        {(fn10)functions[I_AsyncComplete], {0x302, ptr(exact)}, 0},
        {(fn10)functions[I_AsyncComplete], {0x303, ptr(LEGACY_HASH_CANDIDATE)}, 0},
        {(fn10)functions[I_AsyncComplete], {0x304, ptr(ALIAS_ASYNC_NAME)}, 0},
    };
    printf("P11SCOPE_POINTERS {\"unknown_mechanism\":%lu,"
           "\"exact_async\":%lu,\"legacy_name\":%lu,\"alias_name\":%lu}\n",
           ptr(&unknown), ptr(exact), ptr(LEGACY_HASH_CANDIDATE), ptr(ALIAS_ASYNC_NAME));
    fflush(stdout);
    return run_concurrent(calls, sizeof(calls) / sizeof(calls[0]), "blocked hostile subset");
}

static int run_faults(void *module)
{
    void **functions = matrix_functions(module);
    if (!functions) return 1;
    void *mapping = NULL;
    size_t mapping_len = 0;
    CK_ATTRIBUTE *metadata_fault = metadata_fault_template(&mapping, &mapping_len);
    if (!metadata_fault) return 1;
    CK_ATTRIBUTE value_fault = {CKA_TOKEN, (void *)(uintptr_t)1, 1};
    struct concurrent_call calls[] = {
        {(fn10)functions[I_CopyObject], {0x401, 1, ptr(metadata_fault), 1}, 0},
        {(fn10)functions[I_SetAttributeValue], {0x402, 1, ptr(&value_fault), 1}, 0},
    };
    int status = run_concurrent(calls, sizeof(calls) / sizeof(calls[0]),
                                "blocked template faults");
    munmap(mapping, mapping_len);
    return status;
}

#undef MATRIX_CALL

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: %s /path/to/fixture.so matrix|blocked|faults [READY GO]\n", argv[0]);
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    if (strcmp(argv[2], "matrix") == 0 && argc == 3) return run_matrix(h, NULL, NULL);
    if (strcmp(argv[2], "matrix") == 0 && argc == 5) return run_matrix(h, argv[3], argv[4]);
    if (strcmp(argv[2], "blocked") == 0) return run_blocked(h);
    if (strcmp(argv[2], "faults") == 0) return run_faults(h);
    fprintf(stderr, "usage: %s /path/to/fixture.so matrix|blocked|faults [READY GO]\n", argv[0]);
    return 2;
}
