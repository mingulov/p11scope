// Task 8 fixture: attach-first experiment provider + launcher.
//
// One translation unit, three builds:
//   launcher:          gcc ... fixture-provider.c -o launcher-provider -ldl
//   exported provider: gcc ... -shared -fPIC -fvisibility=hidden -DFIXTURE_PROVIDER
//                          -DC_TABLE_EXPORTED -o provider-exported.so fixture-provider.c
//   hidden provider:   gcc ... -shared -fPIC -fvisibility=hidden -DFIXTURE_PROVIDER
//                          -o provider-hidden.so fixture-provider.c
//
// Provider contract (mirrors the frozen A/B discovery shape):
//   - C_GetFunctionList(uint64_t *out) writes &provider_table and then executes
//     a 3-nop marker sequence immediately before returning; the loader program
//     is attached at that marker offset as the export-return pause hook.
//   - provider_table starts with version bytes {3, 2} followed by 104 function
//     pointers at byte offset 8 (the A/B function_list_return record copies
//     exactly this shape once the loader applied the relative relocations).
//   - Table slot 0 is C_Initialize; the constructor calls C_GetFunctionList and
//     then slot 0, printing PROVIDER_CTOR_INIT. The launcher dlopens, then
//     calls the export and slot 0 post-return, printing LAUNCHER_POST_RETURN.
//   - Every table function shares C_GetFunctionList's one-argument shape so the
//     A/B entry/return probe pair can be attached at any slot: each function
//     writes &provider_table back through its argument, keeping every return
//     record's 104-pointer copy readable and failure-free.

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

struct provider_function_list {
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t reserved[6];
    uint64_t pointers[104];
};

// glibc marks write(2) warn_unused_result; route every marker through here so
// -Werror builds stay clean and markers remain best-effort.
static void emit_line(const char *text, size_t length) {
    ssize_t written = write(STDERR_FILENO, text, length);
    (void)written;
}

#define PROVIDER_EXPORT __attribute__((visibility("default")))

#ifdef FIXTURE_PROVIDER

#ifdef C_TABLE_EXPORTED
#define TABLE_FN PROVIDER_EXPORT
#else
#define TABLE_FN static
#endif

#define PROVIDER_FUNCTIONS(X) \
    X(C_Initialize) \
    X(C_Finalize) \
    X(C_GetInfo) \
    X(C_GetSlotList) \
    X(C_GetSlotInfo) \
    X(C_GetTokenInfo) \
    X(C_GetMechanismList) \
    X(C_GetMechanismInfo) \
    X(C_InitToken) \
    X(C_InitPIN) \
    X(C_SetPIN) \
    X(C_OpenSession) \
    X(C_CloseSession) \
    X(C_CloseAllSessions) \
    X(C_GetSessionInfo) \
    X(C_GetOperationState) \
    X(C_SetOperationState) \
    X(C_Login) \
    X(C_Logout) \
    X(C_CreateObject) \
    X(C_CopyObject) \
    X(C_DestroyObject) \
    X(C_GetObjectSize) \
    X(C_GetAttributeValue) \
    X(C_SetAttributeValue) \
    X(C_FindObjectsInit) \
    X(C_FindObjects) \
    X(C_FindObjectsFinal) \
    X(C_EncryptInit) \
    X(C_Encrypt) \
    X(C_EncryptUpdate) \
    X(C_EncryptFinal) \
    X(C_DecryptInit) \
    X(C_Decrypt) \
    X(C_DecryptUpdate) \
    X(C_DecryptFinal) \
    X(C_DigestInit) \
    X(C_Digest) \
    X(C_DigestUpdate) \
    X(C_DigestKey) \
    X(C_DigestFinal) \
    X(C_SignInit) \
    X(C_Sign) \
    X(C_SignUpdate) \
    X(C_SignFinal) \
    X(C_SignRecoverInit) \
    X(C_SignRecover) \
    X(C_VerifyInit) \
    X(C_Verify) \
    X(C_VerifyUpdate) \
    X(C_VerifyFinal) \
    X(C_VerifyRecoverInit) \
    X(C_VerifyRecover) \
    X(C_DigestEncryptUpdate) \
    X(C_DecryptDigestUpdate) \
    X(C_SignEncryptUpdate) \
    X(C_DecryptVerifyUpdate) \
    X(C_GenerateKey) \
    X(C_GenerateKeyPair) \
    X(C_WrapKey) \
    X(C_UnwrapKey) \
    X(C_DeriveKey) \
    X(C_SeedRandom) \
    X(C_GenerateRandom) \
    X(C_GetFunctionStatus) \
    X(C_CancelFunction) \
    X(C_WaitForSlotEvent) \
    X(C_VendorDefine1) \
    X(C_VendorDefine2) \
    X(C_VendorDefine3) \
    X(C_VendorDefine4) \
    X(C_VendorDefine5) \
    X(C_VendorDefine6) \
    X(C_VendorDefine7) \
    X(C_VendorDefine8) \
    X(C_VendorDefine9) \
    X(C_VendorDefine10) \
    X(C_VendorDefine11) \
    X(C_VendorDefine12) \
    X(C_VendorDefine13) \
    X(C_VendorDefine14) \
    X(C_VendorDefine15) \
    X(C_VendorDefine16) \
    X(C_VendorDefine17) \
    X(C_VendorDefine18) \
    X(C_VendorDefine19) \
    X(C_VendorDefine20) \
    X(C_VendorDefine21) \
    X(C_VendorDefine22) \
    X(C_VendorDefine23) \
    X(C_VendorDefine24) \
    X(C_VendorDefine25) \
    X(C_VendorDefine26) \
    X(C_VendorDefine27) \
    X(C_VendorDefine28) \
    X(C_VendorDefine29) \
    X(C_VendorDefine30) \
    X(C_VendorDefine31) \
    X(C_VendorDefine32) \
    X(C_VendorDefine33) \
    X(C_VendorDefine34) \
    X(C_VendorDefine35) \
    X(C_VendorDefine36) \
    X(C_VendorDefine37)

static struct provider_function_list provider_table;
uint64_t C_GetFunctionList(uint64_t *out);

#define DEFINE_TABLE_FUNCTION(name) \
    TABLE_FN __attribute__((noinline, used)) uint64_t name(uint64_t *out) { \
        *out = (uint64_t)(uintptr_t)&provider_table; \
        return 0; \
    }
PROVIDER_FUNCTIONS(DEFINE_TABLE_FUNCTION)

// Static initializer: the 104 function-address slots turn into
// R_X86_64_RELATIVE relocations that the dynamic loader applies (the exact
// transition the negative-timing witness measures), unlike runtime stores.
#define POINTER_INIT(name) (uint64_t)(uintptr_t)&name,
static struct provider_function_list provider_table = {
    .version_major = 3,
    .version_minor = 2,
    .reserved = {0},
    .pointers = {
        PROVIDER_FUNCTIONS(POINTER_INIT)
    },
};

__attribute__((constructor)) static void provider_ctor(void) {
    uint64_t table = 0;
    (void)C_GetFunctionList(&table);
    struct provider_function_list *list =
        (struct provider_function_list *)(uintptr_t)table;
    uint64_t (*slot0)(uint64_t *) = (uint64_t (*)(uint64_t *))(uintptr_t)list->pointers[0];
    (void)slot0(&table);
    emit_line("PROVIDER_CTOR_INIT\n", 19);
}

PROVIDER_EXPORT __attribute__((noinline, used)) uint64_t
C_GetFunctionList(uint64_t *out) {
    *out = (uint64_t)(uintptr_t)&provider_table;
    __asm__ volatile("nop; nop; nop");
    return 0;
}

#else /* launcher */

#include <dlfcn.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    uint8_t gate = 0;
    if (read(0, &gate, 1) != 1) {
        return 3;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        emit_line("DLOPEN_FAILED\n", 14);
        return 4;
    }
    uint64_t (*get_list)(uint64_t *) = (uint64_t (*)(uint64_t *))dlsym(handle, "C_GetFunctionList");
    if (get_list == NULL) {
        emit_line("DLSYM_FAILED\n", 13);
        return 5;
    }
    uint64_t table = 0;
    if (get_list(&table) != 0) {
        return 6;
    }
    struct provider_function_list *list =
        (struct provider_function_list *)(uintptr_t)table;
    uint64_t (*slot0)(uint64_t *) = (uint64_t (*)(uint64_t *))(uintptr_t)list->pointers[0];
    (void)slot0(&table);
    emit_line("LAUNCHER_POST_RETURN\n", 21);
    return 0;
}

#endif
