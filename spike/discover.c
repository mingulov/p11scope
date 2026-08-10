/* spike/discover.c — dlopen a PKCS#11 module, resolve its CK_FUNCTION_LIST
 * pointers to file offsets via /proc/self/maps. Spike quality: x86-64,
 * PKCS#11 v2.x table only, no 3.x interfaces, no ELF parsing.
 * Output per entry: <name> <path> <file_offset_hex> <vaddr_hex>
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* CK_FUNCTION_LIST order, PKCS#11 v2.40, 68 entries. */
static const char *names[] = {
    "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList",
    "C_GetMechanismInfo", "C_InitToken", "C_InitPIN", "C_SetPIN",
    "C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_GetSessionInfo",
    "C_GetOperationState", "C_SetOperationState", "C_Login", "C_Logout",
    "C_CreateObject", "C_CopyObject", "C_DestroyObject", "C_GetObjectSize",
    "C_GetAttributeValue", "C_SetAttributeValue", "C_FindObjectsInit",
    "C_FindObjects", "C_FindObjectsFinal", "C_EncryptInit", "C_Encrypt",
    "C_EncryptUpdate", "C_EncryptFinal", "C_DecryptInit", "C_Decrypt",
    "C_DecryptUpdate", "C_DecryptFinal", "C_DigestInit", "C_Digest",
    "C_DigestUpdate", "C_DigestKey", "C_DigestFinal", "C_SignInit", "C_Sign",
    "C_SignUpdate", "C_SignFinal", "C_SignRecoverInit", "C_SignRecover",
    "C_VerifyInit", "C_Verify", "C_VerifyUpdate", "C_VerifyFinal",
    "C_VerifyRecoverInit", "C_VerifyRecover", "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate", "C_SignEncryptUpdate", "C_DecryptVerifyUpdate",
    "C_GenerateKey", "C_GenerateKeyPair", "C_WrapKey", "C_UnwrapKey",
    "C_DeriveKey", "C_SeedRandom", "C_GenerateRandom", "C_GetFunctionStatus",
    "C_CancelFunction", "C_WaitForSlotEvent",
};
#define NFUNCS (sizeof names / sizeof names[0])

struct map { unsigned long lo, hi, off; char path[512]; };

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s /path/to/module.so\n", argv[0]); return 2; }

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }

    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    if (!gfl) { fprintf(stderr, "no C_GetFunctionList export\n"); return 1; }

    void *list = NULL;
    unsigned long rv = gfl(&list);
    if (rv != 0 || !list) { fprintf(stderr, "C_GetFunctionList rv=0x%lx\n", rv); return 1; }

    /* CK_FUNCTION_LIST = CK_VERSION {2 x CK_BYTE} then 68 function pointers.
     * +8 is an EMPIRICAL property of SoftHSM2 (naturally-aligned table: 2 bytes
     * version + 6 padding, first pointer at 8), NOT universal — the canonical
     * pkcs11.h uses #pragma pack(cryptoki,1); a genuinely packed table puts the
     * first pointer at offset 2. Fine for this spike (SoftHSM2 only); the
     * product MUST derive the offset from proxy-ng's offset_of! field tables,
     * never hardcode 8. */
    void **fns = (void **)((char *)list + 8);

    struct map maps[4096];
    int nmaps = 0;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { perror("maps"); return 1; }
    char line[1024];
    while (nmaps < 4096 && fgets(line, sizeof line, f)) {
        struct map *m = &maps[nmaps];
        m->path[0] = 0;
        if (sscanf(line, "%lx-%lx %*4s %lx %*s %*s %511s",
                   &m->lo, &m->hi, &m->off, m->path) >= 3)
            nmaps++;
    }
    fclose(f);

    for (unsigned i = 0; i < NFUNCS; i++) {
        unsigned long p = (unsigned long)fns[i];
        struct map *hit = NULL, *base = NULL;
        for (int j = 0; j < nmaps; j++)
            if (p >= maps[j].lo && p < maps[j].hi) { hit = &maps[j]; break; }
        if (!hit || !hit->path[0]) {           /* non-file-backed: report, don't guess */
            printf("%s UNRESOLVED 0 0\n", names[i]);
            continue;
        }
        for (int j = 0; j < nmaps; j++)        /* first mapping of same file = load base */
            if (!strcmp(maps[j].path, hit->path)) { base = &maps[j]; break; }
        printf("%s %s 0x%lx 0x%lx\n", names[i], hit->path,
               p - hit->lo + hit->off,          /* file offset (uprobe currency) */
               p - base->lo);                   /* link-time vaddr: DSO first LOAD at 0 */
    }
    return 0;
}
