/* canary_workload.c — plants distinctive, high-entropy sentinels in every
 * argument position the Phase 3 privacy allowlist forbids reading, then
 * exercises exactly those PKCS#11 entry points against SoftHSM2:
 *
 *   - C_Login             pPin           -> CANARY_PIN_*
 *   - C_CreateObject      CKA_VALUE      -> CANARY_KEY_*
 *                         CKA_LABEL      -> CANARY_LABEL_*
 *                         CKA_ID         -> CANARY_ID_*
 *                         CKA_TOKEN      -> CANARY_BOOLLONG_* (deliberately
 *                                            ulValueLen > 1: the specific
 *                                            case the `ulValueLen == 1` gate
 *                                            in the BPF template walk must
 *                                            refuse to dereference)
 *   - C_DigestInit/Digest pData          -> CANARY_PLAINTEXT_*
 *   - C_EncryptInit       CK_GCM_PARAMS.pIv  -> CANARY_IV_*  (legacy v2.20
 *                         CK_GCM_PARAMS.pAAD -> CANARY_AAD_*  layout, 40
 *                         bytes: offsets 0/16 are the pointers, never
 *                         read; only ulIvLen/ulAADLen/ulTagBits at
 *                         offsets 8/24/32 are)
 *   - C_EncryptInit       same sentinels again, against the *modern*
 *                         v2.40/OASIS CK_GCM_PARAMS layout (48 bytes,
 *                         `ulIvBits` inserted at offset 16 — what
 *                         `cryptoki_sys::CK_GCM_PARAMS` actually is):
 *                         pIv@0/pAAD@24 are the pointers, never read;
 *                         only ulIvLen@8/ulAADLen@32/ulTagBits@40 are.
 *                         This is the case the pointer-disclosure defect
 *                         (fixed alongside this canary) needed: the old
 *                         `ulParameterLen >= 40` guard let this 48-byte
 *                         struct through and misread pAAD as aad_len.
 *   - C_EncryptInit       a malformed CK_GCM_PARAMS call, ulParameterLen
 *                         == 24 (matches neither known GCM layout) — must
 *                         decode nothing, never a fabricated combo.
 *   - C_SignInit          CK_RSA_PKCS_PSS_PARAMS { hashAlg, mgf, sLen } —
 *                         exercises the PSS offset path at all (nothing
 *                         else in this workload did before).
 *
 * SoftHSM2 handles every one of these entry points natively (some of the
 * calls are expected to fail — a garbled boolean length, a login with the
 * wrong PIN, an encrypt against a session object that may not exist — but
 * per the task brief that is fine and even useful: the uprobe fires at
 * function entry regardless of what the real implementation does with the
 * arguments afterward, so a fixture provider is not needed here.
 *
 * Calls go through the module's own CK_FUNCTION_LIST (indirect calls),
 * like spike/harness.c. Function indices are PKCS#11 v2.40 order — see
 * spike/discover.c for the canonical list this must match.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char CK_BYTE;
typedef CK_BYTE *CK_BYTE_PTR;
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE, CK_USER_TYPE, CK_ATTRIBUTE_TYPE;
typedef unsigned char CK_UTF8CHAR;
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

#define CKF_SERIAL_SESSION 4UL
#define CKF_RW_SESSION 2UL
#define CKU_USER 1UL
#define CKM_SHA256 0x250UL
#define CKM_AES_GCM 0x1087UL
#define CKM_RSA_PKCS_PSS 0x0DUL
#define CKG_MGF1_SHA256 0x02UL

#define CKA_CLASS 0x00000000UL
#define CKA_TOKEN 0x00000001UL
#define CKA_LABEL 0x00000003UL
#define CKA_VALUE 0x00000011UL
#define CKA_KEY_TYPE 0x00000100UL
#define CKA_ID 0x00000102UL

#define CKO_SECRET_KEY 0x00000004UL
#define CKK_GENERIC_SECRET 0x00000010UL

/* CK_FUNCTION_LIST indices (v2.40 order, see spike/discover.c) */
enum {
    I_Initialize = 0, I_Finalize = 1, I_GetSlotList = 4,
    I_OpenSession = 12, I_CloseSession = 13, I_Login = 18,
    I_CreateObject = 20, I_EncryptInit = 29,
    I_DigestInit = 37, I_Digest = 38, I_SignInit = 42,
};

typedef CK_RV (*fn_gen)(void *);
typedef CK_RV (*fn_slots)(unsigned char, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*fn_open)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
typedef CK_RV (*fn_close)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR *, CK_ULONG);
typedef CK_RV (*fn_create)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (*fn_encinit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
typedef CK_RV (*fn_diginit)(CK_SESSION_HANDLE, CK_MECHANISM *);
typedef CK_RV (*fn_digest)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG,
                           unsigned char *, CK_ULONG *);
typedef CK_RV (*fn_signinit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);

static void **fns;

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

/* Non-fatal: print the outcome and keep going. The point of this workload
 * is that the *call happens* with sentinels in memory, not that it
 * succeeds — a provider rejecting a garbled argument after the uprobe has
 * already fired is a fine (even useful) outcome. */
#define NOTE(what, expr) do { CK_RV _rv = (expr); \
    fprintf(stderr, "%s -> 0x%lx\n", what, _rv); } while (0)
#define CHECK(what, expr) do { CK_RV _rv = (expr); \
    if (_rv != 0) { fprintf(stderr, "%s failed: 0x%lx\n", what, _rv); return 1; } } while (0)

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s /path/to/module.so\n", argv[0]); return 2; }

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "no function list\n"); return 1; }
    fns = (void **)((char *)list + 8);

    CHECK("C_Initialize", ((fn_gen)fns[I_Initialize])(NULL));

    CK_SLOT_ID slots[64]; CK_ULONG nslots = 64;
    CHECK("C_GetSlotList", ((fn_slots)fns[I_GetSlotList])(1, slots, &nslots));
    if (nslots < 1) { fprintf(stderr, "no token present — init a token first\n"); return 1; }

    CK_SESSION_HANDLE sess;
    CHECK("C_OpenSession",
          ((fn_open)fns[I_OpenSession])(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                         NULL, NULL, &sess));

    /* sentinel PIN passed to C_Login. LOGIN never reads pPin in the BPF
     * probe (Phase 2 contract); this call is expected to fail on a real
     * token since the sentinel is not the configured PIN. */
    NOTE("C_Login", ((fn_login)fns[I_Login])(sess, CKU_USER,
                                              (CK_UTF8CHAR *)SENT_PIN,
                                              (CK_ULONG)strlen(SENT_PIN)));

    /* sentinel key material / label / CKA_ID on C_CreateObject, plus a
     * deliberately-malformed CKA_TOKEN (ulValueLen > 1) to probe the
     * `ulValueLen == 1` gate specifically. */
    CK_ULONG cls = CKO_SECRET_KEY;
    CK_ULONG keytype = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS,    &cls,     sizeof(cls) },
        { CKA_KEY_TYPE, &keytype, sizeof(keytype) },
        { CKA_VALUE,    (void *)SENT_KEY,      (CK_ULONG)strlen(SENT_KEY) },
        { CKA_LABEL,    (void *)SENT_LABEL,    (CK_ULONG)strlen(SENT_LABEL) },
        { CKA_ID,       (void *)SENT_ID,       (CK_ULONG)strlen(SENT_ID) },
        { CKA_TOKEN,    (void *)SENT_BOOLLONG, (CK_ULONG)strlen(SENT_BOOLLONG) },
    };
    CK_OBJECT_HANDLE hObject = 0;
    NOTE("C_CreateObject",
         ((fn_create)fns[I_CreateObject])(sess, attrs,
                                           sizeof(attrs) / sizeof(attrs[0]), &hObject));

    /* sentinel plaintext passed to C_Digest. */
    CK_MECHANISM sha256 = { CKM_SHA256, NULL, 0 };
    unsigned char digest_out[64]; CK_ULONG digest_len = sizeof digest_out;
    CHECK("C_DigestInit", ((fn_diginit)fns[I_DigestInit])(sess, &sha256));
    CHECK("C_Digest",
          ((fn_digest)fns[I_Digest])(sess, (unsigned char *)SENT_PLAINTEXT,
                                      (CK_ULONG)strlen(SENT_PLAINTEXT),
                                      digest_out, &digest_len));

    /* sentinel GCM IV and AAD — exactly the pointers CK_GCM_PARAMS.pIv
     * (offset 0) and .pAAD (offset 16) that the allowlist forbids
     * dereferencing. Only ulIvLen/ulAADLen/ulTagBits (offsets 8/24/32) may
     * ever be read. hObject may be invalid if C_CreateObject failed above;
     * C_EncryptInit is expected to fail in that case, which is fine — the
     * uprobe still fires with the sentinels live in argument memory. */
    CK_GCM_PARAMS gcm = {
        .pIv = (CK_BYTE_PTR)SENT_IV, .ulIvLen = (CK_ULONG)strlen(SENT_IV),
        .pAAD = (CK_BYTE_PTR)SENT_AAD, .ulAADLen = (CK_ULONG)strlen(SENT_AAD),
        .ulTagBits = 128,
    };
    CK_MECHANISM gcm_mech = { CKM_AES_GCM, &gcm, sizeof(gcm) };
    NOTE("C_EncryptInit(GCM v2.20)", ((fn_encinit)fns[I_EncryptInit])(sess, &gcm_mech, hObject));

    /* Same sentinels, against the modern v2.40/OASIS CK_GCM_PARAMS layout
     * (48 bytes, ulIvBits inserted at offset 16) — the layout the
     * pointer-disclosure defect was about: the old ulParameterLen >= 40
     * guard let this struct through and misread pAAD (offset 24 here,
     * not 16) as ulAADLen. */
    CK_GCM_PARAMS_V240 gcm240 = {
        .pIv = (CK_BYTE_PTR)SENT_IV, .ulIvLen = (CK_ULONG)strlen(SENT_IV),
        .ulIvBits = (CK_ULONG)strlen(SENT_IV) * 8,
        .pAAD = (CK_BYTE_PTR)SENT_AAD, .ulAADLen = (CK_ULONG)strlen(SENT_AAD),
        .ulTagBits = 128,
    };
    CK_MECHANISM gcm240_mech = { CKM_AES_GCM, &gcm240, sizeof(gcm240) };
    NOTE("C_EncryptInit(GCM v2.40)",
         ((fn_encinit)fns[I_EncryptInit])(sess, &gcm240_mech, hObject));

    /* Malformed ulParameterLen: 24 matches neither the 40-byte legacy nor
     * the 48-byte modern GCM layout. Must decode nothing — never guess at
     * offsets for an unrecognized length. The buffer's bytes must never
     * matter since the length guard should reject this before either
     * pIv/pAAD offset is ever read. */
    CK_BYTE malformed_buf[24] = {0};
    CK_MECHANISM gcm_malformed_mech = { CKM_AES_GCM, malformed_buf, sizeof(malformed_buf) };
    NOTE("C_EncryptInit(GCM malformed len=24)",
         ((fn_encinit)fns[I_EncryptInit])(sess, &gcm_malformed_mech, hObject));

    /* RSA-PSS *Init — exercises the PSS offset path at all (nothing else
     * in this workload did before). hObject is a secret-key handle (or
     * possibly invalid, if C_CreateObject above failed), so this is
     * expected to fail on a real token; the uprobe fires regardless. */
    CK_RSA_PKCS_PSS_PARAMS pss = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_MECHANISM pss_mech = { CKM_RSA_PKCS_PSS, &pss, sizeof(pss) };
    NOTE("C_SignInit(PSS)", ((fn_signinit)fns[I_SignInit])(sess, &pss_mech, hObject));

    NOTE("C_CloseSession", ((fn_close)fns[I_CloseSession])(sess));
    NOTE("C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));

    printf("canary_workload: done\n");
    return 0;
}
