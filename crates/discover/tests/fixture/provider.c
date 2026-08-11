/* Controlled PKCS#11 provider fixture. Exercises what SoftHSM2 (2.40-only)
 * cannot: a 3.0 interface, a vendor interface, a "PKCS 11" interface with a
 * NULL function list, a NULL table entry, a cross-surface alias, and a
 * pointer into another object (helper.so).
 *
 * Struct layout matches cryptoki-sys on linux-x86-64 (natural alignment):
 * CK_VERSION{2 x uchar} + 6 bytes padding, then 8-byte function pointers.
 */
typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;

#define CKR_OK 0UL
#define CKR_ARGUMENTS_BAD 7UL
#define CKR_BUFFER_TOO_SMALL 0x150UL
#define NBASE 68
#define N30 (68 + 24)

CK_RV helper_fn(void); /* lives in helper.so */

/* 92 distinct stubs s00..s91 — distinct so nothing aliases by accident. */
#define S(n) static CK_RV s##n(void) { return CKR_OK; }
#define S10(m) S(m##0) S(m##1) S(m##2) S(m##3) S(m##4) S(m##5) S(m##6) S(m##7) S(m##8) S(m##9)
S10(0) S10(1) S10(2) S10(3) S10(4) S10(5) S10(6) S10(7) S10(8) S(90) S(91)
#define L10(m) s##m##0, s##m##1, s##m##2, s##m##3, s##m##4, s##m##5, s##m##6, s##m##7, s##m##8, s##m##9

static void *stubs[N30] = { L10(0), L10(1), L10(2), L10(3), L10(4), L10(5), L10(6), L10(7), L10(8), s90, s91 };

static struct { CK_VERSION v; void *f[NBASE]; } legacy;
static struct { CK_VERSION v; void *f[N30]; } v30;

static void fill(void) {
    static int done;
    if (done) return;
    done = 1;
    legacy.v = (CK_VERSION){2, 40};
    for (int i = 0; i < NBASE; i++) legacy.f[i] = stubs[i];
    legacy.f[64] = (void *)helper_fn; /* C_GenerateRandom -> cross-object   */
    legacy.f[65] = 0;                 /* C_GetFunctionStatus -> NULL entry  */
    legacy.f[66] = legacy.f[67];      /* C_CancelFunction aliases C_WaitForSlotEvent */
    v30.v = (CK_VERSION){3, 0};
    /* Same base stubs (same names, same targets — corroboration, not an
     * alias) plus 24 distinct 3.0 entries. */
    for (int i = 0; i < N30; i++) v30.f[i] = stubs[i];
}

CK_RV C_GetFunctionList(void **pp) {
    fill();
    *pp = &legacy;
    return CKR_OK;
}

static char name_std[] = "PKCS 11";
static char name_vendor[] = "Vendor NetHSM-Ext";
static unsigned char vendor_blob[64]; /* opaque vendor "table": never walked */

CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    fill();
    if (!count) return CKR_ARGUMENTS_BAD;
    if (!out) { *count = 3; return CKR_OK; }
    if (*count < 3) { *count = 3; return CKR_BUFFER_TOO_SMALL; }
    out[0] = (CK_INTERFACE){ name_std, &v30, 0 };
    out[1] = (CK_INTERFACE){ name_vendor, vendor_blob, 0 };
    out[2] = (CK_INTERFACE){ name_std, 0, 0 };
    *count = 3;
    return CKR_OK;
}
