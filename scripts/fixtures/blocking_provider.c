/* blocking_provider.c — minimal legacy (v2.40, 68-entry) PKCS#11 function
 * table for the "in-flight at end" gap in scripts/verify-induced-gaps.sh.
 * Identification of table entries is by POSITION (see spike/discover.c for
 * the canonical name order this must match), not by name — so all 68
 * slots must be present even though only one (index 67, C_WaitForSlotEvent)
 * does anything interesting: it blocks past any reasonable capture window,
 * so a call entered before the window closes is still in flight when it
 * does.
 *
 * Struct layout matches provider.c: CK_VERSION (2 bytes + 6 padding) then
 * function pointers.
 */
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_RV;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;

#define CKR_OK 0UL
#define NBASE 68
#define I_WaitForSlotEvent 67

static CK_RV ok(void) { return CKR_OK; }
/* Blocks far longer than any --duration this test uses, so the call is
 * still entered-not-returned when the capture window closes. */
static CK_RV blocks_forever(void) { sleep(60); return CKR_OK; }

static struct { CK_VERSION v; void *f[NBASE]; } table;

CK_RV C_GetFunctionList(void **pp)
{
    static int done;
    if (!done) {
        done = 1;
        table.v = (CK_VERSION){2, 40};
        for (int i = 0; i < NBASE; i++) table.f[i] = (void *)ok;
        table.f[I_WaitForSlotEvent] = (void *)blocks_forever;
    }
    *pp = &table;
    return CKR_OK;
}
