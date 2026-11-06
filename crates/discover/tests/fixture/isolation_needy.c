/* Socket-needy fixture: C_GetFunctionList needs an AF_INET socket and fails
 * with CKR_DEVICE_ERROR when creation fails. Under the trusted profile the
 * table is walked; under the isolated profile the failure must be recorded
 * as an acquisition error, never hidden or crashed over.
 */
#include <sys/socket.h>
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_RV;
typedef struct { CK_BYTE major; CK_BYTE minor; } CK_VERSION;

#define CKR_OK 0UL
#define CKR_DEVICE_ERROR 0x30UL
#define NBASE 68

static CK_RV stub(void) { return CKR_OK; }

static struct { CK_VERSION v; void *f[NBASE]; } legacy;

CK_RV C_GetFunctionList(void **pp) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return CKR_DEVICE_ERROR;
    close(s);
    legacy.v = (CK_VERSION){2, 40};
    for (int i = 0; i < NBASE; i++) legacy.f[i] = (void *)stub;
    *pp = &legacy;
    return CKR_OK;
}
