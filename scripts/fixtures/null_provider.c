/* SPDX-License-Identifier: GPL-3.0-or-later */
/* null_provider.c — minimal PKCS#11 provider that returns CKR_OK immediately.
 *
 * Purpose: measure p11scope's own per-call ceiling, not the provider's.
 * SoftHSM2's C_GenerateRandom costs ~0.8 us unobserved, which caps any
 * hammer at ~1.2M calls/s even with no observer; this stub removes the
 * provider from the denominator so the observed slowdown is the observer's.
 *
 * Build: gcc -shared -fPIC -O2 -o null_provider.so null_provider.c
 * Two distinct provider files: copy the .so to two paths; per-provider
 * counts must stay separate.
 *
 * Only the entry points the bench drivers use are implemented
 * (Initialize, Finalize, GetSlotList, OpenSession, CloseSession,
 * GenerateRandom). Every function returns CKR_OK (0) without touching
 * memory beyond its out-parameters. C_GetFunctionList/Interface/List
 * follow the same export shape as real providers so discovery treats
 * this like any other module.
 */
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;

enum {
    I_Initialize = 0,
    I_Finalize = 1,
    I_GetSlotList = 4,
    I_OpenSession = 12,
    I_CloseSession = 13,
    I_GenerateRandom = 64,
    N_FUNCTIONS = 68
};

static unsigned long next_session = 1;

__attribute__((visibility("default"))) CK_RV C_Initialize(void *args)
{
    (void)args;
    return 0;
}

__attribute__((visibility("default"))) CK_RV C_Finalize(void *args)
{
    (void)args;
    return 0;
}

__attribute__((visibility("default")))
CK_RV C_GetSlotList(unsigned char token_present, CK_SLOT_ID *slots, CK_ULONG *count)
{
    (void)token_present;
    if (count == 0)
        return 0;
    if (slots == 0) {
        *count = 1;
        return 0;
    }
    if (*count < 1) {
        *count = 1;
        return 0;
    }
    slots[0] = 7;
    *count = 1;
    return 0;
}

__attribute__((visibility("default")))
CK_RV C_OpenSession(CK_SLOT_ID slot, CK_ULONG flags, void *app, void *notify,
                    CK_SESSION_HANDLE *session)
{
    (void)slot;
    (void)flags;
    (void)app;
    (void)notify;
    if (session == 0)
        return 0;
    *session = __atomic_fetch_add(&next_session, 1, __ATOMIC_RELAXED);
    return 0;
}

__attribute__((visibility("default"))) CK_RV C_CloseSession(CK_SESSION_HANDLE session)
{
    (void)session;
    return 0;
}

__attribute__((visibility("default")))
CK_RV C_GenerateRandom(CK_SESSION_HANDLE session, unsigned char *random, CK_ULONG length)
{
    (void)session;
    (void)random;
    (void)length;
    return 0;
}

/* Build tag: compiling with -DNULL_TAG_STR='"A"' vs '"B"' yields two
 * providers with distinct bytes (distinct sha256), so per-provider
 * counts can be told apart. */
#ifndef NULL_TAG_STR
#define NULL_TAG_STR "?"
#endif
__attribute__((used)) static const char null_build_tag[] =
    "null-provider-" NULL_TAG_STR;

static struct {
    unsigned char major, minor;
    void *functions[N_FUNCTIONS];
} null_function_list = {
    2, 40,
    {
        [I_Initialize] = (void *)C_Initialize,
        [I_Finalize] = (void *)C_Finalize,
        [I_GetSlotList] = (void *)C_GetSlotList,
        [I_OpenSession] = (void *)C_OpenSession,
        [I_CloseSession] = (void *)C_CloseSession,
        [I_GenerateRandom] = (void *)C_GenerateRandom,
    },
};

__attribute__((visibility("default"))) CK_RV C_GetFunctionList(void **list)
{
    if (list != 0)
        *list = &null_function_list;
    return 0;
}

__attribute__((visibility("default")))
CK_RV C_GetInterfaceList(void *out, unsigned long *count)
{
    if (out != 0)
        *(void **)out = 0;
    if (count != 0)
        *count = 0;
    return 0;
}

__attribute__((visibility("default")))
CK_RV C_GetInterface(const char *name, void *version, void **out, unsigned long flags)
{
    (void)name;
    (void)version;
    (void)flags;
    if (out != 0)
        *out = 0;
    return 0;
}
