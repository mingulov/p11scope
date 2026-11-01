/* SPDX-License-Identifier: GPL-3.0-or-later */
/* async-32 stub provider: a PKCS#11 3.2 function table (version 3.2,
 * 104 entries in canonical order) with real exported symbols and real
 * signatures at ordinals 99-101 (C_AsyncComplete, C_AsyncGetID,
 * C_AsyncJoin) plus one CKR_PENDING-capable originating key call
 * (C_Sign after C_SignInit). Sessions are small integers; state is
 * per-process and deterministic. The provider prints nothing.
 *
 * Operation model: C_SignInit arms a session; the first C_Sign allocates
 * an async id (1, 2, ...) and returns CKR_PENDING, and re-polls return
 * CKR_PENDING until C_AsyncComplete on the holding session completes it
 * with CKR_OK. C_AsyncGetID reports the held id; C_AsyncJoin moves the
 * hold to another session.
 *
 * Test hooks (deliberate, not spec behavior): C_AsyncGetID with a NULL
 * pulID returns CKR_OK without writing, so the observer's null-output
 * path is exercisable live. Everything else follows the obvious
 * PKCS#11 refusals (unknown session, unarmed sign, unknown id).
 *
 * Only C_GetFunctionList and the nine implemented entries are
 * exported (build with -fvisibility=hidden); the remaining 95 table
 * slots answer CKR_FUNCTION_NOT_SUPPORTED. */
#include <stddef.h>
#include <string.h>

#include "async-32.h"

/* Table geometry: 2 version bytes + 6 reserved, then 104 pointers. */
_Static_assert(sizeof(Async32FunctionList) ==
                   8 + ASYNC32_TABLE_SLOTS * sizeof(void *),
               "async-32 table holds 104 slots");
_Static_assert(offsetof(Async32FunctionList, C_AsyncComplete) ==
                   8 + 99 * sizeof(void *),
               "C_AsyncComplete is ordinal 99");
_Static_assert(offsetof(Async32FunctionList, C_AsyncGetID) ==
                   8 + 100 * sizeof(void *),
               "C_AsyncGetID is ordinal 100");
_Static_assert(offsetof(Async32FunctionList, C_AsyncJoin) ==
                   8 + 101 * sizeof(void *),
               "C_AsyncJoin is ordinal 101");

#define MAX_SESSIONS 8
#define MAX_OPS 8

static struct {
    int used;
    CK_SESSION_HANDLE handle;
    int sign_armed;
} sessions[MAX_SESSIONS];

static struct {
    int live;
    CK_ULONG id;
    CK_SESSION_HANDLE origin;
    CK_SESSION_HANDLE holder;
} ops[MAX_OPS];

static CK_ULONG next_handle = 1;
static CK_ULONG next_id = 1;

static int find_session(CK_SESSION_HANDLE handle) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].used && sessions[i].handle == handle)
            return i;
    }
    return -1;
}

static int find_live_op(CK_ULONG id) {
    for (int i = 0; i < MAX_OPS; i++) {
        if (ops[i].live && ops[i].id == id)
            return i;
    }
    return -1;
}

static int find_held_op(CK_SESSION_HANDLE holder) {
    for (int i = 0; i < MAX_OPS; i++) {
        if (ops[i].live && ops[i].holder == holder)
            return i;
    }
    return -1;
}

#define EXPORT __attribute__((visibility("default")))

static CK_RV unsupported(void) {
    return ASYNC32_CKR_FUNCTION_NOT_SUPPORTED;
}

EXPORT CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    (void)pInitArgs;
    return ASYNC32_CKR_OK;
}

EXPORT CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    (void)pReserved;
    memset(sessions, 0, sizeof sessions);
    memset(ops, 0, sizeof ops);
    next_handle = 1;
    next_id = 1;
    return ASYNC32_CKR_OK;
}

EXPORT CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                           void *pApplication, CK_NOTIFY Notify,
                           CK_SESSION_HANDLE *phSession) {
    (void)slotID;
    (void)flags;
    (void)pApplication;
    (void)Notify;
    if (phSession == NULL)
        return ASYNC32_CKR_ARGUMENTS_BAD;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].used) {
            sessions[i].used = 1;
            sessions[i].handle = next_handle++;
            sessions[i].sign_armed = 0;
            *phSession = sessions[i].handle;
            return ASYNC32_CKR_OK;
        }
    }
    return ASYNC32_CKR_SESSION_HANDLE_INVALID;
}

EXPORT CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    int at = find_session(hSession);
    if (at < 0)
        return ASYNC32_CKR_SESSION_HANDLE_INVALID;
    sessions[at].used = 0;
    sessions[at].sign_armed = 0;
    return ASYNC32_CKR_OK;
}

EXPORT CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism,
                        CK_OBJECT_HANDLE hKey) {
    (void)hKey;
    int at = find_session(hSession);
    if (at < 0)
        return ASYNC32_CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL)
        return ASYNC32_CKR_ARGUMENTS_BAD;
    sessions[at].sign_armed = 1;
    return ASYNC32_CKR_OK;
}

EXPORT CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen) {
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)pulSignatureLen;
    int at = find_session(hSession);
    if (at < 0)
        return ASYNC32_CKR_SESSION_HANDLE_INVALID;
    if (!sessions[at].sign_armed)
        return ASYNC32_CKR_OPERATION_NOT_INITIALIZED;
    if (find_held_op(hSession) >= 0)
        return ASYNC32_CKR_PENDING;
    for (int i = 0; i < MAX_OPS; i++) {
        if (!ops[i].live && ops[i].id == 0) {
            ops[i].live = 1;
            ops[i].id = next_id++;
            ops[i].origin = hSession;
            ops[i].holder = hSession;
            return ASYNC32_CKR_PENDING;
        }
    }
    return ASYNC32_CKR_OPERATION_NOT_INITIALIZED;
}

EXPORT CK_RV C_AsyncComplete(CK_SESSION_HANDLE hSession,
                             CK_UTF8CHAR *pFunctionName,
                             CK_ASYNC_DATA *pResult) {
    if (pFunctionName == NULL)
        return ASYNC32_CKR_ARGUMENTS_BAD;
    if (find_session(hSession) < 0)
        return ASYNC32_CKR_SESSION_HANDLE_INVALID;
    int at = find_held_op(hSession);
    if (at < 0)
        return ASYNC32_CKR_OPERATION_NOT_INITIALIZED;
    ops[at].live = 0;
    if (pResult != NULL) {
        pResult->ulVersion = 0;
        pResult->pValue = NULL;
        pResult->ulValue = ASYNC32_CKR_OK;
        pResult->hObject = 0;
        pResult->hAdditionalObject = 0;
    }
    return ASYNC32_CKR_OK;
}

EXPORT CK_RV C_AsyncGetID(CK_SESSION_HANDLE hSession,
                          CK_UTF8CHAR *pFunctionName, CK_ULONG *pulID) {
    if (pFunctionName == NULL)
        return ASYNC32_CKR_ARGUMENTS_BAD;
    /* Test hook: NULL output is accepted with CKR_OK so the observer's
     * null-output path runs live. */
    if (pulID == NULL)
        return ASYNC32_CKR_OK;
    if (find_session(hSession) < 0)
        return ASYNC32_CKR_SESSION_HANDLE_INVALID;
    int at = find_held_op(hSession);
    if (at < 0)
        return ASYNC32_CKR_OPERATION_NOT_INITIALIZED;
    *pulID = ops[at].id;
    return ASYNC32_CKR_OK;
}

EXPORT CK_RV C_AsyncJoin(CK_SESSION_HANDLE hSession,
                         CK_UTF8CHAR *pFunctionName, CK_ULONG id,
                         CK_BYTE_PTR pReserved, CK_ULONG ulReserved) {
    (void)pReserved;
    (void)ulReserved;
    if (pFunctionName == NULL)
        return ASYNC32_CKR_ARGUMENTS_BAD;
    if (find_session(hSession) < 0)
        return ASYNC32_CKR_SESSION_HANDLE_INVALID;
    int at = find_live_op(id);
    if (at < 0)
        return ASYNC32_CKR_ARGUMENTS_BAD;
    ops[at].holder = hSession;
    return ASYNC32_CKR_OK;
}

static Async32FunctionList provider_table;

#define ASYNC32_FILL(ord, name, type)                                   \
    {                                                                \
        CK_C_Async32Unimplemented stub = unsupported;                \
        _Static_assert(sizeof stub == sizeof provider_table.name,    \
                       "table entries are pointers");                \
        memcpy(&provider_table.name, &stub, sizeof stub);            \
    }
__attribute__((constructor)) static void provider_init(void) {
    provider_table.major = 3;
    provider_table.minor = 2;
    ASYNC32_FUNCTIONS(ASYNC32_FILL)
    provider_table.C_Initialize = C_Initialize;
    provider_table.C_Finalize = C_Finalize;
    provider_table.C_OpenSession = C_OpenSession;
    provider_table.C_CloseSession = C_CloseSession;
    provider_table.C_SignInit = C_SignInit;
    provider_table.C_Sign = C_Sign;
    provider_table.C_AsyncComplete = C_AsyncComplete;
    provider_table.C_AsyncGetID = C_AsyncGetID;
    provider_table.C_AsyncJoin = C_AsyncJoin;
}
#undef ASYNC32_FILL

EXPORT CK_RV C_GetFunctionList(void **out) {
    if (out == NULL)
        return ASYNC32_CKR_ARGUMENTS_BAD;
    *out = &provider_table;
    return ASYNC32_CKR_OK;
}
