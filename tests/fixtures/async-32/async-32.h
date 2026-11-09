/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* async-32: shared shape for the PKCS#11 3.2 async stub provider and its
 * driver. Minimal CK_* types (LP64/ILP32-portable: CK_ULONG is unsigned
 * long), the CKR codes the stub returns, the real 3.2 async signatures
 * (cryptoki-sys 0.5.0 vendor/pkcs11.h), and the 104-entry function table
 * in canonical catalog order.
 *
 * The table lists every ordinal explicitly so the three async entries
 * land at 99-101 by construction; the provider pins those offsets with
 * _Static_assert. Only the entries the stub implements carry real
 * typedefs; the rest are CK_C_Unimplemented and answer
 * CKR_FUNCTION_NOT_SUPPORTED. The driver only ever calls the
 * implemented entries. */
#ifndef P11SCOPE_ASYNC32_H
#define P11SCOPE_ASYNC32_H

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned char CK_BYTE;
typedef char CK_UTF8CHAR;
typedef void *CK_VOID_PTR;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef void (*CK_NOTIFY)(CK_SESSION_HANDLE, CK_ULONG, CK_VOID_PTR);

typedef struct {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef struct {
    CK_ULONG ulVersion;
    CK_BYTE_PTR pValue;
    CK_ULONG ulValue;
    CK_OBJECT_HANDLE hObject;
    CK_OBJECT_HANDLE hAdditionalObject;
} CK_ASYNC_DATA;

#define ASYNC32_CKR_OK 0UL
#define ASYNC32_CKR_ARGUMENTS_BAD 7UL
#define ASYNC32_CKR_FUNCTION_NOT_SUPPORTED 0x54UL
#define ASYNC32_CKR_OPERATION_NOT_INITIALIZED 0x91UL
#define ASYNC32_CKR_SESSION_HANDLE_INVALID 0xB3UL
#define ASYNC32_CKR_PENDING 0x204UL

#define ASYNC32_CKM_RSA_PKCS 1UL
#define ASYNC32_CKF_RW_SESSION 0x2UL
#define ASYNC32_CKF_SERIAL_SESSION 0x4UL

/* Real signatures for the implemented entries (PKCS#11 3.2). */
typedef CK_RV (*CK_C_Async32Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*CK_C_Async32Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*CK_C_Async32OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags,
                                         void *pApplication, CK_NOTIFY Notify,
                                         CK_SESSION_HANDLE *phSession);
typedef CK_RV (*CK_C_Async32CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_Async32SignInit)(CK_SESSION_HANDLE hSession,
                                      CK_MECHANISM *pMechanism,
                                      CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Async32Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                                  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                                  CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_Async32Complete)(CK_SESSION_HANDLE hSession,
                                      CK_UTF8CHAR *pFunctionName,
                                      CK_ASYNC_DATA *pResult);
typedef CK_RV (*CK_C_Async32GetID)(CK_SESSION_HANDLE hSession,
                                   CK_UTF8CHAR *pFunctionName,
                                   CK_ULONG *pulID);
typedef CK_RV (*CK_C_Async32Join)(CK_SESSION_HANDLE hSession,
                                  CK_UTF8CHAR *pFunctionName, CK_ULONG id,
                                  CK_BYTE_PTR pReserved, CK_ULONG ulReserved);
/* Placeholder for the 95 unimplemented entries; never called. */
typedef CK_RV (*CK_C_Async32Unimplemented)(void);

/* Canonical catalog order, ordinals 0-103. One line per ordinal; the
 * async controls are at 99-101. Keep in sync with the observer's
 * function catalog (68 base + 24 v3.0 + 12 v3.2). */
#define ASYNC32_FUNCTIONS(X)                                                   \
    X(0, C_Initialize, CK_C_Async32Initialize)                                 \
    X(1, C_Finalize, CK_C_Async32Finalize)                                     \
    X(2, C_GetInfo, CK_C_Async32Unimplemented)                                 \
    X(3, C_GetFunctionList, CK_C_Async32Unimplemented)                         \
    X(4, C_GetSlotList, CK_C_Async32Unimplemented)                             \
    X(5, C_GetSlotInfo, CK_C_Async32Unimplemented)                             \
    X(6, C_GetTokenInfo, CK_C_Async32Unimplemented)                            \
    X(7, C_GetMechanismList, CK_C_Async32Unimplemented)                        \
    X(8, C_GetMechanismInfo, CK_C_Async32Unimplemented)                        \
    X(9, C_InitToken, CK_C_Async32Unimplemented)                               \
    X(10, C_InitPIN, CK_C_Async32Unimplemented)                                \
    X(11, C_SetPIN, CK_C_Async32Unimplemented)                                 \
    X(12, C_OpenSession, CK_C_Async32OpenSession)                              \
    X(13, C_CloseSession, CK_C_Async32CloseSession)                            \
    X(14, C_CloseAllSessions, CK_C_Async32Unimplemented)                       \
    X(15, C_GetSessionInfo, CK_C_Async32Unimplemented)                         \
    X(16, C_GetOperationState, CK_C_Async32Unimplemented)                      \
    X(17, C_SetOperationState, CK_C_Async32Unimplemented)                      \
    X(18, C_Login, CK_C_Async32Unimplemented)                                  \
    X(19, C_Logout, CK_C_Async32Unimplemented)                                 \
    X(20, C_CreateObject, CK_C_Async32Unimplemented)                           \
    X(21, C_CopyObject, CK_C_Async32Unimplemented)                             \
    X(22, C_DestroyObject, CK_C_Async32Unimplemented)                          \
    X(23, C_GetObjectSize, CK_C_Async32Unimplemented)                          \
    X(24, C_GetAttributeValue, CK_C_Async32Unimplemented)                      \
    X(25, C_SetAttributeValue, CK_C_Async32Unimplemented)                      \
    X(26, C_FindObjectsInit, CK_C_Async32Unimplemented)                        \
    X(27, C_FindObjects, CK_C_Async32Unimplemented)                            \
    X(28, C_FindObjectsFinal, CK_C_Async32Unimplemented)                       \
    X(29, C_EncryptInit, CK_C_Async32Unimplemented)                            \
    X(30, C_Encrypt, CK_C_Async32Unimplemented)                                \
    X(31, C_EncryptUpdate, CK_C_Async32Unimplemented)                          \
    X(32, C_EncryptFinal, CK_C_Async32Unimplemented)                           \
    X(33, C_DecryptInit, CK_C_Async32Unimplemented)                            \
    X(34, C_Decrypt, CK_C_Async32Unimplemented)                                \
    X(35, C_DecryptUpdate, CK_C_Async32Unimplemented)                          \
    X(36, C_DecryptFinal, CK_C_Async32Unimplemented)                           \
    X(37, C_DigestInit, CK_C_Async32Unimplemented)                             \
    X(38, C_Digest, CK_C_Async32Unimplemented)                                 \
    X(39, C_DigestUpdate, CK_C_Async32Unimplemented)                           \
    X(40, C_DigestKey, CK_C_Async32Unimplemented)                              \
    X(41, C_DigestFinal, CK_C_Async32Unimplemented)                            \
    X(42, C_SignInit, CK_C_Async32SignInit)                                    \
    X(43, C_Sign, CK_C_Async32Sign)                                            \
    X(44, C_SignUpdate, CK_C_Async32Unimplemented)                             \
    X(45, C_SignFinal, CK_C_Async32Unimplemented)                              \
    X(46, C_SignRecoverInit, CK_C_Async32Unimplemented)                        \
    X(47, C_SignRecover, CK_C_Async32Unimplemented)                            \
    X(48, C_VerifyInit, CK_C_Async32Unimplemented)                             \
    X(49, C_Verify, CK_C_Async32Unimplemented)                                 \
    X(50, C_VerifyUpdate, CK_C_Async32Unimplemented)                           \
    X(51, C_VerifyFinal, CK_C_Async32Unimplemented)                            \
    X(52, C_VerifyRecoverInit, CK_C_Async32Unimplemented)                      \
    X(53, C_VerifyRecover, CK_C_Async32Unimplemented)                          \
    X(54, C_DigestEncryptUpdate, CK_C_Async32Unimplemented)                    \
    X(55, C_DecryptDigestUpdate, CK_C_Async32Unimplemented)                    \
    X(56, C_SignEncryptUpdate, CK_C_Async32Unimplemented)                      \
    X(57, C_DecryptVerifyUpdate, CK_C_Async32Unimplemented)                    \
    X(58, C_GenerateKey, CK_C_Async32Unimplemented)                            \
    X(59, C_GenerateKeyPair, CK_C_Async32Unimplemented)                        \
    X(60, C_WrapKey, CK_C_Async32Unimplemented)                                \
    X(61, C_UnwrapKey, CK_C_Async32Unimplemented)                              \
    X(62, C_DeriveKey, CK_C_Async32Unimplemented)                              \
    X(63, C_SeedRandom, CK_C_Async32Unimplemented)                             \
    X(64, C_GenerateRandom, CK_C_Async32Unimplemented)                         \
    X(65, C_GetFunctionStatus, CK_C_Async32Unimplemented)                      \
    X(66, C_CancelFunction, CK_C_Async32Unimplemented)                         \
    X(67, C_WaitForSlotEvent, CK_C_Async32Unimplemented)                       \
    X(68, C_GetInterfaceList, CK_C_Async32Unimplemented)                       \
    X(69, C_GetInterface, CK_C_Async32Unimplemented)                           \
    X(70, C_LoginUser, CK_C_Async32Unimplemented)                              \
    X(71, C_SessionCancel, CK_C_Async32Unimplemented)                          \
    X(72, C_MessageEncryptInit, CK_C_Async32Unimplemented)                     \
    X(73, C_EncryptMessage, CK_C_Async32Unimplemented)                         \
    X(74, C_EncryptMessageBegin, CK_C_Async32Unimplemented)                    \
    X(75, C_EncryptMessageNext, CK_C_Async32Unimplemented)                     \
    X(76, C_MessageEncryptFinal, CK_C_Async32Unimplemented)                    \
    X(77, C_MessageDecryptInit, CK_C_Async32Unimplemented)                     \
    X(78, C_DecryptMessage, CK_C_Async32Unimplemented)                         \
    X(79, C_DecryptMessageBegin, CK_C_Async32Unimplemented)                    \
    X(80, C_DecryptMessageNext, CK_C_Async32Unimplemented)                     \
    X(81, C_MessageDecryptFinal, CK_C_Async32Unimplemented)                    \
    X(82, C_MessageSignInit, CK_C_Async32Unimplemented)                        \
    X(83, C_SignMessage, CK_C_Async32Unimplemented)                            \
    X(84, C_SignMessageBegin, CK_C_Async32Unimplemented)                       \
    X(85, C_SignMessageNext, CK_C_Async32Unimplemented)                        \
    X(86, C_MessageSignFinal, CK_C_Async32Unimplemented)                       \
    X(87, C_MessageVerifyInit, CK_C_Async32Unimplemented)                      \
    X(88, C_VerifyMessage, CK_C_Async32Unimplemented)                          \
    X(89, C_VerifyMessageBegin, CK_C_Async32Unimplemented)                     \
    X(90, C_VerifyMessageNext, CK_C_Async32Unimplemented)                      \
    X(91, C_MessageVerifyFinal, CK_C_Async32Unimplemented)                     \
    X(92, C_EncapsulateKey, CK_C_Async32Unimplemented)                         \
    X(93, C_DecapsulateKey, CK_C_Async32Unimplemented)                         \
    X(94, C_VerifySignatureInit, CK_C_Async32Unimplemented)                    \
    X(95, C_VerifySignature, CK_C_Async32Unimplemented)                        \
    X(96, C_VerifySignatureUpdate, CK_C_Async32Unimplemented)                  \
    X(97, C_VerifySignatureFinal, CK_C_Async32Unimplemented)                   \
    X(98, C_GetSessionValidationFlags, CK_C_Async32Unimplemented)              \
    X(99, C_AsyncComplete, CK_C_Async32Complete)                               \
    X(100, C_AsyncGetID, CK_C_Async32GetID)                                    \
    X(101, C_AsyncJoin, CK_C_Async32Join)                                      \
    X(102, C_WrapKeyAuthenticated, CK_C_Async32Unimplemented)                  \
    X(103, C_UnwrapKeyAuthenticated, CK_C_Async32Unimplemented)

#define ASYNC32_FIELD(ord, name, type) type name;
typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
    CK_BYTE reserved[6];
    ASYNC32_FUNCTIONS(ASYNC32_FIELD)
} Async32FunctionList;
#undef ASYNC32_FIELD

#define ASYNC32_TABLE_SLOTS 104

#endif
