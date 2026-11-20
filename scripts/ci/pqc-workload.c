/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* PQC CI cell workload: ML-DSA-44/65/87 + ML-KEM-512/768/1024 keygen and
 * single use against a PQC-capable provider (kryoptic), with exact known
 * counts for the observer to attribute.
 *
 *   pqc-workload --module P --ready F --go G [--pin P] [--slot N]
 *                  [--post-sleep S] [--pace S] [--settle S]
 * The user PIN comes from --pin, else $P11TEST_PIN, else the default
 * throwaway 1234.
 *
 * Sequence: dlopen the provider first (mapped, but zero PKCS#11 calls),
 * write READY so the observer attaches to the already-mapped provider,
 * wait for the GO file, then initialize and run every operation. No
 * PKCS#11 call happens before GO, so an observer started after READY
 * sees the whole stream; mapping before the observer is required (Joint
 * births pre-existing processes attach-observed at the cut, and a
 * provider that first maps after observer start loses entry capture —
 * the prearm/late-dlopen gap). --settle S sleeps S seconds after login
 * before the first operation, giving the observer's semantic lane time
 * to admit the watched provider. Each set is generated once and used
 * once (DSA: sign + verify; KEM: encapsulate + decapsulate); keys are
 * destroyed after use. Ground truth, observed lengths and the exit
 * verdict print on stdout:
 *
 *   GROUND_TRUTH mldsa_gen=3 mldsa_sign=3 mldsa_verify=3
 *                mlkem_gen=3 mlkem_enc=3 mlkem_dec=3
 *   LENGTHS mldsa44=2420 mldsa65=3309 mldsa87=4627
 *           mlkem512=768 mlkem768=1088 mlkem1024=1568
 *   WORKLOAD_EXIT ok=1
 *
 * Exit 0 only when every count above holds exactly. Buffers are sized
 * for the largest set, so no NULL length probe (which the observer
 * would count as a role-unavailable call) is needed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned long CK_ATTRIBUTE_TYPE;
typedef unsigned long CK_KEY_TYPE;
typedef unsigned long CK_OBJECT_CLASS;
typedef unsigned char CK_BBOOL;
typedef unsigned char CK_BYTE;
typedef unsigned long CK_FLAGS;
struct CK_VERSION { unsigned char major, minor; };
struct CK_MECHANISM { CK_MECHANISM_TYPE mechanism; void *pParameter; CK_ULONG ulParameterLen; };
struct CK_ATTRIBUTE { CK_ATTRIBUTE_TYPE type; void *pValue; CK_ULONG ulValueLen; };
struct CK_FUNCTION_LIST {
  struct CK_VERSION version;
  CK_RV (*C_Initialize)(void*);
  CK_RV (*C_Finalize)(void*);
  CK_RV (*C_GetInfo)(void*);
  CK_RV (*C_GetFunctionList)(void*);
  CK_RV (*C_GetSlotList)(unsigned char, CK_SLOT_ID*, CK_ULONG*);
  CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, void*);
  CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, void*);
  CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE*, CK_ULONG*);
  CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, void*);
  CK_RV (*C_InitToken)(CK_SLOT_ID, unsigned char*, CK_ULONG, unsigned char*);
  CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG);
  CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG);
  CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
  CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
  CK_RV (*C_CloseAllSessions)(CK_SLOT_ID);
  CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE, void*);
  CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG*);
  CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
  CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, unsigned char*, CK_ULONG);
  CK_RV (*C_Logout)(CK_SESSION_HANDLE);
  CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, struct CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
  CK_RV (*C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, struct CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
  CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
  CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG*);
  CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, struct CK_ATTRIBUTE*, CK_ULONG);
  CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, struct CK_ATTRIBUTE*, CK_ULONG);
  CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, struct CK_ATTRIBUTE*, CK_ULONG);
  CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
  CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
  CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE);
  CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG*);
  CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE);
  CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG*);
  CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, struct CK_MECHANISM*);
  CK_RV (*C_Digest)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG);
  CK_RV (*C_DigestKey)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
  CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG*);
  CK_RV (*C_SignInit)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE);
  CK_RV (*C_Sign)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG);
  CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG*);
  CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE);
  CK_RV (*C_SignRecover)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE);
  CK_RV (*C_Verify)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG);
  CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG);
  CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG);
  CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE);
  CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_DigestEncryptUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_DecryptDigestUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_SignEncryptUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_DecryptVerifyUpdate)(CK_SESSION_HANDLE, unsigned char*, CK_ULONG, unsigned char*, CK_ULONG*);
  CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, struct CK_MECHANISM*, struct CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
  CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, struct CK_MECHANISM*, struct CK_ATTRIBUTE*, CK_ULONG, struct CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
  CK_RV (*C_WrapKey)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, unsigned char*, CK_ULONG*);
  CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE, unsigned char*, CK_ULONG, struct CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
  CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE, struct CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
};
struct CK_INTERFACE { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; };
typedef CK_RV (*C_GetFunctionList_t)(struct CK_FUNCTION_LIST**);
typedef CK_RV (*C_GetInterfaceList_t)(struct CK_INTERFACE*, CK_ULONG*);
typedef CK_RV (*C_EncapsulateKey_t)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE, struct CK_ATTRIBUTE*, CK_ULONG, CK_BYTE*, CK_ULONG*, CK_OBJECT_HANDLE*);
typedef CK_RV (*C_DecapsulateKey_t)(CK_SESSION_HANDLE, struct CK_MECHANISM*, CK_OBJECT_HANDLE, struct CK_ATTRIBUTE*, CK_ULONG, CK_BYTE*, CK_ULONG, CK_OBJECT_HANDLE*);

#define CKR_OK 0
#define CKF_SERIAL_SESSION 0x04
#define CKF_RW_SESSION 0x02
#define CKU_USER 1
#define CKO_PUBLIC_KEY 2
#define CKO_PRIVATE_KEY 3
#define CKO_SECRET_KEY 4
#define CKK_GENERIC_SECRET 16
#define CKK_ML_KEM 73
#define CKK_ML_DSA 74
#define CKA_CLASS 0
#define CKA_TOKEN 1
#define CKA_PRIVATE 2
#define CKA_LABEL 3
#define CKA_KEY_TYPE 256
#define CKA_SENSITIVE 259
#define CKA_SIGN 264
#define CKA_VERIFY 266
#define CKA_VALUE_LEN 353
#define CKA_EXTRACTABLE 354
#define CKA_PARAMETER_SET 1565
#define CKA_ENCAPSULATE 1587
#define CKA_DECAPSULATE 1588
#define CKM_ML_KEM_KEY_PAIR_GEN 15
#define CKM_ML_KEM 23
#define CKM_ML_DSA_KEY_PAIR_GEN 28
#define CKM_ML_DSA 29

static const char* rv_name(CK_RV rv){
  switch(rv){
    case 0: return "OK";
    case 0x05: return "GENERAL_ERROR";
    case 0x06: return "FUNCTION_FAILED";
    case 0x07: return "ARGUMENTS_BAD";
    case 0x30: return "MECHANISM_INVALID";
    case 0x31: return "KEY_TYPE_INCONSISTENT";
    case 0x70: return "TEMPLATE_INCOMPLETE";
    case 0x71: return "TEMPLATE_INCONSISTENT";
    case 0x82: return "ATTRIBUTE_VALUE_INVALID";
    case 0x12: return "USER_NOT_LOGGED_IN";
    case 0x101: return "PIN_INCORRECT";
    case 0xA0: return "SIGNATURE_INVALID";
    case 0xB3: return "BUFFER_TOO_SMALL";
    default: return "?";
  }
}
int main(int argc, char**argv){
  const char* module=NULL; const char* ready=NULL; const char* go=NULL; const char* pin=NULL;
  long slot_arg=-1; int post_sleep=5; int pace=1; int settle=0;
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"--module")&&i+1<argc) module=argv[++i];
    else if(!strcmp(argv[i],"--ready")&&i+1<argc) ready=argv[++i];
    else if(!strcmp(argv[i],"--go")&&i+1<argc) go=argv[++i];
    else if(!strcmp(argv[i],"--pin")&&i+1<argc) pin=argv[++i];
    else if(!strcmp(argv[i],"--slot")&&i+1<argc) slot_arg=atol(argv[++i]);
    else if(!strcmp(argv[i],"--post-sleep")&&i+1<argc) post_sleep=atoi(argv[++i]);
    else if(!strcmp(argv[i],"--pace")&&i+1<argc) pace=atoi(argv[++i]);
    else if(!strcmp(argv[i],"--settle")&&i+1<argc) settle=atoi(argv[++i]);
    else {fprintf(stderr,"usage: %s --module P --ready F --go G [--pin P] [--slot N] [--post-sleep S] [--pace S] [--settle S]\n",argv[0]); return 2;}
  }
  if(!module||!ready||!go){fprintf(stderr,"need --module, --ready and --go\n"); return 2;}
  if(!pin) pin=getenv("P11TEST_PIN");
  if(!pin||!*pin) pin="1234";
  if(pace<0) pace=0;
  if(post_sleep<0) post_sleep=0;
  if(settle<0) settle=0;
  void*h=dlopen(module,RTLD_NOW);
  if(!h){fprintf(stderr,"dlopen %s: %s\n",module,dlerror()); return 1;}
  printf("MAPPED %s\n",module); fflush(stdout);
  FILE*f=fopen(ready,"w"); if(f){fprintf(f,"%lu\n",(unsigned long)getpid()); fclose(f);}
  printf("READY %s waiting for %s\n",ready,go); fflush(stdout);
  for(int waited=0;waited<600;waited++){
    if(access(go,R_OK)==0) break;
    sleep(1);
    if(waited==599){fprintf(stderr,"GO file never appeared: %s\n",go); return 1;}
  }
  printf("GO\n"); fflush(stdout);
  C_GetFunctionList_t g=(C_GetFunctionList_t)dlsym(h,"C_GetFunctionList");
  if(!g){fprintf(stderr,"no C_GetFunctionList\n"); return 1;}
  struct CK_FUNCTION_LIST*fl=NULL;
  CK_RV rv=g(&fl);
  if(rv!=0||!fl){fprintf(stderr,"C_GetFunctionList rv=0x%lx\n",(unsigned long)rv); return 1;}
  printf("function-list version %u.%u\n",fl->version.major,fl->version.minor);
  C_EncapsulateKey_t pEnc=NULL; C_DecapsulateKey_t pDec=NULL;
  C_GetInterfaceList_t gil=(C_GetInterfaceList_t)dlsym(h,"C_GetInterfaceList");
  if(gil){
    CK_ULONG n=0; rv=gil(NULL,&n);
    if(rv==0&&n>0){
      struct CK_INTERFACE*ifs=calloc(n,sizeof(*ifs));
      rv=gil(ifs,&n);
      void*best=NULL;
      for(CK_ULONG i=0;i<n&&rv==0;i++){
        if(!ifs[i].pFunctionList) continue;
        unsigned char*maj=(unsigned char*)ifs[i].pFunctionList;
        if(maj[0]==3&&maj[1]==2){best=ifs[i].pFunctionList; break;}
      }
      if(!best) for(CK_ULONG i=0;i<n&&rv==0;i++){
        if(!ifs[i].pFunctionList) continue;
        unsigned char*maj=(unsigned char*)ifs[i].pFunctionList;
        if(maj[0]==3&&(maj[1]==1||maj[1]==0)) best=ifs[i].pFunctionList;
      }
      if(best){
        void*p1=*(void**)((char*)best + 8 + 92*8);
        void*p2=*(void**)((char*)best + 8 + 93*8);
        if(p1&&p2){pEnc=(C_EncapsulateKey_t)p1; pDec=(C_DecapsulateKey_t)p2;}
      }
      free(ifs);
    }
  } else printf("no C_GetInterfaceList (KEM unavailable)\n");
  if(!pEnc||!pDec){fprintf(stderr,"Encapsulate/Decapsulate unavailable\n"); return 1;}
  rv=fl->C_Initialize(NULL);
  printf("C_Initialize rv=0x%lx %s\n",(unsigned long)rv,rv_name(rv));
  if(rv!=0) return 1;
  CK_ULONG scount=0; rv=fl->C_GetSlotList(1,NULL,&scount);
  if(rv!=0||scount==0){fprintf(stderr,"no token slots rv=0x%lx n=%lu\n",(unsigned long)rv,(unsigned long)scount); return 1;}
  CK_SLOT_ID*slots=malloc(scount*sizeof(*slots));
  fl->C_GetSlotList(1,slots,&scount);
  CK_SLOT_ID slot=slots[0];
  if(slot_arg>=0) slot=(CK_SLOT_ID)slot_arg;
  printf("using slot %lu\n",(unsigned long)slot);
  free(slots);
  CK_SESSION_HANDLE sess=0;
  rv=fl->C_OpenSession(slot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&sess);
  printf("C_OpenSession rv=0x%lx %s sess=%lu\n",(unsigned long)rv,rv_name(rv),(unsigned long)sess);
  if(rv!=0) return 1;
  rv=fl->C_Login(sess,CKU_USER,(unsigned char*)pin,strlen(pin));
  printf("C_Login rv=0x%lx %s\n",(unsigned long)rv,rv_name(rv));
  if(rv!=0) return 1;
  if(settle>0){printf("SETTLE %ds\n",settle); fflush(stdout);}
  for(int i=0;i<settle;i++) sleep(1);
  int mldsa_gen=0,mldsa_sign=0,mldsa_verify=0;
  int mlkem_gen=0,mlkem_enc=0,mlkem_dec=0;
  long mldsa_siglen[4]={0,0,0,0}; long mlkem_ctlen[4]={0,0,0,0};
  unsigned char msg[32]; for(int i=0;i<32;i++) msg[i]=(unsigned char)(0x41+i);
  const char* mldsa_names[4]={NULL,"ML-DSA-44","ML-DSA-65","ML-DSA-87"};
  const char* mlkem_names[4]={NULL,"ML-KEM-512","ML-KEM-768","ML-KEM-1024"};
  for(int set=1;set<=3;set++){
    /* Every attribute value below lives in its own variable: the
     * observer refuses template values whose spans alias another
     * attribute's span (same or peer template), so sharing one
     * &kt/&btrue across the two halves would leave every row
     * type-unknown by design. */
    CK_OBJECT_CLASS pub_class=CKO_PUBLIC_KEY, priv_class=CKO_PRIVATE_KEY;
    CK_KEY_TYPE kt_pub=CKK_ML_DSA, kt_priv=CKK_ML_DSA;
    CK_ULONG ps_pub=(CK_ULONG)set, ps_priv=(CK_ULONG)set;
    CK_BBOOL tok_pub=0, tok_priv=0;
    CK_BBOOL b_verify=1, b_private=1, b_sensitive=1, b_sign=1;
    char label[64]; snprintf(label,sizeof label,"pqc-mldsa-%d",set);
    struct CK_ATTRIBUTE pubT[]={
      {CKA_CLASS,&pub_class,sizeof pub_class},
      {CKA_KEY_TYPE,&kt_pub,sizeof kt_pub},
      {CKA_PARAMETER_SET,&ps_pub,sizeof ps_pub},
      {CKA_TOKEN,&tok_pub,sizeof tok_pub},
      {CKA_VERIFY,&b_verify,sizeof b_verify},
      {CKA_LABEL,label,strlen(label)},
    };
    struct CK_ATTRIBUTE privT[]={
      {CKA_CLASS,&priv_class,sizeof priv_class},
      {CKA_KEY_TYPE,&kt_priv,sizeof kt_priv},
      {CKA_PARAMETER_SET,&ps_priv,sizeof ps_priv},
      {CKA_TOKEN,&tok_priv,sizeof tok_priv},
      {CKA_PRIVATE,&b_private,sizeof b_private},
      {CKA_SENSITIVE,&b_sensitive,sizeof b_sensitive},
      {CKA_SIGN,&b_sign,sizeof b_sign},
      {CKA_LABEL,label,strlen(label)},
    };
    struct CK_MECHANISM gen={CKM_ML_DSA_KEY_PAIR_GEN,NULL,0};
    CK_OBJECT_HANDLE pub=0,priv=0;
    rv=fl->C_GenerateKeyPair(sess,&gen,pubT,6,privT,8,&pub,&priv);
    printf("GEN %s rv=0x%lx %s pub=%lu priv=%lu\n",mldsa_names[set],(unsigned long)rv,rv_name(rv),(unsigned long)pub,(unsigned long)priv);
    if(rv!=0) continue;
    mldsa_gen++;
    struct CK_MECHANISM mech={CKM_ML_DSA,NULL,0};
    rv=fl->C_SignInit(sess,&mech,priv);
    if(rv!=0){printf("  SIGNINIT %s rv=0x%lx %s\n",mldsa_names[set],(unsigned long)rv,rv_name(rv)); continue;}
    unsigned char sig[5000]; CK_ULONG sl=sizeof sig;
    rv=fl->C_Sign(sess,msg,sizeof msg,sig,&sl);
    printf("  SIGN %s rv=0x%lx %s len=%lu\n",mldsa_names[set],(unsigned long)rv,rv_name(rv),(unsigned long)sl);
    if(rv!=0) continue;
    mldsa_sign++; mldsa_siglen[set]=(long)sl;
    rv=fl->C_VerifyInit(sess,&mech,pub);
    if(rv!=0){printf("  VERIFYINIT %s rv=0x%lx %s\n",mldsa_names[set],(unsigned long)rv,rv_name(rv)); continue;}
    rv=fl->C_Verify(sess,msg,sizeof msg,sig,sl);
    printf("  VERIFY %s rv=0x%lx %s\n",mldsa_names[set],(unsigned long)rv,rv_name(rv));
    if(rv==0) mldsa_verify++;
    fl->C_DestroyObject(sess,pub); fl->C_DestroyObject(sess,priv);
    for(int i=0;i<pace;i++) sleep(1);
  }
  for(int set=1;set<=3;set++){
    /* Unshared value variables (see above): aliased template spans
     * are refused by design. */
    CK_OBJECT_CLASS pub_class=CKO_PUBLIC_KEY, priv_class=CKO_PRIVATE_KEY;
    CK_KEY_TYPE kt_pub=CKK_ML_KEM, kt_priv=CKK_ML_KEM;
    CK_ULONG ps_pub=(CK_ULONG)set, ps_priv=(CK_ULONG)set;
    CK_BBOOL tok_pub=0, tok_priv=0;
    CK_BBOOL b_enc=1, b_private=1, b_sensitive=1, b_dec=1;
    char label[64]; snprintf(label,sizeof label,"pqc-mlkem-%d",set);
    struct CK_ATTRIBUTE pubT[]={
      {CKA_CLASS,&pub_class,sizeof pub_class},
      {CKA_KEY_TYPE,&kt_pub,sizeof kt_pub},
      {CKA_PARAMETER_SET,&ps_pub,sizeof ps_pub},
      {CKA_TOKEN,&tok_pub,sizeof tok_pub},
      {CKA_ENCAPSULATE,&b_enc,sizeof b_enc},
      {CKA_LABEL,label,strlen(label)},
    };
    struct CK_ATTRIBUTE privT[]={
      {CKA_CLASS,&priv_class,sizeof priv_class},
      {CKA_KEY_TYPE,&kt_priv,sizeof kt_priv},
      {CKA_PARAMETER_SET,&ps_priv,sizeof ps_priv},
      {CKA_TOKEN,&tok_priv,sizeof tok_priv},
      {CKA_PRIVATE,&b_private,sizeof b_private},
      {CKA_SENSITIVE,&b_sensitive,sizeof b_sensitive},
      {CKA_DECAPSULATE,&b_dec,sizeof b_dec},
      {CKA_LABEL,label,strlen(label)},
    };
    struct CK_MECHANISM gen={CKM_ML_KEM_KEY_PAIR_GEN,NULL,0};
    CK_OBJECT_HANDLE pub=0,priv=0;
    rv=fl->C_GenerateKeyPair(sess,&gen,pubT,6,privT,8,&pub,&priv);
    printf("GEN %s rv=0x%lx %s pub=%lu priv=%lu\n",mlkem_names[set],(unsigned long)rv,rv_name(rv),(unsigned long)pub,(unsigned long)priv);
    if(rv!=0) continue;
    mlkem_gen++;
    struct CK_MECHANISM mech={CKM_ML_KEM,NULL,0};
    CK_OBJECT_CLASS sec_class=CKO_SECRET_KEY; CK_KEY_TYPE sec_kt=CKK_GENERIC_SECRET; CK_ULONG sec_len=32;
    CK_BBOOL shr_tok=0, shr_sens=0, shr_ext=1;
    struct CK_ATTRIBUTE shrT[]={
      {CKA_CLASS,&sec_class,sizeof sec_class},
      {CKA_KEY_TYPE,&sec_kt,sizeof sec_kt},
      {CKA_TOKEN,&shr_tok,sizeof shr_tok},
      {CKA_SENSITIVE,&shr_sens,sizeof shr_sens},
      {CKA_EXTRACTABLE,&shr_ext,sizeof shr_ext},
      {CKA_VALUE_LEN,&sec_len,sizeof sec_len},
    };
    CK_BYTE ct[1600]; CK_ULONG ctlen=sizeof ct; CK_OBJECT_HANDLE shr1=0;
    rv=pEnc(sess,&mech,pub,shrT,6,ct,&ctlen,&shr1);
    printf("  ENCAPS %s rv=0x%lx %s ctlen=%lu shr=%lu\n",mlkem_names[set],(unsigned long)rv,rv_name(rv),(unsigned long)ctlen,(unsigned long)shr1);
    if(rv!=0) continue;
    mlkem_enc++; mlkem_ctlen[set]=(long)ctlen;
    CK_OBJECT_HANDLE shr2=0;
    rv=pDec(sess,&mech,priv,shrT,6,ct,ctlen,&shr2);
    printf("  DECAPS %s rv=0x%lx %s shr=%lu\n",mlkem_names[set],(unsigned long)rv,rv_name(rv),(unsigned long)shr2);
    if(rv==0) mlkem_dec++;
    if(shr1) fl->C_DestroyObject(sess,shr1);
    if(shr2) fl->C_DestroyObject(sess,shr2);
    fl->C_DestroyObject(sess,pub); fl->C_DestroyObject(sess,priv);
    for(int i=0;i<pace;i++) sleep(1);
  }
  printf("GROUND_TRUTH mldsa_gen=%d mldsa_sign=%d mldsa_verify=%d mlkem_gen=%d mlkem_enc=%d mlkem_dec=%d\n",mldsa_gen,mldsa_sign,mldsa_verify,mlkem_gen,mlkem_enc,mlkem_dec);
  printf("LENGTHS mldsa44=%ld mldsa65=%ld mldsa87=%ld mlkem512=%ld mlkem768=%ld mlkem1024=%ld\n",mldsa_siglen[1],mldsa_siglen[2],mldsa_siglen[3],mlkem_ctlen[1],mlkem_ctlen[2],mlkem_ctlen[3]);
  fflush(stdout);
  printf("POST-SLEEP %ds\n",post_sleep); fflush(stdout);
  for(int i=0;i<post_sleep;i++) sleep(1);
  fl->C_Logout(sess); fl->C_CloseSession(sess); fl->C_Finalize(NULL);
  int ok=(mldsa_gen==3&&mldsa_sign==3&&mldsa_verify==3&&mlkem_gen==3&&mlkem_enc==3&&mlkem_dec==3);
  printf("WORKLOAD_EXIT ok=%d\n",ok);
  return ok?0:1;
}