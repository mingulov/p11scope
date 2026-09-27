/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mt: N threads hammer C_GenerateRandom on SoftHSM2 for SECS seconds; prints exact total. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_FLAGS;
typedef struct { void *c,*d,*l,*u; CK_FLAGS flags; void *r; } INITARGS;
static void **fns; static CK_SLOT_ID slot; static volatile int go, stop; static unsigned long counts[256];
#define F(i,t) ((t)fns[i])
static void *worker(void *arg){ long id=(long)arg; CK_SESSION_HANDLE s; unsigned char b[16];
  if(F(12,CK_RV(*)(CK_SLOT_ID,CK_ULONG,void*,void*,CK_SESSION_HANDLE*))(slot,4|2,0,0,&s)){fprintf(stderr,"open fail\n");return 0;}
  while(!go) ; while(!stop){ if(F(64,CK_RV(*)(CK_SESSION_HANDLE,unsigned char*,CK_ULONG))(s,b,sizeof b)==0) counts[id]++; }
  F(13,CK_RV(*)(CK_SESSION_HANDLE))(s); return 0; }
int main(int argc,char**argv){ int n=atoi(argv[2]); int secs=atoi(argv[3]); int pre=argc>4?atoi(argv[4]):5; const char*gate=argc>5?argv[5]:0;
  void*h=dlopen(argv[1],RTLD_NOW); unsigned long(*g)(void**)=dlsym(h,"C_GetFunctionList"); void*l; g(&l); fns=(void**)((char*)l+8);
  INITARGS a={0}; a.flags=2; if(F(0,CK_RV(*)(void*))(&a)){fprintf(stderr,"init\n");return 1;}
  CK_SLOT_ID sl[8]; CK_ULONG ns=8; F(4,CK_RV(*)(unsigned char,CK_SLOT_ID*,CK_ULONG*))(1,sl,&ns); slot=sl[0];
  pthread_t t[256]; for(long i=0;i<n;i++) pthread_create(&t[i],0,worker,(void*)i);
  printf("READY pid=%d\n",getpid()); fflush(stdout); if(gate){ while(access(gate,F_OK)!=0) usleep(10000); } else sleep(pre); go=1; sleep(secs); stop=1;
  unsigned long tot=0; for(int i=0;i<n;i++){pthread_join(t[i],0); tot+=counts[i];}
  F(1,CK_RV(*)(void*))(0); printf("TOTAL C_GenerateRandom=%lu threads=%d\n",tot,n); return 0; }
