/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mt: N threads hammer C_GenerateRandom on SoftHSM2 for SECS seconds; prints exact total. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_FLAGS;
typedef struct { void *c,*d,*l,*u; CK_FLAGS flags; void *r; } INITARGS;
static void **fns; static CK_SLOT_ID slot;
static atomic_int go, stop, started, failed;
static unsigned long counts[256], attempts[256];
#define F(i,t) ((t)fns[i])
static int target(void *address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) return 1;
  char line[4096], perms[5]; unsigned long lo, hi, off, ino; unsigned int major, minor;
  uintptr_t ptr = (uintptr_t)address;
  while (fgets(line, sizeof line, maps)) {
    if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &lo, &hi, perms, &off, &major, &minor, &ino) == 7 &&
        ptr >= lo && ptr < hi && perms[2] == 'x' && ino) {
      printf("TARGET {\"name\":\"C_GenerateRandom\",\"dev\":[%u,%u],\"ino\":%lu,\"file_offset\":%lu}\n",
             major, minor, ino, (unsigned long)(ptr - lo) + off);
      fclose(maps); return 0;
    }
  }
  fclose(maps); return 1;
}
static void *worker(void *arg){ long id=(long)arg; CK_SESSION_HANDLE s; unsigned char b[16];
  if(F(12,CK_RV(*)(CK_SLOT_ID,CK_ULONG,void*,void*,CK_SESSION_HANDLE*))(slot,4|2,0,0,&s)){
    fprintf(stderr,"open fail\n"); atomic_store(&failed,1); atomic_fetch_add(&started,1); return 0;
  }
  atomic_fetch_add(&started,1);
  while(!atomic_load(&go)) usleep(1000);
  while(!atomic_load(&stop)){
    attempts[id]++;
    if(F(64,CK_RV(*)(CK_SESSION_HANDLE,unsigned char*,CK_ULONG))(s,b,sizeof b)==0) counts[id]++;
  }
  F(13,CK_RV(*)(CK_SESSION_HANDLE))(s); return 0; }
int main(int argc,char**argv){
  if(argc<4 || argc>6) return 2;
  int n=atoi(argv[2]); int secs=atoi(argv[3]); int pre=argc>4?atoi(argv[4]):5; const char*gate=argc>5?argv[5]:0;
  if(n<1 || n>256 || secs<1 || pre<0) return 2;
  void*h=dlopen(argv[1],RTLD_NOW); if(!h) return 1;
  unsigned long(*g)(void**)=dlsym(h,"C_GetFunctionList"); void*l=0;
  if(!g || g(&l) || !l) return 1;
  fns=(void**)((char*)l+8);
  INITARGS a={0}; a.flags=2; if(F(0,CK_RV(*)(void*))(&a)){fprintf(stderr,"init\n");return 1;}
  CK_SLOT_ID sl[8]; CK_ULONG ns=8;
  if(F(4,CK_RV(*)(unsigned char,CK_SLOT_ID*,CK_ULONG*))(1,sl,&ns) || !ns) return 1;
  slot=sl[0]; if(target(fns[64])) return 1;
  pthread_t t[256]; for(long i=0;i<n;i++) if(pthread_create(&t[i],0,worker,(void*)i)) return 1;
  while(atomic_load(&started)<n) usleep(1000);
  if(atomic_load(&failed)) return 1;
  printf("READY pid=%d\n",getpid()); fflush(stdout);
  if(gate){ while(access(gate,F_OK)!=0) usleep(10000); } else sleep(pre);
  atomic_store(&go,1); sleep(secs); atomic_store(&stop,1);
  unsigned long tot=0, entered=0;
  for(int i=0;i<n;i++){pthread_join(t[i],0); tot+=counts[i]; entered+=attempts[i];}
  F(1,CK_RV(*)(void*))(0);
  printf("LEDGER {\"schema\":\"p11scope/public-cli-ledger/v1\",\"pid\":%d,\"complete\":true,\"functions\":[{\"name\":\"C_GenerateRandom\",\"attempts\":%lu,\"successful\":%lu}]}\n",getpid(),entered,tot);
  fflush(stdout); return entered==tot ? 0 : 1;
}
