/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned LP64 demotion fixture; build this source four times:
 * cc -std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC -DDEMOTION_COMMON \
 *    demotion-ledger.c -o libdemotion-common.so
 * cc ... -shared -fPIC -DDEMOTION_PROVIDER_A demotion-ledger.c \
 *    -LBUILD -ldemotion-common -Wl,-rpath,'$ORIGIN' -Wl,-z,defs -o provider-A.so
 * Repeat for DEMOTION_PROVIDER_B; workload: cc ... demotion-ledger.c -ldl -o workload.
 * usage: workload A B COMMON CONTROL_FIFO LEDGER NONCE DEADLINE_MS
 * CONTROL_FIFO must be an owned FIFO; keep its sole writer open until stop.
 * Newline commands, in order: ready, load-b, shared, unload-a, fence, proof, stop.
 * 'cancel' is accepted at every wait. Total deadline is 1..110000ms.
 * stdout JSON acknowledgements coordinate the external harness. In particular,
 * load-b must happen while that harness holds the observer between passes; shared
 * requires actual B admission, fence requires actual accepted original scan S,
 * proof requires actual selected fence/current proof. These commands establish
 * no observer facts and carry no observer clocks, counts or synthesized receipt.
 * The ledger contains only identity, actual selected call brackets, and terminal
 * acknowledgement. Every C_Initialize call, including errors, is one entry.
 * Provider tables contain only slot0 and their own slot3 root, with null holes.
 * Source-only execution proves topology, not discovery/attachment/count evidence.
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
typedef unsigned long CK_RV;
typedef CK_RV (*Initialize)(void *);
typedef CK_RV (*GetList)(void **);
typedef struct {
    unsigned char major, minor;
    void *slot[68];
} FunctionList;
_Static_assert(sizeof(void *) == 8 && sizeof(CK_RV) == 8, "LP64 fixture only");
_Static_assert(offsetof(FunctionList, slot) == 8, "CK_VERSION LP64 alignment");

#if (defined(DEMOTION_COMMON) + defined(DEMOTION_PROVIDER_A) + defined(DEMOTION_PROVIDER_B)) > 1
#error Select exactly one fixture library mode
#endif
#if defined(DEMOTION_COMMON)
/* The common ELF has no C_GetFunctionList or provider-table root. */
CK_RV demotion_initialize(void *arguments) {
    return arguments ? 7 : 0; /* CKR_ARGUMENTS_BAD / CKR_OK, both real returns */
}
#elif defined(DEMOTION_PROVIDER_A) || defined(DEMOTION_PROVIDER_B)
extern CK_RV demotion_initialize(void *);
CK_RV C_GetFunctionList(void **);
#ifdef DEMOTION_PROVIDER_A
const char demotion_provider_tag[] = "owned-provider-A";
#else
const char demotion_provider_tag[] = "owned-provider-B";
#endif
static FunctionList table = {
    .major = 2, .minor = 40,
    .slot = {[0] = (void *)demotion_initialize, [3] = (void *)C_GetFunctionList}
};
CK_RV C_GetFunctionList(void **out) {
    if (!out) return 7;
    *out = &table;
    return 0;
}
#else
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Small bounded SHA-256 implementation: digests are measured here, never supplied
 * by a controller. Fixed block/state buffers; no external process or dependency. */
typedef struct { uint32_t h[8]; uint64_t bytes; size_t used; unsigned char block[64]; } Sha;
static uint32_t ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static void sha_block(Sha *s) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t w[64];
    for (size_t i=0;i<16;i++) {
        const unsigned char *p=s->block+4*i;
        w[i]=(uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];
    }
    for (size_t i=16;i<64;i++) {
        uint32_t a=w[i-15],b=w[i-2];
        w[i]=w[i-16]+(ror(a,7)^ror(a,18)^(a>>3))+w[i-7]+(ror(b,17)^ror(b,19)^(b>>10));
    }
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for (size_t i=0;i<64;i++) {
        uint32_t t=h+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t u=(ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha_add(Sha *s,const unsigned char *p,size_t n) {
    s->bytes+=n;
    while(n) {
        size_t take=64-s->used;if(take>n)take=n;
        memcpy(s->block+s->used,p,take);s->used+=take;p+=take;n-=take;
        if(s->used==64){sha_block(s);s->used=0;}
    }
}
static void sha_finish(Sha *s,char hex[65]) {
    uint64_t bits=s->bytes*8;
    unsigned char one=0x80,zero=0;sha_add(s,&one,1);
    while(s->used!=56)sha_add(s,&zero,1);
    unsigned char length[8];for(size_t i=0;i<8;i++)length[7-i]=(unsigned char)(bits>>(8*i));
    sha_add(s,length,8);
    for(size_t i=0;i<8;i++)snprintf(hex+8*i,9,"%08" PRIx32,s->h[i]);
}

typedef struct { unsigned major,minor; uint64_t ino,offset; } Physical;
typedef struct { void *handle; FunctionList *table; Initialize call; Physical root,table_file,target; } Provider;
static volatile sig_atomic_t cancelled;
static int ledger=-1,control=-1;
static void *common_handle;
static Provider a,b;
static uint64_t deadline_ns,calls,ledger_bytes;
static unsigned ledger_lines;
static int identity_written,terminal_written;
static void on_signal(int sig) { (void)sig;cancelled=1; }
static int clock_ns(uint64_t *out) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0)return -1;
    if((uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec)/1000000000)return -1;
    *out=(uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;return 0;
}
static int alive(void) { uint64_t n;return !cancelled&&!clock_ns(&n)&&n<deadline_ns; }
static int write_all(int fd,const char *p,size_t n) {
    while(n){ssize_t k=write(fd,p,n);if(k<0&&errno==EINTR)continue;if(k<=0)return -1;p+=k;n-=(size_t)k;}return 0;
}
static int row(const char *fmt,...) {
    char buf[1024];va_list ap;va_start(ap,fmt);int n=vsnprintf(buf,sizeof buf,fmt,ap);va_end(ap);
    if(n<0||(size_t)n>=sizeof buf||ledger_lines>=256||ledger_bytes+(size_t)n+1>262144)return -1;
    buf[n++]='\n';if(write_all(ledger,buf,(size_t)n))return -1;
    ledger_lines++;ledger_bytes+=(size_t)n;return 0;
}
static int ack(const char *event) {
    return printf("{\"event\":\"%s\"}\n",event)<0||fflush(stdout)?-1:0;
}
static int same(Physical x,Physical y) { return x.major==y.major&&x.minor==y.minor&&x.ino==y.ino&&x.offset==y.offset; }
/* Identity comes from the actual VMA, including physical file offset. */
static int physical(void *address,int executable,Physical *out) {
    FILE *f=fopen("/proc/self/maps","r");if(!f)return -1;
    char line[4096],perm[5];unsigned long lo,hi,off,ino;unsigned ma,mi;int result=-1;
    while(fgets(line,sizeof line,f)) {
        if(!strchr(line,'\n'))break;
        if(sscanf(line,"%lx-%lx %4s %lx %x:%x %lu",&lo,&hi,perm,&off,&ma,&mi,&ino)==7 &&
           (uintptr_t)address>=lo&&(uintptr_t)address<hi&&ino&&(!executable||perm[2]=='x')) {
            *out=(Physical){ma,mi,ino,(uintptr_t)address-lo+off};result=0;break;
        }
    }
    if(ferror(f))result=-1;
    fclose(f);return result;
}
static int mapped(Physical x) {
    FILE *f=fopen("/proc/self/maps","r");if(!f)return -1;
    char line[4096],perm[5];unsigned long lo,hi,off,ino;unsigned ma,mi;int result=0;
    while(fgets(line,sizeof line,f)) {
        if(!strchr(line,'\n')){result=-1;break;}
        if(sscanf(line,"%lx-%lx %4s %lx %x:%x %lu",&lo,&hi,perm,&off,&ma,&mi,&ino)==7&&
           ma==x.major&&mi==x.minor&&ino==x.ino)result=1;
    }
    if(ferror(f))result=-1;
    fclose(f);return result;
}
static int acquire(const char *path,Provider *p) {
    p->handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);if(!p->handle)return -1;
    GetList root=(GetList)dlsym(p->handle,"C_GetFunctionList");
    void *table=NULL;
    /* This provider's only non-selected invocation: A before readiness; B only
     * inside the externally quiesced acquisition gate. Never called again. */
    if(!root||root(&table)||!table)return -1;
    p->table=table;
    if(p->table->major!=2||p->table->minor!=40||p->table->slot[3]!=(void *)root)return -1;
    for(unsigned i=1;i<68;i++)if(i!=3&&p->table->slot[i])return -1;
    p->call=(Initialize)p->table->slot[0];
    if(!p->call||physical((void *)root,1,&p->root)||physical(table,0,&p->table_file)||
       physical((void *)p->call,1,&p->target))return -1;
    if(p->root.major!=p->table_file.major||p->root.minor!=p->table_file.minor||p->root.ino!=p->table_file.ino)return -1;
    return 0;
}
static int digest(const char *path,char hex[65],struct stat *identity) {
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return -1;
    struct stat before,after;
    Sha s={.h={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}};
    int result=-1;
    if(fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_size<0||before.st_size>64*1024*1024)goto done;
    unsigned char buf[4096];ssize_t n;
    while((n=read(fd,buf,sizeof buf))!=0) {
        if(n<0){if(errno==EINTR)continue;goto done;}
        if(!alive()||s.bytes+(uint64_t)n>64*1024*1024)goto done;
        sha_add(&s,buf,(size_t)n);
    }
    if(fstat(fd,&after)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||
       before.st_size!=after.st_size||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||
       before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec||before.st_ctim.tv_sec!=after.st_ctim.tv_sec||
       before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec||s.bytes!=(uint64_t)before.st_size)goto done;
    sha_finish(&s,hex);*identity=before;result=0;
done:close(fd);return result;
}
static int start_ticks(uint64_t *out) {
    FILE *f=fopen("/proc/self/stat","r");if(!f)return -1;
    char buf[4096];int ok=fgets(buf,sizeof buf,f)!=NULL&&!ferror(f);fclose(f);
    if(!ok||!strchr(buf,'\n'))return -1;
    char *p=strrchr(buf,')');if(!p||p[1]!=' ')return -1;p+=2;
    /* First token after ')' is field3; the twentieth is field22. */
    for(unsigned field=3;field<22;field++){p=strchr(p,' ');if(!p)return -1;p++;}
    char *end;errno=0;unsigned long long value=strtoull(p,&end,10);
    if(errno||end==p||*end!=' '||*p<'0'||*p>'9')return -1;
    *out=value;return 0;
}
static int wait_command(const char *expected) {
    char token[64];size_t used=0;
    for(;;) {
        uint64_t now;if(!alive()||clock_ns(&now))return -1;
        int ms=(int)((deadline_ns-now)/1000000);if(ms>50)ms=50;if(ms<1)ms=1;
        struct pollfd p={.fd=control,.events=POLLIN};
        int ready=poll(&p,1,ms);if(ready<0){if(errno==EINTR)continue;return -1;}if(!ready)continue;
        char byte;ssize_t n=read(control,&byte,1);
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;
        if(n!=1)return -1; /* EOF, including a partial command, cancels. */
        if(byte=='\n'){token[used]=0;return strcmp(token,expected)?-1:0;}
        if(used>=sizeof token-1||byte<'a'||byte>'z'){
            if(byte!='-')return -1;
            if(used>=sizeof token-1)return -1;
        }
        token[used++]=byte;
    }
}
static int invoke(Initialize fn,unsigned count,unsigned alias,int error_last) {
    for(unsigned i=0;i<count;i++) {
        if(!alive()||calls>=64)return -1;
        /* No ledger writes, allocation, formatting or clock injection between
         * these two samples and the actual real function-pointer call. */
        uint64_t before,after;
        void *arguments=error_last&&i==count-1?(void *)&calls:NULL;
        if(clock_ns(&before))return -1;
        CK_RV rv=fn(arguments);
        if(clock_ns(&after)) {
            calls++;
            (void)row("{\"kind\":\"call\",\"sequence\":%" PRIu64 ",\"caller_identity\":1,\"target_identity\":1,\"function\":\"C_Initialize\",\"alias\":%u,\"before_call_ns\":%" PRIu64 ",\"after_return_ns\":null,\"entered\":true,\"completed\":false,\"return_status\":null}",calls,alias,before);
            return -1;
        }
        calls++;
        if(row("{\"kind\":\"call\",\"sequence\":%" PRIu64 ",\"caller_identity\":1,\"target_identity\":1,\"function\":\"C_Initialize\",\"alias\":%u,\"before_call_ns\":%" PRIu64 ",\"after_return_ns\":%" PRIu64 ",\"entered\":true,\"completed\":true,\"return_status\":%lu}",calls,alias,before,after,rv))return -1;
        if(after<=before||!alive())return -1;
    }
    return 0;
}
static int complete(int success) {
    if(!identity_written||terminal_written)return 0;
    uint64_t now;if(clock_ns(&now))return -1;
    if(row("{\"kind\":\"complete\",\"completed_ns\":%" PRIu64 ",\"calls\":%" PRIu64 ",\"complete\":%s}",now,calls,success?"true":"false"))return -1;
    terminal_written=1;return 0;
}
static int nonce_valid(const char *s) {
    if(strlen(s)!=32)return 0;
    for(unsigned i=0;i<32;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    return 1;
}
int main(int argc,char **argv) {
    if(argc!=8){fprintf(stderr,"usage: workload A B COMMON CONTROL_FIFO LEDGER NONCE DEADLINE_MS\n");return 2;}
    char *end;errno=0;unsigned long ms=strtoul(argv[7],&end,10);
    if(!nonce_valid(argv[6])||errno||end==argv[7]||*end||argv[7][0]<'0'||argv[7][0]>'9'||!ms||ms>110000)return 2;
    uint64_t now;if(clock_ns(&now)||now>UINT64_MAX-ms*1000000)return 1;deadline_ns=now+ms*1000000;
    struct sigaction sa={.sa_handler=on_signal};sigemptyset(&sa.sa_mask);
    if(sigaction(SIGTERM,&sa,NULL)||sigaction(SIGINT,&sa,NULL))return 1;
    sa.sa_handler=SIG_IGN;if(sigaction(SIGPIPE,&sa,NULL))return 1;
    int result=1;
    struct stat control_stat,exe_stat,common_stat;
    char exe_hash[65],common_hash[65],namespace[64];uint64_t start;
    Physical common_target;
    control=open(argv[4],O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
    if(control<0||fstat(control,&control_stat)||!S_ISFIFO(control_stat.st_mode)||control_stat.st_uid!=getuid())goto cleanup;
    ledger=open(argv[5],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(ledger<0)goto cleanup;
    common_handle=dlopen(argv[3],RTLD_NOW|RTLD_LOCAL);if(!common_handle)goto cleanup;
    void *body=dlsym(common_handle,"demotion_initialize");
    if(!body||dlsym(common_handle,"C_GetFunctionList")||physical(body,1,&common_target)||acquire(argv[1],&a)||!same(a.target,common_target))goto cleanup;
    if(digest("/proc/self/exe",exe_hash,&exe_stat)||digest(argv[3],common_hash,&common_stat)||
       common_stat.st_ino!=common_target.ino||exe_stat.st_mtim.tv_sec<0||exe_stat.st_mtim.tv_nsec<0||start_ticks(&start))goto cleanup;
    ssize_t nslen=readlink("/proc/self/ns/time",namespace,sizeof namespace-1);
    if(nslen<=0||(size_t)nslen>=sizeof namespace-1)goto cleanup;
    namespace[nslen]=0;
    for(ssize_t i=0;i<nslen;i++)if(!((namespace[i]>='0'&&namespace[i]<='9')||strchr("time:[]",namespace[i])))goto cleanup;
    if(printf("{\"event\":\"prepared\",\"a_root_ino\":%" PRIu64 ",\"a_root_offset\":%" PRIu64 ",\"a_table_ino\":%" PRIu64 ",\"a_table_offset\":%" PRIu64 "}\n",a.root.ino,a.root.offset,a.table_file.ino,a.table_file.offset)<0||fflush(stdout)||wait_command("ready")||clock_ns(&now))goto cleanup;
    if(row("{\"kind\":\"identity\",\"nonce\":\"%s\",\"caller\":{\"id\":1,\"pid\":%d,\"start_ticks\":%" PRIu64 ",\"incarnation\":0,\"exe_sha256\":\"%s\",\"exe\":{\"dev\":%" PRIu64 ",\"ino\":%" PRIu64 ",\"mtime_secs\":%" PRIu64 ",\"mtime_nanos\":%" PRIu64 "}},\"target\":{\"id\":1,\"dev_major\":%u,\"dev_minor\":%u,\"ino\":%" PRIu64 ",\"sha256\":\"%s\",\"offset\":%" PRIu64 ",\"endpoints\":[%" PRIu64 "]},\"domain_id\":1,\"clock\":\"CLOCK_MONOTONIC\",\"time_namespace\":\"%s\",\"ready_ns\":%" PRIu64 "}",
           argv[6],getpid(),start,exe_hash,(uint64_t)exe_stat.st_dev,(uint64_t)exe_stat.st_ino,(uint64_t)exe_stat.st_mtim.tv_sec,(uint64_t)exe_stat.st_mtim.tv_nsec,
           common_target.major,common_target.minor,common_target.ino,common_hash,common_target.offset,common_target.offset,namespace,now))goto cleanup;
    identity_written=1;
    if(invoke(a.call,5,0,1)||ack("a-done")||wait_command("load-b")||acquire(argv[2],&b)||!same(a.target,b.target)||
       (a.root.major==b.root.major&&a.root.minor==b.root.minor&&a.root.ino==b.root.ino))goto cleanup;
    if(printf("{\"event\":\"b-ready\",\"same_target\":true,\"a_root_ino\":%" PRIu64 ",\"b_root_ino\":%" PRIu64 ",\"b_root_offset\":%" PRIu64 ",\"b_table_ino\":%" PRIu64 ",\"b_table_offset\":%" PRIu64 "}\n",a.root.ino,b.root.ino,b.root.offset,b.table_file.ino,b.table_file.offset)<0||fflush(stdout))goto cleanup;
    if(wait_command("shared")||invoke(a.call,1,0,0)||invoke(b.call,1,1,1)||ack("shared-done")||wait_command("unload-a"))goto cleanup;
    if(dlclose(a.handle))goto cleanup;
    a.handle=NULL;a.table=NULL;a.call=NULL;
    if(mapped(a.root)!=0||mapped(b.root)!=1||mapped(common_target)!=1)goto cleanup;
    if(printf("{\"event\":\"a-unmapped\",\"a_mapped\":false,\"b_mapped\":true,\"common_mapped\":true}\n")<0||fflush(stdout))goto cleanup;
    if(wait_command("fence")||invoke(b.call,1,1,1)||ack("fence-done")||wait_command("proof")||invoke(b.call,2,1,1)||
       complete(1)||ack("final-calls")||wait_command("stop"))goto cleanup;
    result=0;
cleanup:
    if(result)fprintf(stderr,"demotion fixture cancelled or prerequisite failed\n");
    if(complete(0))result=1;
    if(a.handle&&dlclose(a.handle))result=1;
    if(b.handle&&dlclose(b.handle))result=1;
    if(common_handle&&dlclose(common_handle))result=1;
    if(control>=0&&close(control))result=1;
    if(ledger>=0&&close(ledger))result=1;
    if(!result&&ack("done"))result=1;
    return result;
}
#endif
