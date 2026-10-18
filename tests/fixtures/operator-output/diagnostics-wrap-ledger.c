/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Physical entry-count fixture, not semantic/API or full ABI qualification.
 * Two 2.40 tables share32 real CK_RV(void) bodies at slots4..35. The caller
 * invokes those exact fixture types. No argument/payload reads are requested.
 * Modes: DEMOTION_COMMON, DEMOTION_PROVIDER_A/B, or workload (default).
 * Workload: A B COMMON FIFO LEDGER NONCE DEADLINE_MS COUNTED_ROUNDS SHARED_ROUNDS.
 * Commands: ready, count xN, load-b, shared xM, unload-a, fence, proof, stop.
 * Each issued round requires a subsequent actual observer pass in the live
 * test; native ACKs alone establish no observer admission/counting facts.
 */
#define _GNU_SOURCE
#if defined(DEMOTION_COMMON) || defined(DEMOTION_PROVIDER_A) || defined(DEMOTION_PROVIDER_B)
#include <stddef.h>
typedef unsigned long CK_RV;
typedef struct { unsigned char major, minor; void *slot[68]; } FunctionList;
_Static_assert(sizeof(void *) == 8 && sizeof(CK_RV) == 8, "LP64 only");
_Static_assert(offsetof(FunctionList, slot) == 8, "CK_VERSION LP64 alignment");
#define SLOTS(X) X(4) X(5) X(6) X(7) X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15) X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31) X(32) X(33) X(34) X(35)
#ifdef DEMOTION_COMMON
CK_RV demotion_initialize(void *argument) { return argument ? 7 : 0; }
#define BODY(n) __attribute__((noinline, noclone)) CK_RV diagnostics_slot_##n(void) { return 0; }
SLOTS(BODY)
#else
extern CK_RV demotion_initialize(void *);
#define DECLARE(n) extern CK_RV diagnostics_slot_##n(void);
SLOTS(DECLARE)
CK_RV C_GetFunctionList(void **);
#ifdef DEMOTION_PROVIDER_A
const char diagnostics_provider_tag[] = "diagnostics-provider-A";
#else
const char diagnostics_provider_tag[] = "diagnostics-provider-B";
#endif
#define ENTRY(n) [n] = (void *)diagnostics_slot_##n,
static FunctionList table = {.major = 2, .minor = 40,
    .slot = {[0] = (void *)demotion_initialize, [3] = (void *)C_GetFunctionList, SLOTS(ENTRY)}};
CK_RV C_GetFunctionList(void **out) { if (!out) return 7; *out = &table; return 0; }
#endif
#else
/* Reuse actual VMA, SHA256, clock, FIFO and bounded syscall helpers. The old
 * entry point remains separately named, preserving its existing control. */
#define main original_demotion_main
#include "../public-cli/demotion-ledger.c"
#undef main

#define FIRST_SLOT 4
#define SLOT_COUNT 32
static Physical targets[SLOT_COUNT];

static int wrap_row(const char *fmt, ...) {
    char buf[2048]; va_list ap; va_start(ap,fmt);
    int n=vsnprintf(buf,sizeof buf,fmt,ap); va_end(ap);
    if(n<0||(size_t)n>=sizeof buf||ledger_lines>=65536||ledger_bytes+(size_t)n+1>16*1024*1024)return -1;
    buf[n++]='\n'; if(write_all(ledger,buf,(size_t)n))return -1;
    ledger_lines++; ledger_bytes+=(size_t)n; return 0;
}
static int wrap_ack(const char *event,unsigned round) {
    uint64_t now; if(clock_ns(&now))return -1;
    return printf("{\"event\":\"%s\",\"round\":%u,\"calls\":%" PRIu64 ",\"t\":%" PRIu64 "}\n",event,round,calls,now)<0||fflush(stdout)?-1:0;
}
static int wrap_acquire(const char *path,Provider *p) {
    p->handle=dlopen(path,RTLD_NOW|RTLD_LOCAL); if(!p->handle)return -1;
    GetList root=(GetList)dlsym(p->handle,"C_GetFunctionList"); void *table=NULL;
    if(!root||root(&table)||!table)return -1;
    p->table=table;
    if(p->table->major!=2||p->table->minor!=40||p->table->slot[3]!=(void *)root||!p->table->slot[0])return -1;
    for(unsigned slot=1;slot<68;slot++) {
        if(slot==3)continue;
        if(slot>=FIRST_SLOT&&slot<FIRST_SLOT+SLOT_COUNT) { if(!p->table->slot[slot])return -1; }
        else if(p->table->slot[slot])return -1;
    }
    if(physical((void *)root,1,&p->root)||physical(table,0,&p->table_file))return -1;
    if(p->root.major!=p->table_file.major||p->root.minor!=p->table_file.minor||p->root.ino!=p->table_file.ino)return -1;
    return 0;
}
static int wrap_calls(Provider *provider,const char *phase,unsigned round) {
    for(unsigned index=0;index<SLOT_COUNT;index++) {
        if(!alive()||calls>=65536)return -1;
        CK_RV (*body)(void)=(CK_RV (*)(void))provider->table->slot[FIRST_SLOT+index];
        uint64_t before,after; if(clock_ns(&before))return -1;
        CK_RV rv=body(); calls++;
        if(clock_ns(&after)||after<=before)return -1;
        if(wrap_row("{\"kind\":\"call\",\"sequence\":%" PRIu64 ",\"phase\":\"%s\",\"round\":%u,\"slot\":%u,\"before_call_ns\":%" PRIu64 ",\"after_return_ns\":%" PRIu64 ",\"return_status\":%lu}",
                    calls,phase,round,FIRST_SLOT+index,before,after,rv)||rv)return -1;
    }
    return 0;
}
static int number(const char *text,unsigned long bound,unsigned long *out) {
    if(!*text)return -1;
    for(const unsigned char *p=(const unsigned char *)text;*p;p++)if(*p<'0'||*p>'9')return -1;
    char *end; errno=0; *out=strtoul(text,&end,10);
    return errno||*end||!*out||*out>bound?-1:0;
}
int main(int argc,char **argv) {
    unsigned long milliseconds,counted,shared;
    if(argc!=10||!nonce_valid(argv[6])||number(argv[7],900000,&milliseconds)||
       number(argv[8],400,&counted)||number(argv[9],258,&shared))return 2;
    uint64_t now;
    if(clock_ns(&now)||now>UINT64_MAX-milliseconds*1000000)return 1;
    deadline_ns=now+milliseconds*1000000;
    struct sigaction sa={.sa_handler=on_signal}; sigemptyset(&sa.sa_mask);
    if(sigaction(SIGTERM,&sa,NULL)||sigaction(SIGINT,&sa,NULL))return 1;
    sa.sa_handler=SIG_IGN; if(sigaction(SIGPIPE,&sa,NULL))return 1;
    int result=1; struct stat fifo_stat,exe_stat,common_stat;
    char exe_hash[65],common_hash[65]; uint64_t start;
    control=open(argv[4],O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
    if(control<0||fstat(control,&fifo_stat)||!S_ISFIFO(fifo_stat.st_mode)||fifo_stat.st_uid!=getuid())goto cleanup;
    ledger=open(argv[5],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600); if(ledger<0)goto cleanup;
    common_handle=dlopen(argv[3],RTLD_NOW|RTLD_LOCAL);
    if(!common_handle||dlsym(common_handle,"C_GetFunctionList")||wrap_acquire(argv[1],&a))goto cleanup;
    if(digest("/proc/self/exe",exe_hash,&exe_stat)||digest(argv[3],common_hash,&common_stat)||start_ticks(&start))goto cleanup;
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        if(physical(a.table->slot[FIRST_SLOT+i],1,&targets[i])||targets[i].ino!=(uint64_t)common_stat.st_ino)goto cleanup;
        for(unsigned j=0;j<i;j++)if(same(targets[i],targets[j]))goto cleanup;
    }
    if(wrap_ack("prepared",0)||wait_command("ready")||clock_ns(&now))goto cleanup;
    if(wrap_row("{\"kind\":\"identity\",\"nonce\":\"%s\",\"pid\":%d,\"start_ticks\":%" PRIu64 ",\"exe_sha256\":\"%s\",\"common_sha256\":\"%s\",\"ready_ns\":%" PRIu64 "}",
                argv[6],getpid(),start,exe_hash,common_hash,now))goto cleanup;
    identity_written=1;
    for(unsigned i=0;i<SLOT_COUNT;i++)
        if(wrap_row("{\"kind\":\"target\",\"slot\":%u,\"dev_major\":%u,\"dev_minor\":%u,\"ino\":%" PRIu64 ",\"offset\":%" PRIu64 "}",
                    FIRST_SLOT+i,targets[i].major,targets[i].minor,targets[i].ino,targets[i].offset))goto cleanup;
    if(wrap_ack("ready",0))goto cleanup;
    for(unsigned round=1;round<=counted;round++)
        if(wait_command("count")||wrap_calls(&a,"a",round)||wrap_ack("a-done",round))goto cleanup;
    if(wait_command("load-b")||wrap_acquire(argv[2],&b)||same(a.root,b.root))goto cleanup;
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        Physical target;
        if(physical(b.table->slot[FIRST_SLOT+i],1,&target)||!same(target,targets[i]))goto cleanup;
    }
    if(wrap_ack("b-ready",0))goto cleanup;
    for(unsigned round=1;round<=shared;round++)
        if(wait_command("shared")||wrap_calls(&b,"shared",round)||wrap_ack("shared-done",round))goto cleanup;
    if(wait_command("unload-a")||dlclose(a.handle))goto cleanup;
    a.handle=NULL; a.table=NULL;
    if(mapped(a.root)!=0||mapped(b.root)!=1||mapped(targets[0])!=1||wrap_ack("a-unmapped",0))goto cleanup;
    if(wait_command("fence")||wrap_calls(&b,"fence",1)||wrap_ack("fence-done",1)||
       wait_command("proof")||wrap_calls(&b,"proof",1)||wrap_ack("final-calls",1)||wait_command("stop"))goto cleanup;
    if(wrap_row("{\"kind\":\"complete\",\"complete\":true,\"calls\":%" PRIu64 "}",calls)||wrap_ack("done",0))goto cleanup;
    terminal_written=1; result=0;
cleanup:
    if(result) {
        fprintf(stderr,"diagnostics wrap fixture cancelled or prerequisite failed\n");
        if(identity_written&&!terminal_written)(void)wrap_row("{\"kind\":\"complete\",\"complete\":false,\"calls\":%" PRIu64 "}",calls);
    }
    if(a.handle&&dlclose(a.handle))result=1;
    if(b.handle&&dlclose(b.handle))result=1;
    if(common_handle&&dlclose(common_handle))result=1;
    if(control>=0&&close(control))result=1;
    if(ledger>=0&&close(ledger))result=1;
    return result;
}
#endif
