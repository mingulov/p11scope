/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Physical entry-count fixture, not semantic/API or full ABI qualification.
 * 32 indexed A_i/B_i 2.40 table pairs share32 real CK_RV(void) bodies, one
 * body per distinct physical object (libdemotion-common-00..31.so): 32 offsets
 * in one file are one pair, so each slot body lives in its own file to
 * make32 genuine physical count pairs. Provider A_i/B_i carries exactly its
 * own slot4+i body and local root/init helpers, so no common provider
 * reference reconnects the counted objects: each pair's growth installs on
 * its own edges only. The caller invokes those exact fixture types. No
 * argument/payload reads are requested.
 * Modes: DEMOTION_COMMON (once per body, with -DCOMMON_BODY),
 * DEMOTION_PROVIDER_A/B (once per index, with -DPROVIDER_SLOT=4+i), or
 * workload (default).
 * Workload: DIR FIFO LEDGER NONCE DEADLINE_MS COUNTED_ROUNDS SHARED_ROUNDS.
 * DIR holds provider-A-00..31.so, provider-B-00..31.so and
 * libdemotion-common-00..31.so. Commands: ready, count xN,
 * load-b, shared xM, unload-a, fence, proof, stop.
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
#ifdef DEMOTION_COMMON
#ifndef COMMON_BODY
#error One body per object: compile with -DCOMMON_BODY=diagnostics_slot_N
#endif
__attribute__((noinline, noclone)) CK_RV COMMON_BODY(void) { return 0; }
#else
#ifndef PROVIDER_SLOT
#error Indexed provider: compile with -DPROVIDER_SLOT=<4+i>
#endif
#if PROVIDER_SLOT < 4 || PROVIDER_SLOT > 35
#error PROVIDER_SLOT out of range 4..35
#endif
#define PASTE_(a, b) a##b
#define PASTE(a, b) PASTE_(a, b)
#define BODY_NAME PASTE(diagnostics_slot_, PROVIDER_SLOT)
extern CK_RV BODY_NAME(void);
/* Root/init helpers stay local: a shared helper would reconnect the counted
 * objects through one common provider reference. Static, so no dynamic
 * interposition can rebind one provider's init to another object. */
static CK_RV local_initialize(void *argument) { return argument ? 7 : 0; }
CK_RV C_GetFunctionList(void **);
#ifdef DEMOTION_PROVIDER_A
const char diagnostics_provider_tag[] = "diagnostics-provider-A";
#else
const char diagnostics_provider_tag[] = "diagnostics-provider-B";
#endif
static FunctionList table = {.major = 2, .minor = 40,
    .slot = {[0] = (void *)local_initialize, [3] = (void *)C_GetFunctionList, [PROVIDER_SLOT] = (void *)BODY_NAME}};
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
static void *common_handles[SLOT_COUNT];
static Provider providers_a[SLOT_COUNT],providers_b[SLOT_COUNT];

static int wrap_row(const char *fmt, ...) {
    char buf[16384]; va_list ap; va_start(ap,fmt);
    int n=vsnprintf(buf,sizeof buf,fmt,ap); va_end(ap);
    if(n<0||(size_t)n>=sizeof buf||ledger_lines>=65536||ledger_bytes+(size_t)n+1>16*1024*1024)return -1;
    buf[n++]='\n'; if(write_all(ledger,buf,(size_t)n))return -1;
    ledger_lines++; ledger_bytes+=(size_t)n; return 0;
}
static int wrap_ack(const char *event,unsigned round) {
    uint64_t now; if(clock_ns(&now))return -1;
    return printf("{\"event\":\"%s\",\"round\":%u,\"calls\":%" PRIu64 ",\"t\":%" PRIu64 "}\n",event,round,calls,now)<0||fflush(stdout)?-1:0;
}
/* Indexed acquire: provider i carries exactly its own counted slot, with
 * local slot0/slot3 and null holes everywhere else. Any second counted
 * entry would reconnect the pairs through one provider. */
static int wrap_acquire(const char *path,Provider *p,unsigned slot) {
    p->handle=dlopen(path,RTLD_NOW|RTLD_LOCAL); if(!p->handle)return -1;
    GetList root=(GetList)dlsym(p->handle,"C_GetFunctionList"); void *table=NULL;
    if(!root||root(&table)||!table)return -1;
    p->table=table;
    if(p->table->major!=2||p->table->minor!=40||p->table->slot[3]!=(void *)root||!p->table->slot[0])return -1;
    for(unsigned s=1;s<68;s++) {
        if(s==3)continue;
        if(s==slot) { if(!p->table->slot[s])return -1; }
        else if(p->table->slot[s])return -1;
    }
    if(physical((void *)root,1,&p->root)||physical(table,0,&p->table_file))return -1;
    if(p->root.major!=p->table_file.major||p->root.minor!=p->table_file.minor||p->root.ino!=p->table_file.ino)return -1;
    return 0;
}
static int wrap_calls(Provider *providers,const char *phase,unsigned round) {
    for(unsigned index=0;index<SLOT_COUNT;index++) {
        if(!alive()||calls>=65536)return -1;
        CK_RV (*body)(void)=(CK_RV (*)(void))providers[index].table->slot[FIRST_SLOT+index];
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
static int provider_path(char *out,size_t size,const char *dir,char side,unsigned index) {
    int n=snprintf(out,size,"%s/provider-%c-%02u.so",dir,side,index);
    return n<0||(size_t)n>=size?-1:0;
}
int main(int argc,char **argv) {
    unsigned long milliseconds,counted,shared;
    if((argc!=8&&argc!=9)||!nonce_valid(argv[4])||number(argv[5],900000,&milliseconds)||
       number(argv[6],400,&counted)||number(argv[7],258,&shared))return 2;
    int probe=argc==9;
    if(probe&&(strcmp(argv[8],"probe")||counted!=3||shared!=1))return 2;
    uint64_t now;
    if(clock_ns(&now)||now>UINT64_MAX-milliseconds*1000000)return 1;
    deadline_ns=now+milliseconds*1000000;
    struct sigaction sa={.sa_handler=on_signal}; sigemptyset(&sa.sa_mask);
    if(sigaction(SIGTERM,&sa,NULL)||sigaction(SIGINT,&sa,NULL))return 1;
    sa.sa_handler=SIG_IGN; if(sigaction(SIGPIPE,&sa,NULL))return 1;
    int result=1; struct stat fifo_stat,exe_stat,dir_stat,common_stats[SLOT_COUNT];
    char exe_hash[65],common_hashes[SLOT_COUNT][65];
    char provider_a_hashes[SLOT_COUNT][65],provider_b_hashes[SLOT_COUNT][65];
    uint64_t start;
    control=open(argv[2],O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
    if(control<0||fstat(control,&fifo_stat)||!S_ISFIFO(fifo_stat.st_mode)||fifo_stat.st_uid!=getuid())goto cleanup;
    ledger=open(argv[3],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600); if(ledger<0)goto cleanup;
    if(stat(argv[1],&dir_stat)||!S_ISDIR(dir_stat.st_mode)||dir_stat.st_uid!=getuid())goto cleanup;
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        char path[4112]; int n=snprintf(path,sizeof path,"%s/libdemotion-common-%02u.so",argv[1],i);
        if(n<0||(size_t)n>=sizeof path)goto cleanup;
        common_handles[i]=dlopen(path,RTLD_NOW|RTLD_LOCAL);
        if(!common_handles[i]||dlsym(common_handles[i],"C_GetFunctionList"))goto cleanup;
        if(digest(path,common_hashes[i],&common_stats[i]))goto cleanup;
    }
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        char path[4112]; struct stat identity;
        if(provider_path(path,sizeof path,argv[1],'A',i))goto cleanup;
        if(wrap_acquire(path,&providers_a[i],FIRST_SLOT+i))goto cleanup;
        if(provider_path(path,sizeof path,argv[1],'B',i))goto cleanup;
        if(digest(path,provider_b_hashes[i],&identity))goto cleanup;
        if(provider_path(path,sizeof path,argv[1],'A',i))goto cleanup;
        if(digest(path,provider_a_hashes[i],&identity))goto cleanup;
    }
    if(digest("/proc/self/exe",exe_hash,&exe_stat)||start_ticks(&start))goto cleanup;
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        if(physical(providers_a[i].table->slot[FIRST_SLOT+i],1,&targets[i])||targets[i].ino!=(uint64_t)common_stats[i].st_ino)goto cleanup;
        for(unsigned j=0;j<i;j++)if(same(targets[i],targets[j]))goto cleanup;
    }
    if(wrap_ack("prepared",0)||wait_command("ready")||clock_ns(&now))goto cleanup;
    char common_list[32*70],provider_a_list[32*70],provider_b_list[32*70];
    size_t common_used=0,provider_a_used=0,provider_b_used=0;
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        int n=snprintf(common_list+common_used,sizeof common_list-common_used,"%s\"%s\"",i?",":"",common_hashes[i]);
        if(n<0||(size_t)n>=sizeof common_list-common_used)goto cleanup;
        common_used+=(size_t)n;
        n=snprintf(provider_a_list+provider_a_used,sizeof provider_a_list-provider_a_used,"%s\"%s\"",i?",":"",provider_a_hashes[i]);
        if(n<0||(size_t)n>=sizeof provider_a_list-provider_a_used)goto cleanup;
        provider_a_used+=(size_t)n;
        n=snprintf(provider_b_list+provider_b_used,sizeof provider_b_list-provider_b_used,"%s\"%s\"",i?",":"",provider_b_hashes[i]);
        if(n<0||(size_t)n>=sizeof provider_b_list-provider_b_used)goto cleanup;
        provider_b_used+=(size_t)n;
    }
    if(wrap_row("{\"kind\":\"identity\",\"nonce\":\"%s\",\"pid\":%d,\"start_ticks\":%" PRIu64 ",\"exe_sha256\":\"%s\",\"common_sha256\":[%s],\"provider_a_sha256\":[%s],\"provider_b_sha256\":[%s],\"ready_ns\":%" PRIu64 "}",
                argv[4],getpid(),start,exe_hash,common_list,provider_a_list,provider_b_list,now))goto cleanup;
    identity_written=1;
    for(unsigned i=0;i<SLOT_COUNT;i++)
        if(wrap_row("{\"kind\":\"target\",\"slot\":%u,\"dev_major\":%u,\"dev_minor\":%u,\"ino\":%" PRIu64 ",\"offset\":%" PRIu64 "}",
                    FIRST_SLOT+i,targets[i].major,targets[i].minor,targets[i].ino,targets[i].offset))goto cleanup;
    if(wrap_ack("ready",0))goto cleanup;
    for(unsigned round=1;round<=counted;round++)
        if(wait_command("count")||wrap_calls(providers_a,"a",round)||wrap_ack("a-done",round))goto cleanup;
    if(probe) { if(wait_command("stop"))goto cleanup; goto complete; }
    if(wait_command("load-b"))goto cleanup;
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        char path[4112];
        if(provider_path(path,sizeof path,argv[1],'B',i))goto cleanup;
        if(wrap_acquire(path,&providers_b[i],FIRST_SLOT+i))goto cleanup;
        if(same(providers_a[i].root,providers_b[i].root))goto cleanup;
    }
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        Physical target;
        if(physical(providers_b[i].table->slot[FIRST_SLOT+i],1,&target)||!same(target,targets[i]))goto cleanup;
    }
    if(wrap_ack("b-ready",0))goto cleanup;
    for(unsigned round=1;round<=shared;round++)
        if(wait_command("shared")||wrap_calls(providers_b,"shared",round)||wrap_ack("shared-done",round))goto cleanup;
    if(wait_command("unload-a"))goto cleanup;
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        if(!providers_a[i].handle||dlclose(providers_a[i].handle))goto cleanup;
        providers_a[i].handle=NULL; providers_a[i].table=NULL;
    }
    for(unsigned i=0;i<SLOT_COUNT;i++)
        if(mapped(providers_a[i].root)!=0||mapped(providers_b[i].root)!=1)goto cleanup;
    for(unsigned i=0;i<SLOT_COUNT;i++)if(mapped(targets[i])!=1)goto cleanup;
    if(wrap_ack("a-unmapped",0))goto cleanup;
    if(wait_command("fence")||wrap_calls(providers_b,"fence",1)||wrap_ack("fence-done",1)||
       wait_command("proof")||wrap_calls(providers_b,"proof",1)||wrap_ack("final-calls",1)||wait_command("stop"))goto cleanup;
complete:
    if(wrap_row("{\"kind\":\"complete\",\"complete\":true,\"calls\":%" PRIu64 "}",calls)||wrap_ack("done",0))goto cleanup;
    terminal_written=1; result=0;
cleanup:
    if(result) {
        fprintf(stderr,"diagnostics wrap fixture cancelled or prerequisite failed\n");
        if(identity_written&&!terminal_written)(void)wrap_row("{\"kind\":\"complete\",\"complete\":false,\"calls\":%" PRIu64 "}",calls);
    }
    for(unsigned i=0;i<SLOT_COUNT;i++) {
        if(providers_a[i].handle&&dlclose(providers_a[i].handle))result=1;
        if(providers_b[i].handle&&dlclose(providers_b[i].handle))result=1;
    }
    for(unsigned i=0;i<SLOT_COUNT;i++)if(common_handles[i]&&dlclose(common_handles[i]))result=1;
    if(control>=0&&close(control))result=1;
    if(ledger>=0&&close(ledger))result=1;
    return result;
}
#endif
