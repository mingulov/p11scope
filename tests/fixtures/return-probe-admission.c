/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned EXT-01 fixture, built twice: -DRETURN_PROBE_PROVIDER for the SO,
 * otherwise a pthread caller. No observer is attached by this program.
 * Caller argv: PROVIDER worker-pre-filter|worker-late-filter CALLS LEDGER.
 * Protocol: ready -> A -> armed -> G -> done -> R -> normal exit.
 * All waits share a hard 120s lifetime; EOF, bad order and timeout fail.
 */
#define _GNU_SOURCE
#include <stdint.h>

#if !defined(__x86_64__) || defined(__ILP32__)
#error "This return-probe fixture qualifies Linux x86-64 LP64 only"
#endif

#ifdef RETURN_PROBE_PROVIDER
__attribute__((noinline, visibility("default")))
unsigned long C_GetInfo(void *info) {
    __asm__ volatile("" : : "r"(info) : "memory");
    return 0;
}

__attribute__((visibility("default")))
unsigned long C_GetFunctionList(void **out);

/* Deliberately sparse: provider support must not require populated slots. */
static struct {
    unsigned char major, minor;
    void *functions[68];
} functions = {2, 40, {[2] = (void *)C_GetInfo, [3] = (void *)C_GetFunctionList}};

unsigned long C_GetFunctionList(void **out) {
    if (!out) return 7;
    *out = &functions;
    return 0;
}
#else
#include <dlfcn.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>

typedef unsigned long (*get_info_fn)(void *);
static get_info_fn get_info;
static FILE *ledger;
static unsigned int calls;
static int pre_filter;
static long long deadline_ns;

static long long now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int seccomp_mode(long tid) {
    char path[96], row[256];
    if (snprintf(path, sizeof(path), "/proc/self/task/%ld/status", tid) <= 0) return -1;
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    int result = -1;
    while (fgets(row, sizeof(row), file)) {
        if (!strncmp(row, "Seccomp:", 8)) {
            char tail;
            if (sscanf(row + 8, "%d %c", &result, &tail) != 1) result = -1;
            break;
        }
    }
    if (fclose(file)) return -1;
    return result;
}

/* No TSYNC: only the worker installs this filter. Everything except335
 * remains allowed, including the protocol, ledger and provider plumbing. */
static int arm(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 335, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter };
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
           syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

static int command(void) {
    long long remaining = deadline_ns - now_ns();
    if (remaining <= 0) return -1;
    struct pollfd fd = { .fd = STDIN_FILENO, .events = POLLIN };
    int rc;
    do { rc = poll(&fd, 1, (int)(remaining / 1000000LL)); } while (rc < 0 && errno == EINTR);
    if (rc <= 0 || !(fd.revents & POLLIN)) return -1;
    char bytes[2];
    if (read(STDIN_FILENO, bytes, sizeof(bytes)) != 2 || bytes[1] != '\n') return -1;
    return bytes[0];
}

static int say(const char *phase, long tid, unsigned int count) {
    int leader = seccomp_mode(getpid()), worker = seccomp_mode(tid);
    if (leader < 0 || worker < 0) return -1;
    return printf("{\"phase\":\"%s\",\"pid\":%ld,\"tid\":%ld,"
                  "\"leader_seccomp\":%d,\"worker_seccomp\":%d,\"calls\":%u}\n",
                  phase, (long)getpid(), tid, leader, worker, count) < 0 || fflush(stdout);
}

static void *worker(void *unused) {
    (void)unused;
    long tid = syscall(SYS_gettid);
    if ((pre_filter && arm()) || say("ready", tid, 0)) return (void *)(uintptr_t)3;
    if (command() != 'A') return (void *)(uintptr_t)4;
    if ((!pre_filter && arm()) || say("armed", tid, 0)) return (void *)(uintptr_t)5;
    int go = command();
    if (go != 'G') return (void *)(uintptr_t)7;
    for (unsigned int i = 1; i <= calls; i++) {
        unsigned long info[16] = {0};
        unsigned long rv = get_info(info);
        if (fprintf(ledger, "{\"index\":%u,\"pid\":%ld,\"tid\":%ld,\"rv\":%lu}\n",
                    i, (long)getpid(), tid, rv) < 0 || rv) return (void *)(uintptr_t)8;
    }
    if (fclose(ledger)) { ledger = NULL; return (void *)(uintptr_t)9; }
    ledger = NULL;
    if (say("done", tid, calls) || command() != 'R') return (void *)(uintptr_t)10;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    if (!strcmp(argv[2], "worker-pre-filter")) pre_filter = 1;
    else if (strcmp(argv[2], "worker-late-filter")) return 2;
    char *end = NULL;
    unsigned long n = strtoul(argv[3], &end, 10);
    if (!*argv[3] || *end || n < 1 || n > 64) return 2;
    calls = (unsigned int)n;
    deadline_ns = now_ns() + 120000000000LL;
    alarm(120); /* Hard ownership backstop, including blocked pipe writes. */
    ledger = fopen(argv[4], "wx");
    if (!ledger) return 3;
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) { fclose(ledger); return 3; }
    get_info = (get_info_fn)dlsym(module, "C_GetInfo");
    if (!get_info) { fclose(ledger); dlclose(module); return 3; }
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) {
        fclose(ledger); dlclose(module); return 3;
    }
    void *result = NULL;
    int joined = pthread_join(thread, &result);
    if (ledger) fclose(ledger);
    int closed = dlclose(module);
    return joined || closed ? 3 : (int)(uintptr_t)result;
}
#endif
