/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Private LP64 x86-64 exec fixture: DSO, before driver, and distinct after driver.
 * The raw clone worker makes no libc/TLS calls. Only that worker reads stdin
 * after THREAD; the leader waits outside the provider until killed by exec or
 * the failed-exec worker's final kernel clear_child_tid. No uretprobe unwinding.
 * Mode argv[6]: '0' nonleader exec, '1' failed exec, '2' leader thread-exit then
 * nonleader exec (the leader emits LEADER_EXIT, then exits; the worker owns
 * everything after THREAD). The provider additionally
 * exports a v2.40 C_GetFunctionList table (slot 0 is the real C_Initialize, the
 * rest honest NOT_SUPPORTED stubs) so public scan-only discovery can attach;
 * the driver calls the getter once before READY. The getter itself is never a
 * probed slot, so single-slot libtest counts are unchanged. Optional
 * argv[7]/argv[8] set the after-image measured total (default 17) and the
 * inter-call delay in ms (default 0); defaults preserve the exact legacy
 * NEW_DONE counts.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>

#if !defined(__x86_64__) || defined(__ILP32__)
#error "This owned exec cell currently qualifies LP64 x86-64 only"
#endif

static inline long raw6(long nr, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(nr)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return nr;
}

static _Noreturn void fail(int status) {
    (void)raw6(SYS_exit_group, status, 0, 0, 0, 0, 0);
    for (;;) {}
}

static unsigned long clock_ns(void) {
    struct timespec now;
    if (raw6(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&now, 0, 0, 0, 0)) fail(90);
    return (unsigned long)now.tv_sec * 1000000000UL + (unsigned long)now.tv_nsec;
}

static void write_all(int fd, const char *buffer, size_t length) {
    while (length) {
        long written = raw6(SYS_write, fd, (long)buffer, (long)length, 0, 0, 0);
        if (written == -EINTR) continue;
        if (written <= 0) fail(91);
        buffer += written;
        length -= (size_t)written;
    }
}

static size_t number(char *buffer, unsigned long value) {
    char reversed[20];
    size_t count = 0;
    do {
        reversed[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    for (size_t i = 0; i < count; ++i) buffer[i] = reversed[count - i - 1];
    return count;
}

static void emit(const char *phase, const unsigned long *fields, size_t count) {
    char buffer[256];
    size_t length = 0;
    while (*phase) buffer[length++] = *phase++;
    for (size_t i = 0; i < count; ++i) {
        buffer[length++] = ' ';
        length += number(buffer + length, fields[i]);
    }
    buffer[length++] = ' ';
    length += number(buffer + length, clock_ns());
    buffer[length++] = '\n';
    write_all(1, buffer, length);
}

static void receive(int fd, char expected) {
    unsigned long deadline = clock_ns() + 30000000000UL;
    for (;;) {
        unsigned long now = clock_ns();
        if (now >= deadline) fail(92);
        struct pollfd readiness = { .fd = fd, .events = POLLIN, .revents = 0 };
        long ready = raw6(SYS_poll, (long)&readiness, 1,
                          (long)((deadline - now + 999999UL) / 1000000UL), 0, 0, 0);
        if (ready == -EINTR || ready == 0) continue;
        if (ready < 0 || !(readiness.revents & POLLIN)) fail(93);
        char byte;
        long got = raw6(SYS_read, fd, (long)&byte, 1, 0, 0, 0);
        if (got == -EINTR) continue;
        if (got != 1 || byte != expected) fail(94);
        return;
    }
}

struct request {
    unsigned long rv;
    unsigned long token;
    int operation; /* 0: ordinary return; 1: exec inside frame; 2: held new call */
    int expect_failure;
    const char *exec_path;
    char *const *exec_argv;
    char *const *exec_envp;
};

#ifdef DETAILED_EXEC_PROVIDER

__attribute__((noinline, visibility("default")))
unsigned long C_Initialize(void *argument) {
    const struct request *request = argument;
    __asm__ volatile("" ::: "memory");
    if (request->operation == 1) {
        unsigned long fields[] = {
            (unsigned long)raw6(SYS_getpid, 0, 0, 0, 0, 0, 0),
            (unsigned long)raw6(SYS_gettid, 0, 0, 0, 0, 0, 0), request->token
        };
        emit("EXEC_BODY", fields, 3);
        receive(0, 'X');
        /* exec consumes the prepared argv/envp while this probed frame is live. */
        long result = raw6(SYS_execve, (long)request->exec_path,
                           (long)request->exec_argv, (long)request->exec_envp, 0, 0, 0);
        if (!request->expect_failure || result != -ENOENT) fail(95);
        unsigned long failed[] = { fields[0], fields[1], (unsigned long)-result, request->token };
        emit("EXEC_FAILED", failed, 4);
        receive(0, 'R');
    } else if (request->operation == 2) {
        unsigned long fields[] = {
            (unsigned long)raw6(SYS_getpid, 0, 0, 0, 0, 0, 0),
            (unsigned long)raw6(SYS_gettid, 0, 0, 0, 0, 0, 0), request->token
        };
        emit("POST_BODY", fields, 3);
        receive(0, 'R');
    }
    return request->rv;
}

/* v2.40 table for public-scan attachment: slot 0 is the real C_Initialize, slot 3
 * is the real getter (matching observed real-provider tables), and every other
 * slot is an exported named stub the fixture never calls. Each stub has a
 * distinct address and a distinct constant body so identical-code folding
 * cannot alias the table. Slot order matches the provider the scan names. */
#define EXEC_NAMED_STUBS \
    Y(C_Finalize, 1) Y(C_GetInfo, 2) \
    Y(C_GetSlotList, 4) Y(C_GetSlotInfo, 5) Y(C_GetTokenInfo, 6) \
    Y(C_GetMechanismList, 7) Y(C_GetMechanismInfo, 8) \
    Y(C_InitToken, 9) Y(C_InitPIN, 10) Y(C_SetPIN, 11) \
    Y(C_OpenSession, 12) Y(C_CloseSession, 13) Y(C_CloseAllSessions, 14) \
    Y(C_GetSessionInfo, 15) Y(C_GetOperationState, 16) Y(C_SetOperationState, 17) \
    Y(C_Login, 18) Y(C_Logout, 19) \
    Y(C_CreateObject, 20) Y(C_CopyObject, 21) Y(C_DestroyObject, 22) \
    Y(C_GetObjectSize, 23) Y(C_GetAttributeValue, 24) Y(C_SetAttributeValue, 25) \
    Y(C_FindObjectsInit, 26) Y(C_FindObjects, 27) Y(C_FindObjectsFinal, 28) \
    Y(C_EncryptInit, 29) Y(C_Encrypt, 30) Y(C_EncryptUpdate, 31) Y(C_EncryptFinal, 32) \
    Y(C_DecryptInit, 33) Y(C_Decrypt, 34) Y(C_DecryptUpdate, 35) Y(C_DecryptFinal, 36) \
    Y(C_DigestInit, 37) Y(C_Digest, 38) Y(C_DigestUpdate, 39) Y(C_DigestKey, 40) \
    Y(C_DigestFinal, 41) \
    Y(C_SignInit, 42) Y(C_Sign, 43) Y(C_SignUpdate, 44) Y(C_SignFinal, 45) \
    Y(C_SignRecoverInit, 46) Y(C_SignRecover, 47) \
    Y(C_VerifyInit, 48) Y(C_Verify, 49) Y(C_VerifyUpdate, 50) Y(C_VerifyFinal, 51) \
    Y(C_VerifyRecoverInit, 52) Y(C_VerifyRecover, 53) \
    Y(C_DigestEncryptUpdate, 54) Y(C_DecryptDigestUpdate, 55) \
    Y(C_SignEncryptUpdate, 56) Y(C_DecryptVerifyUpdate, 57) \
    Y(C_GenerateKey, 58) Y(C_GenerateKeyPair, 59) \
    Y(C_WrapKey, 60) Y(C_UnwrapKey, 61) Y(C_DeriveKey, 62) \
    Y(C_SeedRandom, 63) Y(C_GenerateRandom, 64) \
    Y(C_GetFunctionStatus, 65) Y(C_CancelFunction, 66) Y(C_WaitForSlotEvent, 67)
#define Y(name, n) \
    __attribute__((visibility("default"))) unsigned long name(void) { return 0x540ul + (n); }
EXEC_NAMED_STUBS
#undef Y

struct exec_function_list {
    unsigned char major, minor;
    void *functions[68];
};

static struct exec_function_list function_list;
static int function_list_ready;

__attribute__((visibility("default")))
unsigned long C_GetFunctionList(void **list) {
    if (!function_list_ready) {
        function_list.major = 2;
        function_list.minor = 40;
        function_list.functions[0] = (void *)C_Initialize;
        function_list.functions[3] = (void *)C_GetFunctionList;
#define Y(name, n) function_list.functions[n] = (void *)name;
        EXEC_NAMED_STUBS
#undef Y
        function_list_ready = 1;
    }
    *list = &function_list;
    return 0;
}

#else

#include <dlfcn.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef unsigned long (*call_fn)(void *);

static unsigned long positive(const char *text) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (!value || errno || !end || *end) fail(80);
    return value;
}

static unsigned long nonnegative(const char *text) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !end || *end) fail(80);
    return value;
}

static void calls(call_fn call, unsigned long first, unsigned long end,
                  unsigned long *success, unsigned long *errors, unsigned long delay_ms) {
    for (unsigned long i = first; i < end; ++i) {
        if (delay_ms) {
            struct timespec wait = { .tv_sec = (long)(delay_ms / 1000),
                                     .tv_nsec = (long)(delay_ms % 1000) * 1000000L };
            while (nanosleep(&wait, &wait)) {
                if (errno != EINTR) fail(105);
            }
        }
        struct request request = { .rv = (i & 1) ? 5 : 0 };
        unsigned long rv = call(&request);
        if (rv != request.rv) fail(96);
        if (rv == 0) ++*success;
        else ++*errors;
    }
}

#ifndef DETAILED_EXEC_AFTER
struct worker_args {
    call_fn call;
    int go;
    unsigned long parent;
    struct request exec;
};

static void kernel_join(int *child_tid) {
    unsigned long deadline = clock_ns() + 30000000000UL;
    for (;;) {
        int observed = __atomic_load_n(child_tid, __ATOMIC_ACQUIRE);
        if (observed == 0) return;
        unsigned long now = clock_ns();
        if (now >= deadline) fail(98);
        unsigned long remaining = deadline - now;
        struct timespec timeout = {
            .tv_sec = (long)(remaining / 1000000000UL),
            .tv_nsec = (long)(remaining % 1000000000UL)
        };
        long result = raw6(SYS_futex, (long)child_tid, FUTEX_WAIT, observed,
                           (long)&timeout, 0, 0);
        if (result != 0 && result != -EAGAIN && result != -EINTR) fail(99);
    }
}

static int worker(void *argument) {
    const struct worker_args *args = argument;
    /* Parent-death custody is per-thread; clone does not copy the setting. */
    if (raw6(SYS_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0, 0)
        || (unsigned long)raw6(SYS_getppid, 0, 0, 0, 0, 0, 0) != args->parent) fail(100);
    receive(args->go, 'W');
    unsigned long success = 0, errors = 0;
    calls(args->call, 0, 11, &success, &errors, 0);
    unsigned long pid = (unsigned long)raw6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    unsigned long tid = (unsigned long)raw6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    unsigned long completed[] = { pid, tid, 11, success, errors };
    emit("WORKER_DONE", completed, 5);
    unsigned long actual_rv = args->call((void *)&args->exec);
    /* The successful branch cannot return; errno2 is never a PKCS#11 RV. */
    if (!args->exec.expect_failure || actual_rv != 5) fail(97);
    ++errors;
    calls(args->call, 0, 17, &success, &errors, 0);
    unsigned long done[] = { pid, tid, 29, success, errors, actual_rv };
    emit("DONE", done, 6);
    receive(0, 'F');
    (void)raw6(SYS_exit, 0, 0, 0, 0, 0, 0);
    fail(101);
}
#endif

int main(int argc, char **argv) {
#ifdef DETAILED_EXEC_AFTER
    if (argc != 4 && argc != 5 && argc != 6) return 2;
    unsigned long parent = positive(argv[2]), token = positive(argv[3]);
    unsigned long measured = argc > 4 ? positive(argv[4]) : 17;
    unsigned long delay_ms = argc > 5 ? nonnegative(argv[5]) : 0;
    if (measured < 1 || measured > 10000 || delay_ms > 60000) return 3;
#else
    if (argc != 7 && argc != 8 && argc != 9) return 2;
    unsigned long parent = positive(argv[4]), token = positive(argv[5]);
    if (argv[2][0] != '/' || argv[3][0] != '/'
        || (argv[6][0] != '0' && argv[6][0] != '1' && argv[6][0] != '2') || argv[6][1]) return 3;
    /* Validate the after-image pacing passthrough before the worker exists. */
    unsigned long passthrough_measured = argc > 7 ? positive(argv[7]) : 17;
    unsigned long passthrough_delay = argc > 8 ? nonnegative(argv[8]) : 0;
    if (passthrough_measured < 1 || passthrough_measured > 10000
        || passthrough_delay > 60000) return 3;
    struct stat absent;
    if (lstat(argv[3], &absent) == 0 || errno != ENOENT) return 4;
#endif
    if (argv[1][0] != '/') return 5;
    /* Re-arm after exec before NEW_READY; check the actual parent's identity. */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || (unsigned long)getppid() != parent) return 6;
    void *provider = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!provider) return 7;
    call_fn call = (call_fn)dlsym(provider, "C_Initialize");
    struct stat physical;
    if (!call || stat(argv[1], &physical)) return 8;
    /* Publish the table once so public scan-only discovery can attach. The
     * getter itself is never a probed slot. */
    typedef unsigned long (*list_fn)(void **);
    list_fn get_list = (list_fn)dlsym(provider, "C_GetFunctionList");
    void *table = NULL;
    if (!get_list || get_list(&table) || !table) return 15;
    unsigned long pid = (unsigned long)getpid();
    unsigned long ready[] = { pid, (unsigned long)raw6(SYS_gettid, 0, 0, 0, 0, 0, 0),
                              (unsigned long)physical.st_dev, (unsigned long)physical.st_ino, token };
#ifdef DETAILED_EXEC_AFTER
    emit("NEW_READY", ready, 5);
    receive(0, 'P');
    struct request held = { .rv = 0, .token = token, .operation = 2 };
    unsigned long rv = call(&held);
    if (rv != 0) fail(102);
    unsigned long success = 1, errors = 0;
    calls(call, 1, measured, &success, &errors, delay_ms);
    unsigned long done[] = { pid, pid, measured, success, errors, token };
    emit("NEW_DONE", done, 6);
    receive(0, 'F');
#else
    emit("READY", ready, 5);
    receive(0, 'G');
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 9;
    size_t stack_size = 1024 * 1024, allocation = stack_size + 2 * (size_t)page;
    char *stack = mmap(NULL, allocation, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED || mprotect(stack + page, stack_size, PROT_READ | PROT_WRITE)) return 10;
    int go[2];
    if (pipe2(go, O_CLOEXEC)) return 11;
    /* Everything the execing frame dereferences is prepared before clone,
     * including the optional measured-phase pacing passthrough. */
    char *next_argv[7];
    next_argv[0] = argv[2];
    next_argv[1] = argv[1];
    next_argv[2] = argv[4];
    next_argv[3] = argv[5];
    int next_argc = 4;
    if (argc > 7) next_argv[next_argc++] = argv[7];
    if (argc > 8) next_argv[next_argc++] = argv[8];
    next_argv[next_argc] = NULL;
    char *next_envp[] = { "LC_ALL=C", NULL };
    struct worker_args args = {
        .call = call, .go = go[0], .parent = parent,
        .exec = { .rv = 5, .token = token, .operation = 1,
                  .expect_failure = argv[6][0] == '1',
                  .exec_path = argv[6][0] == '1' ? argv[3] : argv[2],
                  .exec_argv = next_argv, .exec_envp = next_envp }
    };
    _Alignas(4) int child_tid = -1;
    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
              | CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
    int tid = clone(worker, stack + page + stack_size, flags, &args, &child_tid, NULL, &child_tid);
    if (tid <= 0 || __atomic_load_n(&child_tid, __ATOMIC_ACQUIRE) != tid) return 12;
    unsigned long started[] = { pid, (unsigned long)tid, (unsigned long)child_tid };
    emit("THREAD", started, 3);
    write_all(go[1], "W", 1);
    if (argv[6][0] == '2') {
        /* Leader thread-exit: the worker owns the rest of the protocol. */
        unsigned long gone[] = { pid, (unsigned long)tid };
        emit("LEADER_EXIT", gone, 2);
        (void)raw6(SYS_exit, 0, 0, 0, 0, 0, 0);
        fail(104);
    }
    /* On success this physical leader dies in de_thread. The old child_tid
     * address is never claimed as proof of the execing task's termination. */
    kernel_join(&child_tid);
    if (!args.exec.expect_failure) fail(103);
    if (munmap(stack, allocation) || close(go[0]) || close(go[1])) return 13;
#endif
    if (dlclose(provider)) return 14;
    return 0;
}
#endif
