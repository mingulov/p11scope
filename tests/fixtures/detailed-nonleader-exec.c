/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Private LP64 x86-64 exec fixture: DSO, before driver, and distinct after driver.
 * The raw clone worker makes no libc/TLS calls. Only that worker reads stdin
 * after THREAD; the leader waits outside the provider until killed by exec or
 * the failed-exec worker's final kernel clear_child_tid. No uretprobe unwinding.
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

static void calls(call_fn call, unsigned long first, unsigned long end,
                  unsigned long *success, unsigned long *errors) {
    for (unsigned long i = first; i < end; ++i) {
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
    calls(args->call, 0, 11, &success, &errors);
    unsigned long pid = (unsigned long)raw6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    unsigned long tid = (unsigned long)raw6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    unsigned long completed[] = { pid, tid, 11, success, errors };
    emit("WORKER_DONE", completed, 5);
    unsigned long actual_rv = args->call((void *)&args->exec);
    /* The successful branch cannot return; errno2 is never a PKCS#11 RV. */
    if (!args->exec.expect_failure || actual_rv != 5) fail(97);
    ++errors;
    calls(args->call, 0, 17, &success, &errors);
    unsigned long done[] = { pid, tid, 29, success, errors, actual_rv };
    emit("DONE", done, 6);
    receive(0, 'F');
    (void)raw6(SYS_exit, 0, 0, 0, 0, 0, 0);
    fail(101);
}
#endif

int main(int argc, char **argv) {
#ifdef DETAILED_EXEC_AFTER
    if (argc != 4) return 2;
    unsigned long parent = positive(argv[2]), token = positive(argv[3]);
#else
    if (argc != 7) return 2;
    unsigned long parent = positive(argv[4]), token = positive(argv[5]);
    if (argv[2][0] != '/' || argv[3][0] != '/'
        || (argv[6][0] != '0' && argv[6][0] != '1') || argv[6][1]) return 3;
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
    calls(call, 1, 17, &success, &errors);
    unsigned long done[] = { pid, pid, 17, success, errors, token };
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
    /* Everything the execing frame dereferences is prepared before clone. */
    char *next_argv[] = { argv[2], argv[1], argv[4], argv[5], NULL };
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
