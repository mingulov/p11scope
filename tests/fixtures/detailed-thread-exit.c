/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Private x86-64 fixture. Build once as a DSO and once as its owned driver.
 * The raw clone worker never calls libc or accesses shared glibc TLS. The
 * probed C_Initialize frame uses SYS_exit, never pthread_exit/unwinding.
 * Only the kernel clears child_tid; the leader waits with shared FUTEX_WAIT.
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
#error "This owned lifecycle cell currently qualifies LP64 x86-64 only"
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

/* Each bounded line is written atomically to the private pipe. No stdio/TLS. */
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

static void receive(int fd, char expected, unsigned long seconds) {
    unsigned long deadline = clock_ns() + seconds * 1000000000UL;
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
    int abandon;
    int exit_gate;
};

#ifdef DETAILED_THREAD_EXIT_PROVIDER

__attribute__((noinline, visibility("default")))
unsigned long C_Initialize(void *argument) {
    const struct request *request = argument;
    __asm__ volatile("" ::: "memory");
    if (request->abandon) {
        unsigned long fields[] = {
            (unsigned long)raw6(SYS_getpid, 0, 0, 0, 0, 0, 0),
            (unsigned long)raw6(SYS_gettid, 0, 0, 0, 0, 0, 0)
        };
        emit("BODY", fields, 2);
        receive(request->exit_gate, 'X', 30);
        /* The actual probed frame does not return. This is per-thread exit. */
        (void)raw6(SYS_exit, 0, 0, 0, 0, 0, 0);
        fail(95);
    }
    return request->rv;
}

#else

#include <dlfcn.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef unsigned long (*call_fn)(void *);
struct worker_args {
    call_fn call;
    int go;
};

static void calls(call_fn call, unsigned long count, const char *phase) {
    unsigned long success = 0, error = 0;
    for (unsigned long i = 0; i < count; ++i) {
        struct request request = { .rv = (i & 1) ? 5 : 0, .abandon = 0, .exit_gate = 0 };
        unsigned long rv = call(&request);
        if (rv != request.rv) fail(96);
        if (rv == 0) ++success;
        else ++error;
    }
    unsigned long fields[] = {
        (unsigned long)raw6(SYS_getpid, 0, 0, 0, 0, 0, 0),
        (unsigned long)raw6(SYS_gettid, 0, 0, 0, 0, 0, 0),
        count, success, error
    };
    emit(phase, fields, 5);
}

static int worker(void *argument) {
    const struct worker_args *args = argument;
    receive(args->go, 'W', 30);
    calls(args->call, 11, "WORKER_DONE");
    struct request abandoned = { .rv = 777, .abandon = 1, .exit_gate = 0 };
    (void)args->call(&abandoned);
    fail(97);
}

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
        /* clear_child_tid wakes shared futex waiters, not FUTEX_WAIT_PRIVATE. */
        long result = raw6(SYS_futex, (long)child_tid, FUTEX_WAIT, observed,
                           (long)&timeout, 0, 0);
        if (result != 0 && result != -EAGAIN && result != -EINTR) fail(99);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char *end = NULL;
    unsigned long parent = strtoul(argv[2], &end, 10);
    if (!parent || !end || *end) return 3;
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || (unsigned long)getppid() != parent) return 4;
    void *provider = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!provider) return 5;
    call_fn call = (call_fn)dlsym(provider, "C_Initialize");
    struct stat physical;
    if (!call || stat(argv[1], &physical)) return 6;
    unsigned long pid = (unsigned long)getpid();
    unsigned long ready[] = { pid, (unsigned long)raw6(SYS_gettid, 0, 0, 0, 0, 0, 0),
                              (unsigned long)physical.st_dev, (unsigned long)physical.st_ino };
    emit("READY", ready, 4);
    receive(0, 'G', 60);

    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 7;
    size_t stack_size = 1024 * 1024;
    size_t allocation = stack_size + 2 * (size_t)page;
    char *stack = mmap(NULL, allocation, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED || mprotect(stack + page, stack_size, PROT_READ | PROT_WRITE)) return 8;
    int go[2];
    if (pipe(go)) return 9;
    struct worker_args args = { .call = call, .go = go[0] };
    _Alignas(4) int child_tid = -1;
    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
              | CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
    int tid = clone(worker, stack + page + stack_size, flags, &args, &child_tid, NULL, &child_tid);
    if (tid <= 0 || __atomic_load_n(&child_tid, __ATOMIC_ACQUIRE) != tid) return 10;
    unsigned long started[] = { pid, (unsigned long)tid, (unsigned long)child_tid };
    emit("THREAD", started, 3);
    write_all(go[1], "W", 1);

    kernel_join(&child_tid);
    unsigned long exited[] = { pid, (unsigned long)tid, (unsigned long)__atomic_load_n(&child_tid, __ATOMIC_ACQUIRE) };
    emit("EXITED", exited, 3);
    receive(0, 'L', 30);
    calls(call, 17, "LEADER_DONE");
    receive(0, 'F', 30);
    /* Retain stack, shared arguments and provider until the entire protocol ends. */
    if (munmap(stack, allocation) || close(go[0]) || close(go[1]) || dlclose(provider)) return 11;
    return 0;
}

#endif
