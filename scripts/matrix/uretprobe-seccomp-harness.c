/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Stand-in for a seccomp-hardened process hosting a PKCS#11 provider.
 *
 * Linux 6.11 moved uretprobes to a syscall-based trampoline: when a probed
 * function returns, the kernel makes the *target* issue __NR_uretprobe
 * (x86-64 nr 335) from a trampoline page. A seccomp filter that does not
 * allow that number therefore fires on a syscall the target never wrote --
 * so attaching a uretprobe can kill the process being observed.
 *
 * This harness arms an allowlist that deliberately omits 335 and then calls
 * probe_me() in a loop. scripts/matrix/verify-uretprobe-seccomp.sh attaches
 * the probe and classifies the kernel from how this process ends.
 *
 * argv[1]  kill | killthread | errno | log | none   seccomp default action
 * argv[2]  "control"  call a syscall the filter blocks, proving it bites
 *
 * Build: cc -O1 -static -o uretprobe-seccomp-harness uretprobe-seccomp-harness.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Everything the loop needs once the filter is armed. Deliberately excludes
 * __NR_uretprobe (the syscall under test) and __NR_getppid (the control). */
static const int ALLOWED[] = {
    __NR_write,   __NR_read,       __NR_brk,             __NR_futex,
    __NR_exit,    __NR_exit_group, __NR_rt_sigreturn,    __NR_nanosleep,
    __NR_mmap,    __NR_munmap,     __NR_mprotect,        __NR_madvise,
    __NR_getpid,  __NR_rt_sigaction,  __NR_rt_sigprocmask,
    __NR_clock_nanosleep,
};
#define NALLOWED ((int)(sizeof(ALLOWED) / sizeof(ALLOWED[0])))

static int arm(unsigned int action) {
    struct sock_filter f[8 + NALLOWED];
    int n = 0;
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                          offsetof(struct seccomp_data, arch));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                          AUDIT_ARCH_X86_64, 1, 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                          SECCOMP_RET_KILL_PROCESS);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                          offsetof(struct seccomp_data, nr));
    for (int i = 0; i < NALLOWED; i++) {
        /* jt hops to the trailing ALLOW; jf falls through to the next test. */
        f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                              ALLOWED[i], NALLOWED - i, 0);
    }
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, action);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = {.len = (unsigned short)n, .filter = f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 1;
    return syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0;
}

static void say(const char *s) {
    ssize_t ignored = write(1, s, strlen(s));
    (void)ignored;
}

/* The probe target. noinline plus the barrier keep the call and the return
 * that the uretprobe needs; without them the loop folds away at -O1. */
__attribute__((noinline)) static long probe_me(long x) {
    asm volatile("" ::: "memory");
    return x + 1;
}

int main(int argc, char **argv) {
    unsigned int action = SECCOMP_RET_KILL_PROCESS;
    const char *mode = argc > 1 ? argv[1] : "kill";
    if (!strcmp(mode, "killthread"))    action = SECCOMP_RET_KILL_THREAD;
    else if (!strcmp(mode, "errno"))    action = SECCOMP_RET_ERRNO | EPERM;
    else if (!strcmp(mode, "log"))      action = SECCOMP_RET_LOG;

    if (strcmp(mode, "none") && arm(action)) { say("ARM-FAILED\n"); return 3; }
    say("ARMED\n");

    if (argc > 2 && !strcmp(argv[2], "control")) {
        say("CONTROL: calling getppid, which the filter blocks\n");
        syscall(__NR_getppid);
        say("CONTROL-SURVIVED\n"); /* reachable only for errno/log/none */
        return 0;
    }

    long acc = 0;
    for (int i = 0; i < 600; i++) { /* ~30s, ample room to attach into */
        acc = probe_me(acc);
        struct timespec ts = {0, 50 * 1000 * 1000};
        clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
        if (i % 20 == 0) say("tick\n");
    }
    say(acc == 600 ? "LOOP-DONE\n" : "LOOP-MISCOUNTED\n");
    return 0;
}
