/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mt_fork: multi-process deterministic mixed-function SoftHSM2 workload.
 *
 * usage: mt_fork MODULE PROCS THREADS ITERS GATE ERRORS
 *
 * The parent forks PROCS children after the gate opens; every child runs
 * the mt_mixed sessions workload (THREADS threads x ITERS mixed
 * iterations plus ERRORS bogus-handle probes per thread) and reports its
 * exact counts through a pipe. The parent prints one TARGET set, one
 * READY and one merged LEDGER v2, so the system-scope cell judges the
 * combined multi-process total exactly like a single workload. Any
 * child failure exits nonzero with no LEDGER.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MT_MIXED_AS_LIB 1
#include "mt_mixed.c"

static void mf_xread(int fd, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (char *)buf + got, len - got);
        if (n <= 0) {
            fprintf(stderr, "mt_fork: short child count read: %s\n",
                    n ? strerror(errno) : "eof");
            exit(1);
        }
        got += (size_t)n;
    }
}

static void mf_xwrite(int fd, const void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, (const char *)buf + done, len - done);
        if (n <= 0) {
            fprintf(stderr, "mt_fork: child count write failed\n");
            exit(1);
        }
        done += (size_t)n;
    }
}

int main(int argc, char **argv)
{
    struct mt_ctx ctx;
    struct mt_counts grand, one;
    long procs, threads, iters, errors;
    if (argc != 7) {
        fprintf(stderr, "usage: %s MODULE PROCS THREADS ITERS GATE ERRORS\n", argv[0]);
        return 2;
    }
    procs = atol(argv[2]);
    threads = atol(argv[3]);
    iters = atol(argv[4]);
    errors = atol(argv[6]);
    if (procs < 1 || procs > 16 || threads < 1 || threads > 256 || iters < 1 || errors < 0 ||
        errors > 100000) {
        fprintf(stderr, "bad PROCS/THREADS/ITERS/ERRORS\n");
        return 2;
    }
    memset(&ctx, 0, sizeof ctx);
    ctx.threads = (int)threads;
    ctx.iters = (int)iters;
    ctx.errors = (int)errors;
    mt_setup(&ctx.fns, &ctx.slot, argv[1]);
    mt_emit_targets(ctx.fns);
    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    mt_wait_gate(argv[5]);
    memset(&grand, 0, sizeof grand);
    for (long p = 0; p < procs; p++) {
        int pipefd[2];
        pid_t child;
        int status;
        if (pipe(pipefd) != 0) {
            perror("mt_fork: pipe");
            return 1;
        }
        child = fork();
        if (child < 0) {
            perror("mt_fork: fork");
            return 1;
        }
        if (child == 0) {
            /* No stdio here: only the parent prints TARGET/READY/LEDGER. */
            close(pipefd[0]);
            mt_run(&ctx, 0, &one);
            mt_verify(&one, (unsigned long)threads, (unsigned long)iters,
                      (unsigned long)errors);
            mf_xwrite(pipefd[1], &one, sizeof one);
            close(pipefd[1]);
            _exit(0);
        }
        printf("CHILD pid=%d\n", (int)child);
        fflush(stdout);
        close(pipefd[1]);
        mf_xread(pipefd[0], &one, sizeof one);
        close(pipefd[0]);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR)
            ;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "mt_fork: child %d failed\n", (int)child);
            return 1;
        }
        mt_add(&grand, &one);
    }
    mt_verify(&grand, (unsigned long)(procs * threads), (unsigned long)iters,
              (unsigned long)errors);
    mt_emit_ledger(&grand);
    mt_finalize(ctx.fns);
    return 0;
}
