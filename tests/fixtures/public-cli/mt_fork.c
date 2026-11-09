/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* mt_fork: multi-process deterministic mixed-function SoftHSM2 workload.
 *
 * usage: mt_fork MODULE PROCS THREADS ITERS GATE ERRORS
 *
 * The parent forks PROCS children before READY; every child waits on the
 * same gate, then runs the mt_mixed sessions workload (THREADS threads x
 * ITERS mixed iterations plus ERRORS bogus-handle probes per thread) and
 * reports its exact counts through a pipe. The parent prints one TARGET set, one
 * READY and one merged LEDGER v2, so the system-scope cell judges the
 * combined multi-process total exactly like a single workload. Any
 * child failure exits nonzero with no LEDGER. MT_MIXED_HOLD=1 holds the
 * parent AND the children after LEDGER (witness rows bind only to live
 * incarnations); the parent forwards SIGTERM/SIGINT to the children and
 * every process exits 0. Without the hold, children exit once counted.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MT_MIXED_AS_LIB 1
#include "mt_mixed.c"

#ifndef PR_SET_PDEATHSIG
#define PR_SET_PDEATHSIG 1
#endif

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
    /* Fork before READY so every workload process exists when the observer
     * attaches; children wait on the same gate and run after release. */
    {
        int (*pipefds)[2] = calloc((size_t)procs, sizeof *pipefds);
        pid_t *children = calloc((size_t)procs, sizeof *children);
        if (!pipefds || !children) {
            perror("mt_fork: alloc");
            return 1;
        }
        for (long p = 0; p < procs; p++) {
            pid_t child;
            if (pipe(pipefds[p]) != 0) {
                perror("mt_fork: pipe");
                return 1;
            }
            child = fork();
            if (child < 0) {
                perror("mt_fork: fork");
                return 1;
            }
            if (child == 0) {
                /* No stdio here: only the parent prints TARGET/READY/LEDGER.
                 * Children never finalize the inherited library. */
                const char *hold;
                close(pipefds[p][0]);
                prctl(PR_SET_PDEATHSIG, SIGTERM);
                mt_wait_gate(argv[5]);
                mt_run(&ctx, 0, &one);
                mt_verify(&one, (unsigned long)threads, (unsigned long)iters,
                          (unsigned long)errors, (unsigned long)threads, 0);
                mf_xwrite(pipefds[p][1], &one, sizeof one);
                close(pipefds[p][1]);
                /* Held mode keeps children alive for pass-based observers
                 * (witness rows bind only to live incarnations); the
                 * parent forwards termination, the death signal is backup. */
                hold = getenv("MT_MIXED_HOLD");
                if (hold && !strcmp(hold, "1"))
                    mt_hold_if_asked();
                _exit(0);
            }
            children[p] = child;
            printf("CHILD pid=%d\n", (int)child);
            fflush(stdout);
            close(pipefds[p][1]);
        }
        printf("READY pid=%d\n", (int)getpid());
        fflush(stdout);
        mt_wait_gate(argv[5]);
        {
            const char *hold = getenv("MT_MIXED_HOLD");
            int holding = hold && !strcmp(hold, "1");
            memset(&grand, 0, sizeof grand);
            for (long p = 0; p < procs; p++) {
                mf_xread(pipefds[p][0], &one, sizeof one);
                close(pipefds[p][0]);
                if (!holding) {
                    int status;
                    while (waitpid(children[p], &status, 0) < 0 && errno == EINTR)
                        ;
                    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                        fprintf(stderr, "mt_fork: child %d failed\n", (int)children[p]);
                        return 1;
                    }
                }
                mt_add(&grand, &one);
            }
            mt_finalize(ctx.fns, &grand);
            mt_verify(&grand, (unsigned long)(procs * threads), (unsigned long)iters,
                      (unsigned long)errors, (unsigned long)(procs * threads), 1);
            mt_emit_ledger(&grand);
            if (holding) {
                /* Forward termination to the held children, then reap. */
                mt_hold_if_asked();
                for (long p = 0; p < procs; p++)
                    kill(children[p], SIGTERM);
                for (long p = 0; p < procs; p++) {
                    int status;
                    while (waitpid(children[p], &status, 0) < 0 && errno == EINTR)
                        ;
                    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                        fprintf(stderr, "mt_fork: child %d failed\n", (int)children[p]);
                        return 1;
                    }
                }
            }
        }
        free(pipefds);
        free(children);
    }
    return 0;
}
