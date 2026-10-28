/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Uprobe fixture for the image-bank proof kernel cells (T-F2 E3).
 *
 * One symbol, `p11_bank_target`, carries every probed call; the mode comes
 * from argv and the control channel is always stdin (one line per release).
 * Modes:
 *   call <n>            call the target <n> times and exit 0.
 *   hold                call the target once with release armed: the target
 *                       prints ENTERED, blocks for one stdin line (EOF also
 *                       releases, so a dead controller cannot hang the cell),
 *                       then returns.
 *   fork <n>            fork <n> children that exit immediately; wait all.
 *                       Pure births: children never call the target.
 *   callfork <n>        fork <n> children; each calls the target once, then
 *                       exits. Distinct leaders, one admission each.
 *   threads <t> <n>     spawn <t> threads calling the target <n> times each;
 *                       every thread pauses after <n>/2 calls until stdin
 *                       releases it (one line per thread), so the controller
 *                       cuts deterministically mid-run. Prints HALF when all
 *                       threads reach the barrier.
 *   exec_call           print EXECED, wait for one stdin line, call the
 *                       target once, print CALLED, wait again, then exit.
 *                       Used after exec_prep re-images the child.
 *   exec_prep           fork; the child calls the target once (pre-exec
 *                       admission), then execs this binary in exec_call mode.
 *                       The parent waits and exits the child's status. The
 *                       child inherits stdin, so the controller handshake
 *                       survives the exec.
 *
 * Exit status is 0 on success, 2 on usage errors, 1 on failures. stdout is
 * line-oriented for the controller handshake (ENTERED/HALF/EXECED/DONE).
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned long long p11_bank_sink;
static int p11_bank_hold_armed;

/* The single probed symbol. Noinline, external linkage, opaque body so no
 * toolchain inlines, clones or tail-merges the probe site away. */
__attribute__((noinline)) unsigned long long p11_bank_target(unsigned long long x)
{
    unsigned long long y = x + 0x9e3779b97f4a7c15ULL;

    y ^= y >> 29;
    y *= 0xbf58476d1ce4e5b9ULL;
    y ^= y >> 32;
    p11_bank_sink += y;
    if (p11_bank_hold_armed) {
        char line[64];

        p11_bank_hold_armed = 0;
        fputs("ENTERED\n", stdout);
        fflush(stdout);
        /* One control line releases; EOF releases too (fail-open against a
         * dead controller, so cells cannot hang forever). */
        if (!fgets(line, sizeof(line), stdin))
            fputs("RELEASED-EOF\n", stdout);
        else
            fputs("RELEASED\n", stdout);
        fflush(stdout);
    }
    return y;
}

static int do_call(unsigned long long n)
{
    unsigned long long i;

    for (i = 0; i < n; i++)
        p11_bank_target(i);
    puts("DONE");
    return 0;
}

static int do_hold(void)
{
    p11_bank_hold_armed = 1;
    p11_bank_target(1);
    puts("DONE");
    return 0;
}

static int wait_all(unsigned long long n)
{
    unsigned long long i;
    int status = 0;

    for (i = 0; i < n; i++) {
        int code;
        pid_t got = wait(&code);

        if (got < 0) {
            perror("wait");
            return 1;
        }
        if (!WIFEXITED(code) || WEXITSTATUS(code) != 0)
            status = 1;
    }
    return status;
}

static int do_fork(unsigned long long n)
{
    unsigned long long i;

    for (i = 0; i < n; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid == 0)
            _exit(0);
    }
    return wait_all(n);
}

static int do_callfork(unsigned long long n)
{
    unsigned long long i;

    for (i = 0; i < n; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid == 0) {
            p11_bank_target(i);
            _exit(0);
        }
    }
    return wait_all(n);
}

/* In-flight N8 warmup: every thread makes this many calls before the
 * STARTED barrier, so they land in A deterministically; must match the
 * driver's INFLIGHT_WARMUP. */
#define INFLIGHT_WARMUP 100

struct thread_arg {
    unsigned long long n;
    unsigned long long base;
    pthread_barrier_t *barrier;
};

struct inflight_arg {
    unsigned long long n;
    unsigned long long base;
    pthread_barrier_t *barrier;
};

static void *inflight_thread(void *arg)
{
    struct inflight_arg *t = arg;
    unsigned long long i;

    for (i = 0; i < INFLIGHT_WARMUP; i++)
        p11_bank_target(t->base + i);
    pthread_barrier_wait(t->barrier);
    /* No stdin pause: free calls while the controller cuts. */
    for (i = 0; i < t->n; i++)
        p11_bank_target(t->base + INFLIGHT_WARMUP + i);
    return NULL;
}

static int do_inflight(unsigned long long t, unsigned long long n)
{
    pthread_t *threads;
    struct inflight_arg *args;
    pthread_barrier_t barrier;
    unsigned long long i;

    if (t == 0 || t > 64 || n == 0) {
        fprintf(stderr, "inflight needs 1..64 threads and n >= 1\n");
        return 2;
    }
    threads = calloc(t, sizeof(*threads));
    args = calloc(t, sizeof(*args));
    if (!threads || !args) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    pthread_barrier_init(&barrier, NULL, (unsigned)t + 1);
    for (i = 0; i < t; i++) {
        args[i].n = n;
        args[i].base = i * (n + INFLIGHT_WARMUP);
        args[i].barrier = &barrier;
        if (pthread_create(&threads[i], NULL, inflight_thread, &args[i])) {
            perror("pthread_create");
            return 1;
        }
    }
    /* Main joins the barrier: STARTED prints exactly when every thread
     * is past warmup, while all of them keep calling. */
    pthread_barrier_wait(&barrier);
    puts("STARTED");
    fflush(stdout);
    for (i = 0; i < t; i++)
        pthread_join(threads[i], NULL);
    pthread_barrier_destroy(&barrier);
    puts("DONE");
    return 0;
}

static void *thread_main(void *arg)
{
    struct thread_arg *t = arg;
    unsigned long long i;
    char line[64];

    for (i = 0; i < t->n / 2; i++)
        p11_bank_target(t->base + i);
    pthread_barrier_wait(t->barrier);
    /* The barrier serializes the halves; stdin releases each thread. */
    if (!fgets(line, sizeof(line), stdin))
        fputs("RELEASED-EOF\n", stdout);
    for (i = t->n / 2; i < t->n; i++)
        p11_bank_target(t->base + i);
    return NULL;
}

static int do_threads(unsigned long long t, unsigned long long n)
{
    pthread_t *threads;
    struct thread_arg *args;
    pthread_barrier_t barrier;
    unsigned long long i;

    if (t == 0 || t > 64 || n == 0 || n % 2) {
        fprintf(stderr, "threads needs 1..64 threads and even n\n");
        return 2;
    }
    threads = calloc(t, sizeof(*threads));
    args = calloc(t, sizeof(*args));
    if (!threads || !args) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    pthread_barrier_init(&barrier, NULL, (unsigned)t + 1);
    for (i = 0; i < t; i++) {
        args[i].n = n;
        args[i].base = i * n;
        args[i].barrier = &barrier;
        if (pthread_create(&threads[i], NULL, thread_main, &args[i])) {
            perror("pthread_create");
            return 1;
        }
    }
    /* Main joins the barrier: HALF prints exactly when every thread has
     * finished its first half, before any second-half call runs. */
    pthread_barrier_wait(&barrier);
    puts("HALF");
    fflush(stdout);
    for (i = 0; i < t; i++)
        pthread_join(threads[i], NULL);
    pthread_barrier_destroy(&barrier);
    puts("DONE");
    return 0;
}

static const char *self_argv0;

static int do_exec_prep(void)
{
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        p11_bank_target(3);
        execlp(self_argv0, self_argv0, "exec_call", (char *)NULL);
        perror("execlp");
        _exit(127);
    }
    return wait_all(1);
}

static int do_exec_call(void)
{
    char line[64];

    puts("EXECED");
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin))
        fputs("RELEASED-EOF\n", stdout);
    p11_bank_target(2);
    /* Stay alive for the re-seed query: the post-exec call must be
     * observable on a live task. */
    puts("CALLED");
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin))
        fputs("RELEASED-EOF\n", stdout);
    puts("DONE");
    return 0;
}

static unsigned long long parse_count(const char *text)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno || !end || *end || text == end) {
        fprintf(stderr, "bad count %s\n", text);
        exit(2);
    }
    return value;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: %s call <n>|hold|fork <n>|callfork <n>|threads <t> <n>|exec_call|exec_prep\n",
                argv[0]);
        return 2;
    }
    /* Line-buffered stdout even when piped: the controller handshake must
     * not wait for a full block. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    self_argv0 = argv[0];
    if (!strcmp(argv[1], "call") && argc == 3)
        return do_call(parse_count(argv[2]));
    if (!strcmp(argv[1], "hold") && argc == 2)
        return do_hold();
    if (!strcmp(argv[1], "fork") && argc == 3)
        return do_fork(parse_count(argv[2]));
    if (!strcmp(argv[1], "callfork") && argc == 3)
        return do_callfork(parse_count(argv[2]));
    if (!strcmp(argv[1], "threads") && argc == 4)
        return do_threads(parse_count(argv[2]), parse_count(argv[3]));
    if (!strcmp(argv[1], "inflight") && argc == 4)
        return do_inflight(parse_count(argv[2]), parse_count(argv[3]));
    if (!strcmp(argv[1], "exec_call") && argc == 2)
        return do_exec_call();
    if (!strcmp(argv[1], "exec_prep") && argc == 2)
        return do_exec_prep();
    fprintf(stderr, "usage: %s call <n>|hold|fork <n>|callfork <n>|threads <t> <n>|inflight <t> <n>|exec_call|exec_prep\n",
            argv[0]);
    return 2;
}
