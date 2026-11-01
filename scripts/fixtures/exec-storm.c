/* SPDX-License-Identifier: GPL-3.0-or-later */
/* exec_storm: self-timed fork+exec churn for the birth-marker cost bench.
 * usage: exec_storm PROG OPS
 * Runs OPS x {fork, exec PROG, wait for exit} sequentially. PROG must exit
 * 0 quickly (/bin/true); any other outcome fails the run. Times only the
 * loop with CLOCK_MONOTONIC and prints one line:
 *   EXEC_STORM ops=N wall_ns=T prog=P
 * Exit nonzero (with FAIL on stderr) on any shortfall, so a sample that did
 * not run exactly OPS execs can never be mistaken for a measurement. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        fprintf(stderr, "FAIL clock\n");
        exit(1);
    }
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s PROG OPS\n", argc > 0 ? argv[0] : "exec_storm");
        return 2;
    }
    char *end = NULL;

    errno = 0;
    long ops = strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' || ops <= 0) {
        fprintf(stderr, "FAIL ops\n");
        return 2;
    }
    uint64_t start = now_ns();

    for (long i = 0; i < ops; i++) {
        pid_t child = fork();
        if (child < 0) {
            fprintf(stderr, "FAIL fork %ld: %s\n", i, strerror(errno));
            return 1;
        }
        if (child == 0) {
            execl(argv[1], argv[1], (char *)NULL);
            fprintf(stderr, "FAIL exec %ld: %s\n", i, strerror(errno));
            _exit(127);
        }
        int status = 0;

        while (waitpid(child, &status, 0) < 0) {
            if (errno != EINTR) {
                fprintf(stderr, "FAIL wait %ld: %s\n", i, strerror(errno));
                return 1;
            }
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "FAIL status %ld: %#x\n", i, (unsigned)status);
            return 1;
        }
    }
    uint64_t wall_ns = now_ns() - start;

    if (wall_ns == 0) {
        fprintf(stderr, "FAIL zero wall time\n");
        return 1;
    }
    printf("EXEC_STORM ops=%ld wall_ns=%lu prog=%s\n", ops, (unsigned long)wall_ns, argv[1]);
    return 0;
}
