/* SPDX-License-Identifier: GPL-3.0-or-later */
/* subreaper-parent: adopting launcher for the parent-chain subreaper cell.
 * Usage: subreaper-parent PROG ARGS...
 * Marks itself PR_SET_CHILD_SUBREAPER, forks an intermediate that forks
 * PROG and exits at once, then waits for the adopted PROG and exits with
 * its status. Behavioural twin of chain-parent under adoption: same
 * READY/GATE contract, but PROG's parent is the adopting subreaper. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s PROG ARGS...\n", argv[0]);
        return 2;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        perror("prctl PR_SET_CHILD_SUBREAPER");
        return 3;
    }
    pid_t mid = fork();
    if (mid < 0) {
        perror("fork");
        return 3;
    }
    if (mid == 0) {
        pid_t leaf = fork();
        if (leaf < 0) {
            perror("fork");
            _exit(3);
        }
        if (leaf == 0) {
            execv(argv[1], &argv[1]);
            perror("exec workload");
            _exit(127);
        }
        _exit(0);
    }
    int status = 0;
    pid_t got;
    do {
        got = waitpid(mid, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got < 0) {
        perror("waitpid intermediate");
        return 3;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return 3;
    }
    /* The only child left is the adopted PROG. */
    do {
        got = wait(&status);
    } while (got < 0 && errno == EINTR);
    if (got < 0) {
        perror("wait adopted");
        return 3;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 3;
}
