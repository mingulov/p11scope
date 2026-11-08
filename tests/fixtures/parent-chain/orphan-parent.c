/* SPDX-License-Identifier: GPL-3.0-or-later */
/* orphan-parent: double-fork launcher for the parent-chain orphan cell.
 * Usage: orphan-parent PROG ARGS...
 * Forks twice so PROG is reparented to init (pid 1), then reaps the
 * intermediate child and exits 0: the caller under test keeps no
 * userspace parent. PROG's own lifetime is gate-driven (see
 * chain-client.c); this parent never waits for it. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s PROG ARGS...\n", argv[0]);
        return 2;
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
        perror("waitpid");
        return 3;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }
    return 3;
}
