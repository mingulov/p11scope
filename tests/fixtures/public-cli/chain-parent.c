/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* chain-parent: named launcher for the parent-chain public-CLI cell.
 * Usage: chain-parent PROG ARGS...
 * Forks and execs PROG, waits for it, and exits with its status, so the
 * workload has a stable, distinct parent exe name ("chain-parent"). */
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
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 3;
    }
    if (child == 0) {
        execv(argv[1], &argv[1]);
        perror("exec workload");
        _exit(127);
    }
    int status = 0;
    pid_t got;
    do {
        got = waitpid(child, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got < 0) {
        perror("waitpid");
        return 3;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 3;
}
